//! The PEP's episodes (E1, A1).
//!
//! For each live episode the registry holds its actor's two senders, its intent and its rate
//! bucket (T1); for each intent, its ledger (R1), which the episode's actor hands back when it
//! stops. An intent has at most one live episode, an ended one whose upstream legs are still
//! running included, and at most `limits.episodes` are live in all (E1).
//!
//! Connection threads use only [`Registry::admit`], which verifies an Episode Token and gives
//! back the episode's [`AgentSender`]. Starting, ending, approving and the rest take
//! `&HostAuthority` or the episode's [`HostSender`], which only the control thread holds.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read};
use std::sync::{Arc, Mutex, MutexGuard, mpsc};
use std::time::{Duration, Instant};

use crate::actor::{self, AgentSender, HostMessage, HostSender, Services};
use crate::config::IntentConfig;
use crate::control::{ControlError, PendingPayment};
use crate::engine::{HostAuthority, Ledger, PepEngine, Shared, ToolPins, encode_ulid};
use crate::tokens::{
    EPISODE_MAX_LIFETIME_SECS, EpisodeClaims, EpisodeStates, Es256Signer, Es256Verifier,
    mint_episode_token, verify_episode_token_with,
};

/// The Week 2 `client_id` claim (E1); Week 5's RAR replaces it.
pub const CLIENT_ID: &str = "pep-sidecar-week2";
/// Episodes whose tokens the registry remembers, ended ones included, until they expire.
pub const MAX_REMEMBERED_EPISODES: usize = 4096;
/// How long `end` waits for the actor to release its waiting payments.
pub const END_TIMEOUT: Duration = Duration::from_secs(5);

/// The registry's fixed inputs.
#[derive(Debug, Clone)]
pub struct RegistryConfig {
    /// The configured intents, by name.
    pub intents: BTreeMap<String, IntentConfig>,
    /// The pins.
    pub pins: ToolPins,
    /// The agent's uid, the token's `peer_uid` (M1).
    pub agent_uid: u32,
    /// Live episodes at once (E1).
    pub episodes: usize,
    /// Calls an episode may make at once (T1).
    pub call_burst: u32,
    /// Calls per second an episode may sustain (T1).
    pub call_rate_per_s: u32,
    /// An episode with no call for this long is over (T1).
    pub idle_secs: u64,
    /// Clock skew allowed on token times.
    pub skew_secs: u64,
}

/// A started episode, as `start_episode` returns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Started {
    /// The fresh eid (E1).
    pub eid: u128,
    /// Its Episode Token.
    pub token: String,
    /// The token's expiry, in Unix seconds.
    pub exp: u64,
}

/// Why a connection's token was not admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// A missing, invalid, expired, idle or ended token: `PEP_DENIED` (U1 step 14).
    Denied,
    /// The episode's rate limit, or a PEP fault: `PEP_UNAVAILABLE` (U1 step 15).
    Unavailable,
}

/// A token bucket, in thousandths of a call, so whole-number arithmetic suffices.
#[derive(Debug, Clone, Copy)]
struct Bucket {
    millicalls: u64,
    last_ms: u64,
}

struct Live {
    intent_digest: String,
    agent: AgentSender,
    host: HostSender,
    bucket: Bucket,
    ending: bool,
}

struct Inner {
    ledgers: BTreeMap<String, Ledger>,
    live: BTreeMap<u128, Live>,
    busy: BTreeSet<String>,
}

/// The PEP's episodes.
pub struct Registry {
    config: RegistryConfig,
    episode_key: Es256Signer,
    verifier: Es256Verifier,
    states: EpisodeStates,
    shared: Shared,
    services: Arc<Services>,
    started: Instant,
    inner: Mutex<Inner>,
}

impl std::fmt::Debug for Registry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Registry")
            .field("states", &self.states)
            .finish_non_exhaustive()
    }
}

impl Registry {
    /// A registry whose intents start from `ledgers`, the journal's replay (R1). The Episode
    /// Token key is `episode_key`, separate from the Call Proof key (E1).
    #[must_use]
    pub fn new(
        config: RegistryConfig,
        episode_key: Es256Signer,
        ledgers: BTreeMap<String, Ledger>,
        shared: Shared,
        services: Arc<Services>,
    ) -> Arc<Self> {
        let states =
            EpisodeStates::new(MAX_REMEMBERED_EPISODES, config.idle_secs, config.skew_secs);
        Arc::new(Self {
            verifier: episode_key.verifier(),
            config,
            episode_key,
            states,
            shared,
            services,
            started: Instant::now(),
            inner: Mutex::new(Inner {
                ledgers,
                live: BTreeMap::new(),
                busy: BTreeSet::new(),
            }),
        })
    }

    fn lock(&self) -> Result<MutexGuard<'_, Inner>, ControlError> {
        self.inner.lock().map_err(|_| ControlError::Unavailable)
    }

    /// `start_episode` (E1): a fresh eid, an engine built from the intent's ledger, its actor,
    /// and its Episode Token.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::UnknownIntent`], [`ControlError::IntentBusy`] while the intent
    /// has a live episode, [`ControlError::EpisodesFull`] once `limits.episodes` are live,
    /// [`ControlError::Refused`] if the engine refuses the intent, or
    /// [`ControlError::Unavailable`] for a PEP fault.
    pub fn start(
        self: &Arc<Self>,
        host: &HostAuthority,
        intent_name: &str,
    ) -> Result<Started, ControlError> {
        let configured = self
            .config
            .intents
            .get(intent_name)
            .ok_or(ControlError::UnknownIntent)?;
        let now = (self.services.now)().map_err(|_| ControlError::Unavailable)?;
        let mut inner = self.lock()?;
        if inner.busy.contains(intent_name) {
            return Err(ControlError::IntentBusy);
        }
        if inner.busy.len() >= self.config.episodes {
            return Err(ControlError::EpisodesFull);
        }
        let eid = self.new_id(now)?;
        let mut intent = configured.intent.clone();
        intent.episode_id = eid;
        let ledger = inner
            .ledgers
            .get(intent_name)
            .cloned()
            .unwrap_or_else(Ledger::empty);
        let engine = PepEngine::new(
            host,
            intent.clone(),
            self.config.pins.clone(),
            configured.seq.clone(),
            self.shared.clone(),
            ledger,
        )
        .map_err(|_| ControlError::Refused)?;
        let exp = now
            .checked_add(EPISODE_MAX_LIFETIME_SECS)
            .ok_or(ControlError::Unavailable)?;
        let claims = EpisodeClaims {
            eid,
            intent_digest: intent.intent_digest.clone(),
            sub: intent_name.to_owned(),
            client_id: CLIENT_ID.to_owned(),
            peer_uid: self.config.agent_uid,
            release_epoch: self.config.pins.release_epoch,
            rar_digest: intent.intent_digest.clone(),
            iat: now,
            exp,
        };
        let token = mint_episode_token(&self.episode_key, &claims)
            .map_err(|_| ControlError::Unavailable)?;
        self.states
            .start(eid, exp, now)
            .map_err(|_| ControlError::Unavailable)?;
        let registry = Arc::clone(self);
        let name = intent_name.to_owned();
        let (agent, host_sender, _thread) = actor::spawn(
            engine,
            name.clone(),
            Arc::clone(&self.services),
            Box::new(move |ledger| registry.finish(&name, eid, ledger)),
        )
        .map_err(|_| ControlError::Unavailable)?;
        inner.busy.insert(intent_name.to_owned());
        inner.live.insert(
            eid,
            Live {
                intent_digest: intent.intent_digest,
                agent,
                host: host_sender,
                bucket: Bucket {
                    // A burst too large to count starts empty (fail closed).
                    millicalls: u64::from(self.config.call_burst)
                        .checked_mul(1000)
                        .unwrap_or(0),
                    last_ms: self.now_ms(),
                },
                ending: false,
            },
        );
        Ok(Started { eid, token, exp })
    }

    /// The actor stopped: keep the intent's ledger for its next episode, and free the intent.
    fn finish(&self, intent: &str, eid: u128, ledger: Ledger) {
        // A poisoned registry refuses every later start, so a ledger it cannot keep is never
        // replaced by a stale one.
        if let Ok(mut inner) = self.inner.lock() {
            inner.ledgers.insert(intent.to_owned(), ledger);
            inner.busy.remove(intent);
            inner.live.remove(&eid);
        }
    }

    /// `end_episode` (E1): every later use of its tokens is refused, and its waiting payments
    /// are released; upstream legs finish, and the intent stays busy until the last one does.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::UnknownEpisode`] if the episode is not live.
    pub fn end(&self, _host: &HostAuthority, eid: u128) -> Result<(), ControlError> {
        let sender = {
            let mut inner = self.lock()?;
            let live = inner
                .live
                .get_mut(&eid)
                .ok_or(ControlError::UnknownEpisode)?;
            live.ending = true;
            live.host.clone()
        };
        // Refuse the episode's tokens before its actor hears of the end. An episode the table
        // has already dropped has no token left to refuse.
        drop(self.states.end(eid));
        let (reply, answer) = mpsc::sync_channel(1);
        if sender.send(HostMessage::End { reply }).is_ok() {
            let _ = answer.recv_timeout(END_TIMEOUT);
        }
        Ok(())
    }

    /// Ends every live episode that is idle, expired or already ended in the token table, so
    /// its intent can start another. Returns the eids it ended.
    pub fn reap(&self, host: &HostAuthority, now: u64) -> Vec<u128> {
        let over: Vec<u128> = match self.inner.lock() {
            Ok(inner) => inner
                .live
                .iter()
                .filter(|(eid, live)| !live.ending && self.states.is_over(**eid, now))
                .map(|(eid, _)| *eid)
                .collect(),
            Err(_) => Vec::new(),
        };
        over.into_iter()
            .filter(|eid| self.end(host, *eid).is_ok())
            .collect()
    }

    /// The host side of a live episode, for approvals and trusted inputs.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::UnknownEpisode`] if the episode is not live.
    pub fn host(&self, eid: u128) -> Result<HostSender, ControlError> {
        self.lock()?
            .live
            .get(&eid)
            .filter(|live| !live.ending)
            .map(|live| live.host.clone())
            .ok_or(ControlError::UnknownEpisode)
    }

    /// Every payment awaiting approval, in every live episode.
    #[must_use]
    pub fn pending(&self) -> Vec<PendingPayment> {
        let senders: Vec<HostSender> = match self.inner.lock() {
            Ok(inner) => inner.live.values().map(|live| live.host.clone()).collect(),
            Err(_) => Vec::new(),
        };
        let mut payments = Vec::new();
        for sender in senders {
            let (reply, answer) = mpsc::sync_channel(1);
            if sender.send(HostMessage::Pending { reply }).is_ok()
                && let Ok(found) = answer.recv_timeout(END_TIMEOUT)
            {
                payments.extend(found);
            }
        }
        payments
    }

    /// The intent's ledger, as its last finished episode left it.
    #[must_use]
    pub fn ledger(&self, intent: &str) -> Option<Ledger> {
        self.inner.lock().ok()?.ledgers.get(intent).cloned()
    }

    /// Admits one use of `token` on a connection from `peer_uid` (U1 steps 14 and 15): the
    /// token must verify, name a live episode with its own intent's digest, and find a call in
    /// the episode's rate bucket.
    ///
    /// # Errors
    ///
    /// Returns [`Admission::Denied`] for the token, or [`Admission::Unavailable`] for the rate
    /// limit or a PEP fault.
    pub fn admit(&self, token: &str, peer_uid: u32, now: u64) -> Result<AgentSender, Admission> {
        let mut inner = self.inner.lock().map_err(|_| Admission::Unavailable)?;
        let claims = verify_episode_token_with(
            token,
            &self.verifier,
            peer_uid,
            self.config.pins.release_epoch,
            // An ended episode's tokens are refused by the token table (T1), which `end`
            // updates before the actor hears of it.
            |eid| inner.live.get(&eid).map(|live| live.intent_digest.clone()),
            &self.states,
            now,
        )
        .map_err(|_| Admission::Denied)?;
        let now_ms = self.now_ms();
        let config = &self.config;
        let live = inner.live.get_mut(&claims.eid).ok_or(Admission::Denied)?;
        if !take(
            &mut live.bucket,
            now_ms,
            config.call_burst,
            config.call_rate_per_s,
        ) {
            return Err(Admission::Unavailable);
        }
        Ok(live.agent.clone())
    }

    /// A fresh PEP-assigned id for one agent call (M1): a ULID, unique across boots.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Unavailable`] if the clock or the entropy fails.
    pub fn call_id(&self) -> Result<String, ControlError> {
        let now = (self.services.now)().map_err(|_| ControlError::Unavailable)?;
        self.new_id(now).map(encode_ulid)
    }

    /// Milliseconds since the registry started, from the monotonic clock.
    fn now_ms(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// A fresh ULID: the time, then 80 random bits.
    fn new_id(&self, now: u64) -> Result<u128, ControlError> {
        let mut entropy = self
            .services
            .entropy
            .lock()
            .map_err(|_| ControlError::Unavailable)?;
        let millis = now.checked_mul(1000).ok_or(ControlError::Unavailable)?;
        new_ulid(&mut **entropy, millis).map_err(|_| ControlError::Unavailable)
    }
}

/// Takes one call from `bucket` at `now_ms`, after refilling it at `rate_per_s` up to
/// `burst`. A clock that steps back refills nothing.
fn take(bucket: &mut Bucket, now_ms: u64, burst: u32, rate_per_s: u32) -> bool {
    const ONE: u64 = 1000;
    let cap = u64::from(burst).checked_mul(ONE).unwrap_or(0);
    // Saturating gives 0, no refill, the stricter outcome; the clock is monotonic anyway.
    let elapsed = now_ms.saturating_sub(bucket.last_ms);
    // `rate_per_s` calls per second is `rate_per_s` thousandths of a call per millisecond.
    let refill = elapsed.checked_mul(u64::from(rate_per_s)).unwrap_or(cap);
    bucket.millicalls = bucket
        .millicalls
        .checked_add(refill)
        .map_or(cap, |total| total.min(cap));
    bucket.last_ms = bucket.last_ms.max(now_ms);
    match bucket.millicalls.checked_sub(ONE) {
        Some(left) => {
            bucket.millicalls = left;
            true
        }
        None => false,
    }
}

/// A ULID from `now_ms` (its low 48 bits) and 80 bits read from `entropy`.
///
/// # Errors
///
/// Returns the error of reading `entropy`.
pub fn new_ulid(entropy: &mut dyn Read, now_ms: u64) -> io::Result<u128> {
    let mut bytes = [0u8; 16];
    let time = now_ms.to_be_bytes();
    if let (Some(head), Some(low)) = (bytes.get_mut(..6), time.get(2..)) {
        head.copy_from_slice(low);
    }
    if let Some(tail) = bytes.get_mut(6..) {
        entropy.read_exact(tail)?;
    }
    Ok(u128::from_be_bytes(bytes))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use crate::actor::Upstream;
    use crate::engine::{
        Confidentiality, Entities, EntitySet, InMemoryLabelStore, Limits, PepIntent, SeqPolicy,
        ServerStates, UnresolvedEntities,
    };
    use crate::forward::UpstreamRequest;
    use crate::jcs::{self, ParseOptions};
    use crate::journal::{Journal, spawn_writer};
    use crate::lockfile::parse_payload;
    use crate::tokens::{os_entropy, unix_now};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    const PINS: &str = r#"{"lockfile_version":1,"release_epoch":7,"stores":{},
      "servers":{"a":{"endpoint":"http://a/mcp","identity":"spiffe://a","protocol_version":"2026-07-28","discover":{},"tools":{
        "get_ticket":{"definition":{"name":"get_ticket"},"policy":{"effect":"read","args":[{"pointer":"/id","role":"data"}],
          "sink_clearance":"secret","output_label":{"conf":"internal","integ":"untrusted_external"},"max_result_bytes":65536,"max_result_nodes":1024}}}}}}"#;
    const AGENT: u32 = 20_001;

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    #[derive(Debug)]
    struct Silent;

    impl Upstream for Silent {
        fn call(&self, _: &UpstreamRequest, _: Duration) -> Option<Vec<u8>> {
            None
        }
    }

    struct Fixture {
        registry: Arc<Registry>,
        dir: std::path::PathBuf,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            drop(std::fs::remove_dir_all(&self.dir));
        }
    }

    /// Answers nothing, after `delay`.
    #[derive(Debug)]
    struct Slow(Duration);

    impl Upstream for Slow {
        fn call(&self, _: &UpstreamRequest, _: Duration) -> Option<Vec<u8>> {
            thread::sleep(self.0);
            None
        }
    }

    fn fixture(episodes: usize, call_burst: u32, idle_secs: u64) -> Fixture {
        fixture_with(Arc::new(Silent), episodes, call_burst, idle_secs)
    }

    fn fixture_with(
        upstream: Arc<dyn Upstream>,
        episodes: usize,
        call_burst: u32,
        idle_secs: u64,
    ) -> Fixture {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("pep-registry-{}-{n}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let (journal, _) =
            Journal::open(&dir.join("journal.jsonl"), &dir.join("journal.lock")).unwrap();
        let (handle, _writer) = spawn_writer(journal).unwrap();
        let value = jcs::parse_with(PINS.as_bytes(), &ParseOptions::definition())
            .unwrap()
            .value;
        let lockfile = parse_payload(&value, "pins").unwrap();
        let intent = |name: &str| IntentConfig {
            intent: PepIntent {
                episode_id: 0,
                intent_digest: format!("sha-256:{name}"),
                release_epoch: 7,
                lockfile_digest: lockfile.digest.clone(),
                limits: Limits {
                    currency: "USD".to_owned(),
                    per_call_max_minor: 100,
                    cumulative_max_minor: 100,
                    max_calls: 1,
                    step_up_over_minor: 100,
                },
                entities: Entities {
                    ids: EntitySet::RecipientIds(["rcpt_A".to_owned()].into()),
                    per_entity_max_uses: 1,
                },
            },
            seq: SeqPolicy::Unconstrained,
        };
        let servers = Arc::new(ServerStates::empty());
        servers.set_serving("a").unwrap();
        let shared = Shared {
            labels: Arc::new(InMemoryLabelStore::with_capacity(100)),
            servers,
            unresolved: Arc::new(UnresolvedEntities::empty()),
        };
        let services = Arc::new(Services {
            host: Arc::new(HostAuthority::for_tests()),
            journal: handle,
            proof_key: Es256Signer::from_secret_bytes(&[3; 32]).unwrap(),
            entropy: Mutex::new(Box::new(os_entropy().unwrap())),
            upstream,
            pins: lockfile.pins.clone(),
            step_up_timeout: Duration::from_secs(5),
            upstream_timeout: Duration::from_secs(5),
            now: unix_now,
        });
        let config = RegistryConfig {
            intents: ["a", "b", "c"]
                .into_iter()
                .map(|name| (name.to_owned(), intent(name)))
                .collect(),
            pins: lockfile.pins,
            agent_uid: AGENT,
            episodes,
            call_burst,
            call_rate_per_s: 1,
            idle_secs,
            skew_secs: 2,
        };
        let registry = Registry::new(
            config,
            Es256Signer::from_secret_bytes(&[4; 32]).unwrap(),
            BTreeMap::new(),
            shared,
            services,
        );
        Fixture { registry, dir }
    }

    fn host() -> HostAuthority {
        HostAuthority::for_tests()
    }

    fn now() -> u64 {
        unix_now().unwrap()
    }

    /// Starts `intent` once its previous episode has stopped.
    fn start_when_free(registry: &Arc<Registry>, intent: &str) -> Started {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match registry.start(&host(), intent) {
                Err(ControlError::IntentBusy) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(5));
                }
                other => return other.unwrap(),
            }
        }
    }

    #[test]
    fn one_live_episode_per_intent_and_a_limit_on_all() {
        let fixture = fixture(2, 10, 1800);
        let registry = &fixture.registry;
        let a = registry.start(&host(), "a").unwrap();
        assert!(registry.admit(&a.token, AGENT, now()).is_ok());
        assert_eq!(registry.start(&host(), "a"), Err(ControlError::IntentBusy));
        let b = registry.start(&host(), "b").unwrap();
        assert_ne!(a.eid, b.eid);
        assert_eq!(
            registry.start(&host(), "c"),
            Err(ControlError::EpisodesFull)
        );
        assert_eq!(
            registry.start(&host(), "zz"),
            Err(ControlError::UnknownIntent)
        );
        registry.end(&host(), a.eid).unwrap();
        registry.end(&host(), b.eid).unwrap();
    }

    #[test]
    fn tokens_are_bound_to_their_peer_their_key_and_a_live_episode() {
        let fixture = fixture(2, 10, 1800);
        let registry = &fixture.registry;
        let started = registry.start(&host(), "a").unwrap();
        assert_eq!(
            registry.admit(&started.token, AGENT + 1, now()).err(),
            Some(Admission::Denied)
        );
        assert_eq!(
            registry.admit("eyJ.not.a-token", AGENT, now()).err(),
            Some(Admission::Denied)
        );
        let other = foreign_token();
        assert_eq!(
            registry.admit(&other, AGENT, now()).err(),
            Some(Admission::Denied)
        );
        registry.end(&host(), started.eid).unwrap();
        assert_eq!(
            registry.admit(&started.token, AGENT, now()).err(),
            Some(Admission::Denied)
        );
    }

    /// A token for an episode of another registry, signed with another key.
    fn foreign_token() -> String {
        let other = fixture(1, 10, 1800);
        let started = other.registry.start(&host(), "a").unwrap();
        other.registry.end(&host(), started.eid).unwrap();
        started.token
    }

    #[test]
    fn an_ended_episode_refuses_tokens_while_its_legs_run() {
        // E1: after end the episode stays live until its last upstream leg is done; its
        // tokens are refused from the moment it ends.
        let fixture = fixture_with(Arc::new(Slow(Duration::from_millis(400))), 1, 10, 1800);
        let registry = &fixture.registry;
        let started = registry.start(&host(), "a").unwrap();
        let agent = registry.admit(&started.token, AGENT, now()).unwrap();
        let pep_id = encode_ulid(42);
        let (reply, answer) = mpsc::sync_channel(1);
        agent
            .send(actor::AgentMessage::Call {
                pep_id: pep_id.clone(),
                request: format!(
                    r#"{{"id":"{pep_id}","jsonrpc":"2.0","method":"tools/call","params":{{"arguments":{{"id":"T-1"}},"name":"get_ticket"}}}}"#
                )
                .into_bytes(),
                reply,
            })
            .unwrap();
        // Let the call reach its worker before ending.
        thread::sleep(Duration::from_millis(100));
        registry.end(&host(), started.eid).unwrap();
        assert_eq!(registry.start(&host(), "a"), Err(ControlError::IntentBusy));
        assert_eq!(
            registry.admit(&started.token, AGENT, now()).err(),
            Some(Admission::Denied)
        );
        // The leg still finishes, and its outcome reaches the agent.
        assert_eq!(
            answer.recv_timeout(Duration::from_secs(5)).unwrap(),
            actor::CallReply::Unavailable
        );
        let next = start_when_free(registry, "a");
        registry.end(&host(), next.eid).unwrap();
    }

    #[test]
    fn end_frees_the_intent_and_keeps_its_ledger() {
        let fixture = fixture(1, 10, 1800);
        let registry = &fixture.registry;
        let first = registry.start(&host(), "a").unwrap();
        let (reply, answer) = mpsc::sync_channel(1);
        registry
            .host(first.eid)
            .unwrap()
            .send(HostMessage::TrustedInput {
                input_id: "u1".to_owned(),
                value: br#"{"note":"confidential"}"#.to_vec(),
                conf: Confidentiality::Confidential,
                reply,
            })
            .unwrap();
        assert_eq!(answer.recv_timeout(Duration::from_secs(5)).unwrap(), Ok(()));
        registry.end(&host(), first.eid).unwrap();
        assert_eq!(
            registry.host(first.eid).err(),
            Some(ControlError::UnknownEpisode)
        );
        // The next episode of the intent starts from the first one's ledger (R1).
        let second = start_when_free(registry, "a");
        assert_ne!(second.eid, first.eid);
        assert_eq!(
            registry.ledger("a").unwrap().context_conf,
            Confidentiality::Confidential
        );
        registry.end(&host(), second.eid).unwrap();
    }

    #[test]
    fn the_rate_limit_answers_unavailable() {
        let fixture = fixture(1, 2, 1800);
        let registry = &fixture.registry;
        let started = registry.start(&host(), "a").unwrap();
        assert!(registry.admit(&started.token, AGENT, now()).is_ok());
        assert!(registry.admit(&started.token, AGENT, now()).is_ok());
        assert_eq!(
            registry.admit(&started.token, AGENT, now()).err(),
            Some(Admission::Unavailable)
        );
        registry.end(&host(), started.eid).unwrap();
    }

    #[test]
    fn idle_episodes_are_reaped() {
        let fixture = fixture(1, 10, 60);
        let registry = &fixture.registry;
        let started = registry.start(&host(), "a").unwrap();
        assert!(registry.reap(&host(), now()).is_empty());
        assert_eq!(registry.reap(&host(), now() + 120), vec![started.eid]);
        assert_eq!(
            registry.admit(&started.token, AGENT, now() + 120).err(),
            Some(Admission::Denied)
        );
        let next = start_when_free(registry, "a");
        registry.end(&host(), next.eid).unwrap();
    }

    #[test]
    fn ulids_carry_the_time_then_randomness() {
        let id = new_ulid(&mut io::repeat(0xab), 0x0123_4567_89ab).unwrap();
        assert_eq!(
            &id.to_be_bytes()[..6],
            &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab]
        );
        assert!(id.to_be_bytes()[6..].iter().all(|&byte| byte == 0xab));
        assert_eq!(encode_ulid(id).len(), 26);
        assert!(new_ulid(&mut io::empty(), 0).is_err());
    }
}
