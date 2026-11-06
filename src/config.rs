//! The PEP's config file (`WEEK2_PLAN` §2a), parsed with `jcs`.
//!
//! The whole file is parsed once under the definition profile, because its `pins` section is
//! the unsigned lockfile v1 payload, whose upstream definitions hold fractions and can be large
//! (RV4 #13). Every other section admits only safe non-negative integers, which is what the
//! request profile would admit. Unknown fields are load errors at every depth, and each error
//! names the path of the field it is about.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::engine::{
    ConfigError, Entities, EntitySet, Limits, PepIntent, SeqPolicy, validate_config,
};
use crate::jcs::{self, JcsError, JcsObject, JcsValue, ParseOptions};
use crate::lockfile::{self, Lockfile};
use crate::tokens::Es256Verifier;

/// The longest the step-up wait and the upstream leg may take together, in milliseconds: the
/// TypeScript SDK's 60-second request timer, less a margin (P1).
pub const MAX_STEP_UP_PLUS_UPSTREAM_MS: u64 = 55_000;
/// The default upstream timeout (P1).
pub const DEFAULT_UPSTREAM_TIMEOUT_MS: u64 = 10_000;
/// The default step-up wait (P1).
pub const DEFAULT_STEP_UP_TIMEOUT_MS: u64 = 45_000;
/// The default drift poll interval (L1).
pub const DEFAULT_DRIFT_POLL_MS: u64 = 5_000;
/// The default deadline of one drift poll (L1).
pub const DEFAULT_DRIFT_POLL_DEADLINE_MS: u64 = 3_000;
/// Longest intent name: it keys the journal's ledger (R1).
pub const MAX_INTENT_NAME: usize = 64;

/// A config that could not be loaded: where, and what is wrong.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{path}: {problem}")]
pub struct LoadError {
    /// The field's path, such as `intents.pay.limits.currency`; empty for the whole file.
    pub path: String,
    /// What is wrong with it.
    pub problem: Problem,
}

impl LoadError {
    /// An error about the field at `path`.
    #[must_use]
    pub fn at(path: &str, problem: Problem) -> Self {
        Self {
            path: path.to_owned(),
            problem,
        }
    }
}

/// What is wrong with a field.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Problem {
    /// The file is not JSON under the definition profile.
    #[error("not valid JSON: {0}")]
    Json(JcsError),
    /// A required field is absent.
    #[error("missing")]
    Missing,
    /// A field the format does not define.
    #[error("unexpected field")]
    Unexpected,
    /// A field of the wrong JSON type.
    #[error("expected {0}")]
    Type(&'static str),
    /// A field whose value is not allowed.
    #[error("{0}")]
    Invalid(&'static str),
    /// The engine refused an intent with these pins.
    #[error("refused by the engine: {0}")]
    Engine(ConfigError),
}

/// Reads the fields of one JSON object, and refuses any it was not asked for.
#[derive(Debug)]
pub(crate) struct Fields<'a> {
    object: &'a JcsObject,
    path: String,
    read: BTreeSet<String>,
}

impl<'a> Fields<'a> {
    /// The fields of `value`, which must be an object.
    pub(crate) fn of(value: &'a JcsValue, path: &str) -> Result<Self, LoadError> {
        let object = value
            .as_object()
            .ok_or_else(|| LoadError::at(path, Problem::Type("an object")))?;
        Ok(Self {
            object,
            path: path.to_owned(),
            read: BTreeSet::new(),
        })
    }

    /// The path of the field `key`.
    pub(crate) fn path_of(&self, key: &str) -> String {
        join(&self.path, key)
    }

    /// The field `key`, if present.
    pub(crate) fn optional(&mut self, key: &str) -> Option<&'a JcsValue> {
        self.read.insert(key.to_owned());
        self.object.get(key)
    }

    /// The field `key`.
    pub(crate) fn value(&mut self, key: &str) -> Result<&'a JcsValue, LoadError> {
        self.optional(key)
            .ok_or_else(|| LoadError::at(&self.path_of(key), Problem::Missing))
    }

    /// The string field `key`.
    pub(crate) fn string(&mut self, key: &str) -> Result<&'a str, LoadError> {
        let path = self.path_of(key);
        as_str(self.value(key)?, &path)
    }

    /// The safe non-negative integer field `key`.
    pub(crate) fn u64(&mut self, key: &str) -> Result<u64, LoadError> {
        let path = self.path_of(key);
        as_u64(self.value(key)?, &path)
    }

    /// The field `key` as a `u32`.
    pub(crate) fn u32(&mut self, key: &str) -> Result<u32, LoadError> {
        let path = self.path_of(key);
        u32::try_from(self.u64(key)?)
            .map_err(|_| LoadError::at(&path, Problem::Invalid("too large")))
    }

    /// The field `key` as a positive `usize`.
    pub(crate) fn positive_usize(&mut self, key: &str) -> Result<usize, LoadError> {
        let path = self.path_of(key);
        usize::try_from(self.positive(key)?)
            .map_err(|_| LoadError::at(&path, Problem::Invalid("too large")))
    }

    /// The field `key` as a positive integer.
    pub(crate) fn positive(&mut self, key: &str) -> Result<u64, LoadError> {
        let path = self.path_of(key);
        let value = self.u64(key)?;
        if value == 0 {
            return Err(LoadError::at(&path, Problem::Invalid("must be at least 1")));
        }
        Ok(value)
    }

    /// The boolean field `key`.
    pub(crate) fn bool(&mut self, key: &str) -> Result<bool, LoadError> {
        let path = self.path_of(key);
        self.value(key)?
            .as_bool()
            .ok_or_else(|| LoadError::at(&path, Problem::Type("a boolean")))
    }

    /// The object field `key`.
    pub(crate) fn object(&mut self, key: &str) -> Result<Fields<'a>, LoadError> {
        let path = self.path_of(key);
        Fields::of(self.value(key)?, &path)
    }

    /// The absolute path field `key`.
    pub(crate) fn path(&mut self, key: &str) -> Result<PathBuf, LoadError> {
        let path = self.path_of(key);
        let text = self.string(key)?;
        if !text.starts_with('/') || text.contains('\0') {
            return Err(LoadError::at(
                &path,
                Problem::Invalid("must be an absolute path"),
            ));
        }
        Ok(PathBuf::from(text))
    }

    /// The members of this object, in key order, with their paths.
    pub(crate) fn members(&mut self) -> Vec<(&'a str, &'a JcsValue, String)> {
        let members: Vec<_> = self
            .object
            .entries()
            .iter()
            .map(|(key, value)| (key.as_str(), value, join(&self.path, key.as_str())))
            .collect();
        for (key, _, _) in &members {
            self.read.insert((*key).to_owned());
        }
        members
    }

    /// Refuses every field that was not read.
    pub(crate) fn done(self) -> Result<(), LoadError> {
        match self
            .object
            .entries()
            .iter()
            .find(|(key, _)| !self.read.contains(key.as_str()))
        {
            Some((key, _)) => Err(LoadError::at(
                &join(&self.path, key.as_str()),
                Problem::Unexpected,
            )),
            None => Ok(()),
        }
    }
}

fn join(path: &str, key: &str) -> String {
    if path.is_empty() {
        key.to_owned()
    } else {
        format!("{path}.{key}")
    }
}

/// `value` as a string.
pub(crate) fn as_str<'a>(value: &'a JcsValue, path: &str) -> Result<&'a str, LoadError> {
    value
        .as_str()
        .ok_or_else(|| LoadError::at(path, Problem::Type("a string")))
}

/// `value` as a safe non-negative integer.
pub(crate) fn as_u64(value: &JcsValue, path: &str) -> Result<u64, LoadError> {
    value
        .as_i64()
        .and_then(|number| u64::try_from(number).ok())
        .ok_or_else(|| LoadError::at(path, Problem::Type("a safe non-negative integer")))
}

/// `value` as an array.
pub(crate) fn as_array<'a>(value: &'a JcsValue, path: &str) -> Result<&'a [JcsValue], LoadError> {
    value
        .as_array()
        .ok_or_else(|| LoadError::at(path, Problem::Type("an array")))
}

/// Whether `name` is 1 to `max` characters of `[A-Za-z0-9_.-]`, and not `.` or `..`.
pub(crate) fn is_plain_name(name: &str, max: usize) -> bool {
    (1..=max).contains(&name.len())
        && !matches!(name, "." | "..")
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

/// A peer the PEP admits on one socket: its uid and gid (Q1), and the socket's path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    /// The peer's uid.
    pub uid: u32,
    /// The peer's gid.
    pub gid: u32,
    /// The socket.
    pub socket: PathBuf,
}

/// The `pep` section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PepSection {
    /// The PEP's workload identity, the Call Proof's `iss`.
    pub spiffe_id: String,
    /// Where the PEP writes its Call Proof public key for the broker (`/run/pep-pub`).
    pub pubkey_dir: PathBuf,
}

/// One lockfile signer key and its role (L1).
#[derive(Debug, Clone)]
pub struct Signer {
    /// The role the key signs for.
    pub role: String,
    /// The key.
    pub key: Es256Verifier,
}

/// The `lockfile` section. Step 7 loads its pins from the config; step 10 verifies the signed
/// lockfile at `path` with these signers.
#[derive(Debug, Clone)]
pub struct LockfileSection {
    /// The signed lockfile.
    pub path: PathBuf,
    /// The trusted keys, each in exactly one role.
    pub signers: Vec<Signer>,
    /// Distinct keys needed per role, each at least 1.
    pub thresholds: BTreeMap<String, u32>,
    /// The rollback floor: a lockfile with a lower `release_epoch` is refused.
    pub min_accepted_epoch: u64,
}

/// The `journal` section (R1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalSection {
    /// The journal file.
    pub path: PathBuf,
    /// Its lock file.
    pub lock: PathBuf,
}

/// The `log` section (RV3 B4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogSection {
    /// The decision log, on its own volume.
    pub path: PathBuf,
    /// The size at which it stops growing.
    pub max_bytes: u64,
}

/// One configured intent, the Week 2 stand-in for a RAR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentConfig {
    /// The intent. `episode_id` is 0 here; each episode gets a fresh one (E1).
    /// `intent_digest` is the digest of the intent's config entry.
    pub intent: PepIntent,
    /// The tool transitions it allows.
    pub seq: SeqPolicy,
}

/// The `limits` section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeLimits {
    /// Agent connections served at once.
    pub connections: usize,
    /// Control connections served at once (H1).
    pub control_connections: usize,
    /// Largest request head, at most [`crate::http::MAX_HEAD_BYTES`].
    pub header_bytes: usize,
    /// Largest request body, at most [`crate::http::MAX_BODY_BYTES`].
    pub body_bytes: usize,
    /// Deadline for a whole request to arrive.
    pub read_timeout_ms: u64,
    /// Deadline for the broker's answer (P1).
    pub upstream_timeout_ms: u64,
    /// Longest wait for a step-up decision (P1).
    pub step_up_timeout_ms: u64,
    /// An episode with no call for this long ends (T1).
    pub episode_idle_ms: u64,
    /// Live episodes at once (E1).
    pub episodes: usize,
    /// Calls an episode may make at once before the rate applies.
    pub call_burst: u32,
    /// Calls per second an episode may sustain.
    pub call_rate_per_s: u32,
    /// Clock skew allowed on token times.
    pub clock_skew_ms: u64,
    /// Entries in the replay cache.
    pub replay_cache_entries: usize,
    /// Interval between drift polls of one server (L1).
    pub drift_poll_ms: u64,
    /// Deadline of one drift poll (L1).
    pub drift_poll_deadline_ms: u64,
}

/// The whole config.
#[derive(Debug, Clone)]
pub struct Config {
    /// The agent, on the agent socket.
    pub agent: Peer,
    /// The operator, on the control socket (RV3 F7).
    pub operator: Peer,
    /// The broker, on the broker socket (RV3 F7).
    pub broker: Peer,
    /// The PEP's identity and key directory.
    pub pep: PepSection,
    /// The lockfile's signers and rollback floor.
    pub lockfile: LockfileSection,
    /// The journal (R1).
    pub journal: JournalSection,
    /// The decision log.
    pub log: LogSection,
    /// The intents, by name; the name keys the intent's ledger (R1, RV4 #5).
    pub intents: BTreeMap<String, IntentConfig>,
    /// Runtime limits.
    pub limits: RuntimeLimits,
    /// The pins: the unsigned lockfile v1 payload (L1).
    pub pins: Lockfile,
}

/// Loads a config from its bytes.
///
/// # Errors
///
/// Returns a [`LoadError`] naming the first field that is missing, unexpected, of the wrong
/// type or not allowed.
pub fn load(bytes: &[u8]) -> Result<Config, LoadError> {
    let root = jcs::parse_with(bytes, &ParseOptions::definition())
        .map_err(|error| LoadError::at("", Problem::Json(error)))?
        .value;
    let mut fields = Fields::of(&root, "")?;
    let agent = peer(fields.object("agent")?)?;
    let operator = peer(fields.object("operator")?)?;
    let broker = peer(fields.object("broker")?)?;
    let pep = pep_section(fields.object("pep")?)?;
    let lockfile_section = lockfile_section(fields.object("lockfile")?)?;
    let journal = journal_section(fields.object("journal")?)?;
    let log = log_section(fields.object("log")?)?;
    let limits = limits_section(fields.object("limits")?)?;
    let pins_path = fields.path_of("pins");
    let pins = lockfile::parse_payload(fields.value("pins")?, &pins_path)?;
    if pins.release_epoch < lockfile_section.min_accepted_epoch {
        return Err(LoadError::at(
            &join(&pins_path, "release_epoch"),
            Problem::Invalid("below lockfile.min_accepted_epoch"),
        ));
    }
    let intents_path = fields.path_of("intents");
    let intents = intents_section(fields.value("intents")?, &intents_path, &pins)?;
    fields.done()?;
    Ok(Config {
        agent,
        operator,
        broker,
        pep,
        lockfile: lockfile_section,
        journal,
        log,
        intents,
        limits,
        pins,
    })
}

fn peer(mut fields: Fields<'_>) -> Result<Peer, LoadError> {
    let peer = Peer {
        uid: fields.u32("uid")?,
        gid: fields.u32("gid")?,
        socket: fields.path("socket")?,
    };
    fields.done()?;
    Ok(peer)
}

fn pep_section(mut fields: Fields<'_>) -> Result<PepSection, LoadError> {
    let spiffe_path = fields.path_of("spiffe_id");
    let spiffe_id = fields.string("spiffe_id")?;
    if !spiffe_id.starts_with("spiffe://") {
        return Err(LoadError::at(
            &spiffe_path,
            Problem::Invalid("must be a spiffe:// id"),
        ));
    }
    let section = PepSection {
        spiffe_id: spiffe_id.to_owned(),
        pubkey_dir: fields.path("pubkey_dir")?,
    };
    fields.done()?;
    Ok(section)
}

fn lockfile_section(mut fields: Fields<'_>) -> Result<LockfileSection, LoadError> {
    let path = fields.path("path")?;
    let min_accepted_epoch = fields.u64("min_accepted_epoch")?;
    let signers_path = fields.path_of("signers");
    let mut signers = Vec::new();
    let mut kids = BTreeSet::new();
    for (index, entry) in as_array(fields.value("signers")?, &signers_path)?
        .iter()
        .enumerate()
    {
        let entry_path = format!("{signers_path}[{index}]");
        let mut signer = Fields::of(entry, &entry_path)?;
        let role = signer.string("role")?;
        if role.is_empty() {
            return Err(LoadError::at(
                &signer.path_of("role"),
                Problem::Invalid("empty role"),
            ));
        }
        let key_path = signer.path_of("key");
        let key = verifier(signer.value("key")?, &key_path)?;
        if !kids.insert(key.kid().to_owned()) {
            return Err(LoadError::at(
                &key_path,
                Problem::Invalid("a key may appear only once, in one role"),
            ));
        }
        signer.done()?;
        signers.push(Signer {
            role: role.to_owned(),
            key,
        });
    }
    let mut thresholds = BTreeMap::new();
    let mut threshold_fields = fields.object("thresholds")?;
    for (role, value, role_path) in threshold_fields.members() {
        let needed = u32::try_from(as_u64(value, &role_path)?)
            .map_err(|_| LoadError::at(&role_path, Problem::Invalid("too large")))?;
        let keys = signers.iter().filter(|signer| signer.role == role).count();
        if needed == 0
            || usize::try_from(needed)
                .ok()
                .is_none_or(|needed| needed > keys)
        {
            return Err(LoadError::at(
                &role_path,
                Problem::Invalid("must be at least 1 and at most the role's key count"),
            ));
        }
        thresholds.insert(role.to_owned(), needed);
    }
    threshold_fields.done()?;
    if let Some(signer) = signers
        .iter()
        .find(|signer| !thresholds.contains_key(&signer.role))
    {
        return Err(LoadError::at(
            &join(&fields.path_of("thresholds"), &signer.role),
            Problem::Missing,
        ));
    }
    fields.done()?;
    Ok(LockfileSection {
        path,
        signers,
        thresholds,
        min_accepted_epoch,
    })
}

/// A signer key: unpadded base64url of an uncompressed SEC1 point, or an EC JWK with exactly
/// `kty`, `crv`, `x` and `y`.
fn verifier(value: &JcsValue, path: &str) -> Result<Es256Verifier, LoadError> {
    let invalid = || LoadError::at(path, Problem::Invalid("not a P-256 public key"));
    if let Some(text) = value.as_str() {
        let bytes = URL_SAFE_NO_PAD.decode(text).map_err(|_| invalid())?;
        return Es256Verifier::from_sec1(&bytes).map_err(|_| invalid());
    }
    let mut jwk = Fields::of(value, path)?;
    if jwk.string("kty")? != "EC" || jwk.string("crv")? != "P-256" {
        return Err(invalid());
    }
    let key = Es256Verifier::from_jwk(jwk.string("x")?, jwk.string("y")?).map_err(|_| invalid())?;
    jwk.done()?;
    Ok(key)
}

fn journal_section(mut fields: Fields<'_>) -> Result<JournalSection, LoadError> {
    let section = JournalSection {
        path: fields.path("path")?,
        lock: fields.path("lock")?,
    };
    if section.path == section.lock {
        return Err(LoadError::at(
            &fields.path_of("lock"),
            Problem::Invalid("must differ from the journal"),
        ));
    }
    fields.done()?;
    Ok(section)
}

fn log_section(mut fields: Fields<'_>) -> Result<LogSection, LoadError> {
    let section = LogSection {
        path: fields.path("path")?,
        max_bytes: fields.positive("max_bytes")?,
    };
    fields.done()?;
    Ok(section)
}

fn defaulted(fields: &mut Fields<'_>, key: &str, default: u64) -> Result<u64, LoadError> {
    match fields.optional(key) {
        None => Ok(default),
        Some(_) => fields.positive(key),
    }
}

fn positive_u32(fields: &mut Fields<'_>, key: &str) -> Result<u32, LoadError> {
    let path = fields.path_of(key);
    u32::try_from(fields.positive(key)?)
        .map_err(|_| LoadError::at(&path, Problem::Invalid("too large")))
}

fn limits_section(mut fields: Fields<'_>) -> Result<RuntimeLimits, LoadError> {
    let limits = RuntimeLimits {
        connections: fields.positive_usize("connections")?,
        control_connections: fields.positive_usize("control_connections")?,
        header_bytes: fields.positive_usize("header_bytes")?,
        body_bytes: fields.positive_usize("body_bytes")?,
        read_timeout_ms: fields.positive("read_timeout_ms")?,
        upstream_timeout_ms: defaulted(
            &mut fields,
            "upstream_timeout_ms",
            DEFAULT_UPSTREAM_TIMEOUT_MS,
        )?,
        step_up_timeout_ms: defaulted(
            &mut fields,
            "step_up_timeout_ms",
            DEFAULT_STEP_UP_TIMEOUT_MS,
        )?,
        episode_idle_ms: fields.positive("episode_idle_ms")?,
        episodes: fields.positive_usize("episodes")?,
        call_burst: positive_u32(&mut fields, "call_burst")?,
        call_rate_per_s: positive_u32(&mut fields, "call_rate_per_s")?,
        clock_skew_ms: fields.u64("clock_skew_ms")?,
        replay_cache_entries: fields.positive_usize("replay_cache_entries")?,
        drift_poll_ms: defaulted(&mut fields, "drift_poll_ms", DEFAULT_DRIFT_POLL_MS)?,
        drift_poll_deadline_ms: defaulted(
            &mut fields,
            "drift_poll_deadline_ms",
            DEFAULT_DRIFT_POLL_DEADLINE_MS,
        )?,
    };
    let fail = |key: &str, why| Err(LoadError::at(&fields.path_of(key), Problem::Invalid(why)));
    if limits.header_bytes > crate::http::MAX_HEAD_BYTES {
        return fail("header_bytes", "above the HTTP subset's 16 KiB cap");
    }
    if limits.body_bytes > crate::http::MAX_BODY_BYTES {
        return fail("body_bytes", "above the HTTP subset's 1 MiB cap");
    }
    if limits
        .step_up_timeout_ms
        .checked_add(limits.upstream_timeout_ms)
        .is_none_or(|total| total > MAX_STEP_UP_PLUS_UPSTREAM_MS)
    {
        return fail(
            "step_up_timeout_ms",
            "step_up_timeout_ms plus upstream_timeout_ms exceeds 55,000 (P1)",
        );
    }
    if limits.drift_poll_deadline_ms >= limits.drift_poll_ms {
        return fail("drift_poll_deadline_ms", "must be below drift_poll_ms");
    }
    fields.done()?;
    Ok(limits)
}

/// Refuses invoice ids that differ only by case, in one intent or across intents. Invoice claims
/// compare ids exactly (RV5 V1), so two spellings of one invoice in a case-insensitive store
/// would count as two invoices. Only the operator's config can do this, so it is a load error.
fn check_invoice_spellings(
    intents: &BTreeMap<String, IntentConfig>,
    path: &str,
) -> Result<(), LoadError> {
    let mut seen: BTreeMap<String, &str> = BTreeMap::new();
    for intent in intents.values() {
        let EntitySet::InvoiceIds(ids) = &intent.intent.entities.ids else {
            continue;
        };
        for id in ids {
            let spelling = seen.entry(id.to_lowercase()).or_insert(id.as_str());
            if *spelling != id.as_str() {
                return Err(LoadError::at(
                    path,
                    Problem::Invalid("two invoice ids differ only by case"),
                ));
            }
        }
    }
    Ok(())
}

fn intents_section(
    value: &JcsValue,
    path: &str,
    pins: &Lockfile,
) -> Result<BTreeMap<String, IntentConfig>, LoadError> {
    let mut fields = Fields::of(value, path)?;
    let mut intents = BTreeMap::new();
    for (name, entry, entry_path) in fields.members() {
        if !is_plain_name(name, MAX_INTENT_NAME) {
            return Err(LoadError::at(
                &entry_path,
                Problem::Invalid("an intent name is 1 to 64 characters of [A-Za-z0-9_.-]"),
            ));
        }
        intents.insert(name.to_owned(), intent(entry, &entry_path, pins)?);
    }
    fields.done()?;
    check_invoice_spellings(&intents, path)?;
    if intents.is_empty() {
        return Err(LoadError::at(
            path,
            Problem::Invalid("no intent configured"),
        ));
    }
    Ok(intents)
}

fn intent(value: &JcsValue, path: &str, pins: &Lockfile) -> Result<IntentConfig, LoadError> {
    let mut fields = Fields::of(value, path)?;
    let release_epoch = fields.u64("release_epoch")?;
    let lockfile_digest = fields.string("lockfile_digest")?;
    if release_epoch != pins.release_epoch || lockfile_digest != pins.digest {
        return Err(LoadError::at(
            path,
            Problem::Invalid("release_epoch and lockfile_digest must match the loaded pins"),
        ));
    }
    let mut limit_fields = fields.object("limits")?;
    let limits = Limits {
        currency: limit_fields.string("currency")?.to_owned(),
        per_call_max_minor: limit_fields.u64("per_call_max_minor")?,
        cumulative_max_minor: limit_fields.u64("cumulative_max_minor")?,
        max_calls: limit_fields.u32("max_calls")?,
        step_up_over_minor: limit_fields.u64("step_up_over_minor")?,
        max_declines: limit_fields.u32("max_declines")?,
    };
    limit_fields.done()?;
    let entities = entities(fields.object("entities")?)?;
    let seq_path = fields.path_of("seq");
    let seq = seq_policy(fields.value("seq")?, &seq_path, pins)?;
    fields.done()?;
    let intent = PepIntent {
        episode_id: 0,
        intent_digest: jcs::digest_value(value),
        release_epoch,
        lockfile_digest: lockfile_digest.to_owned(),
        limits,
        entities,
    };
    validate_config(&intent, &pins.pins)
        .map_err(|error| LoadError::at(path, Problem::Engine(error)))?;
    Ok(IntentConfig { intent, seq })
}

fn entities(mut fields: Fields<'_>) -> Result<Entities, LoadError> {
    let kind_path = fields.path_of("kind");
    let kind = fields.string("kind")?;
    let ids_path = fields.path_of("ids");
    let mut ids = BTreeSet::new();
    for (index, id) in as_array(fields.value("ids")?, &ids_path)?
        .iter()
        .enumerate()
    {
        let id_path = format!("{ids_path}[{index}]");
        let id = as_str(id, &id_path)?;
        if id.is_empty() || !ids.insert(id.to_owned()) {
            return Err(LoadError::at(
                &id_path,
                Problem::Invalid("empty or repeated id"),
            ));
        }
    }
    if ids.is_empty() {
        return Err(LoadError::at(&ids_path, Problem::Invalid("no entity")));
    }
    let uses_path = fields.path_of("per_entity_max_uses");
    let per_entity_max_uses = fields.u32("per_entity_max_uses")?;
    let ids = match kind {
        "invoice" => {
            // RV4 #1: a system of record that lags after a commit would otherwise fund a
            // second payment of the same invoice.
            if per_entity_max_uses != 1 {
                return Err(LoadError::at(
                    &uses_path,
                    Problem::Invalid("an invoice intent must set per_entity_max_uses to 1"),
                ));
            }
            EntitySet::InvoiceIds(ids)
        }
        "recipient" => {
            if per_entity_max_uses == 0 {
                return Err(LoadError::at(
                    &uses_path,
                    Problem::Invalid("must be at least 1"),
                ));
            }
            EntitySet::RecipientIds(ids)
        }
        _ => {
            return Err(LoadError::at(
                &kind_path,
                Problem::Invalid("must be \"invoice\" or \"recipient\""),
            ));
        }
    };
    fields.done()?;
    Ok(Entities {
        ids,
        per_entity_max_uses,
    })
}

/// `"unconstrained"`, or `{"transitions": [[from, to], ...]}` where `from` is a tool or `null`
/// for the first call, and every tool named is pinned.
fn seq_policy(value: &JcsValue, path: &str, pins: &Lockfile) -> Result<SeqPolicy, LoadError> {
    if value.as_str() == Some("unconstrained") {
        return Ok(SeqPolicy::Unconstrained);
    }
    let mut fields = Fields::of(value, path)
        .map_err(|_| LoadError::at(path, Problem::Type("\"unconstrained\" or an object")))?;
    let list_path = fields.path_of("transitions");
    let mut transitions = BTreeSet::new();
    for (index, pair) in as_array(fields.value("transitions")?, &list_path)?
        .iter()
        .enumerate()
    {
        let pair_path = format!("{list_path}[{index}]");
        let [from, to] = as_array(pair, &pair_path)? else {
            return Err(LoadError::at(
                &pair_path,
                Problem::Type("a [from, to] pair"),
            ));
        };
        let pinned = |tool: &str| pins.pins.tools.contains_key(tool);
        let from = match from {
            JcsValue::Null => None,
            other => Some(as_str(other, &pair_path)?.to_owned()),
        };
        let to = as_str(to, &pair_path)?.to_owned();
        if !from.as_deref().is_none_or(pinned) || !pinned(&to) {
            return Err(LoadError::at(
                &pair_path,
                Problem::Invalid("names a tool that is not pinned"),
            ));
        }
        transitions.insert((from, to));
    }
    fields.done()?;
    Ok(SeqPolicy::Transitions(transitions))
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
    use crate::engine::EffectClass;
    use crate::tokens::Es256Signer;

    /// Two servers: `a` with a bound lookup and a payment, `b` with a note writer, a store
    /// reader and a sink. `search_notes` declares a fraction, which only the definition
    /// profile admits.
    const PINS: &str = r#"{
      "lockfile_version": 1, "release_epoch": 7,
      "stores": {"billing://invoices": {"case_insensitive": true}, "notes://agent": {"case_insensitive": false}},
      "servers": {
        "a": {"endpoint": "http://tools-a:8080/mcp", "identity": "spiffe://corp.example/tools/a", "protocol_version": "2026-07-28",
          "discover": {"cacheScope": "public", "capabilities": {"tools": {}}, "resultType": "complete", "supportedVersions": ["2026-07-28"], "ttlMs": 0},
          "tools": {
            "get_invoice": {
              "definition": {"name": "get_invoice", "description": "Look up an invoice.", "inputSchema": {"type": "object", "properties": {"invoice_id": {"type": "string", "maxLength": 64}}, "required": ["invoice_id"], "additionalProperties": false}},
              "policy": {"effect": "read", "args": [{"pointer": "/invoice_id", "role": "store_key"}], "store_uri": "billing://invoices", "sink_clearance": "secret",
                "output_label": {"conf": "internal", "integ": "trusted"}, "trusted_fields": ["/structuredContent/amount_due_minor", "/structuredContent/currency"],
                "max_result_bytes": 1048576, "max_result_nodes": 8192}},
            "pay_invoice": {
              "definition": {"name": "pay_invoice", "description": "Pay an invoice.", "inputSchema": {"type": "object"}},
              "policy": {"effect": "mutating_financial", "args": [{"pointer": "/invoice_id", "role": "entity", "kind": "invoice"}, {"pointer": "/amount", "role": "amount"}, {"pointer": "/currency", "role": "currency"}],
                "sink_clearance": "internal", "output_label": {"conf": "internal", "integ": "untrusted_external"},
                "amount_binding": {"lookup_tool": "get_invoice", "entity_arg_pointer": "/invoice_id", "lookup_entity_pointer": "/invoice_id", "result_amount_pointer": "/structuredContent/amount_due_minor", "result_currency_pointer": "/structuredContent/currency"},
                "max_result_bytes": 65536, "max_result_nodes": 1024}}}},
        "b": {"endpoint": "http://tools-b:8080/mcp", "identity": "spiffe://corp.example/tools/b", "protocol_version": "2026-07-28",
          "discover": {"cacheScope": "public", "capabilities": {"tools": {}}, "resultType": "complete", "supportedVersions": ["2026-07-28"], "ttlMs": 0},
          "tools": {
            "save_note": {
              "definition": {"name": "save_note", "inputSchema": {"type": "object"}},
              "policy": {"effect": "mutating_internal", "args": [{"pointer": "/key", "role": "store_key"}, {"pointer": "/text", "role": "store_write"}], "store_uri": "notes://agent",
                "sink_clearance": "secret", "output_label": {"conf": "internal", "integ": "untrusted_external"}, "max_result_bytes": 65536, "max_result_nodes": 1024}},
            "search_notes": {
              "definition": {"name": "search_notes", "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}, "score": {"type": "number", "minimum": 0.5}}}},
              "policy": {"effect": "read", "args": [{"pointer": "/query", "role": "data"}], "sink_clearance": "secret",
                "output_label": {"conf": "secret", "integ": "untrusted_agent_write"}, "reads_stores": ["notes://agent"], "max_result_bytes": 65536, "max_result_nodes": 1024}},
            "fetch": {
              "definition": {"name": "fetch", "inputSchema": {"type": "object"}},
              "policy": {"effect": "read", "args": [{"pointer": "/url", "role": "sink_destination"}], "sink_clearance": "public",
                "destinations": {"https://partner.example": "confidential"},
                "output_label": {"conf": "internal", "integ": "untrusted_external"}, "max_result_bytes": 65536, "max_result_nodes": 1024}}}}}
    }"#;

    const CONFIG: &str = r#"{
      "agent": {"uid": 20001, "gid": 20001, "socket": "/run/pep/agent.sock"},
      "operator": {"uid": 20004, "gid": 20004, "socket": "/run/pep-control/control.sock"},
      "broker": {"uid": 20003, "gid": 20003, "socket": "/run/broker/broker.sock"},
      "pep": {"spiffe_id": "spiffe://corp.example/pep", "pubkey_dir": "/run/pep-pub"},
      "lockfile": {"path": "/etc/pep/lockfile.dsse.json", "min_accepted_epoch": 7,
        "signers": [{"role": "security", "key": "@SEC1@"}, {"role": "release", "key": {"kty": "EC", "crv": "P-256", "x": "@X@", "y": "@Y@"}}],
        "thresholds": {"release": 1, "security": 1}},
      "journal": {"path": "/var/lib/pep/journal.jsonl", "lock": "/var/lib/pep/journal.lock"},
      "log": {"path": "/var/log/pep/decisions.jsonl", "max_bytes": 104857600},
      "limits": {"connections": 32, "control_connections": 4, "header_bytes": 16384, "body_bytes": 1048576, "read_timeout_ms": 5000,
        "episode_idle_ms": 600000, "episodes": 8, "call_burst": 10, "call_rate_per_s": 5, "clock_skew_ms": 2000, "replay_cache_entries": 100000},
      "intents": {
        "pay-invoices": {"release_epoch": 7, "lockfile_digest": "@DIGEST@",
          "limits": {"currency": "USD", "per_call_max_minor": 100000, "cumulative_max_minor": 500000, "max_calls": 5, "step_up_over_minor": 50000, "max_declines": 3},
          "entities": {"kind": "invoice", "ids": ["INV-1001", "INV-1002"], "per_entity_max_uses": 1},
          "seq": {"transitions": [[null, "get_invoice"], ["get_invoice", "pay_invoice"]]}},
        "notes": {"release_epoch": 7, "lockfile_digest": "@DIGEST@",
          "limits": {"currency": "EUR", "per_call_max_minor": 1000, "cumulative_max_minor": 1000, "max_calls": 1, "step_up_over_minor": 1000, "max_declines": 1},
          "entities": {"kind": "recipient", "ids": ["rcpt_A"], "per_entity_max_uses": 2},
          "seq": "unconstrained"}},
      "pins": @PINS@
    }"#;

    fn sec1(seed: u8) -> Vec<u8> {
        Es256Signer::from_secret_bytes(&[seed; 32])
            .unwrap()
            .verifier()
            .to_sec1_uncompressed()
    }

    /// The config around `pins`, with the intents pinned to its digest.
    fn config_with(pins: &str) -> String {
        config_from(CONFIG, pins)
    }

    fn config_from(template: &str, pins: &str) -> String {
        let value = jcs::parse_with(pins.as_bytes(), &ParseOptions::definition())
            .unwrap()
            .value;
        let jwk = sec1(2);
        template
            .replace("@SEC1@", &URL_SAFE_NO_PAD.encode(sec1(1)))
            .replace("@X@", &URL_SAFE_NO_PAD.encode(&jwk[1..33]))
            .replace("@Y@", &URL_SAFE_NO_PAD.encode(&jwk[33..]))
            .replace("@DIGEST@", &jcs::digest_value(&value))
            .replace("@PINS@", pins)
    }

    fn edit(text: &str, old: &str, new: &str) -> String {
        assert_eq!(text.matches(old).count(), 1, "{old}");
        text.replacen(old, new, 1)
    }

    fn load_str(text: &str) -> Result<Config, LoadError> {
        load(text.as_bytes())
    }

    /// The error for the config with `old` replaced by `new` (in the pins when `in_pins`).
    fn error(in_pins: bool, old: &str, new: &str) -> (String, Problem) {
        let text = if in_pins {
            config_with(&edit(PINS, old, new))
        } else {
            edit(&config_with(PINS), old, new)
        };
        let error = load_str(&text).expect_err("the edit should be refused");
        (error.path, error.problem)
    }

    fn invalid(path: &str, why: &'static str) -> (String, Problem) {
        (path.to_owned(), Problem::Invalid(why))
    }

    #[test]
    fn the_fixture_loads() {
        let config = load_str(&config_with(PINS)).unwrap();
        assert_eq!(config.agent.uid, 20001);
        assert_eq!(
            config.operator.socket,
            PathBuf::from("/run/pep-control/control.sock")
        );
        assert_eq!(config.lockfile.signers.len(), 2);
        assert_eq!(config.lockfile.thresholds["security"], 1);
        // Defaults (P1, L1).
        assert_eq!(config.limits.upstream_timeout_ms, 10_000);
        assert_eq!(config.limits.step_up_timeout_ms, 45_000);
        assert_eq!(config.limits.drift_poll_ms, 5_000);
        assert_eq!(config.limits.drift_poll_deadline_ms, 3_000);
        // Pins.
        let pins = &config.pins;
        assert_eq!(pins.release_epoch, 7);
        assert_eq!(pins.pins.tools.len(), 5);
        assert_eq!(pins.pins.tools["pay_invoice"].effect, EffectClass::Payment);
        assert_eq!(pins.pins.tools["save_note"].server_id, "b");
        let definition = &pins.servers["a"].definitions[0];
        assert_eq!(
            definition.get("name").unwrap().as_str(),
            Some("get_invoice")
        );
        assert_eq!(
            pins.pins.tools["get_invoice"].schema_digest,
            jcs::digest_value(definition)
        );
        assert_eq!(pins.instructions, None);
        // The digest is the pins section's.
        let value = jcs::parse_with(PINS.as_bytes(), &ParseOptions::definition())
            .unwrap()
            .value;
        assert_eq!(pins.digest, jcs::digest_value(&value));
        assert_eq!(pins.pins.lockfile_digest, pins.digest);
        // Intents.
        let pay = &config.intents["pay-invoices"];
        assert_eq!(pay.intent.lockfile_digest, pins.digest);
        assert_eq!(pay.intent.entities.per_entity_max_uses, 1);
        assert!(
            matches!(&pay.seq, SeqPolicy::Transitions(set) if set.contains(&(None, "get_invoice".to_owned())))
        );
        assert_eq!(config.intents["notes"].seq, SeqPolicy::Unconstrained);
        assert_ne!(
            pay.intent.intent_digest,
            config.intents["notes"].intent.intent_digest
        );
    }

    #[test]
    fn tools_list_follows_server_states() {
        let config = load_str(&config_with(PINS)).unwrap();
        let names = |serving: &dyn Fn(&str) -> bool| {
            config
                .pins
                .tools_list(serving)
                .iter()
                .map(|tool| tool.get("name").unwrap().as_str().unwrap().to_owned())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            names(&|_| true),
            [
                "get_invoice",
                "pay_invoice",
                "fetch",
                "save_note",
                "search_notes"
            ]
        );
        assert_eq!(
            names(&|server| server == "b"),
            ["fetch", "save_note", "search_notes"]
        );
        assert!(names(&|_| false).is_empty());
    }

    #[test]
    fn unknown_missing_and_mistyped_fields() {
        assert_eq!(
            error(false, r#""episodes": 8,"#, r#""episodes": 8, "extra": 1,"#),
            ("limits.extra".to_owned(), Problem::Unexpected)
        );
        assert_eq!(
            error(
                true,
                r#""kind": "invoice"}"#,
                r#""kind": "invoice", "why": 1}"#
            ),
            (
                "pins.servers.a.tools.pay_invoice.policy.args[0].why".to_owned(),
                Problem::Unexpected
            )
        );
        assert_eq!(
            error(false, r#""gid": 20003, "#, ""),
            ("broker.gid".to_owned(), Problem::Missing)
        );
        assert_eq!(
            error(false, r#""uid": 20001"#, r#""uid": "20001""#),
            (
                "agent.uid".to_owned(),
                Problem::Type("a safe non-negative integer")
            )
        );
        for bad in ["-1", "1.5", "9007199254740993"] {
            assert_eq!(
                error(false, r#""episodes": 8"#, &format!(r#""episodes": {bad}"#)),
                (
                    "limits.episodes".to_owned(),
                    Problem::Type("a safe non-negative integer")
                ),
                "{bad}"
            );
        }
        assert_eq!(
            error(false, r#""episodes": 8"#, r#""episodes": 0"#),
            invalid("limits.episodes", "must be at least 1")
        );
        assert_eq!(
            error(
                false,
                r#""socket": "/run/pep/agent.sock""#,
                r#""socket": "run/pep/agent.sock""#
            ),
            invalid("agent.socket", "must be an absolute path")
        );
        assert!(matches!(
            load_str("{").unwrap_err().problem,
            Problem::Json(_)
        ));
    }

    #[test]
    fn limits_rules() {
        let with = |extra: &str| {
            error(
                false,
                r#""episodes": 8,"#,
                &format!(r#""episodes": 8, {extra},"#),
            )
        };
        assert_eq!(
            with(r#""step_up_timeout_ms": 45001"#),
            invalid(
                "limits.step_up_timeout_ms",
                "step_up_timeout_ms plus upstream_timeout_ms exceeds 55,000 (P1)"
            )
        );
        assert_eq!(
            with(r#""upstream_timeout_ms": 10001"#).0,
            "limits.step_up_timeout_ms"
        );
        let fits = edit(
            &config_with(PINS),
            r#""episodes": 8,"#,
            r#""episodes": 8, "step_up_timeout_ms": 50000, "upstream_timeout_ms": 5000,"#,
        );
        assert_eq!(load_str(&fits).unwrap().limits.step_up_timeout_ms, 50_000);
        assert_eq!(
            with(r#""drift_poll_deadline_ms": 5000"#),
            invalid(
                "limits.drift_poll_deadline_ms",
                "must be below drift_poll_ms"
            )
        );
        assert_eq!(
            error(
                false,
                r#""header_bytes": 16384"#,
                r#""header_bytes": 16385"#
            ),
            invalid("limits.header_bytes", "above the HTTP subset's 16 KiB cap")
        );
        assert_eq!(
            error(
                false,
                r#""body_bytes": 1048576"#,
                r#""body_bytes": 1048577"#
            ),
            invalid("limits.body_bytes", "above the HTTP subset's 1 MiB cap")
        );
    }

    #[test]
    fn intent_rules() {
        // RV4 #1: an invoice intent pays each invoice once.
        assert_eq!(
            error(
                false,
                r#""ids": ["INV-1001", "INV-1002"], "per_entity_max_uses": 1"#,
                r#""ids": ["INV-1001", "INV-1002"], "per_entity_max_uses": 2"#
            ),
            invalid(
                "intents.pay-invoices.entities.per_entity_max_uses",
                "an invoice intent must set per_entity_max_uses to 1"
            )
        );
        assert_eq!(
            error(
                false,
                r#""per_entity_max_uses": 2"#,
                r#""per_entity_max_uses": 0"#
            ),
            invalid(
                "intents.notes.entities.per_entity_max_uses",
                "must be at least 1"
            )
        );
        assert_eq!(
            error(false, r#""kind": "recipient""#, r#""kind": "payee""#),
            invalid(
                "intents.notes.entities.kind",
                "must be \"invoice\" or \"recipient\""
            )
        );
        assert_eq!(
            error(false, r#""ids": ["rcpt_A"]"#, r#""ids": []"#),
            invalid("intents.notes.entities.ids", "no entity")
        );
        assert_eq!(
            error(
                false,
                r#""ids": ["rcpt_A"]"#,
                r#""ids": ["rcpt_A", "rcpt_A"]"#
            ),
            invalid("intents.notes.entities.ids[1]", "empty or repeated id")
        );
        // Bound to the loaded pins.
        let mismatch = invalid(
            "intents.notes",
            "release_epoch and lockfile_digest must match the loaded pins",
        );
        assert_eq!(
            error(
                false,
                r#""notes": {"release_epoch": 7"#,
                r#""notes": {"release_epoch": 8"#
            ),
            mismatch
        );
        let template = edit(
            CONFIG,
            r#""notes": {"release_epoch": 7, "lockfile_digest": "@DIGEST@""#,
            r#""notes": {"release_epoch": 7, "lockfile_digest": "sha-256:other""#,
        );
        let other = load_str(&config_from(&template, PINS)).unwrap_err();
        assert_eq!((other.path, other.problem), mismatch);
        // The engine's own checks.
        assert_eq!(
            error(false, r#""currency": "EUR""#, r#""currency": "eur""#),
            (
                "intents.notes".to_owned(),
                Problem::Engine(ConfigError::InvalidCurrency)
            )
        );
        // Names key the ledger.
        assert_eq!(
            error(false, r#""notes": {"#, r#""no tes": {"#),
            invalid(
                "intents.no tes",
                "an intent name is 1 to 64 characters of [A-Za-z0-9_.-]"
            )
        );
        assert_eq!(
            error(
                false,
                r#""seq": {"transitions": [[null, "get_invoice"], ["get_invoice", "pay_invoice"]]}"#,
                r#""seq": {"transitions": [[null, "get_invoice"], ["get_invoice", "pay_bill"]]}"#
            ),
            invalid(
                "intents.pay-invoices.seq.transitions[1]",
                "names a tool that is not pinned"
            )
        );
        assert_eq!(
            error(
                false,
                r#"[null, "get_invoice"],"#,
                r#"[null, "get_invoice", "x"],"#
            ),
            (
                "intents.pay-invoices.seq.transitions[0]".to_owned(),
                Problem::Type("a [from, to] pair")
            )
        );
        assert_eq!(
            error(false, r#""seq": "unconstrained""#, r#""seq": "free""#),
            (
                "intents.notes.seq".to_owned(),
                Problem::Type("\"unconstrained\" or an object")
            )
        );
    }

    #[test]
    fn signer_rules() {
        let config = config_with(PINS);
        let sec1_text = URL_SAFE_NO_PAD.encode(sec1(1));
        // The same key twice.
        let repeated = edit(
            &config,
            r#"{"role": "release", "key": {"kty""#,
            &format!(
                r#"{{"role": "release", "key": "{sec1_text}"}}, {{"role": "release", "key": {{"kty""#
            ),
        );
        assert_eq!(
            (
                load_str(&repeated).unwrap_err().path,
                load_str(&repeated).unwrap_err().problem
            ),
            invalid(
                "lockfile.signers[1].key",
                "a key may appear only once, in one role"
            )
        );
        assert_eq!(
            error(
                false,
                r#""thresholds": {"release": 1, "security": 1}"#,
                r#""thresholds": {"release": 1, "security": 2}"#
            ),
            invalid(
                "lockfile.thresholds.security",
                "must be at least 1 and at most the role's key count"
            )
        );
        assert_eq!(
            error(
                false,
                r#""thresholds": {"release": 1, "security": 1}"#,
                r#""thresholds": {"release": 0, "security": 1}"#
            )
            .0,
            "lockfile.thresholds.release"
        );
        assert_eq!(
            error(
                false,
                r#""thresholds": {"release": 1, "security": 1}"#,
                r#""thresholds": {"release": 1, "security": 1, "audit": 1}"#
            )
            .0,
            "lockfile.thresholds.audit"
        );
        assert_eq!(
            error(
                false,
                r#""thresholds": {"release": 1, "security": 1}"#,
                r#""thresholds": {"security": 1}"#
            ),
            ("lockfile.thresholds.release".to_owned(), Problem::Missing)
        );
        assert_eq!(
            error(false, r#""crv": "P-256""#, r#""crv": "P-384""#),
            invalid("lockfile.signers[1].key", "not a P-256 public key")
        );
        assert_eq!(
            error(false, &sec1_text, sec1_text.get(..40).unwrap()),
            invalid("lockfile.signers[0].key", "not a P-256 public key")
        );
        assert_eq!(
            error(false, r#""crv": "P-256""#, r#""crv": "P-256", "kid": "k""#),
            (
                "lockfile.signers[1].key.kid".to_owned(),
                Problem::Unexpected
            )
        );
        assert_eq!(
            error(
                false,
                r#""min_accepted_epoch": 7"#,
                r#""min_accepted_epoch": 8"#
            ),
            invalid("pins.release_epoch", "below lockfile.min_accepted_epoch")
        );
    }

    #[test]
    fn tool_names_and_servers() {
        assert_eq!(
            error(
                true,
                r#""definition": {"name": "fetch""#,
                r#""definition": {"name": "fetch2""#
            ),
            invalid(
                "pins.servers.b.tools.fetch.definition",
                "its name must equal the tool's key"
            )
        );
        let renamed = edit(
            &edit(PINS, r#""fetch": {"#, r#""fetch me": {"#),
            r#""name": "fetch""#,
            r#""name": "fetch me""#,
        );
        let error_text = load_str(&config_with(&renamed)).unwrap_err();
        assert_eq!(
            (error_text.path, error_text.problem),
            invalid(
                "pins.servers.b.tools.fetch me.definition",
                "a tool name is 1 to 128 characters of [A-Za-z0-9_.-]"
            )
        );
        // A name on two servers (RV4 #12, mutation #12).
        let twice = edit(
            PINS,
            r#""save_note": {"#,
            r#""get_invoice": {"definition": {"name": "get_invoice"}, "policy": {}}, "save_note": {"#,
        );
        let error_text = load_str(&config_with(&twice)).unwrap_err();
        assert_eq!(
            (error_text.path, error_text.problem),
            invalid(
                "pins.servers.b.tools.get_invoice",
                "a tool name may be pinned on one server only"
            )
        );
        for bad in ["a/b", "..", ""] {
            let renamed = edit(
                PINS,
                r#""b": {"endpoint""#,
                &format!(r#""{bad}": {{"endpoint""#),
            );
            assert_eq!(
                load_str(&config_with(&renamed)).unwrap_err().problem,
                Problem::Invalid("a server_id is 1 to 64 characters of [A-Za-z0-9_.-]"),
                "{bad}"
            );
        }
        assert_eq!(
            error(
                true,
                r#""identity": "spiffe://corp.example/tools/b", "protocol_version": "2026-07-28""#,
                r#""identity": "spiffe://corp.example/tools/b", "protocol_version": "2025-11-25""#
            ),
            invalid(
                "pins.servers.b.protocol_version",
                "the PEP speaks only 2026-07-28"
            )
        );
        assert_eq!(
            error(true, r#""lockfile_version": 1"#, r#""lockfile_version": 2"#),
            invalid("pins.lockfile_version", "unsupported lockfile version")
        );
        assert_eq!(
            error(
                true,
                r#""endpoint": "http://tools-b:8080/mcp""#,
                r#""endpoint": """#
            ),
            invalid("pins.servers.b.endpoint", "empty")
        );
    }

    #[test]
    fn definitions_with_x_mcp_header_rejected() {
        assert_eq!(
            error(
                true,
                r#""query": {"type": "string"}"#,
                r#""query": {"type": "string", "x-mcp-header": "Query"}"#
            ),
            invalid(
                "pins.servers.b.tools.search_notes.definition",
                "x-mcp-header is not supported in Week 2"
            )
        );
        // Anywhere in the definition, however deep.
        assert_eq!(
            error(
                true,
                r#""definition": {"name": "fetch", "inputSchema": {"type": "object"}}"#,
                r#""definition": {"name": "fetch", "inputSchema": {"type": "object", "allOf": [{"properties": {"u": {"x-mcp-header": "U"}}}]}}"#
            ),
            invalid(
                "pins.servers.b.tools.fetch.definition",
                "x-mcp-header is not supported in Week 2"
            )
        );
    }

    #[test]
    fn policy_rules() {
        let effect = r#""policy": {"effect": "read", "args": [{"pointer": "/url""#;
        for (bad, why) in [
            ("destructive", "not allowed in Week 2"),
            ("code_exec", "not allowed in Week 2"),
            ("writes", "unknown effect class"),
        ] {
            assert_eq!(
                error(
                    true,
                    effect,
                    &effect.replace("\"read\"", &format!("\"{bad}\""))
                ),
                invalid("pins.servers.b.tools.fetch.policy.effect", why)
            );
        }
        // A payment must declare its currency.
        assert_eq!(
            error(
                true,
                r#", {"pointer": "/currency", "role": "currency"}"#,
                ""
            ),
            invalid(
                "pins.servers.a.tools.pay_invoice.policy.args",
                "a payment tool must declare a currency argument"
            )
        );
        assert_eq!(
            error(
                true,
                r#""role": "entity", "kind": "invoice""#,
                r#""role": "entity", "kind": "account""#
            ),
            invalid(
                "pins.servers.a.tools.pay_invoice.policy.args[0].kind",
                "must be \"invoice\" or \"recipient\""
            )
        );
        assert_eq!(
            error(
                true,
                r#""role": "sink_destination""#,
                r#""role": "dynamic_sink""#
            ),
            invalid(
                "pins.servers.b.tools.fetch.policy.args[0].role",
                "unknown role"
            )
        );
        assert_eq!(
            error(
                true,
                r#""sink_clearance": "public""#,
                r#""sink_clearance": "top""#
            ),
            invalid(
                "pins.servers.b.tools.fetch.policy.sink_clearance",
                "must be public, internal, confidential or secret"
            )
        );
        assert_eq!(
            error(true, r#""integ": "trusted""#, r#""integ": "verified""#),
            invalid(
                "pins.servers.a.tools.get_invoice.policy.output_label.integ",
                "must be trusted, untrusted_external or untrusted_agent_write"
            )
        );
        assert_eq!(
            error(
                true,
                r#""https://partner.example": "confidential""#,
                r#""https://partner.example": "open""#
            )
            .0,
            "pins.servers.b.tools.fetch.policy.destinations.https://partner.example"
        );
        assert_eq!(
            error(
                true,
                r#""/structuredContent/currency"]"#,
                r#""/structuredContent/currency", "/structuredContent/currency"]"#
            ),
            invalid(
                "pins.servers.a.tools.get_invoice.policy.trusted_fields[2]",
                "repeated"
            )
        );
        // The engine's pins checks, reported at the pins.
        assert_eq!(
            error(true, r#""/structuredContent/currency"]"#, r#""/currency"]"#),
            (
                "pins".to_owned(),
                Problem::Engine(ConfigError::InvalidTrustedField)
            )
        );
        // Five-Track fields L1 rejects are simply unknown here.
        assert_eq!(
            error(
                true,
                r#""sink_clearance": "public","#,
                r#""sink_clearance": "public", "role_contracts": {},"#
            ),
            (
                "pins.servers.b.tools.fetch.policy.role_contracts".to_owned(),
                Problem::Unexpected
            )
        );
    }

    #[test]
    fn store_readers_carry_the_high_water_label() {
        // RV4 #8: `save_note` writes notes://agent, so its reader must be Secret and
        // agent-written.
        let reader = r#""output_label": {"conf": "secret", "integ": "untrusted_agent_write"}, "reads_stores""#;
        for label in [
            r#"{"conf": "confidential", "integ": "untrusted_agent_write"}"#,
            r#"{"conf": "secret", "integ": "untrusted_external"}"#,
            r#"{"conf": "secret", "integ": "trusted"}"#,
        ] {
            assert_eq!(
                error(
                    true,
                    reader,
                    &format!(r#""output_label": {label}, "reads_stores""#)
                ),
                invalid(
                    "pins.servers.b.tools.search_notes.policy",
                    "a reader of a store agents write must carry output_label secret, untrusted_agent_write (RV4 #8)"
                ),
                "{label}"
            );
        }
        // A store nobody writes needs no such label.
        let unwritten = edit(
            &edit(
                PINS,
                reader,
                r#""output_label": {"conf": "internal", "integ": "untrusted_external"}, "reads_stores""#,
            ),
            r#""reads_stores": ["notes://agent"]"#,
            r#""reads_stores": ["billing://invoices"]"#,
        );
        assert!(load_str(&config_with(&unwritten)).is_ok());
        // Unless some tool takes its store as an argument: it can write any store.
        let dynamic_writer = edit(
            &unwritten,
            r#""save_note": {"#,
            r#""move_note": {"definition": {"name": "move_note"}, "policy": {"effect": "mutating_internal",
              "args": [{"pointer": "/store", "role": "store_uri"}, {"pointer": "/key", "role": "store_key"}, {"pointer": "/text", "role": "store_write"}],
              "sink_clearance": "secret", "output_label": {"conf": "internal", "integ": "untrusted_external"}, "max_result_bytes": 1024, "max_result_nodes": 64}},
            "save_note": {"#,
        );
        assert_eq!(
            load_str(&config_with(&dynamic_writer)).unwrap_err().problem,
            Problem::Invalid(
                "a reader of a store agents write must carry output_label secret, untrusted_agent_write (RV4 #8)"
            )
        );
        assert_eq!(
            error(
                true,
                r#""reads_stores": ["notes://agent"]"#,
                r#""reads_stores": ["files://share"]"#
            ),
            invalid(
                "pins.servers.b.tools.search_notes.policy",
                "reads_stores names a store that is not pinned"
            )
        );
        assert_eq!(
            error(
                true,
                r#""effect": "read", "args": [{"pointer": "/query", "role": "data"}], "sink_clearance": "secret""#,
                r#""effect": "external_sink", "args": [{"pointer": "/query", "role": "data"}], "sink_clearance": "internal""#
            ),
            invalid(
                "pins.servers.b.tools.search_notes.policy",
                "only a read tool declares reads_stores"
            )
        );
    }

    #[test]
    fn a_decline_limit_is_between_one_and_max_calls() {
        let limits = r#""max_calls": 5, "step_up_over_minor": 50000, "max_declines": 3"#;
        let with = |declines: u32| {
            error(
                false,
                limits,
                &limits.replace(
                    "\"max_declines\": 3",
                    &format!("\"max_declines\": {declines}"),
                ),
            )
        };
        for declines in [0, 6] {
            let (path, _) = with(declines);
            assert_eq!(path, "intents.pay-invoices");
        }
    }

    #[test]
    fn two_spellings_of_one_invoice_are_refused() {
        let (_, problem) = error(
            false,
            r#""ids": ["INV-1001", "INV-1002"]"#,
            r#""ids": ["INV-1001", "inv-1001"]"#,
        );
        assert_eq!(
            problem,
            Problem::Invalid("two invoice ids differ only by case")
        );
    }

    #[test]
    fn secret_clearance_is_only_for_tools_that_stay_with_the_data() {
        let clearance = "pins.servers.b.tools.fetch.policy.sink_clearance";
        // A read tool that reads a pinned store may keep it: its server holds that store.
        assert!(load_str(&config_with(PINS)).is_ok());
        // One that does not, may not: its `data` arguments would go out unchecked.
        assert_eq!(
            error(
                true,
                r#""args": [{"pointer": "/url", "role": "sink_destination"}], "sink_clearance": "public""#,
                r#""args": [{"pointer": "/url", "role": "data"}], "sink_clearance": "secret""#
            ),
            invalid(
                clearance,
                "a read tool with data arguments must read a pinned store to be cleared for secret"
            )
        );
        // No sink, and no payment, whose memo would be one.
        assert_eq!(
            error(
                true,
                r#""effect": "read", "args": [{"pointer": "/url", "role": "sink_destination"}], "sink_clearance": "public""#,
                r#""effect": "external_sink", "args": [{"pointer": "/url", "role": "sink_destination"}], "sink_clearance": "secret""#
            ),
            invalid(
                clearance,
                "a sink or a payment cannot be cleared for secret"
            )
        );
        assert_eq!(
            error(
                true,
                r#""sink_clearance": "internal", "output_label": {"conf": "internal", "integ": "untrusted_external"},"#,
                r#""sink_clearance": "secret", "output_label": {"conf": "internal", "integ": "untrusted_external"},"#
            ),
            invalid(
                "pins.servers.a.tools.pay_invoice.policy.sink_clearance",
                "a sink or a payment cannot be cleared for secret"
            )
        );
        // And no destination.
        assert_eq!(
            error(
                true,
                r#""https://partner.example": "confidential""#,
                r#""https://partner.example": "secret""#
            ),
            invalid(clearance, "a destination cannot be cleared for secret")
        );
    }

    #[test]
    fn the_digest_covers_every_definition() {
        let base = load_str(&config_with(PINS)).unwrap().pins.digest;
        let changed = edit(
            PINS,
            r#""description": "Pay an invoice.""#,
            r#""description": "Pay an invoice now.""#,
        );
        let other = load_str(&config_with(&changed)).unwrap();
        assert_ne!(other.pins.digest, base);
        assert_ne!(
            other.pins.pins.tools["pay_invoice"].schema_digest,
            load_str(&config_with(PINS)).unwrap().pins.pins.tools["pay_invoice"].schema_digest
        );
        let instructions = edit(
            PINS,
            r#""lockfile_version": 1,"#,
            r#""lockfile_version": 1, "instructions": "Pinned text.","#,
        );
        assert_eq!(
            load_str(&config_with(&instructions))
                .unwrap()
                .pins
                .instructions
                .as_deref(),
            Some("Pinned text.")
        );
    }
}
