//! The `pep-sidecar` binary (`WEEK2_PLAN` §2a): `pep-sidecar CONFIG`.
//!
//! Boot, in order:
//! 1. load the config ([`pep_sidecar::config`]) and claim the host's authority;
//! 2. take the journal's lock, truncate a torn tail and replay it (R1);
//! 3. restore the label store, the quarantines of the loaded lockfile, and the PEP-wide set of
//!    entities with an unresolved payment;
//! 4. generate this boot's Episode Token and Call Proof keys, and publish the Call Proof key
//!    for the broker;
//! 5. poll every server once through the broker (RV4 #5): a match serves it, a difference
//!    quarantines it, and a failure suspends it;
//! 6. serve the control socket, then, last, the agent socket.
//!
//! Logs go to stderr, one line each, and never carry a token, proof, key or credential.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use pep_sidecar::actor::Services;
use pep_sidecar::config::{self, Config};
use pep_sidecar::decision_log::DecisionLog;
use pep_sidecar::engine::{HostAuthority, ServerStates, Shared, UnresolvedEntities, encode_ulid};
use pep_sidecar::jcs;
use pep_sidecar::journal::{Journal, JournaledLabels, Record, replay, spawn_writer};
use pep_sidecar::peercred::bind_safe_listener;
use pep_sidecar::poll::{PollOutcome, poll};
use pep_sidecar::registry::{Registry, RegistryConfig, new_ulid};
use pep_sidecar::serve::{AgentContext, ControlContext, accept_loop, serve_agent, serve_control};
use pep_sidecar::tokens::{Es256Signer, os_entropy, unix_now};
use pep_sidecar::upstream::BrokerClient;

/// Largest config file read.
const MAX_CONFIG_BYTES: u64 = 16 * 1024 * 1024;
/// Entries the PEP-wide label store holds.
const LABEL_CAPACITY: usize = 1 << 20;
/// The file, in `pep.pubkey_dir`, holding the Call Proof public key: unpadded base64url of
/// its uncompressed SEC1 point, then a newline.
const CALL_PROOF_KEY_FILE: &str = "call-proof.pub";
/// How often idle and expired episodes are ended.
const REAP_EVERY: Duration = Duration::from_secs(30);
/// Margin on top of the step-up wait and the upstream leg for a call's answer.
const CALL_MARGIN: Duration = Duration::from_secs(5);

fn main() -> ExitCode {
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let (check, path) = match args.as_slice() {
        [path] => (false, path),
        [flag, path] if flag == "--check" => (true, path),
        _ => {
            log("usage: pep-sidecar [--check] CONFIG");
            return ExitCode::from(2);
        }
    };
    if check {
        // A container healthcheck: is the server accepting connections?
        return if check_ready(Path::new(path)) {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        };
    }
    match run(Path::new(path)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            log(&format!("pep-sidecar: {error}"));
            ExitCode::FAILURE
        }
    }
}

/// One line to stderr.
fn log(message: &str) {
    let stderr = io::stderr();
    let mut lock = stderr.lock();
    drop(writeln!(lock, "{message}"));
}

fn millis(duration_ms: u64) -> Duration {
    Duration::from_millis(duration_ms)
}

fn run(path: &Path) -> Result<(), String> {
    // 1. The config, and the host's authority.
    let config = load_config(path)?;
    let host = Arc::new(
        HostAuthority::claim()
            .ok_or_else(|| "the host authority was already claimed".to_owned())?,
    );

    // 2. The journal.
    let (journal, records) = Journal::open(&config.journal.path, &config.journal.lock)
        .map_err(|error| format!("journal: {error}"))?;
    let replayed = replay(&records).map_err(|error| format!("journal: {error}"))?;
    log(&format!(
        "pep-sidecar: journal replayed: {} records, {} unresolved entities",
        records.len(),
        replayed.unresolved.len()
    ));
    let (journal, _writer) =
        spawn_writer(journal).map_err(|error| format!("journal writer: {error}"))?;

    // 3. The PEP-wide state.
    let labels = JournaledLabels::restore(
        LABEL_CAPACITY,
        journal.clone(),
        &replayed.taint,
        &config.pins.pins.stores,
    )
    .map_err(|error| format!("label store: {error}"))?;
    let servers = Arc::new(ServerStates::empty());
    for (server_id, digest) in &replayed.quarantined {
        if *digest == config.pins.digest {
            servers
                .quarantine(server_id)
                .map_err(|error| format!("server states: {error}"))?;
        }
    }
    let unresolved = Arc::new(UnresolvedEntities::empty());
    for entity in &replayed.unresolved {
        unresolved
            .insert(entity)
            .map_err(|error| format!("unresolved set: {error}"))?;
    }
    let shared = Shared {
        labels,
        servers: servers.clone(),
        unresolved,
    };

    // 4. This boot's keys.
    let mut entropy = os_entropy().map_err(|error| format!("entropy: {error}"))?;
    let proof_key =
        Es256Signer::generate(&mut entropy).map_err(|error| format!("keys: {error}"))?;
    let episode_key =
        Es256Signer::generate(&mut entropy).map_err(|error| format!("keys: {error}"))?;
    publish_key(&config, &proof_key)?;

    // 5. One poll of every server before the agent socket binds (RV4 #5).
    let broker = Arc::new(BrokerClient::new(
        config.broker.socket.clone(),
        config.broker.uid,
        config.broker.gid,
        jcs::MAX_DEFINITION_BYTES,
    ));
    first_polls(&config, &broker, &servers, &journal, &mut entropy)?;

    // 6. Serve.
    let decisions = Arc::new(
        DecisionLog::open(&config.log.path, config.log.max_bytes)
            .map_err(|error| format!("decision log {}: {error}", config.log.path.display()))?,
    );
    let limits = &config.limits;
    let services = Arc::new(Services {
        host: host.clone(),
        journal,
        proof_key,
        entropy: Mutex::new(Box::new(entropy)),
        upstream: broker,
        pins: config.pins.pins.clone(),
        step_up_timeout: millis(limits.step_up_timeout_ms),
        upstream_timeout: millis(limits.upstream_timeout_ms),
        now: unix_now,
        log: decisions.clone(),
    });
    let registry = Registry::new(
        RegistryConfig {
            intents: config.intents.clone(),
            pins: config.pins.pins.clone(),
            agent_uid: config.agent.uid,
            episodes: limits.episodes,
            call_burst: limits.call_burst,
            call_rate_per_s: limits.call_rate_per_s,
            idle_secs: limits.episode_idle_ms.checked_div(1000).unwrap_or(0),
            skew_secs: limits.clock_skew_ms.checked_div(1000).unwrap_or(0),
        },
        episode_key,
        replayed.ledgers.into_iter().collect::<BTreeMap<_, _>>(),
        shared,
        services,
    );
    let read_timeout = millis(limits.read_timeout_ms);

    let control = bind_safe_listener(&config.operator.socket)
        .map_err(|error| format!("control socket: {error}"))?;
    let control_context = ControlContext {
        registry: registry.clone(),
        host: host.clone(),
        peer: config.operator.clone(),
        read_timeout,
    };
    let control_limit = limits.control_connections;
    thread::Builder::new()
        .name("control".to_owned())
        .spawn(move || {
            accept_loop(control.listener(), control_limit, move |stream| {
                serve_control(stream, &control_context);
            });
            log("pep-sidecar: the control socket stopped accepting");
        })
        .map_err(|error| format!("control thread: {error}"))?;

    let reaper = registry.clone();
    let reaper_host = host.clone();
    thread::Builder::new()
        .name("reaper".to_owned())
        .spawn(move || {
            loop {
                thread::sleep(REAP_EVERY);
                if let Ok(now) = unix_now() {
                    for eid in reaper.reap(&reaper_host, now) {
                        log(&format!(
                            "pep-sidecar: episode {} ended idle",
                            encode_ulid(eid)
                        ));
                    }
                }
            }
        })
        .map_err(|error| format!("reaper thread: {error}"))?;

    let agent = bind_safe_listener(&config.agent.socket)
        .map_err(|error| format!("agent socket: {error}"))?;
    let call_timeout = millis(limits.step_up_timeout_ms)
        .checked_add(millis(limits.upstream_timeout_ms))
        .and_then(|total| total.checked_add(CALL_MARGIN))
        .ok_or_else(|| "call timeout overflows".to_owned())?;
    let agent_context = AgentContext {
        registry,
        lockfile: Arc::new(config.pins.clone()),
        servers,
        peer: config.agent.clone(),
        read_timeout,
        call_timeout,
        now: unix_now,
        log: decisions,
    };
    log("pep-sidecar: serving");
    accept_loop(agent.listener(), limits.connections, move |stream| {
        serve_agent(stream, &agent_context);
    });
    Err("the agent socket stopped accepting".to_owned())
}

fn load_config(path: &Path) -> Result<Config, String> {
    let size = fs::metadata(path)
        .map_err(|error| format!("config {}: {error}", path.display()))?
        .len();
    if size > MAX_CONFIG_BYTES {
        return Err(format!("config {}: larger than 16 MiB", path.display()));
    }
    let bytes = fs::read(path).map_err(|error| format!("config {}: {error}", path.display()))?;
    config::load(&bytes).map_err(|error| format!("config {}: {error}", path.display()))
}

/// Writes the Call Proof public key for the broker, which re-reads it per connection: to a
/// temporary file, then renamed into place, readable by all.
fn publish_key(config: &Config, key: &Es256Signer) -> Result<(), String> {
    let directory = &config.pep.pubkey_dir;
    let target = directory.join(CALL_PROOF_KEY_FILE);
    let temporary = directory.join(format!(".{CALL_PROOF_KEY_FILE}.new"));
    let text = format!(
        "{}\n",
        URL_SAFE_NO_PAD.encode(key.verifier().to_sec1_uncompressed())
    );
    let write = || -> io::Result<()> {
        fs::write(&temporary, text.as_bytes())?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o644))?;
        fs::rename(&temporary, &target)
    };
    write().map_err(|error| format!("call proof key {}: {error}", target.display()))
}

/// Polls every server not already quarantined, once, and sets its state.
fn first_polls(
    config: &Config,
    broker: &BrokerClient,
    servers: &ServerStates,
    journal: &pep_sidecar::journal::JournalHandle,
    entropy: &mut fs::File,
) -> Result<(), String> {
    let deadline = millis(config.limits.drift_poll_deadline_ms);
    let mut next_id = || {
        let now = unix_now().ok()?.checked_mul(1000)?;
        new_ulid(entropy, now).ok().map(encode_ulid)
    };
    for (server_id, pinned) in &config.pins.servers {
        if servers.state(server_id) == pep_sidecar::engine::ServerState::Quarantined {
            log(&format!(
                "pep-sidecar: server {server_id}: quarantined (journal)"
            ));
            continue;
        }
        let outcome = poll(broker, server_id, pinned, &mut next_id, deadline);
        let applied = match outcome {
            PollOutcome::Matches => servers.set_serving(server_id),
            PollOutcome::Failed => servers.suspend(server_id),
            PollOutcome::Differs => {
                // Durable before anything depends on it (RV4 #5).
                journal
                    .commit(&[Record::Quarantine {
                        server_id: server_id.clone(),
                        lockfile_digest: config.pins.digest.clone(),
                    }])
                    .map_err(|error| format!("journal: {error}"))?;
                servers.quarantine(server_id)
            }
        };
        applied.map_err(|error| format!("server states: {error}"))?;
        log(&format!("pep-sidecar: server {server_id}: {outcome:?}"));
    }
    Ok(())
}

/// Whether the agent socket named in the config at `path` accepts a connection.
fn check_ready(path: &Path) -> bool {
    load_config(path)
        .is_ok_and(|config| std::os::unix::net::UnixStream::connect(&config.agent.socket).is_ok())
}
