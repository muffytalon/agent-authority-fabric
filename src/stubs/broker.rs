//! The stub broker (`WEEK2_PLAN` §2a, PEP↔broker).
//!
//! One request per connection from the PEP, whose uid and gid it requires. It routes
//! `/mcp/{server_id}` through its own static table (RV4 #12) and:
//! - refuses, with a status and nothing forwarded, a body that is not one of the shapes the PEP
//!   builds, so nothing the proof does not cover can reach a tool server (F-16); and any status
//!   but 200 means nothing was forwarded (SPEC §3.4);
//! - forwards a proof-less request only for `server/discover` and `tools/list` (drift polls);
//! - verifies a `tools/call`'s Call Proof against its own lockfile: the server, the epoch, the
//!   tool's pinned digest, the `action_digest` it recomputes from the forwarded body, and for
//!   a payment the forwarded amount and currency; the proof's `jti` enters the replay cache
//!   (T1). A refused proof gets `refused`, with no tool result;
//! - strips every `dev.pep-sidecar/*` member from the forwarded `_meta`, so the tool server
//!   never sees the proof, and injects the server's own credential and, for a payment, the
//!   F-07 `Idempotency-Key`. The PEP's JSON-RPC id is kept;
//! - answers the PEP with JSON only: for a payment, its outcome in
//!   `_meta["dev.pep-sidecar/outcome"]`, after stripping any such member the tool server sent.
//!   The tool's `status` maps as P1 says: `executed`, `declined` to `refused`, and anything
//!   else, or no answer, to `unknown`;
//! - gives each route its own share of connections for calls, so one slow server cannot take a
//!   healthy server's, and a call past its route's share is refused unsent;
//! - logs one line per request, and for a call a line before the upstream write as well, so an
//!   execution always has a broker record, even if the broker dies mid-call (RV5 V12).

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::config::{Fields, LoadError, Problem, is_plain_name};
use crate::engine::{ArgRole, EffectClass, EntityKind, ToolPolicy, entity_key, idempotency_key};
use crate::forward::{CALL_PROOF_META_KEY, OUTCOME_META_KEY, PROTOCOL_VERSION};
use crate::http::{Request, Status, response};
use crate::jcs::{self, JcsObject, JcsString, JcsValue, ParseOptions};
use crate::lockfile::{Lockfile, MAX_SERVER_ID, parse_payload};
use crate::peercred::{bind_safe_listener, require_peer};
use crate::serve::accept_loop_with;
use crate::tokens::{
    CallProofExpectations, Es256Verifier, ExpectedPayment, ReplayCache, TokenError, unix_now,
    verify_call_proof,
};
use crate::upstream::{Endpoint, LegTimer, Post, post, residence_us};

use super::{answer_finally, now_ms};

/// The prefix of every reserved `_meta` member.
const RESERVED: &str = "dev.pep-sidecar/";
/// The header carrying a payment's [`entity_key`] to the tool server (RV5 D5).
pub const ENTITY_KEY_HEADER: &str = "Pep-Entity-Key";
/// Connections kept out of the routes' shares, for proof-less drift polls (RV4 #9).
const POLL_RESERVE: usize = 2;

/// One route: where a server listens, and its credential.
#[derive(Clone)]
pub struct Route {
    /// The tool server's endpoint.
    pub endpoint: Endpoint,
    /// Its credential, injected as `Authorization: Bearer …`.
    pub credential: String,
}

impl fmt::Debug for Route {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Route")
            .field("endpoint", &self.endpoint)
            .field("credential", &"<redacted>")
            .finish()
    }
}

/// The broker's own config (RV4 #12).
#[derive(Debug, Clone)]
pub struct BrokerConfig {
    /// The socket the PEP connects to.
    pub socket: PathBuf,
    /// The PEP's uid and gid.
    pub pep: (u32, u32),
    /// The PEP's published Call Proof key, re-read per connection.
    pub pep_key: PathBuf,
    /// The lockfile payload, the same as the PEP's.
    pub pins: Lockfile,
    /// The static routes, by `server_id`.
    pub routes: BTreeMap<String, Route>,
    /// Live `jti`s the replay cache holds.
    pub replay_cache_entries: usize,
    /// Clock skew allowed on proof times.
    pub clock_skew_secs: u64,
    /// Connections served at once.
    pub connections: usize,
    /// The deadline for a tool server's answer.
    pub upstream_timeout: Duration,
    /// The broker's log.
    pub log: PathBuf,
}

/// Loads a broker config. `read` reads a file the config names.
///
/// # Errors
///
/// Returns a [`LoadError`] for anything malformed.
pub fn load(
    bytes: &[u8],
    read: &dyn Fn(&Path) -> Option<Vec<u8>>,
) -> Result<BrokerConfig, LoadError> {
    let root = jcs::parse(bytes).map_err(|error| LoadError::at("", Problem::Json(error)))?;
    let mut fields = Fields::of(&root, "")?;
    let socket = fields.path("socket")?;
    let mut pep = fields.object("pep")?;
    let pep_ids = (pep.u32("uid")?, pep.u32("gid")?);
    pep.done()?;
    let pep_key = fields.path("pep_key")?;
    let pins_path = fields.path("pins")?;
    let pins_bytes =
        read(&pins_path).ok_or_else(|| LoadError::at("pins", Problem::Invalid("unreadable")))?;
    let pins_value = jcs::parse_with(&pins_bytes, &ParseOptions::definition())
        .map_err(|error| LoadError::at("pins", Problem::Json(error)))?
        .value;
    let pins = parse_payload(&pins_value, "pins")?;
    let mut routes = BTreeMap::new();
    let mut route_fields = fields.object("routes")?;
    for (server_id, value, path) in route_fields.members() {
        if !is_plain_name(server_id, MAX_SERVER_ID) || !pins.servers.contains_key(server_id) {
            return Err(LoadError::at(
                &path,
                Problem::Invalid("not a pinned server"),
            ));
        }
        let mut route = Fields::of(value, &path)?;
        let endpoint_path = route.path_of("endpoint");
        let endpoint_text = route.string("endpoint")?;
        let endpoint = Endpoint::parse(endpoint_text).ok_or_else(|| {
            LoadError::at(
                &endpoint_path,
                Problem::Invalid("unix:/path or tcp:host:port"),
            )
        })?;
        // The lockfile holds the reviewed endpoint (RV4 #12): a route elsewhere would hand this
        // server's credential to whatever listens there.
        if pins
            .servers
            .get(server_id)
            .is_none_or(|server| server.endpoint != endpoint_text)
        {
            return Err(LoadError::at(
                &endpoint_path,
                Problem::Invalid("differs from the endpoint pinned for this server"),
            ));
        }
        let credential_path = route.path("credential")?;
        // The file's exact bytes (§4): a tool's verifier is the hash of the file, so a trimmed
        // credential could never match, and a file with a newline in it is refused here.
        let credential = read(&credential_path)
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .filter(|text| !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_graphic()))
            .ok_or_else(|| {
                LoadError::at(
                    &path,
                    Problem::Invalid("credential unreadable or not visible ASCII"),
                )
            })?;
        route.done()?;
        routes.insert(
            server_id.to_owned(),
            Route {
                endpoint,
                credential,
            },
        );
    }
    route_fields.done()?;
    let config = BrokerConfig {
        socket,
        pep: pep_ids,
        pep_key,
        pins,
        routes,
        replay_cache_entries: fields.positive_usize("replay_cache_entries")?,
        clock_skew_secs: fields.u64("clock_skew_ms")?.checked_div(1000).unwrap_or(0),
        connections: fields.positive_usize("connections")?,
        upstream_timeout: Duration::from_millis(fields.positive("upstream_timeout_ms")?),
        log: fields.path("log")?,
    };
    fields.done()?;
    Ok(config)
}

/// A running broker.
#[derive(Debug)]
pub struct Broker {
    config: BrokerConfig,
    cache: ReplayCache,
    log: Mutex<File>,
    /// Calls upstream now, per route.
    in_use: BTreeMap<String, AtomicUsize>,
    /// Calls one route may have upstream at once.
    route_limit: usize,
}

/// How far a request got, for the log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Verified, and about to be written upstream.
    Forwarding,
    /// Written upstream.
    Forwarded,
    /// Refused here: nothing was written upstream.
    Rejected,
}

impl Phase {
    const fn name(self) -> &'static str {
        match self {
            Self::Forwarding => "forwarding",
            Self::Forwarded => "forwarded",
            Self::Rejected => "rejected",
        }
    }
}

/// What one request came to, for the log.
#[derive(Debug)]
struct Verdict {
    jti: Option<String>,
    action_digest: Option<String>,
    idempotency_key: Option<String>,
    entity_key: Option<String>,
    phase: Phase,
    reason: &'static str,
    outcome: Option<&'static str>,
    /// The upstream leg, which O1's residence leaves out.
    leg: Option<Duration>,
}

/// When a request arrived: the times its checks and its log lines use.
#[derive(Clone, Copy, Debug)]
struct When {
    now: u64,
    now_ms: u64,
    started: Instant,
}

/// A request's last log line, written once its reply has gone, because O1's residence runs to
/// the last byte written.
#[derive(Debug)]
pub struct Closing {
    server_id: String,
    method: String,
    upstream_id: String,
    verdict: Verdict,
    when: When,
}

/// One call's share of its route; given back on drop.
struct RouteSlot<'a>(&'a AtomicUsize);

impl Drop for RouteSlot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// The deadline for one request.
const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Runs a broker from the config at `path` until its listener stops. `observe` sees every request
/// from the PEP before the broker handles it, and `ready` runs once the socket is bound.
///
/// # Errors
///
/// Returns a description of a config it cannot load or a socket it cannot bind, or says that the
/// listener stopped.
pub fn serve(
    path: &Path,
    observe: impl Fn(&Request) + Send + Sync + 'static,
    ready: impl FnOnce(),
) -> Result<(), String> {
    let bytes = std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let config =
        load(&bytes, &|path| std::fs::read(path).ok()).map_err(|error| error.to_string())?;
    let boot_second = unix_now().map_err(|error| error.to_string())?;
    let socket = config.socket.clone();
    let connections = config.connections;
    let pep = config.pep;
    let broker = Arc::new(Broker::open(config, boot_second)?);
    let bound = bind_safe_listener(&socket).map_err(|error| error.to_string())?;
    ready();
    accept_loop_with(
        bound.listener(),
        connections,
        move |mut stream| {
            // The PEP, and only the PEP (RV3 F7).
            if require_peer(&stream, pep.0, pep.1).is_err() {
                return;
            }
            let routes = |target: &str| broker.routes(target);
            answer_finally(
                &mut stream,
                &routes,
                READ_TIMEOUT,
                |request| {
                    observe(request);
                    let now = unix_now().unwrap_or(0);
                    let (reply, closing) = broker.handle(request, now, now_ms());
                    (reply, None, closing)
                },
                |closing| {
                    if let Some(closing) = closing {
                        broker.close(&closing);
                    }
                },
            );
        },
        refuse_overflow,
    );
    Err("stopped accepting".to_owned())
}

/// What a connection past the broker's limit gets, instead of a close the PEP could not tell
/// from a broker that died mid-call: a status, which says nothing was forwarded (RV5 V4).
pub fn refuse_overflow(mut stream: UnixStream) {
    drop(stream.set_write_timeout(Some(OVERFLOW_TIMEOUT)));
    drop(stream.set_read_timeout(Some(OVERFLOW_TIMEOUT)));
    let reply =
        b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    drop(stream.write_all(reply));
    drop(stream.shutdown(Shutdown::Write));
    // Closing with unread data could reset the peer before it reads the reply.
    let mut sink = [0u8; 4096];
    drop(stream.read(&mut sink));
}

/// How long the accept thread gives one refused connection.
const OVERFLOW_TIMEOUT: Duration = Duration::from_millis(5);

impl Broker {
    /// Opens the log; `boot_second` starts the replay cache's cutoff (R1).
    ///
    /// # Errors
    ///
    /// Returns a description of the log that could not be opened.
    pub fn open(config: BrokerConfig, boot_second: u64) -> Result<Self, String> {
        let log = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&config.log)
            .map_err(|error| format!("{}: {error}", config.log.display()))?;
        let routes = config.routes.len().max(1);
        let route_limit = config
            .connections
            .saturating_sub(POLL_RESERVE)
            .checked_div(routes)
            .unwrap_or(0)
            .max(1);
        Ok(Self {
            cache: ReplayCache::new(
                config.replay_cache_entries,
                boot_second,
                config.clock_skew_secs,
            ),
            in_use: config
                .routes
                .keys()
                .map(|server| (server.clone(), AtomicUsize::new(0)))
                .collect(),
            route_limit,
            config,
            log: Mutex::new(log),
        })
    }

    /// The broker's config.
    #[must_use]
    pub const fn config(&self) -> &BrokerConfig {
        &self.config
    }

    /// Whether `target` is a route: `/mcp/{server_id}`.
    #[must_use]
    pub fn routes(&self, target: &str) -> bool {
        target
            .strip_prefix("/mcp/")
            .is_some_and(|server_id| self.config.routes.contains_key(server_id))
    }

    /// Answers one request from the PEP: the HTTP response bytes, and what [`Broker::close`]
    /// needs once they have gone.
    #[must_use]
    pub fn handle(&self, request: &Request, now: u64, now_ms: u64) -> (Vec<u8>, Option<Closing>) {
        let when = When {
            now,
            now_ms,
            started: request.first_byte,
        };
        let Some((server_id, route)) = request
            .head
            .target
            .strip_prefix("/mcp/")
            .and_then(|id| self.config.routes.get_key_value(id))
        else {
            return (response(Status::NotFound, None), None);
        };
        if !request.head.is_post() {
            return (response(Status::MethodNotAllowed, None), None);
        }
        let Ok(message) = jcs::parse(&request.body) else {
            return (response(Status::BadRequest, None), None);
        };
        let (Some(id), Some(method)) = (
            message.get("id").and_then(JcsValue::as_str),
            message.get("method").and_then(JcsValue::as_str),
        ) else {
            return (response(Status::BadRequest, None), None);
        };
        if !known_shape(&message, method) {
            return (response(Status::BadRequest, None), None);
        }
        let proof = message
            .pointer("/params/_meta")
            .and_then(|meta| meta.get(CALL_PROOF_META_KEY))
            .and_then(JcsValue::as_str);
        let (body, verdict) = match (method, proof) {
            ("server/discover" | "tools/list", None) => {
                self.forward(server_id, route, &message, method, None, &[])
            }
            ("tools/call", Some(proof)) => self.call(server_id, route, &message, proof, when),
            _ => (
                refused(id, false),
                Verdict {
                    jti: None,
                    action_digest: None,
                    idempotency_key: None,
                    entity_key: None,
                    phase: Phase::Rejected,
                    reason: "a proof-less request other than discover or list",
                    outcome: None,
                    leg: None,
                },
            ),
        };
        let closing = Closing {
            server_id: server_id.clone(),
            method: method.to_owned(),
            upstream_id: id.to_owned(),
            verdict,
            when,
        };
        (
            response(Status::Ok, Some(("application/json", &body))),
            Some(closing),
        )
    }

    /// Writes a request's last log line, with its residence (O1), once its reply has gone.
    pub fn close(&self, closing: &Closing) {
        // A leg that never came back has no end to subtract, so no residence: the deadline it ran
        // into is no time the broker spent.
        let broker_us = match (closing.verdict.phase, closing.verdict.leg) {
            (Phase::Forwarded, None) => None,
            (_, leg) => Some(residence_us(closing.when.started, leg)),
        };
        self.write_log(
            &closing.server_id,
            &closing.method,
            &closing.upstream_id,
            &closing.verdict,
            closing.when,
            broker_us,
        );
    }

    fn call(
        &self,
        server_id: &str,
        route: &Route,
        message: &JcsValue,
        proof: &str,
        when: When,
    ) -> (Vec<u8>, Verdict) {
        let id = message
            .get("id")
            .and_then(JcsValue::as_str)
            .unwrap_or_default();
        let reject = |reason: &'static str, payment: bool, digest: Option<String>| {
            (
                refused(id, payment),
                Verdict {
                    jti: None,
                    action_digest: digest,
                    idempotency_key: None,
                    entity_key: None,
                    phase: Phase::Rejected,
                    reason,
                    outcome: payment.then_some("refused"),
                    leg: None,
                },
            )
        };
        let Some(name) = message.pointer("/params/name").and_then(JcsValue::as_str) else {
            return reject("no tool name", false, None);
        };
        let Some(arguments) = message.pointer("/params/arguments") else {
            return reject("no arguments", false, None);
        };
        let Some(policy) = self
            .config
            .pins
            .pins
            .tools
            .get(name)
            .filter(|policy| policy.server_id == server_id)
        else {
            return reject("tool not pinned on this server", false, None);
        };
        let payment = policy.effect == EffectClass::Payment;
        let digest = jcs::action_digest(name, arguments);
        let expected_payment = if payment {
            match expected_payment(policy, arguments) {
                Some(expected) => Some(expected),
                None => return reject("payment without amount or currency", true, Some(digest)),
            }
        } else {
            None
        };
        let Some(verifier) = self.pep_verifier() else {
            return reject("PEP key unreadable", payment, Some(digest));
        };
        let expect = CallProofExpectations {
            server_id,
            release_epoch: self.config.pins.release_epoch,
            tool_schema_digest: &policy.schema_digest,
            action_digest: &digest,
            payment: expected_payment
                .as_ref()
                .map(|(amount_minor, currency)| ExpectedPayment {
                    amount_minor: *amount_minor,
                    currency,
                }),
        };
        let claims = match verify_call_proof(proof, &verifier, &expect, &self.cache, when.now) {
            Ok(claims) => claims,
            // Its own reason, so G3 can tell the replay cache refused it, not some other check.
            Err(TokenError::Replayed) => {
                return reject("call proof replayed", payment, Some(digest));
            }
            Err(_) => return reject("call proof refused", payment, Some(digest)),
        };
        let key = claims
            .payment
            .as_ref()
            .map(|payment| idempotency_key(claims.eid, payment.rid(), &digest));
        let invoice_key = expected_payment
            .as_ref()
            .and_then(|payment| invoice_key(policy, arguments, payment));
        let Some(_slot) = self.route_slot(server_id) else {
            return reject("route at capacity", payment, Some(digest));
        };
        // Before the upstream write, as the PEP's `allow` is (RV3 A6): if the broker dies during
        // the leg, the execution still joins through this line.
        self.write_log(
            server_id,
            "tools/call",
            id,
            &Verdict {
                jti: Some(claims.jti.clone()),
                action_digest: Some(digest.clone()),
                idempotency_key: key.clone(),
                entity_key: invoice_key.clone(),
                phase: Phase::Forwarding,
                reason: "",
                outcome: None,
                leg: None,
            },
            when,
            None,
        );
        let mut extra = Vec::new();
        if let Some(key) = &key {
            extra.push(("Idempotency-Key", key.clone()));
        }
        if let Some(key) = &invoice_key {
            extra.push((ENTITY_KEY_HEADER, key.clone()));
        }
        let (body, mut verdict) =
            self.forward(server_id, route, message, "tools/call", Some(name), &extra);
        let (body, outcome) = match (payment, verdict.phase) {
            // The tool server cannot have seen it, so it did not execute.
            (true, Phase::Rejected) => (refused(id, true), Some("refused")),
            (true, _) => settle(id, &body),
            (false, _) => (body, None),
        };
        verdict.jti = Some(claims.jti);
        verdict.action_digest = Some(digest);
        verdict.idempotency_key = key;
        verdict.entity_key = invoice_key;
        verdict.outcome = outcome;
        (body, verdict)
    }

    /// Forwards `message`, `dev.pep-sidecar/*` stripped from its `_meta`, with the server's
    /// credential and `extra`, a payment's keys. Returns the reply to give the PEP (the tool
    /// server's, with its reserved `_meta` members stripped) and the verdict.
    fn forward(
        &self,
        server_id: &str,
        route: &Route,
        message: &JcsValue,
        method: &str,
        name: Option<&str>,
        extra: &[(&'static str, String)],
    ) -> (Vec<u8>, Verdict) {
        let id = message
            .get("id")
            .and_then(JcsValue::as_str)
            .unwrap_or_default();
        let mut headers = vec![
            ("Content-Type", "application/json".to_owned()),
            ("Accept", "application/json".to_owned()),
            ("MCP-Protocol-Version", PROTOCOL_VERSION.to_owned()),
            ("Mcp-Method", method.to_owned()),
            ("Authorization", format!("Bearer {}", route.credential)),
        ];
        if let Some(name) = name {
            headers.push(("Mcp-Name", name.to_owned()));
        }
        headers.extend_from_slice(extra);
        let body = strip_params_meta(message).to_canonical_bytes();
        let leg = LegTimer::default();
        let reply = post(&Post {
            endpoint: &route.endpoint,
            path: "/mcp",
            host: server_id,
            headers: &headers,
            body: &body,
            timeout: self.config.upstream_timeout,
            max_body: jcs::MAX_DEFINITION_BYTES,
            peer: None,
            timer: Some(&leg),
        });
        let verdict = |phase, reason| Verdict {
            jti: None,
            action_digest: None,
            idempotency_key: None,
            entity_key: None,
            phase,
            reason,
            outcome: None,
            leg: leg.duration(),
        };
        match reply {
            Err(error) if error.not_delivered() => (
                no_answer(id),
                verdict(Phase::Rejected, "tool server unreachable"),
            ),
            Err(_) => (
                no_answer(id),
                verdict(Phase::Forwarded, "no usable answer from the tool server"),
            ),
            Ok(body) => match clean_reply(id, &body) {
                Some(clean) => (clean, verdict(Phase::Forwarded, "")),
                None => (
                    no_answer(id),
                    verdict(Phase::Forwarded, "no usable answer from the tool server"),
                ),
            },
        }
    }

    /// A share of `server_id`'s connections for one call, if it has any left.
    fn route_slot(&self, server_id: &str) -> Option<RouteSlot<'_>> {
        let counter = self.in_use.get(server_id)?;
        counter
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
                (count < self.route_limit).then(|| count.saturating_add(1))
            })
            .ok()
            .map(|_| RouteSlot(counter))
    }

    fn pep_verifier(&self) -> Option<Es256Verifier> {
        let text = std::fs::read_to_string(&self.config.pep_key).ok()?;
        let bytes = URL_SAFE_NO_PAD.decode(text.trim()).ok()?;
        Es256Verifier::from_sec1(&bytes).ok()
    }

    fn write_log(
        &self,
        server_id: &str,
        method: &str,
        upstream_id: &str,
        verdict: &Verdict,
        when: When,
        broker_us: Option<u64>,
    ) {
        let text = |value: Option<&str>| {
            value.map_or_else(
                || "null".to_owned(),
                |value| JcsValue::string(value).to_canonical_string(),
            )
        };
        let line = format!(
            r#"{{"action_digest":{},"broker_us":{},"entity_key":{},"idempotency_key":{},"jti":{},"method":{},"outcome":{},"reason":{},"server_id":{},"ts_ms":{},"upstream_id":{},"v":1,"verdict":{}}}"#,
            text(verdict.action_digest.as_deref()),
            broker_us.map_or_else(|| "null".to_owned(), |us| us.to_string()),
            text(verdict.entity_key.as_deref()),
            text(verdict.idempotency_key.as_deref()),
            text(verdict.jti.as_deref()),
            text(Some(method)),
            text(verdict.outcome),
            text(Some(verdict.reason)),
            text(Some(server_id)),
            when.now_ms,
            text(Some(upstream_id)),
            text(Some(verdict.phase.name())),
        );
        if let Ok(mut log) = self.log.lock() {
            drop(
                log.write_all(line.as_bytes())
                    .and_then(|()| log.write_all(b"\n")),
            );
        }
    }
}

/// Whether `message` is one of the shapes the PEP builds (F-16). The Call Proof covers only the
/// name and the arguments, so nothing else may be forwarded on its strength.
fn known_shape(message: &JcsValue, method: &str) -> bool {
    let Some(object) = message.as_object() else {
        return false;
    };
    let members_ok = object
        .entries()
        .iter()
        .all(|(key, _)| matches!(key.as_str(), "id" | "jsonrpc" | "method" | "params"));
    let params: &[&str] = match method {
        "tools/call" => &["_meta", "arguments", "name"],
        "tools/list" => &["_meta", "cursor"],
        _ => &["_meta"],
    };
    members_ok
        && message
            .get("params")
            .and_then(JcsValue::as_object)
            .is_some_and(|given| {
                given
                    .entries()
                    .iter()
                    .all(|(key, _)| params.contains(&key.as_str()))
            })
}

/// The forwarded amount and currency of a payment, at its declared pointers.
fn expected_payment(policy: &ToolPolicy, arguments: &JcsValue) -> Option<(u64, String)> {
    let at = |role: ArgRole| {
        let pointer = &policy.args.iter().find(|spec| spec.role == role)?.pointer;
        arguments.pointer(pointer)
    };
    let amount = u64::try_from(at(ArgRole::Amount)?.as_i64()?).ok()?;
    let currency = at(ArgRole::Currency)?.as_str()?.to_owned();
    Some((amount, currency))
}

/// A payment's [`entity_key`], if it pays an invoice (RV5 D5). A recipient has none: paying one
/// payee twice can be legitimate.
fn invoice_key(
    policy: &ToolPolicy,
    arguments: &JcsValue,
    (amount, currency): &(u64, String),
) -> Option<String> {
    let spec = policy
        .args
        .iter()
        .find(|spec| spec.role == ArgRole::Entity(EntityKind::Invoice))?;
    let invoice = arguments.pointer(&spec.pointer)?.as_str()?;
    Some(entity_key(invoice, *amount, currency))
}

/// `message` with every reserved member removed from `params._meta`.
fn strip_params_meta(message: &JcsValue) -> JcsValue {
    let Some(object) = message.as_object() else {
        return message.clone();
    };
    let entries = object
        .entries()
        .iter()
        .map(|(key, value)| {
            if key.as_str() != "params" {
                return (key.clone(), value.clone());
            }
            let params = value.as_object().map_or_else(
                || value.clone(),
                |params| {
                    let inner = params
                        .entries()
                        .iter()
                        .map(|(name, member)| {
                            if name.as_str() == "_meta" {
                                (name.clone(), without_reserved(member))
                            } else {
                                (name.clone(), member.clone())
                            }
                        })
                        .collect();
                    JcsObject::from_entries(inner).map_or_else(|_| value.clone(), JcsValue::Object)
                },
            );
            (key.clone(), params)
        })
        .collect();
    JcsObject::from_entries(entries).map_or_else(|_| message.clone(), JcsValue::Object)
}

/// An object without its `dev.pep-sidecar/*` members.
fn without_reserved(value: &JcsValue) -> JcsValue {
    let Some(object) = value.as_object() else {
        return value.clone();
    };
    let kept: Vec<(JcsString, JcsValue)> = object
        .entries()
        .iter()
        .filter(|(key, _)| !key.as_str().starts_with(RESERVED))
        .cloned()
        .collect();
    JcsObject::from_entries(kept).map_or_else(|_| value.clone(), JcsValue::Object)
}

/// The tool server's reply as the PEP gets it: one JSON-RPC response with this id, and every
/// reserved member of its result's `_meta` stripped. `None` for anything else.
fn clean_reply(id: &str, body: &[u8]) -> Option<Vec<u8>> {
    let value = jcs::parse_with(body, &ParseOptions::definition())
        .ok()?
        .value;
    if value.get("id").and_then(JcsValue::as_str) != Some(id) {
        return None;
    }
    let result = match (value.get("result"), value.get("error")) {
        (Some(result), None) => {
            let object = result.as_object()?;
            let entries = object
                .entries()
                .iter()
                .map(|(key, member)| {
                    if key.as_str() == "_meta" {
                        (key.clone(), without_reserved(member))
                    } else {
                        (key.clone(), member.clone())
                    }
                })
                .collect();
            (
                "result",
                JcsValue::Object(JcsObject::from_entries(entries).ok()?),
            )
        }
        (None, Some(error)) => ("error", error.clone()),
        _ => return None,
    };
    let reply = JcsObject::from_entries(vec![
        (JcsString::new("id"), JcsValue::string(id)),
        (JcsString::new("jsonrpc"), JcsValue::string("2.0")),
        (JcsString::new(result.0), result.1),
    ])
    .ok()?;
    Some(JcsValue::Object(reply).to_canonical_bytes())
}

/// A payment's reply with the broker's outcome: the tool's `status` mapped as P1 says, in the
/// result's `_meta`; an error or no result is `unknown`.
fn settle(id: &str, body: &[u8]) -> (Vec<u8>, Option<&'static str>) {
    let parsed = jcs::parse_with(body, &ParseOptions::definition())
        .ok()
        .map(|parsed| parsed.value);
    let Some(result) = parsed
        .as_ref()
        .and_then(|value| value.get("result"))
        .and_then(JcsValue::as_object)
    else {
        return (no_answer_payment(id), Some("unknown"));
    };
    let outcome = match result
        .get("structuredContent")
        .and_then(|content| content.get("status"))
        .and_then(JcsValue::as_str)
    {
        Some("executed") => "executed",
        Some("declined") => "refused",
        _ => "unknown",
    };
    let mut entries: Vec<(JcsString, JcsValue)> = result
        .entries()
        .iter()
        .filter(|(key, _)| key.as_str() != "_meta")
        .cloned()
        .collect();
    let mut meta: Vec<(JcsString, JcsValue)> = result
        .get("_meta")
        .and_then(JcsValue::as_object)
        .map(|meta| meta.entries().to_vec())
        .unwrap_or_default();
    meta.push((JcsString::new(OUTCOME_META_KEY), JcsValue::string(outcome)));
    let Ok(meta) = JcsObject::from_entries(meta) else {
        return (no_answer_payment(id), Some("unknown"));
    };
    entries.push((JcsString::new("_meta"), JcsValue::Object(meta)));
    let Ok(result) = JcsObject::from_entries(entries) else {
        return (no_answer_payment(id), Some("unknown"));
    };
    let mut out = br#"{"id":"#.to_vec();
    out.extend(JcsValue::string(id).to_canonical_bytes());
    out.extend_from_slice(br#","jsonrpc":"2.0","result":"#);
    out.extend(JcsValue::Object(result).to_canonical_bytes());
    out.push(b'}');
    (out, Some(outcome))
}

/// A JSON-RPC error for the PEP, with the payment outcome in `data` when there is one.
fn error_reply(id: &str, message: &str, outcome: Option<&str>) -> Vec<u8> {
    let data = outcome.map_or_else(String::new, |outcome| {
        format!(r#""data":{{"{OUTCOME_META_KEY}":"{outcome}"}},"#)
    });
    format!(
        r#"{{"error":{{"code":-31503,{data}"message":{}}},"id":{},"jsonrpc":"2.0"}}"#,
        JcsValue::string(message).to_canonical_string(),
        JcsValue::string(id).to_canonical_string()
    )
    .into_bytes()
}

/// A refused Call Proof: nothing reached the tool server.
fn refused(id: &str, payment: bool) -> Vec<u8> {
    error_reply(id, "refused", payment.then_some("refused"))
}

/// No usable answer from a tool server, for a call that is not a payment.
fn no_answer(id: &str) -> Vec<u8> {
    error_reply(id, "no answer", None)
}

/// No usable answer for a payment: its outcome is unknown.
fn no_answer_payment(id: &str) -> Vec<u8> {
    error_reply(id, "no answer", Some("unknown"))
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

    /// A config for `connections` connections and routes to servers `a` and `b`, with `a`'s
    /// route at `endpoint`.
    fn config_text(connections: usize, endpoint: &str) -> String {
        let log = std::env::temp_dir().join(format!(
            "pep-broker-log-{}-{connections}",
            std::process::id()
        ));
        format!(
            r#"{{"socket":"/s","pep":{{"uid":1,"gid":1}},"pep_key":"/k","pins":"/pins",
            "routes":{{"a":{{"endpoint":"{endpoint}","credential":"/c"}},"b":{{"endpoint":"unix:/b","credential":"/c"}}}},
            "replay_cache_entries":16,"clock_skew_ms":0,"connections":{connections},"upstream_timeout_ms":1000,"log":"{}"}}"#,
            log.display()
        )
    }

    /// Loads [`config_text`], with its pins and credentials read from nowhere.
    fn load_config(connections: usize, endpoint: &str) -> Result<BrokerConfig, LoadError> {
        load_with(connections, endpoint, b"s3cret")
    }

    /// [`load_config`], with the file bytes of every credential.
    fn load_with(
        connections: usize,
        endpoint: &str,
        credential: &[u8],
    ) -> Result<BrokerConfig, LoadError> {
        let server = |name: &str, endpoint: &str| {
            format!(
                r#""{name}":{{"endpoint":"{endpoint}","identity":"spiffe://{name}","protocol_version":"2026-07-28","discover":{{}},"tools":{{}}}}"#
            )
        };
        let pins = format!(
            r#"{{"lockfile_version":1,"release_epoch":7,"stores":{{}},"servers":{{{},{}}}}}"#,
            server("a", "unix:/a"),
            server("b", "unix:/b"),
        );
        load(config_text(connections, endpoint).as_bytes(), &|path| {
            Some(if path == Path::new("/pins") {
                pins.clone().into_bytes()
            } else {
                credential.to_vec()
            })
        })
    }

    #[test]
    fn a_credential_is_the_files_exact_bytes() {
        // A tool's verifier hashes the file, so a trimmed newline could never match it.
        assert!(load_with(8, "unix:/a", b"s3cret\n").is_err());
        assert!(load_with(8, "unix:/a", b" s3cret").is_err());
        assert!(load_with(8, "unix:/a", b"").is_err());
        assert_eq!(
            load_with(8, "unix:/a", b"s3cret").unwrap().routes["a"].credential,
            "s3cret"
        );
    }

    #[test]
    fn a_route_never_prints_its_credential() {
        let config = load_config(8, "unix:/a").unwrap();
        assert_eq!(config.routes["a"].credential, "s3cret");
        assert!(!format!("{config:?}").contains("s3cret"));
    }

    #[test]
    fn a_route_must_go_where_the_lockfile_says() {
        assert!(load_config(8, "unix:/a").is_ok());
        let elsewhere = load_config(8, "unix:/attacker");
        assert!(
            elsewhere
                .unwrap_err()
                .to_string()
                .contains("differs from the endpoint pinned")
        );
    }

    #[test]
    fn one_route_cannot_take_every_connection() {
        let config = load_config(10, "unix:/a").unwrap();
        let log = config.log.clone();
        let broker = Broker::open(config, 0).unwrap();
        // Ten connections, two kept back for polls, and two routes: four each.
        let taken: Vec<_> = (0..4).map(|_| broker.route_slot("a").unwrap()).collect();
        assert!(broker.route_slot("a").is_none());
        assert!(
            broker.route_slot("b").is_some(),
            "the other route is not affected"
        );
        assert!(broker.route_slot("unrouted").is_none());
        drop(taken);
        assert!(broker.route_slot("a").is_some(), "slots are given back");
        // Whatever the arithmetic says, a route can always make progress.
        let few = load_config(1, "unix:/a").unwrap();
        let log_few = few.log.clone();
        assert!(Broker::open(few, 0).unwrap().route_slot("a").is_some());
        drop(std::fs::remove_file(log));
        drop(std::fs::remove_file(log_few));
    }

    #[test]
    fn only_the_shapes_the_pep_builds_are_forwarded() {
        let shape =
            |text: &str, method: &str| known_shape(&jcs::parse(text.as_bytes()).unwrap(), method);
        assert!(shape(
            r#"{"id":"01J","jsonrpc":"2.0","method":"tools/call","params":{"_meta":{},"arguments":{},"name":"t"}}"#,
            "tools/call"
        ));
        assert!(shape(
            r#"{"id":"01J","jsonrpc":"2.0","method":"tools/list","params":{"_meta":{},"cursor":"c"}}"#,
            "tools/list"
        ));
        // The proof covers the name and the arguments only, so nothing else may ride on it.
        assert!(!shape(
            r#"{"id":"01J","jsonrpc":"2.0","method":"tools/call","extra":1,"params":{"_meta":{},"arguments":{},"name":"t"}}"#,
            "tools/call"
        ));
        assert!(!shape(
            r#"{"id":"01J","jsonrpc":"2.0","method":"tools/call","params":{"_meta":{},"arguments":{},"name":"t","task":{}}}"#,
            "tools/call"
        ));
        assert!(!shape(
            r#"{"id":"01J","jsonrpc":"2.0","method":"tools/list","params":{"_meta":{},"arguments":{}}}"#,
            "tools/list"
        ));
        assert!(!shape(
            r#"{"id":"01J","jsonrpc":"2.0","method":"tools/list"}"#,
            "tools/list"
        ));
        assert!(!shape("[]", "tools/list"));
    }

    #[test]
    fn a_connection_past_the_limit_gets_a_status_not_a_close() {
        let (mut client, server) = UnixStream::pair().unwrap();
        refuse_overflow(server);
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).unwrap();
        assert!(reply.starts_with(b"HTTP/1.1 503 "));
    }

    #[test]
    fn the_tool_server_never_sees_reserved_meta() {
        let message = jcs::parse(
            br#"{"id":"01J","jsonrpc":"2.0","method":"tools/call","params":{"_meta":{"dev.pep-sidecar/call-proof":"eyJ.p","dev.pep-sidecar/other":1,"io.modelcontextprotocol/protocolVersion":"2026-07-28"},"arguments":{},"name":"t"}}"#,
        )
        .unwrap();
        let stripped = String::from_utf8(strip_params_meta(&message).to_canonical_bytes()).unwrap();
        assert!(!stripped.contains("dev.pep-sidecar"));
        assert!(
            stripped
                .contains(r#""_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}"#)
        );
        assert!(stripped.contains(r#""id":"01J""#));
    }

    #[test]
    fn the_pep_never_gets_a_tool_servers_reserved_meta() {
        // A tool server cannot forge the outcome: its own reserved members are stripped.
        let body = br#"{"id":"01J","jsonrpc":"2.0","result":{"_meta":{"dev.pep-sidecar/outcome":"executed","x":1},"resultType":"complete"}}"#;
        let clean = String::from_utf8(clean_reply("01J", body).unwrap()).unwrap();
        assert_eq!(
            clean,
            r#"{"id":"01J","jsonrpc":"2.0","result":{"_meta":{"x":1},"resultType":"complete"}}"#
        );
        assert_eq!(clean_reply("01K", body), None, "another id");
        assert_eq!(clean_reply("01J", b"{"), None);
    }

    #[test]
    fn payment_statuses_map_as_p1_says() {
        for (status, outcome) in [
            (r#""executed""#, "executed"),
            (r#""declined""#, "refused"),
            (r#""pending""#, "unknown"),
            ("7", "unknown"),
        ] {
            let body = format!(
                r#"{{"id":"01J","jsonrpc":"2.0","result":{{"resultType":"complete","structuredContent":{{"status":{status}}}}}}}"#
            );
            let (reply, found) = settle("01J", body.as_bytes());
            assert_eq!(found, Some(outcome), "{status}");
            let reply = jcs::parse(&reply).unwrap();
            assert_eq!(
                reply
                    .pointer("/result/_meta")
                    .unwrap()
                    .get(OUTCOME_META_KEY)
                    .unwrap()
                    .as_str(),
                Some(outcome)
            );
        }
        // No result at all is unknown, as an error with the outcome in `data`.
        let (reply, found) = settle(
            "01J",
            br#"{"id":"01J","jsonrpc":"2.0","error":{"code":1,"message":"x"}}"#,
        );
        assert_eq!(found, Some("unknown"));
        let reply = jcs::parse(&reply).unwrap();
        assert_eq!(
            reply
                .pointer("/error/data")
                .unwrap()
                .get(OUTCOME_META_KEY)
                .unwrap()
                .as_str(),
            Some("unknown")
        );
        assert_eq!(
            jcs::canonicalize(&refused("01J", true)).unwrap(),
            refused("01J", true)
        );
    }
}
