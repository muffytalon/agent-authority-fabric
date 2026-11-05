//! The stub broker (`WEEK2_PLAN` §2a, PEP↔broker).
//!
//! One request per connection from the PEP, whose uid and gid it requires. It routes
//! `/mcp/{server_id}` through its own static table (RV4 #12) and:
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
//! - logs one line per request.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::config::{Fields, LoadError, Problem, is_plain_name};
use crate::engine::{ArgRole, EffectClass, ToolPolicy, idempotency_key};
use crate::forward::{CALL_PROOF_META_KEY, OUTCOME_META_KEY, PROTOCOL_VERSION};
use crate::http::{Request, Status, response};
use crate::jcs::{self, JcsObject, JcsString, JcsValue, ParseOptions};
use crate::lockfile::{Lockfile, MAX_SERVER_ID, parse_payload};
use crate::tokens::{
    CallProofExpectations, Es256Verifier, ExpectedPayment, ReplayCache, verify_call_proof,
};
use crate::upstream::{Endpoint, Post, post};

/// The prefix of every reserved `_meta` member.
const RESERVED: &str = "dev.pep-sidecar/";

/// One route: where a server listens, and its credential.
#[derive(Debug, Clone)]
pub struct Route {
    /// The tool server's endpoint.
    pub endpoint: Endpoint,
    /// Its credential, injected as `Authorization: Bearer …`.
    pub credential: String,
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
        let endpoint = Endpoint::parse(route.string("endpoint")?).ok_or_else(|| {
            LoadError::at(
                &endpoint_path,
                Problem::Invalid("unix:/path or tcp:host:port"),
            )
        })?;
        let credential_path = route.path("credential")?;
        let credential = read(&credential_path)
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .map(|text| text.trim().to_owned())
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
}

/// What one request came to, for the log.
struct Verdict {
    jti: Option<String>,
    action_digest: Option<String>,
    idempotency_key: Option<String>,
    forwarded: bool,
    reason: &'static str,
    outcome: Option<&'static str>,
}

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
        Ok(Self {
            cache: ReplayCache::new(
                config.replay_cache_entries,
                boot_second,
                config.clock_skew_secs,
            ),
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

    /// Answers one request from the PEP: the HTTP response bytes.
    #[must_use]
    pub fn handle(&self, request: &Request, now: u64, now_ms: u64) -> Vec<u8> {
        let Some((server_id, route)) = request
            .head
            .target
            .strip_prefix("/mcp/")
            .and_then(|id| self.config.routes.get_key_value(id))
        else {
            return response(Status::NotFound, None);
        };
        if !request.head.is_post() {
            return response(Status::MethodNotAllowed, None);
        }
        let Ok(message) = jcs::parse(&request.body) else {
            return response(Status::BadRequest, None);
        };
        let (Some(id), Some(method)) = (
            message.get("id").and_then(JcsValue::as_str),
            message.get("method").and_then(JcsValue::as_str),
        ) else {
            return response(Status::BadRequest, None);
        };
        let proof = message
            .pointer("/params/_meta")
            .and_then(|meta| meta.get(CALL_PROOF_META_KEY))
            .and_then(JcsValue::as_str);
        let (body, verdict) = match (method, proof) {
            ("server/discover" | "tools/list", None) => {
                self.forward(server_id, route, &message, method, None, None)
            }
            ("tools/call", Some(proof)) => self.call(server_id, route, &message, proof, now),
            _ => (
                refused(id, false),
                Verdict {
                    jti: None,
                    action_digest: None,
                    idempotency_key: None,
                    forwarded: false,
                    reason: "a proof-less request other than discover or list",
                    outcome: None,
                },
            ),
        };
        self.write_log(server_id, method, id, &verdict, now_ms);
        response(Status::Ok, Some(("application/json", &body)))
    }

    fn call(
        &self,
        server_id: &str,
        route: &Route,
        message: &JcsValue,
        proof: &str,
        now: u64,
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
                    forwarded: false,
                    reason,
                    outcome: payment.then_some("refused"),
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
        let Ok(claims) = verify_call_proof(proof, &verifier, &expect, &self.cache, now) else {
            return reject("call proof refused", payment, Some(digest));
        };
        let key = claims
            .payment
            .as_ref()
            .map(|payment| idempotency_key(claims.eid, payment.rid(), &digest));
        let (body, mut verdict) = self.forward(
            server_id,
            route,
            message,
            "tools/call",
            Some(name),
            key.as_deref(),
        );
        let (body, outcome) = if payment {
            settle(id, &body)
        } else {
            (body, None)
        };
        verdict.jti = Some(claims.jti);
        verdict.action_digest = Some(digest);
        verdict.idempotency_key = key;
        verdict.outcome = outcome;
        (body, verdict)
    }

    /// Forwards `message`, `dev.pep-sidecar/*` stripped from its `_meta`, with the server's
    /// credential and, for a payment, its `Idempotency-Key`. Returns the reply to give the PEP
    /// (the tool server's, with its reserved `_meta` members stripped) and the verdict.
    fn forward(
        &self,
        server_id: &str,
        route: &Route,
        message: &JcsValue,
        method: &str,
        name: Option<&str>,
        key: Option<&str>,
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
        if let Some(key) = key {
            headers.push(("Idempotency-Key", key.to_owned()));
        }
        let body = strip_params_meta(message).to_canonical_bytes();
        let reply = post(&Post {
            endpoint: &route.endpoint,
            path: "/mcp",
            host: server_id,
            headers: &headers,
            body: &body,
            timeout: self.config.upstream_timeout,
            max_body: jcs::MAX_DEFINITION_BYTES,
            peer: None,
        });
        let verdict = |reason| Verdict {
            jti: None,
            action_digest: None,
            idempotency_key: None,
            forwarded: true,
            reason,
            outcome: None,
        };
        match reply.ok().and_then(|body| clean_reply(id, &body)) {
            Some(clean) => (clean, verdict("")),
            None => (
                no_answer(id),
                verdict("no usable answer from the tool server"),
            ),
        }
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
        now_ms: u64,
    ) {
        let text = |value: Option<&str>| {
            value.map_or_else(
                || "null".to_owned(),
                |value| JcsValue::string(value).to_canonical_string(),
            )
        };
        let line = format!(
            r#"{{"action_digest":{},"idempotency_key":{},"jti":{},"method":{},"outcome":{},"reason":{},"server_id":{},"ts_ms":{now_ms},"upstream_id":{},"v":1,"verdict":{}}}"#,
            text(verdict.action_digest.as_deref()),
            text(verdict.idempotency_key.as_deref()),
            text(verdict.jti.as_deref()),
            text(Some(method)),
            text(verdict.outcome),
            text(Some(verdict.reason)),
            text(Some(server_id)),
            text(Some(upstream_id)),
            text(Some(if verdict.forwarded {
                "forwarded"
            } else {
                "rejected"
            })),
        );
        if let Ok(mut log) = self.log.lock() {
            drop(
                log.write_all(line.as_bytes())
                    .and_then(|()| log.write_all(b"\n")),
            );
        }
    }
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
