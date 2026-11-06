//! The stub tool server (`WEEK2_PLAN` §2a): the Week 1 test tools behind one `server_id`.
//!
//! - It serves its pinned `server/discover` result and tool definitions, read from the same
//!   lockfile payload the PEP and the broker load, so a poll matches unless a misbehaviour mode
//!   says otherwise.
//! - Every request must carry the server's own credential (`Authorization: Bearer …`). The
//!   server keeps only its SHA-256, as lowercase hex, and compares in constant time; a
//!   rejected call executes nothing (C-CRED, RV4 #7).
//! - A payment needs an `Idempotency-Key` and is executed at most once per key, in a store
//!   that survives restarts. Its result carries an explicit `status`: `executed`, `declined`
//!   or `pending` (RV3 B6).
//! - A payment of an invoice also needs a `Pep-Entity-Key`, and executes at most once per key
//!   whichever reservation asks, as a provider's own invoice check would: this holds even if
//!   the PEP's journal is lost. Only an execution uses it up, so a declined invoice can be
//!   retried (RV5 D5).
//! - Every `tools/call` adds one line to the execution log, which the oracle joins (§2a).

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use sha2::{Digest as _, Sha256};

use crate::config::{Fields, LoadError, Problem};
use crate::engine::{ArgRole, EffectClass, EntityKind};
use crate::http::{Request, Status, response};
use crate::jcs::{self, JcsValue, ParseOptions};
use crate::lockfile::{Lockfile, PinnedServer, parse_payload};

/// The tool server's config.
#[derive(Debug, Clone)]
pub struct ToolConfig {
    /// The server it is.
    pub server_id: String,
    /// Where it listens: `unix:/path` or `tcp:host:port`.
    pub listen: String,
    /// Lowercase hex SHA-256 of its credential.
    pub verifier: String,
    /// The lockfile payload.
    pub pins: Lockfile,
    /// The dedupe store.
    pub store: PathBuf,
    /// The execution log.
    pub log: PathBuf,
    /// Invoices by id: amount due, currency, and the status a payment of it gets.
    pub invoices: BTreeMap<String, Invoice>,
}

/// One invoice the server knows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invoice {
    /// Amount due, in minor units.
    pub amount_due_minor: u64,
    /// Its currency.
    pub currency: String,
    /// What paying it returns: `executed`, `declined` or `pending`.
    pub status: String,
}

/// Loads a tool server config. `read` reads a file the config names.
///
/// # Errors
///
/// Returns a [`LoadError`] for anything malformed.
pub fn load(
    bytes: &[u8],
    read: &dyn Fn(&Path) -> Option<Vec<u8>>,
) -> Result<ToolConfig, LoadError> {
    let root = jcs::parse(bytes).map_err(|error| LoadError::at("", Problem::Json(error)))?;
    let mut fields = Fields::of(&root, "")?;
    let server_id = fields.string("server_id")?.to_owned();
    let listen = fields.string("listen")?.to_owned();
    let verifier_path = fields.path("verifier")?;
    let verifier = read(&verifier_path)
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .map(|text| text.trim().to_owned())
        .filter(|text| {
            text.len() == 64
                && text
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        })
        .ok_or_else(|| {
            LoadError::at(
                "verifier",
                Problem::Invalid("not 64 lowercase hex characters"),
            )
        })?;
    let pins_path = fields.path("pins")?;
    let pins_bytes =
        read(&pins_path).ok_or_else(|| LoadError::at("pins", Problem::Invalid("unreadable")))?;
    let pins_value = jcs::parse_with(&pins_bytes, &ParseOptions::definition())
        .map_err(|error| LoadError::at("pins", Problem::Json(error)))?
        .value;
    let pins = parse_payload(&pins_value, "pins")?;
    if !pins.servers.contains_key(&server_id) {
        return Err(LoadError::at("server_id", Problem::Invalid("not pinned")));
    }
    let store = fields.path("store")?;
    let log = fields.path("log")?;
    let mut invoices = BTreeMap::new();
    let mut invoice_fields = fields.object("invoices")?;
    for (id, value, path) in invoice_fields.members() {
        let mut invoice = Fields::of(value, &path)?;
        let status = invoice.string("status")?.to_owned();
        if !matches!(status.as_str(), "executed" | "declined" | "pending") {
            return Err(LoadError::at(
                &path,
                Problem::Invalid("status must be executed, declined or pending"),
            ));
        }
        invoices.insert(
            id.to_owned(),
            Invoice {
                amount_due_minor: invoice.u64("amount_due_minor")?,
                currency: invoice.string("currency")?.to_owned(),
                status,
            },
        );
        invoice.done()?;
    }
    invoice_fields.done()?;
    fields.done()?;
    Ok(ToolConfig {
        server_id,
        listen,
        verifier,
        pins,
        store,
        log,
        invoices,
    })
}

/// Whether `left` and `right` are equal, in time that depends only on their lengths.
#[must_use]
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0u8, |difference, (a, b)| difference | (a ^ b))
            == 0
}

/// Lowercase hex SHA-256 of `data`.
#[must_use]
pub fn sha256_hex(data: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(64);
    for byte in Sha256::digest(data) {
        // Writing to a String cannot fail.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// A running tool server's state.
#[derive(Debug)]
pub struct ToolServer {
    config: ToolConfig,
    pinned: PinnedServer,
    state: Mutex<State>,
}

/// A `tools/call`'s payment headers.
#[derive(Clone, Copy)]
struct PaymentKeys<'a> {
    idempotency: Option<&'a str>,
    entity: Option<&'a str>,
}

#[derive(Debug)]
struct State {
    /// Results already returned, by `Idempotency-Key`.
    done: BTreeMap<String, Vec<u8>>,
    /// Results of executed payments, by `Pep-Entity-Key`.
    paid: BTreeMap<String, Vec<u8>>,
    store: File,
    log: File,
    notes: BTreeMap<String, String>,
}

impl ToolServer {
    /// Opens the server's dedupe store and log.
    ///
    /// # Errors
    ///
    /// Returns a description of the file that could not be opened or read.
    pub fn open(config: ToolConfig) -> Result<Self, String> {
        let pinned = config
            .pins
            .servers
            .get(&config.server_id)
            .cloned()
            .ok_or_else(|| "server not pinned".to_owned())?;
        let mut done = BTreeMap::new();
        let mut paid = BTreeMap::new();
        if let Ok(existing) = File::open(&config.store) {
            for line in BufReader::new(existing).lines() {
                let line = line.map_err(|error| format!("store: {error}"))?;
                let value = jcs::parse_with(line.as_bytes(), &ParseOptions::definition())
                    .map_err(|error| format!("store: {error}"))?
                    .value;
                if let (Some(key), Some(result)) = (
                    value.get("idempotency_key").and_then(JcsValue::as_str),
                    value.get("result"),
                ) {
                    done.insert(key.to_owned(), result.to_canonical_bytes());
                    if let Some(entity_key) = value.get("entity_key").and_then(JcsValue::as_str) {
                        paid.insert(entity_key.to_owned(), result.to_canonical_bytes());
                    }
                }
            }
        }
        let append = |path: &Path| {
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map_err(|error| format!("{}: {error}", path.display()))
        };
        let state = State {
            done,
            paid,
            store: append(&config.store)?,
            log: append(&config.log)?,
            notes: BTreeMap::new(),
        };
        Ok(Self {
            config,
            pinned,
            state: Mutex::new(state),
        })
    }

    /// Answers one request: the HTTP response bytes.
    #[must_use]
    pub fn handle(&self, request: &Request, now_ms: u64) -> Vec<u8> {
        if !request.head.is_post() {
            return response(Status::MethodNotAllowed, None);
        }
        let credential = request
            .head
            .headers
            .get("authorization")
            .and_then(|value| value.strip_prefix("Bearer "));
        let authorized = credential.is_some_and(|credential| {
            constant_time_eq(
                sha256_hex(credential.as_bytes()).as_bytes(),
                self.config.verifier.as_bytes(),
            )
        });
        if !authorized {
            // C-CRED: nothing executes.
            return response(Status::Forbidden, None);
        }
        let Ok(message) = jcs::parse(&request.body) else {
            return response(Status::BadRequest, None);
        };
        let (Some(id), Some(method)) = (
            message.get("id").cloned(),
            message.get("method").and_then(JcsValue::as_str),
        ) else {
            return response(Status::BadRequest, None);
        };
        let result = match method {
            "server/discover" => Some(self.pinned.discover.to_canonical_bytes()),
            "tools/list" => Some(tools_list(&self.pinned.definitions)),
            "tools/call" => {
                let keys = PaymentKeys {
                    idempotency: request.head.headers.get("idempotency-key"),
                    entity: request.head.headers.get("pep-entity-key"),
                };
                self.call(&message, &id, keys, now_ms)
            }
            _ => None,
        };
        let body = if let Some(result) = result {
            let mut body = br#"{"id":"#.to_vec();
            body.extend(id.to_canonical_bytes());
            body.extend_from_slice(br#","jsonrpc":"2.0","result":"#);
            body.extend(result);
            body.push(b'}');
            body
        } else {
            let mut body =
                br#"{"error":{"code":-32601,"message":"Method not found"},"id":"#.to_vec();
            body.extend(id.to_canonical_bytes());
            body.extend_from_slice(br#","jsonrpc":"2.0"}"#);
            body
        };
        response(Status::Ok, Some(("application/json", &body)))
    }

    fn call(
        &self,
        message: &JcsValue,
        id: &JcsValue,
        keys: PaymentKeys<'_>,
        now_ms: u64,
    ) -> Option<Vec<u8>> {
        let idempotency_key = keys.idempotency;
        let name = message.pointer("/params/name")?.as_str()?.to_owned();
        let empty = JcsValue::Object(jcs::JcsObject::from_entries(Vec::new()).ok()?);
        let arguments = message
            .pointer("/params/arguments")
            .unwrap_or(&empty)
            .clone();
        let policy = self.config.pins.pins.tools.get(&name)?;
        if policy.server_id != self.config.server_id {
            return None;
        }
        let digest = jcs::action_digest(&name, &arguments);
        let text = |key: &str| {
            arguments
                .get(key)
                .and_then(JcsValue::as_str)
                .map(str::to_owned)
        };
        let mut state = self.state.lock().ok()?;
        let (result, executed) = if policy.effect == EffectClass::Payment {
            let key = idempotency_key?.to_owned();
            let invoice_tool = policy
                .args
                .iter()
                .any(|spec| spec.role == ArgRole::Entity(EntityKind::Invoice));
            if invoice_tool && keys.entity.is_none() {
                return None;
            }
            let paid = keys.entity.and_then(|entity| state.paid.get(entity));
            if let Some(previous) = state.done.get(&key).or(paid) {
                (previous.clone(), false)
            } else {
                let invoice = text("invoice_id").and_then(|invoice| {
                    self.config
                        .invoices
                        .get(&invoice)
                        .map(|found| (invoice, found))
                });
                let status = invoice.map_or("declined", |(_, found)| found.status.as_str());
                let result = complete(
                    &format!(
                        r#"{{"status":{}}}"#,
                        JcsValue::string(status).to_canonical_string()
                    ),
                    &format!("payment {status}"),
                );
                // Only an execution uses the invoice up, so a decline can be retried.
                let spent = keys.entity.filter(|_| status == "executed");
                let record = format!(
                    r#"{{"entity_key":{},"idempotency_key":{},"result":{}}}"#,
                    spent.map_or_else(
                        || "null".to_owned(),
                        |entity| JcsValue::string(entity).to_canonical_string()
                    ),
                    JcsValue::string(key.as_str()).to_canonical_string(),
                    String::from_utf8_lossy(&result)
                );
                // Durable before the reply: a restart must not pay twice.
                state.store.write_all(record.as_bytes()).ok()?;
                state.store.write_all(b"\n").ok()?;
                state.store.sync_data().ok()?;
                state.done.insert(key, result.clone());
                if let Some(entity) = spent {
                    state.paid.insert(entity.to_owned(), result.clone());
                }
                (result, status == "executed")
            }
        } else {
            (
                self.read_or_write(&name, &arguments, &mut state.notes),
                true,
            )
        };
        let log = format!(
            r#"{{"action_digest":{},"entity_key":{},"executed":{executed},"idempotency_key":{},"server_id":{},"tool":{},"ts_ms":{now_ms},"upstream_id":{},"v":1}}"#,
            JcsValue::string(digest.as_str()).to_canonical_string(),
            keys.entity.map_or_else(
                || "null".to_owned(),
                |key| JcsValue::string(key).to_canonical_string()
            ),
            idempotency_key.map_or_else(
                || "null".to_owned(),
                |key| JcsValue::string(key).to_canonical_string()
            ),
            JcsValue::string(self.config.server_id.as_str()).to_canonical_string(),
            JcsValue::string(name.as_str()).to_canonical_string(),
            id.to_canonical_string(),
        );
        state.log.write_all(log.as_bytes()).ok()?;
        state.log.write_all(b"\n").ok()?;
        state.log.flush().ok()?;
        Some(result)
    }

    /// The non-payment tools of the Week 1 set.
    fn read_or_write(
        &self,
        name: &str,
        arguments: &JcsValue,
        notes: &mut BTreeMap<String, String>,
    ) -> Vec<u8> {
        let text = |key: &str| {
            arguments
                .get(key)
                .and_then(JcsValue::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        let quote = |value: &str| JcsValue::string(value).to_canonical_string();
        match name {
            "get_invoice" => {
                let id = text("invoice_id");
                match self.config.invoices.get(&id) {
                    Some(invoice) => complete(
                        &format!(
                            r#"{{"amount_due_minor":{},"currency":{},"invoice_id":{}}}"#,
                            invoice.amount_due_minor,
                            quote(&invoice.currency),
                            quote(&id)
                        ),
                        &format!("invoice {id}"),
                    ),
                    None => error_result("no such invoice"),
                }
            }
            "save_note" => {
                let key = text("key");
                notes.insert(key.clone(), text("text"));
                complete(&format!(r#"{{"saved":{}}}"#, quote(&key)), "saved")
            }
            "get_note" => {
                let key = text("key");
                let note = notes.get(&key).cloned().unwrap_or_default();
                complete(
                    &format!(r#"{{"key":{},"text":{}}}"#, quote(&key), quote(&note)),
                    &note,
                )
            }
            "search_notes" => {
                let query = text("query");
                let found: Vec<String> = notes
                    .values()
                    .filter(|note| note.contains(&query))
                    .map(|note| quote(note))
                    .collect();
                complete(&format!(r#"{{"notes":[{}]}}"#, found.join(",")), "notes")
            }
            _ => complete("{}", &format!("{name} done")),
        }
    }
}

/// A complete result with `structured` content and one text item.
fn complete(structured: &str, text: &str) -> Vec<u8> {
    format!(
        r#"{{"content":[{{"text":{},"type":"text"}}],"isError":false,"resultType":"complete","structuredContent":{structured}}}"#,
        JcsValue::string(text).to_canonical_string()
    )
    .into_bytes()
}

fn error_result(text: &str) -> Vec<u8> {
    format!(
        r#"{{"content":[{{"text":{},"type":"text"}}],"isError":true,"resultType":"complete"}}"#,
        JcsValue::string(text).to_canonical_string()
    )
    .into_bytes()
}

fn tools_list(definitions: &[JcsValue]) -> Vec<u8> {
    let mut out = br#"{"resultType":"complete","tools":["#.to_vec();
    for (index, definition) in definitions.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        out.extend(definition.to_canonical_bytes());
    }
    out.extend_from_slice(b"]}");
    out
}

/// The path the tool server serves.
pub const TOOL_ENDPOINT: &str = "/mcp";

/// Reads a file, for [`load`].
#[must_use]
pub fn read_file(path: &Path) -> Option<Vec<u8>> {
    std::fs::read(path).ok()
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
    fn credentials_compare_by_verifier_in_constant_time() {
        let verifier = sha256_hex(b"credential-a");
        assert_eq!(verifier.len(), 64);
        assert!(constant_time_eq(
            sha256_hex(b"credential-a").as_bytes(),
            verifier.as_bytes()
        ));
        assert!(!constant_time_eq(
            sha256_hex(b"credential-b").as_bytes(),
            verifier.as_bytes()
        ));
        assert!(!constant_time_eq(b"short", verifier.as_bytes()));
        // The well-known digest of the empty string.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
