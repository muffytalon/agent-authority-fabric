//! The PEP's decision log (`WEEK2_PLAN` §2a): JSONL, one JCS-canonical object per line with
//! `"v": 1`, on its own volume (RV3 B4), rotated at `log.max_bytes`.
//!
//! Two records per forwarded call (RV3 A6): a decision, written and flushed before the
//! upstream write, and an outcome after the leg ends, joined by the call's `upstream_id`, a
//! ULID unique across boots (M1). Denials, step-ups and protocol errors get a decision record
//! too. `reason` is host-side only. No record holds a token, proof, key, credential, or any
//! argument value but the bound entity, amount and currency.
//!
//! A record with no episode, which any connection can cause with no token and no rate limit,
//! goes to its own file (`<path>.protocol`) with its own rotation, so that noise can never rotate
//! a decision away: a 16 KiB header per request did that in under 2 seconds (RV5 V5). Text the
//! sender chose is clamped ([`MAX_SENDER_TEXT`]).
//!
//! An episode's own records cannot rotate another's away either: its allowed calls are bounded
//! by `MAX_CALLS_PER_EPISODE`, and past a quota the actor sends its denials, the one record a
//! token holder can make without limit, to that same file ([`DecisionLog::overflow`], RV5 D3).
//! So flushing the decision log takes many episodes, and only the operator can start one. `seq`
//! restarts at every boot, so `boot_ms` says which boot a record belongs to.
//!
//! Writing is best effort: a record the log cannot take is lost, never the call. The oracle
//! counts an execution with no `allow` as a bypass, so a lost record fails loud, not open.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::engine::encode_ulid;
use crate::jcs::{JcsObject, JcsString, JcsValue};

/// Most bytes of text a sender chose that one record keeps: every valid MCP method and tool name
/// fits.
pub const MAX_SENDER_TEXT: usize = 128;

/// The smallest rotation size of the noise file.
const MIN_NOISE_BYTES: u64 = 1024 * 1024;

/// A decision's verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Allowed, and about to be forwarded.
    Allow,
    /// Denied: `PEP_DENIED`.
    Deny,
    /// A payment waiting for approval.
    StepUp,
    /// `PEP_UNAVAILABLE`.
    Unavailable,
    /// Refused by the transport (U1 steps 1 to 13).
    ProtocolError,
}

impl Verdict {
    const fn name(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::StepUp => "step_up",
            Self::Unavailable => "unavailable",
            Self::ProtocolError => "protocol_error",
        }
    }
}

/// How a call ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ending {
    /// The tool executed it (a payment's explicit outcome, or a non-payment's result).
    Executed,
    /// The broker refused it, or it never reached the tool server.
    Refused,
    /// The tool server declined a payment.
    Declined,
    /// No one knows: a payment left unresolved.
    Unknown,
    /// A payment released before its point of forwarding.
    Released,
    /// A non-payment call whose leg failed.
    Abandoned,
    /// A non-payment call stopped before its point of forwarding.
    NotForwarded,
}

impl Ending {
    const fn name(self) -> &'static str {
        match self {
            Self::Executed => "executed",
            Self::Refused => "refused",
            Self::Declined => "declined",
            Self::Unknown => "unknown",
            Self::Released => "released",
            Self::Abandoned => "abandoned",
            Self::NotForwarded => "not_forwarded",
        }
    }
}

/// One decision record.
#[derive(Debug, Clone, Default)]
pub struct Decision<'a> {
    /// The episode, once a token named one.
    pub eid: Option<u128>,
    /// The connection's peer uid.
    pub peer_uid: Option<u32>,
    /// The MCP method.
    pub method: &'a str,
    /// The tool.
    pub tool: Option<&'a str>,
    /// The call's `action_digest`.
    pub action_digest: Option<&'a str>,
    /// The guard or error variant, host-side only.
    pub reason: Option<String>,
    /// The payment's reservation.
    pub rid: Option<u64>,
    /// The payment's amount.
    pub amount_minor: Option<u64>,
    /// The payment's currency.
    pub currency: Option<&'a str>,
    /// The payment's entity.
    pub entity: Option<&'a str>,
    /// The Call Proof's `jti`.
    pub jti: Option<&'a str>,
    /// The payment's F-07 key.
    pub idempotency_key: Option<&'a str>,
    /// The PEP-assigned id the call goes upstream under.
    pub upstream_id: Option<&'a str>,
}

/// The decision log.
#[derive(Debug)]
pub struct DecisionLog {
    writer: Option<Mutex<Writer>>,
    noise: Option<Mutex<Writer>>,
    seq: AtomicU64,
    boot_ms: u64,
}

#[derive(Debug)]
struct Writer {
    path: PathBuf,
    file: File,
    size: u64,
    max_bytes: u64,
}

impl DecisionLog {
    /// Appends to `path`, rotating it to `path.1` before it would pass `max_bytes`. Records with
    /// no episode go to `path.protocol`, rotated at a quarter of that.
    ///
    /// # Errors
    ///
    /// Returns the error of opening either file.
    pub fn open(path: &Path, max_bytes: u64) -> io::Result<Self> {
        let mut noise = path.as_os_str().to_owned();
        noise.push(".protocol");
        let noise_bytes = max_bytes.checked_div(4).unwrap_or(0).max(MIN_NOISE_BYTES);
        Ok(Self {
            writer: Some(Mutex::new(Writer::open(path, max_bytes)?)),
            noise: Some(Mutex::new(Writer::open(Path::new(&noise), noise_bytes)?)),
            seq: AtomicU64::new(0),
            boot_ms: unix_ms(),
        })
    }

    /// A log that records nothing, for tests.
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            writer: None,
            noise: None,
            seq: AtomicU64::new(0),
            boot_ms: 0,
        }
    }

    /// Writes a decision record with `verdict` at `ts_ms`. `false` if the log could not take it.
    pub fn decision(&self, verdict: Verdict, record: &Decision<'_>, ts_ms: u64) -> bool {
        let line = self.decision_line(verdict, record, ts_ms);
        let target = if record.eid.is_some() {
            &self.writer
        } else {
            &self.noise
        };
        write(target.as_ref(), &line)
    }

    /// Writes a decision record to the noise file, whatever its episode: a denial past the
    /// episode's quota (RV5 D3). Nothing depends on one, so a failed write is not reported.
    pub fn overflow(&self, verdict: Verdict, record: &Decision<'_>, ts_ms: u64) {
        let line = self.decision_line(verdict, record, ts_ms);
        let _ = write(self.noise.as_ref(), &line);
    }

    fn decision_line(&self, verdict: Verdict, record: &Decision<'_>, ts_ms: u64) -> Vec<u8> {
        let seq = self.seq.fetch_add(1, Ordering::SeqCst);
        object(vec![
            ("action_digest", text(record.action_digest)),
            ("amount_minor", number(record.amount_minor)),
            ("boot_ms", number(Some(self.boot_ms))),
            ("currency", text(record.currency)),
            ("eid", text(record.eid.map(encode_ulid).as_deref())),
            ("entity", text(record.entity)),
            ("idempotency_key", text(record.idempotency_key)),
            ("jti", text(record.jti)),
            ("method", JcsValue::string(clamp(record.method))),
            ("peer_uid", number(record.peer_uid.map(u64::from))),
            ("reason", text(record.reason.as_deref())),
            ("rid", number(record.rid)),
            ("seq", number(Some(seq))),
            ("tool", text(record.tool.map(clamp))),
            ("ts_ms", number(Some(ts_ms))),
            ("upstream_id", text(record.upstream_id)),
            ("v", number(Some(1))),
            ("verdict", JcsValue::string(verdict.name())),
        ])
    }

    /// Writes an outcome record: how the call `upstream_id` of episode `eid` ended, `pep_us`
    /// after its decision.
    pub fn outcome(
        &self,
        eid: u128,
        upstream_id: &str,
        jti: Option<&str>,
        ending: Ending,
        pep_us: u64,
        ts_ms: u64,
    ) {
        let line = object(vec![
            ("boot_ms", number(Some(self.boot_ms))),
            ("eid", JcsValue::string(encode_ulid(eid))),
            ("jti", text(jti)),
            ("outcome", JcsValue::string(ending.name())),
            ("pep_us", number(Some(pep_us))),
            ("ts_ms", number(Some(ts_ms))),
            ("upstream_id", JcsValue::string(upstream_id)),
            ("v", number(Some(1))),
        ]);
        // The decision before it is what the oracle needs, and the journal has the outcome.
        let _ = write(self.writer.as_ref(), &line);
    }
}

impl Writer {
    fn open(path: &Path, max_bytes: u64) -> io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        let size = file.metadata()?.len();
        Ok(Self {
            path: path.to_path_buf(),
            file,
            size,
            max_bytes,
        })
    }
}

/// Appends `line`, rotating first if it would pass the cap. `false` if it could not be written.
fn write(writer: Option<&Mutex<Writer>>, line: &[u8]) -> bool {
    let Some(writer) = writer else {
        return true;
    };
    let Ok(mut writer) = writer.lock() else {
        return false;
    };
    let length = u64::try_from(line.len())
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    // Rotation keeps the volume within its cap; the sizes only steer that.
    if writer.size.saturating_add(length) > writer.max_bytes && writer.size > 0 {
        let mut rotated = writer.path.clone().into_os_string();
        rotated.push(".1");
        let reopened = fs::rename(&writer.path, &rotated).and_then(|()| {
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(&writer.path)
        });
        if let Ok(file) = reopened {
            writer.file = file;
            writer.size = 0;
        }
    }
    let written = writer
        .file
        .write_all(line)
        .and_then(|()| writer.file.write_all(b"\n"))
        .and_then(|()| writer.file.flush())
        .is_ok();
    if written {
        writer.size = writer.size.saturating_add(length);
    }
    written
}

/// `text`, cut at a character boundary at or below [`MAX_SENDER_TEXT`] bytes.
fn clamp(text: &str) -> &str {
    if text.len() <= MAX_SENDER_TEXT {
        return text;
    }
    let mut end = MAX_SENDER_TEXT;
    while !text.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    text.get(..end).unwrap_or_default()
}

/// Unix milliseconds, for records; 0 if the clock is before 1970.
#[must_use]
pub fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())
        .unwrap_or(0)
}

fn text(value: Option<&str>) -> JcsValue {
    value.map_or(JcsValue::Null, JcsValue::string)
}

fn number(value: Option<u64>) -> JcsValue {
    value
        .and_then(|value| i64::try_from(value).ok())
        .and_then(JcsValue::int)
        .unwrap_or(JcsValue::Null)
}

fn object(members: Vec<(&str, JcsValue)>) -> Vec<u8> {
    JcsObject::from_entries(
        members
            .into_iter()
            .map(|(key, value)| (JcsString::new(key), value))
            .collect(),
    )
    .map(|object| JcsValue::Object(object).to_canonical_bytes())
    .unwrap_or_default()
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
    use crate::jcs;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("pep-dlog-{}-{name}", std::process::id()));
        drop(fs::remove_dir_all(&dir));
        fs::create_dir(&dir).unwrap();
        dir
    }

    #[test]
    fn records_are_canonical_and_carry_their_fields() {
        let dir = temp("fields");
        let path = dir.join("decisions.jsonl");
        let log = DecisionLog::open(&path, 1 << 20).unwrap();
        log.decision(
            Verdict::Allow,
            &Decision {
                eid: Some(1),
                peer_uid: Some(20_001),
                method: "tools/call",
                tool: Some("pay_invoice"),
                rid: Some(3),
                amount_minor: Some(30_000),
                currency: Some("USD"),
                entity: Some("INV-1001"),
                upstream_id: Some("01J"),
                ..Decision::default()
            },
            1_700_000_000_000,
        );
        log.outcome(
            1,
            "01J",
            Some("jti-1"),
            Ending::Executed,
            1234,
            1_700_000_000_001,
        );
        let text = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        for line in &lines {
            assert_eq!(jcs::canonicalize(line.as_bytes()).unwrap(), line.as_bytes());
        }
        let decision = jcs::parse(lines[0].as_bytes()).unwrap();
        assert_eq!(decision.get("verdict").unwrap().as_str(), Some("allow"));
        assert_eq!(decision.get("seq").unwrap().as_i64(), Some(0));
        assert_eq!(decision.get("jti"), Some(&JcsValue::Null));
        let outcome = jcs::parse(lines[1].as_bytes()).unwrap();
        assert_eq!(outcome.get("outcome").unwrap().as_str(), Some("executed"));
        assert_eq!(outcome.get("upstream_id").unwrap().as_str(), Some("01J"));
        drop(fs::remove_dir_all(dir));
    }

    #[test]
    fn the_log_rotates_at_its_cap() {
        let dir = temp("rotate");
        let path = dir.join("decisions.jsonl");
        let log = DecisionLog::open(&path, 300).unwrap();
        for _ in 0..10 {
            log.outcome(1, "01J", None, Ending::Abandoned, 1, 1);
        }
        assert!(fs::metadata(&path).unwrap().len() <= 300);
        assert!(dir.join("decisions.jsonl.1").exists());
        drop(fs::remove_dir_all(dir));
    }

    #[test]
    fn a_flood_with_no_episode_cannot_touch_the_decision_records() {
        let dir = temp("noise");
        let path = dir.join("decisions.jsonl");
        let log = DecisionLog::open(&path, 4096).unwrap();
        log.decision(
            Verdict::Allow,
            &Decision {
                eid: Some(1),
                method: "tools/call",
                ..Decision::default()
            },
            1,
        );
        let kept = fs::read(&path).unwrap();
        let junk = "A".repeat(16_000);
        for _ in 0..40_000 {
            log.decision(
                Verdict::ProtocolError,
                &Decision {
                    method: &junk,
                    tool: Some(&junk),
                    ..Decision::default()
                },
                1,
            );
        }
        assert_eq!(fs::read(&path).unwrap(), kept);
        assert!(!dir.join("decisions.jsonl.1").exists());
        let noise = dir.join("decisions.jsonl.protocol");
        assert!(fs::metadata(&noise).unwrap().len() <= MIN_NOISE_BYTES);
        assert!(dir.join("decisions.jsonl.protocol.1").exists());
        drop(fs::remove_dir_all(dir));
    }

    #[test]
    fn sender_text_is_cut_on_a_character_boundary() {
        assert_eq!(clamp("tools/call"), "tools/call");
        let exact = "a".repeat(MAX_SENDER_TEXT);
        assert_eq!(clamp(&exact), exact);
        // Two-byte characters, so the cap falls inside one when it is odd, and a one-byte lead
        // moves it inside one when it is even.
        for lead in ["", "a"] {
            let long = format!("{lead}{}", "é".repeat(MAX_SENDER_TEXT));
            let cut = clamp(&long);
            assert!(cut.len() <= MAX_SENDER_TEXT);
            assert!(cut.len() >= MAX_SENDER_TEXT - 1);
            assert!(long.starts_with(cut));
        }
    }

    #[test]
    fn an_overflow_goes_to_the_noise_file_and_keeps_its_episode() {
        let dir = temp("overflow");
        let path = dir.join("decisions.jsonl");
        let log = DecisionLog::open(&path, 1 << 20).unwrap();
        let record = Decision {
            eid: Some(1),
            method: "tools/call",
            ..Decision::default()
        };
        log.overflow(Verdict::Deny, &record, 1);
        assert!(fs::read(&path).unwrap().is_empty());
        let noise = fs::read_to_string(dir.join("decisions.jsonl.protocol")).unwrap();
        assert!(noise.contains(&format!(r#""eid":"{}""#, encode_ulid(1))));
        drop(fs::remove_dir_all(dir));
    }

    #[test]
    fn every_record_says_which_boot_wrote_it() {
        let dir = temp("boot");
        let path = dir.join("decisions.jsonl");
        let log = DecisionLog::open(&path, 1 << 20).unwrap();
        let record = Decision {
            eid: Some(1),
            method: "tools/call",
            ..Decision::default()
        };
        assert!(log.decision(Verdict::Allow, &record, 1));
        log.outcome(1, "01J", None, Ending::Declined, 0, 2);
        let text = fs::read_to_string(&path).unwrap();
        let boot = format!(r#""boot_ms":{}"#, log.boot_ms);
        assert!(log.boot_ms > 0);
        assert_eq!(text.lines().filter(|line| line.contains(&boot)).count(), 2);
        assert!(text.contains(r#""outcome":"declined""#));
        drop(fs::remove_dir_all(dir));
    }

    #[test]
    fn a_full_volume_is_reported() {
        let dir = temp("full");
        let path = dir.join("decisions.jsonl");
        std::os::unix::fs::symlink("/dev/full", &path).unwrap();
        let log = DecisionLog::open(&path, 1 << 20).unwrap();
        let record = Decision {
            eid: Some(1),
            method: "tools/call",
            ..Decision::default()
        };
        assert!(!log.decision(Verdict::Allow, &record, 1));
        assert!(DecisionLog::disabled().decision(Verdict::Allow, &record, 1));
        drop(fs::remove_dir_all(dir));
    }

    #[test]
    fn a_disabled_log_writes_nothing() {
        DecisionLog::disabled().outcome(1, "01J", None, Ending::Released, 0, 0);
    }
}
