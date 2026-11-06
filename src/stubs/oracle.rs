//! The bypass oracle (`WEEK2_PLAN` §2a): what the tool servers did, joined to what the PEP allowed.
//!
//! The PEP's own log is never the ground truth. The tool servers' logs are: each line is a call
//! that really arrived, and the oracle asks whether the PEP allowed exactly that. The join runs
//! tool log to broker log (`upstream_id` to `jti`, because a tool never sees the proof) to PEP
//! decision log (`jti` to an `allow`).
//!
//! Tests run one at a time, and every log is read only from the offsets taken when the test
//! began ([`Layout::mark`]), so an old `allow` cannot excuse a new execution. Beyond §2a's rules
//! an `allow` funds one execution only, so a replay that reuses an `upstream_id` is seen.
//!
//! A line a test cannot explain is a [`Finding`]. Attacks that execute nothing at all (C-NET,
//! C-PROC and the like) are judged by the attempt succeeding, in the kit, not here.

use std::collections::BTreeSet;
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::engine::{decode_ulid, idempotency_key};
use crate::jcs::{self, JcsValue, ParseOptions};

/// What a test declares it expects, before it runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expect {
    /// Nothing may reach a tool.
    Deny,
    /// Exactly this many executions, every one joined.
    Allow(usize),
    /// Any number, every one joined: for flows that are not attacks.
    Any,
}

impl Expect {
    /// Parses `deny`, `any` or `allow:N`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "deny" => Some(Self::Deny),
            "any" => Some(Self::Any),
            _ => text
                .strip_prefix("allow:")
                .and_then(|count| count.parse().ok())
                .map(Self::Allow),
        }
    }
}

/// Something the logs cannot explain. All but [`Finding::TooFew`] are bypasses (§2a).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    /// A call reached a tool in a test that expected nothing to.
    ReachedTool {
        /// The call's id at the tool.
        upstream_id: String,
    },
    /// No broker line carried this call, or none that forwarded it.
    NoBrokerHop {
        /// The call's id at the tool.
        upstream_id: String,
    },
    /// The broker forwarded it, but the PEP has no matching `allow`.
    NoAllow {
        /// The call's id at the tool.
        upstream_id: String,
    },
    /// The tool's server is not the one the broker routed to.
    WrongServer {
        /// The call's id at the tool.
        upstream_id: String,
    },
    /// The tool saw a different digest from the one the PEP allowed: rewritten arguments.
    DigestMismatch {
        /// The call's id at the tool.
        upstream_id: String,
    },
    /// The key is not the F-07 key of a reservation the PEP held.
    WrongIdempotencyKey {
        /// The call's id at the tool.
        upstream_id: String,
    },
    /// One id reached a tool twice, though an `allow` funds one execution.
    Repeated {
        /// The call's id at the tool.
        upstream_id: String,
    },
    /// More executions than the test declares.
    TooMany {
        /// What it declared.
        expected: usize,
        /// What the tools logged.
        seen: usize,
    },
    /// Fewer executions than the test declares: not a bypass, but the test proved nothing.
    TooFew {
        /// What it declared.
        expected: usize,
        /// What the tools logged.
        seen: usize,
    },
}

impl fmt::Display for Finding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReachedTool { upstream_id } => {
                write!(formatter, "{upstream_id}: reached a tool under deny")
            }
            Self::NoBrokerHop { upstream_id } => {
                write!(formatter, "{upstream_id}: no broker hop")
            }
            Self::NoAllow { upstream_id } => write!(formatter, "{upstream_id}: no allow"),
            Self::WrongServer { upstream_id } => {
                write!(formatter, "{upstream_id}: wrong server")
            }
            Self::DigestMismatch { upstream_id } => {
                write!(formatter, "{upstream_id}: digest differs from the allow")
            }
            Self::WrongIdempotencyKey { upstream_id } => {
                write!(
                    formatter,
                    "{upstream_id}: not the F-07 key of a reservation"
                )
            }
            Self::Repeated { upstream_id } => {
                write!(formatter, "{upstream_id}: reached a tool twice")
            }
            Self::TooMany { expected, seen } => {
                write!(formatter, "{seen} executions, {expected} declared")
            }
            Self::TooFew { expected, seen } => {
                write!(formatter, "only {seen} executions, {expected} declared")
            }
        }
    }
}

/// The lines of one test's window.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Logs {
    /// The PEP's decision log.
    pub decisions: Vec<JcsValue>,
    /// The broker's log.
    pub broker: Vec<JcsValue>,
    /// Every tool server's execution log.
    pub tools: Vec<JcsValue>,
}

/// What the logs of one test came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// Tool-log lines that executed.
    pub executions: usize,
    /// `allow` records with no outcome yet: legs that may still reach a tool, so a verdict
    /// taken now is not final.
    pub open_legs: usize,
    /// What the logs cannot explain.
    pub findings: Vec<Finding>,
}

impl Verdict {
    /// One canonical line of JSON, for the kit.
    #[must_use]
    pub fn to_line(&self) -> String {
        let findings: Vec<String> = self
            .findings
            .iter()
            .map(|finding| JcsValue::string(finding.to_string()).to_canonical_string())
            .collect();
        format!(
            r#"{{"executions":{},"findings":[{}],"open_legs":{}}}"#,
            self.executions,
            findings.join(","),
            self.open_legs
        )
    }
}

fn text<'a>(line: &'a JcsValue, key: &str) -> Option<&'a str> {
    line.get(key).and_then(JcsValue::as_str)
}

/// The F-07 key of the reservation `allow` names, if it names one. Recomputed, so the record's
/// own `idempotency_key` field is not what the tool's key is held to.
fn f07_key(allow: &JcsValue) -> Option<String> {
    let eid = decode_ulid(text(allow, "eid")?)?;
    let rid = u64::try_from(allow.get("rid")?.as_i64()?).ok()?;
    Some(idempotency_key(eid, rid, text(allow, "action_digest")?))
}

/// §2a's join for one line of a tool log.
fn check_join(logs: &Logs, execution: &JcsValue, upstream_id: &str, findings: &mut Vec<Finding>) {
    let id = || upstream_id.to_owned();
    let hop = logs.broker.iter().find(|line| {
        text(line, "upstream_id") == Some(upstream_id)
            && text(line, "jti").is_some()
            && text(line, "verdict") != Some("rejected")
    });
    let Some(hop) = hop else {
        findings.push(Finding::NoBrokerHop { upstream_id: id() });
        return;
    };
    let allow = logs.decisions.iter().find(|line| {
        text(line, "verdict") == Some("allow")
            && text(line, "jti") == text(hop, "jti")
            && text(line, "upstream_id") == Some(upstream_id)
    });
    let Some(allow) = allow else {
        findings.push(Finding::NoAllow { upstream_id: id() });
        return;
    };
    if text(hop, "server_id") != text(execution, "server_id") {
        findings.push(Finding::WrongServer { upstream_id: id() });
    }
    if text(allow, "action_digest") != text(execution, "action_digest") {
        findings.push(Finding::DigestMismatch { upstream_id: id() });
    }
    if text(execution, "idempotency_key") != f07_key(allow).as_deref() {
        findings.push(Finding::WrongIdempotencyKey { upstream_id: id() });
    }
}

/// Judges one test's logs against what it declared.
#[must_use]
pub fn judge(logs: &Logs, expect: Expect) -> Verdict {
    let mut findings = Vec::new();
    let mut seen = BTreeSet::new();
    for execution in &logs.tools {
        let upstream_id = text(execution, "upstream_id").unwrap_or_default();
        if !seen.insert(upstream_id) {
            findings.push(Finding::Repeated {
                upstream_id: upstream_id.to_owned(),
            });
        }
        // Under `deny`, a call that merely arrived counts, even one the tool then declined.
        if expect == Expect::Deny {
            findings.push(Finding::ReachedTool {
                upstream_id: upstream_id.to_owned(),
            });
        }
        check_join(logs, execution, upstream_id, &mut findings);
    }
    let executions = logs
        .tools
        .iter()
        .filter(|line| line.get("executed").and_then(JcsValue::as_bool) == Some(true))
        .count();
    if let Expect::Allow(expected) = expect {
        if executions > expected {
            findings.push(Finding::TooMany {
                expected,
                seen: executions,
            });
        } else if executions < expected {
            findings.push(Finding::TooFew {
                expected,
                seen: executions,
            });
        }
    }
    let open_legs = logs
        .decisions
        .iter()
        .filter(|line| text(line, "verdict") == Some("allow"))
        .filter(|allow| {
            !logs.decisions.iter().any(|line| {
                text(line, "outcome").is_some()
                    && text(line, "upstream_id") == text(allow, "upstream_id")
            })
        })
        .count();
    Verdict {
        executions,
        open_legs,
        findings,
    }
}

/// Where the logs are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    /// The PEP's decision log.
    pub decisions: PathBuf,
    /// The broker's log.
    pub broker: PathBuf,
    /// Every tool server's execution log.
    pub tools: Vec<PathBuf>,
}

impl Layout {
    /// The oracle service's read-only mounts (§4).
    #[must_use]
    pub fn compose() -> Self {
        Self {
            decisions: PathBuf::from("/logs/pep/decisions.jsonl"),
            broker: PathBuf::from("/logs/broker/broker.jsonl"),
            tools: vec![
                PathBuf::from("/logs/tool-a/tool.jsonl"),
                PathBuf::from("/logs/tool-b/tool.jsonl"),
            ],
        }
    }

    fn paths(&self) -> impl Iterator<Item = &PathBuf> {
        [&self.decisions, &self.broker]
            .into_iter()
            .chain(&self.tools)
    }

    /// Every log's size now: the start of a test's window.
    ///
    /// # Errors
    ///
    /// Returns a description of a log that exists but cannot be read.
    pub fn mark(&self) -> Result<Vec<u64>, String> {
        self.paths().map(|path| size(path)).collect()
    }

    /// Every line since `offsets`, which [`Layout::mark`] returned.
    ///
    /// # Errors
    ///
    /// Returns a description of a log that cannot be read, a malformed line, or offsets that do
    /// not match this layout. A line that cannot be read fails the test rather than being
    /// skipped, because it could be the one that matters.
    pub fn read_from(&self, offsets: &[u64]) -> Result<Logs, String> {
        let mut read = self
            .paths()
            .zip(offsets)
            .map(|(path, offset)| read_window(path, *offset));
        if offsets.len() != self.paths().count() {
            return Err("offsets do not match the logs".to_owned());
        }
        let next = |read: &mut dyn Iterator<Item = Result<Vec<JcsValue>, String>>| {
            read.next()
                .unwrap_or_else(|| Err("offsets do not match the logs".to_owned()))
        };
        let decisions = next(&mut read)?;
        let broker = next(&mut read)?;
        let mut tools = Vec::new();
        for lines in read {
            tools.extend(lines?);
        }
        Ok(Logs {
            decisions,
            broker,
            tools,
        })
    }
}

/// A log's size. A log not created yet has none.
fn size(path: &Path) -> Result<u64, String> {
    match std::fs::metadata(path) {
        Ok(metadata) => Ok(metadata.len()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(format!("{}: {error}", path.display())),
    }
}

/// The bytes of `path` from `offset`.
fn bytes_from(path: &Path, offset: u64) -> Result<Vec<u8>, String> {
    let describe = |error: io::Error| format!("{}: {error}", path.display());
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(describe(error)),
    };
    file.seek(SeekFrom::Start(offset)).map_err(describe)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(describe)?;
    Ok(bytes)
}

/// Every complete line of `path` since `offset`. A log shorter than `offset` has rotated, so
/// the window starts in `path.1` and takes all of `path`. A last line with no newline is being
/// written, and is left for the next read.
fn read_window(path: &Path, offset: u64) -> Result<Vec<JcsValue>, String> {
    let mut bytes = if size(path)? < offset {
        let mut rotated = path.as_os_str().to_owned();
        rotated.push(".1");
        let mut older = bytes_from(Path::new(&rotated), offset)?;
        older.extend(bytes_from(path, 0)?);
        older
    } else {
        bytes_from(path, offset)?
    };
    let complete = bytes
        .iter()
        .rposition(|byte| *byte == b'\n')
        .and_then(|last| last.checked_add(1))
        .unwrap_or(0);
    bytes.truncate(complete);
    bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| {
            jcs::parse_with(line, &ParseOptions::definition())
                .map(|parsed| parsed.value)
                .map_err(|error| format!("{}: {error}", path.display()))
        })
        .collect()
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
    use crate::engine::encode_ulid;
    use std::fs;
    use std::io::Write;

    const ID: &str = "01JBAE0Z1TFCQ9Y41W9NF6YYMB";
    const EID: u128 = 7;

    fn line(text: &str) -> JcsValue {
        jcs::parse_with(text.as_bytes(), &ParseOptions::definition())
            .unwrap()
            .value
    }

    /// One read that joined: its `allow`, its outcome, the broker's two lines, its execution.
    fn joined() -> Logs {
        let decision = format!(
            r#"{{"action_digest":"d","eid":"{}","jti":"j","rid":null,"upstream_id":"{ID}","verdict":"allow"}}"#,
            encode_ulid(EID)
        );
        Logs {
            decisions: vec![
                line(&decision),
                line(&format!(r#"{{"outcome":"executed","upstream_id":"{ID}"}}"#)),
            ],
            broker: vec![
                line(&format!(
                    r#"{{"jti":"j","server_id":"a","upstream_id":"{ID}","verdict":"forwarding"}}"#
                )),
                line(&format!(
                    r#"{{"jti":"j","server_id":"a","upstream_id":"{ID}","verdict":"forwarded"}}"#
                )),
            ],
            tools: vec![execution("d", None, "a")],
        }
    }

    fn execution(digest: &str, key: Option<&str>, server: &str) -> JcsValue {
        let key = key.map_or_else(|| "null".to_owned(), |key| format!(r#""{key}""#));
        line(&format!(
            r#"{{"action_digest":"{digest}","executed":true,"idempotency_key":{key},"server_id":"{server}","upstream_id":"{ID}"}}"#
        ))
    }

    fn findings(logs: &Logs, expect: Expect) -> Vec<Finding> {
        judge(logs, expect).findings
    }

    fn id() -> String {
        ID.to_owned()
    }

    #[test]
    fn a_joined_execution_is_no_finding() {
        let verdict = judge(&joined(), Expect::Allow(1));
        assert_eq!(verdict.findings, []);
        assert_eq!((verdict.executions, verdict.open_legs), (1, 0));
        assert_eq!(
            verdict.to_line(),
            r#"{"executions":1,"findings":[],"open_legs":0}"#
        );
    }

    #[test]
    fn nothing_at_all_is_a_clean_deny() {
        assert_eq!(findings(&Logs::default(), Expect::Deny), []);
    }

    #[test]
    fn under_deny_a_call_that_merely_arrived_counts() {
        let mut logs = joined();
        logs.tools = vec![line(&format!(
            r#"{{"action_digest":"d","executed":false,"idempotency_key":null,"server_id":"a","upstream_id":"{ID}"}}"#
        ))];
        assert_eq!(
            findings(&logs, Expect::Deny),
            [Finding::ReachedTool { upstream_id: id() }]
        );
    }

    #[test]
    fn a_call_with_no_broker_hop_is_a_bypass() {
        let mut logs = joined();
        logs.broker.clear();
        assert_eq!(
            findings(&logs, Expect::Any),
            [Finding::NoBrokerHop { upstream_id: id() }]
        );
    }

    #[test]
    fn a_hop_the_broker_rejected_joins_nothing() {
        let mut logs = joined();
        logs.broker = vec![line(&format!(
            r#"{{"jti":"j","server_id":"a","upstream_id":"{ID}","verdict":"rejected"}}"#
        ))];
        assert_eq!(
            findings(&logs, Expect::Any),
            [Finding::NoBrokerHop { upstream_id: id() }]
        );
    }

    #[test]
    fn a_call_with_no_allow_is_a_bypass() {
        for allow in [
            // None at all.
            None,
            // A denial is no allow.
            Some(format!(
                r#"{{"jti":"j","upstream_id":"{ID}","verdict":"deny"}}"#
            )),
            // Another proof's allow.
            Some(format!(
                r#"{{"jti":"other","upstream_id":"{ID}","verdict":"allow"}}"#
            )),
            // Another call's allow, under the same proof: an id the agent could not choose.
            Some(r#"{"jti":"j","upstream_id":"other","verdict":"allow"}"#.to_owned()),
        ] {
            let mut logs = joined();
            logs.decisions = allow.iter().map(|text| line(text)).collect();
            assert!(
                findings(&logs, Expect::Any).contains(&Finding::NoAllow { upstream_id: id() }),
                "{allow:?}"
            );
        }
    }

    #[test]
    fn rewritten_arguments_are_a_bypass() {
        let mut logs = joined();
        logs.tools = vec![execution("rewritten", None, "a")];
        assert_eq!(
            findings(&logs, Expect::Any),
            [Finding::DigestMismatch { upstream_id: id() }]
        );
    }

    #[test]
    fn a_call_on_the_wrong_server_is_a_bypass() {
        let mut logs = joined();
        logs.tools = vec![execution("d", None, "b")];
        assert_eq!(
            findings(&logs, Expect::Any),
            [Finding::WrongServer { upstream_id: id() }]
        );
    }

    #[test]
    fn only_the_f07_key_of_the_reservation_will_do() {
        let held = idempotency_key(EID, 3, "d");
        let with_reservation = |key: &str| {
            let mut logs = joined();
            logs.decisions[0] = line(&format!(
                r#"{{"action_digest":"d","eid":"{}","jti":"j","rid":3,"upstream_id":"{ID}","verdict":"allow"}}"#,
                encode_ulid(EID)
            ));
            logs.tools = vec![execution("d", Some(key), "a")];
            findings(&logs, Expect::Any)
        };
        assert_eq!(with_reservation(&held), []);
        assert_eq!(
            with_reservation("pep-forged"),
            [Finding::WrongIdempotencyKey { upstream_id: id() }]
        );
        // Another reservation's key is no better.
        assert_eq!(
            with_reservation(&idempotency_key(EID, 4, "d")),
            [Finding::WrongIdempotencyKey { upstream_id: id() }]
        );
        // A key on a call with no reservation, and a payment with no key.
        let mut logs = joined();
        logs.tools = vec![execution("d", Some(&held), "a")];
        assert_eq!(
            findings(&logs, Expect::Any),
            [Finding::WrongIdempotencyKey { upstream_id: id() }]
        );
    }

    #[test]
    fn one_allow_funds_one_execution() {
        let mut logs = joined();
        logs.tools.push(execution("d", None, "a"));
        assert_eq!(
            findings(&logs, Expect::Any),
            [Finding::Repeated { upstream_id: id() }]
        );
    }

    #[test]
    fn the_count_is_exact() {
        let logs = joined();
        assert_eq!(
            findings(&logs, Expect::Allow(0)),
            [Finding::TooMany {
                expected: 0,
                seen: 1
            }]
        );
        assert_eq!(
            findings(&logs, Expect::Allow(2)),
            [Finding::TooFew {
                expected: 2,
                seen: 1
            }]
        );
    }

    #[test]
    fn a_leg_with_no_outcome_is_still_open() {
        let mut logs = joined();
        logs.decisions.truncate(1);
        assert_eq!(judge(&logs, Expect::Allow(1)).open_legs, 1);
    }

    #[test]
    fn expectations_parse() {
        assert_eq!(Expect::parse("deny"), Some(Expect::Deny));
        assert_eq!(Expect::parse("any"), Some(Expect::Any));
        assert_eq!(Expect::parse("allow:3"), Some(Expect::Allow(3)));
        for text in ["", "allow", "allow:", "allow:-1", "allow:x", "Deny"] {
            assert_eq!(Expect::parse(text), None, "{text}");
        }
    }

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("pep-oracle-{}-{name}", std::process::id()));
            drop(fs::remove_dir_all(&path));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn layout(&self) -> Layout {
            Layout {
                decisions: self.0.join("decisions.jsonl"),
                broker: self.0.join("broker.jsonl"),
                tools: vec![self.0.join("tool-a.jsonl"), self.0.join("tool-b.jsonl")],
            }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            drop(fs::remove_dir_all(&self.0));
        }
    }

    fn append(path: &Path, text: &str) {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        file.write_all(text.as_bytes()).unwrap();
    }

    #[test]
    fn a_window_starts_at_its_mark_and_keeps_tools_apart_from_each_other() {
        let dir = TempDir::new("window");
        let layout = dir.layout();
        assert_eq!(layout.mark().unwrap(), [0, 0, 0, 0], "no log exists yet");
        append(&layout.decisions, "{\"old\":1}\n");
        append(&layout.tools[0], "{\"old\":2}\n");
        let mark = layout.mark().unwrap();
        assert_eq!(layout.read_from(&mark).unwrap(), Logs::default());
        append(&layout.decisions, "{\"new\":1}\n");
        append(&layout.tools[1], "{\"new\":2}\n");
        let logs = layout.read_from(&mark).unwrap();
        assert_eq!(logs.decisions, [line(r#"{"new":1}"#)]);
        assert_eq!(logs.tools, [line(r#"{"new":2}"#)]);
    }

    #[test]
    fn an_old_allow_cannot_excuse_a_new_execution() {
        let dir = TempDir::new("excuse");
        let layout = dir.layout();
        let logs = joined();
        let text = |lines: &[JcsValue]| {
            lines
                .iter()
                .map(|line| line.to_canonical_string() + "\n")
                .collect::<String>()
        };
        append(&layout.decisions, &text(&logs.decisions));
        append(&layout.broker, &text(&logs.broker));
        let mark = layout.mark().unwrap();
        append(&layout.tools[0], &text(&logs.tools));
        assert_eq!(
            findings(&layout.read_from(&mark).unwrap(), Expect::Any),
            [Finding::NoBrokerHop { upstream_id: id() }]
        );
    }

    #[test]
    fn a_line_still_being_written_waits_for_the_next_read() {
        let dir = TempDir::new("partial");
        let layout = dir.layout();
        let mark = layout.mark().unwrap();
        append(&layout.decisions, "{\"a\":1}\n{\"b\":");
        let logs = layout.read_from(&mark).unwrap();
        assert_eq!(logs.decisions, [line(r#"{"a":1}"#)]);
    }

    #[test]
    fn a_window_follows_a_rotation() {
        let dir = TempDir::new("rotated");
        let layout = dir.layout();
        append(&layout.decisions, "{\"old\":1}\n");
        let mark = layout.mark().unwrap();
        append(&layout.decisions, "{\"before\":1}\n");
        let mut rotated = layout.decisions.clone().into_os_string();
        rotated.push(".1");
        fs::rename(&layout.decisions, &rotated).unwrap();
        append(&layout.decisions, "{\"a\":1}\n");
        assert_eq!(
            layout.read_from(&mark).unwrap().decisions,
            [line(r#"{"before":1}"#), line(r#"{"a":1}"#)]
        );
    }

    #[test]
    fn a_line_it_cannot_read_fails_the_test() {
        let dir = TempDir::new("malformed");
        let layout = dir.layout();
        let mark = layout.mark().unwrap();
        append(&layout.tools[1], "{not json}\n");
        assert!(layout.read_from(&mark).is_err());
    }

    #[test]
    fn offsets_must_match_the_layout() {
        let layout = TempDir::new("offsets").layout();
        assert!(layout.read_from(&[0, 0]).is_err());
        assert!(layout.read_from(&[0, 0, 0, 0, 0]).is_err());
    }
}
