//! The R1 journal: what must survive a restart.
//!
//! One JCS-canonical JSON record per line, appended to a file on the PEP's own volume, under
//! an exclusive lock on its lock file ([`crate::peercred::take_lock`]):
//! - payment records: `reserve` when a reservation is made, `forwarded` at the point of
//!   forwarding (P1), and `outcome` when it ends;
//! - `taint`: one call's F-08 entries, as one record ([`crate::engine::LabelStore::record_all`]);
//! - `ratchet`: an intent's F-09 level, whenever it rises;
//! - `quarantine`: a server quarantined under a lockfile digest (RV4 #5).
//!
//! At boot, [`Journal::open`] takes the lock, truncates a torn tail (bytes after the last
//! newline: an append whose fsync never completed, so its call was never forwarded), fsyncs,
//! and parses every other line, any of which, if malformed, stops the PEP. [`replay`] then
//! rebuilds each intent's [`Ledger`], the PEP-wide set of entities with an unresolved payment,
//! the quarantines and the taint.
//!
//! At run time one writer thread ([`spawn_writer`]) appends for every episode. Appends that
//! arrive together are written at once, with at most one fsync (group commit, RV3 A9). After
//! any write or fsync error the journal refuses every later append, so the PEP fails closed:
//! after a failed fsync the file's state is unknown.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions, Permissions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::thread::{self, JoinHandle};

use crate::engine::{
    Confidentiality, ContentDigest, InMemoryLabelStore, Integrity, KeyPolicy, Label, LabelEntry,
    LabelStore, Ledger, RestoredReservation, StoreError, StoreKey, TaintIndex, decode_ulid,
    encode_ulid,
};
use crate::jcs::{self, JcsObject, JcsString, JcsValue, ParseOptions};
use crate::peercred::{PeerError, take_lock};

/// The journal file's mode: readable and writable by the PEP alone.
pub const JOURNAL_MODE: u32 = 0o600;
/// Longest journal line. Records are parsed under the definition profile, because one call's
/// taint record can hold up to 4,096 indexes with keys of up to 1 KiB, beyond the request
/// profile's 1 MiB and 8,192 values. A record beyond these limits is refused when it is
/// written, so every line written can be read back at boot.
pub const MAX_LINE_BYTES: usize = jcs::MAX_DEFINITION_BYTES;
/// Most values in one journal line.
pub const MAX_LINE_VALUES: usize = jcs::MAX_DEFINITION_NODES;
/// Appends that may wait for the writer.
pub const WRITER_QUEUE: usize = 1024;

/// Why the journal could not be opened, read or written.
#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    /// Another instance holds the lock, or the lock file failed its checks.
    #[error("journal lock: {0}")]
    Lock(#[from] PeerError),
    /// An I/O error.
    #[error("journal I/O: {0}")]
    Io(#[from] io::Error),
    /// The journal file is a symlink, not a regular file, not owned by the PEP, not mode 0600,
    /// or linked more than once.
    #[error("journal file failed its checks")]
    UnsafeFile,
    /// A complete line that is not a valid record. `line` counts from 1.
    #[error("journal line {line} is malformed")]
    Malformed {
        /// The line.
        line: usize,
    },
    /// A record that contradicts the records before it, such as an outcome with no
    /// reservation. `line` counts from 1.
    #[error("journal line {line} is inconsistent")]
    Inconsistent {
        /// The line.
        line: usize,
    },
    /// A record that cannot be encoded, such as an amount beyond the safe-integer range.
    #[error("record cannot be encoded")]
    Encoding,
    /// An earlier write or fsync failed, so every later append is refused.
    #[error("journal failed earlier")]
    Failed,
    /// The writer thread is gone.
    #[error("journal writer stopped")]
    Stopped,
}

/// How a payment's reservation ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutcomeKind {
    /// The broker reported it executed: committed.
    Executed,
    /// Not executed, and the tool never saw it, or the broker refused it: released.
    Refused,
    /// The tool declined it: released, and counted against `limits.max_declines` (RV5 D6).
    Declined,
    /// No explicit outcome: unresolved (`NeedsReconcile`).
    Unknown,
    /// Released before its point of forwarding: a decline, a step-up timeout, a disconnect, a
    /// failed re-check or `end_episode`.
    Released,
}

impl OutcomeKind {
    const fn name(self) -> &'static str {
        match self {
            Self::Executed => "executed",
            Self::Refused => "refused",
            Self::Declined => "declined",
            Self::Unknown => "unknown",
            Self::Released => "released",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        match name {
            "executed" => Some(Self::Executed),
            "refused" => Some(Self::Refused),
            "declined" => Some(Self::Declined),
            "unknown" => Some(Self::Unknown),
            "released" => Some(Self::Released),
            _ => None,
        }
    }
}

/// A label-store index as journaled: store locations by their normalized parts, rebuilt
/// against the loaded pins at replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournaledIndex {
    /// [`TaintIndex::Location`].
    Location {
        /// Normalized store URI.
        uri: String,
        /// Normalized key.
        key: String,
    },
    /// [`TaintIndex::Below`].
    Below {
        /// Normalized store URI.
        uri: String,
        /// Normalized key.
        key: String,
    },
    /// [`TaintIndex::Content`].
    Content(String),
}

impl From<&TaintIndex> for JournaledIndex {
    fn from(index: &TaintIndex) -> Self {
        match index {
            TaintIndex::Location(key) => Self::Location {
                uri: key.uri().to_owned(),
                key: key.key().to_owned(),
            },
            TaintIndex::Below(key) => Self::Below {
                uri: key.uri().to_owned(),
                key: key.key().to_owned(),
            },
            TaintIndex::Content(digest) => Self::Content(digest.as_str().to_owned()),
        }
    }
}

impl JournaledIndex {
    /// The index under the loaded stores. `None` for a location whose store is no longer
    /// pinned, or whose key the store no longer accepts: no pinned tool can read it, so its
    /// taint cannot matter, and the record stays in the journal for a lockfile that pins the
    /// store again.
    #[must_use]
    pub fn rebuild(&self, stores: &BTreeMap<String, KeyPolicy>) -> Option<TaintIndex> {
        match self {
            Self::Location { uri, key } => StoreKey::new(uri, key, stores)
                .ok()
                .map(TaintIndex::Location),
            Self::Below { uri, key } => StoreKey::new(uri, key, stores).ok().map(TaintIndex::Below),
            Self::Content(digest) => ContentDigest::from_journaled(digest).map(TaintIndex::Content),
        }
    }
}

/// One journal record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    /// A payment reservation was made, step-up waits included.
    Reserve {
        /// The intent's config name, which keys its ledger.
        intent: String,
        /// The episode.
        eid: u128,
        /// The reservation.
        rid: u64,
        /// The paid entity.
        entity: String,
        /// The amount in minor units.
        amount_minor: u64,
        /// The intent's currency.
        currency: String,
        /// The payment's `action_digest`.
        action_digest: String,
        /// Its F-07 idempotency key.
        idempotency_key: String,
    },
    /// The reservation reached its point of forwarding (P1). Fsynced before the upstream write.
    Forwarded {
        /// The episode.
        eid: u128,
        /// The reservation.
        rid: u64,
    },
    /// The reservation ended.
    Outcome {
        /// The episode.
        eid: u128,
        /// The reservation.
        rid: u64,
        /// How.
        result: OutcomeKind,
    },
    /// One call's F-08 entries. Fsynced before the call is forwarded.
    Taint {
        /// The writing episode.
        writer: u128,
        /// The label joined in.
        label: Label,
        /// The indexes.
        indexes: Vec<JournaledIndex>,
    },
    /// An intent's ratchet rose (F-09). Fsynced before the reply that depends on it (RV4 #4).
    Ratchet {
        /// The intent's config name.
        intent: String,
        /// The new level.
        conf: Confidentiality,
    },
    /// A server was quarantined under a lockfile digest (RV4 #5).
    Quarantine {
        /// The server.
        server_id: String,
        /// The loaded lockfile's digest.
        lockfile_digest: String,
    },
}

impl Record {
    /// The record as one canonical JSON line, newline included.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::Encoding`] for an integer beyond the safe range, or a record
    /// beyond [`MAX_LINE_BYTES`] or [`MAX_LINE_VALUES`], which boot could not read back.
    pub fn to_line(&self) -> Result<Vec<u8>, JournalError> {
        let value = self.to_value()?;
        let mut out = value.to_canonical_bytes();
        if out.len() > MAX_LINE_BYTES || value.nodes().len() > MAX_LINE_VALUES {
            return Err(JournalError::Encoding);
        }
        out.push(b'\n');
        Ok(out)
    }

    fn to_value(&self) -> Result<JcsValue, JournalError> {
        let text = |value: &str| JcsValue::string(value);
        let int = |value: u64| {
            i64::try_from(value)
                .ok()
                .and_then(JcsValue::int)
                .ok_or(JournalError::Encoding)
        };
        let eid_text = |eid: u128| JcsValue::string(encode_ulid(eid));
        let members = match self {
            Self::Reserve {
                intent,
                eid,
                rid,
                entity,
                amount_minor,
                currency,
                action_digest,
                idempotency_key,
            } => vec![
                ("type", text("reserve")),
                ("intent", text(intent.as_str())),
                ("eid", eid_text(*eid)),
                ("rid", int(*rid)?),
                ("entity", text(entity.as_str())),
                ("amount_minor", int(*amount_minor)?),
                ("currency", text(currency.as_str())),
                ("action_digest", text(action_digest.as_str())),
                ("idempotency_key", text(idempotency_key.as_str())),
            ],
            Self::Forwarded { eid, rid } => vec![
                ("type", text("forwarded")),
                ("eid", eid_text(*eid)),
                ("rid", int(*rid)?),
            ],
            Self::Outcome { eid, rid, result } => vec![
                ("type", text("outcome")),
                ("eid", eid_text(*eid)),
                ("rid", int(*rid)?),
                ("result", text(result.name())),
            ],
            Self::Taint {
                writer,
                label,
                indexes,
            } => vec![
                ("type", text("taint")),
                ("writer", eid_text(*writer)),
                ("label", label_value(*label)?),
                (
                    "indexes",
                    JcsValue::Array(
                        indexes
                            .iter()
                            .map(index_value)
                            .collect::<Result<Vec<_>, _>>()?,
                    ),
                ),
            ],
            Self::Ratchet { intent, conf } => vec![
                ("type", text("ratchet")),
                ("intent", text(intent.as_str())),
                ("conf", text(conf.name())),
            ],
            Self::Quarantine {
                server_id,
                lockfile_digest,
            } => vec![
                ("type", text("quarantine")),
                ("server_id", text(server_id.as_str())),
                ("lockfile_digest", text(lockfile_digest.as_str())),
            ],
        };
        object(members)
    }

    /// Parses one line, newline excluded. The line must be the record's canonical JSON.
    ///
    /// # Errors
    ///
    /// Returns `None` for anything else.
    #[must_use]
    pub fn parse(line: &[u8]) -> Option<Self> {
        let value = jcs::parse_with(line, &ParseOptions::definition())
            .ok()?
            .value;
        let record = Fields::of(&value)?;
        let parsed = match record.str("type")? {
            "reserve" => Self::Reserve {
                intent: record.str("intent")?.to_owned(),
                eid: record.eid("eid")?,
                rid: record.u64("rid")?,
                entity: record.str("entity")?.to_owned(),
                amount_minor: record.u64("amount_minor")?,
                currency: record.str("currency")?.to_owned(),
                action_digest: record.str("action_digest")?.to_owned(),
                idempotency_key: record.str("idempotency_key")?.to_owned(),
            },
            "forwarded" => Self::Forwarded {
                eid: record.eid("eid")?,
                rid: record.u64("rid")?,
            },
            "outcome" => Self::Outcome {
                eid: record.eid("eid")?,
                rid: record.u64("rid")?,
                result: OutcomeKind::from_name(record.str("result")?)?,
            },
            "taint" => Self::Taint {
                writer: record.eid("writer")?,
                label: parse_label(record.get("label")?)?,
                indexes: record
                    .get("indexes")?
                    .as_array()?
                    .iter()
                    .map(parse_index)
                    .collect::<Option<Vec<_>>>()?,
            },
            "ratchet" => Self::Ratchet {
                intent: record.str("intent")?.to_owned(),
                conf: Confidentiality::from_name(record.str("conf")?)?,
            },
            "quarantine" => Self::Quarantine {
                server_id: record.str("server_id")?.to_owned(),
                lockfile_digest: record.str("lockfile_digest")?.to_owned(),
            },
            _ => return None,
        };
        // Canonical, with exactly the record's members and canonical ULIDs: re-encoding gives
        // the same bytes.
        (parsed.to_value().ok()?.to_canonical_bytes() == line).then_some(parsed)
    }
}

fn object(members: Vec<(&str, JcsValue)>) -> Result<JcsValue, JournalError> {
    JcsObject::from_entries(
        members
            .into_iter()
            .map(|(key, value)| (JcsString::new(key), value))
            .collect(),
    )
    .map(JcsValue::Object)
    .map_err(|_| JournalError::Encoding)
}

fn label_value(label: Label) -> Result<JcsValue, JournalError> {
    object(vec![
        ("conf", JcsValue::string(label.conf.name())),
        ("integ", JcsValue::string(label.integ.name())),
    ])
}

fn parse_label(value: &JcsValue) -> Option<Label> {
    let fields = Fields::of(value)?;
    Some(Label::new(
        Confidentiality::from_name(fields.str("conf")?)?,
        Integrity::from_name(fields.str("integ")?)?,
    ))
}

fn index_value(index: &JournaledIndex) -> Result<JcsValue, JournalError> {
    let location = |uri: &str, key: &str| {
        object(vec![
            ("key", JcsValue::string(key)),
            ("uri", JcsValue::string(uri)),
        ])
    };
    match index {
        JournaledIndex::Location { uri, key } => object(vec![("location", location(uri, key)?)]),
        JournaledIndex::Below { uri, key } => object(vec![("below", location(uri, key)?)]),
        JournaledIndex::Content(digest) => {
            object(vec![("content", JcsValue::string(digest.as_str()))])
        }
    }
}

fn parse_index(value: &JcsValue) -> Option<JournaledIndex> {
    let object = value.as_object()?;
    let [(kind, inner)] = object.entries() else {
        return None;
    };
    let location = || {
        let fields = Fields::of(inner)?;
        Some((fields.str("uri")?.to_owned(), fields.str("key")?.to_owned()))
    };
    match kind.as_str() {
        "location" => location().map(|(uri, key)| JournaledIndex::Location { uri, key }),
        "below" => location().map(|(uri, key)| JournaledIndex::Below { uri, key }),
        "content" => inner
            .as_str()
            .map(|digest| JournaledIndex::Content(digest.to_owned())),
        _ => None,
    }
}

/// Typed reads of one record object. Unknown members are caught by re-encoding.
struct Fields<'a>(&'a JcsObject);

impl<'a> Fields<'a> {
    fn of(value: &'a JcsValue) -> Option<Self> {
        value.as_object().map(Self)
    }

    fn get(&self, key: &str) -> Option<&'a JcsValue> {
        self.0.get(key)
    }

    fn str(&self, key: &str) -> Option<&'a str> {
        self.get(key)?.as_str()
    }

    fn u64(&self, key: &str) -> Option<u64> {
        u64::try_from(self.get(key)?.as_i64()?).ok()
    }

    fn eid(&self, key: &str) -> Option<u128> {
        decode_ulid(self.str(key)?)
    }
}

/// What [`replay`] rebuilds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replay {
    /// Each intent's ledger, by the intent's config name. An intent the config no longer
    /// names keeps its ledger here; its unresolved entities still block (below).
    pub ledgers: BTreeMap<String, Ledger>,
    /// Every entity with an unresolved payment, in any intent (RV4 #1).
    pub unresolved: BTreeSet<String>,
    /// Every quarantine, as (`server_id`, `lockfile_digest`).
    pub quarantined: BTreeSet<(String, String)>,
    /// The taint records, in order.
    pub taint: Vec<(Vec<JournaledIndex>, LabelEntry)>,
}

/// One reservation's history.
struct Payment {
    intent: String,
    entity: String,
    amount_minor: u64,
    forwarded: bool,
    outcome: Option<OutcomeKind>,
}

/// Rebuilds the state the journal records (R1):
/// - every `reserve` counts in its intent's `calls`, released ones included (SPEC §3.1);
/// - an `executed` outcome counts in committed spend and in its entity's uses;
/// - a reservation forwarded with no outcome, or with `unknown`, is unresolved: restored by
///   its original (eid, rid), counted in reserved, calls and entity uses, and its entity is
///   blocked PEP-wide;
/// - a reservation never forwarded, `refused` or `released` counts in calls only;
/// - a `declined` one counts in calls and in the intent's declines;
/// - an intent's ratchet is its highest level.
///
/// # Errors
///
/// Returns [`JournalError::Inconsistent`] for a record that contradicts the ones before it:
/// a repeated reservation, a forward or outcome with no reservation, a second forward or
/// outcome, `released` after `forwarded`, or an upstream outcome with no `forwarded`.
pub fn replay(records: &[Record]) -> Result<Replay, JournalError> {
    let mut payments: BTreeMap<(u128, u64), Payment> = BTreeMap::new();
    let mut state = Replay {
        ledgers: BTreeMap::new(),
        unresolved: BTreeSet::new(),
        quarantined: BTreeSet::new(),
        taint: Vec::new(),
    };
    for (index, record) in records.iter().enumerate() {
        // Line numbers only label errors, so saturating cannot change a decision.
        let inconsistent = || JournalError::Inconsistent {
            line: index.saturating_add(1),
        };
        match record {
            Record::Reserve {
                intent,
                eid,
                rid,
                entity,
                amount_minor,
                ..
            } => {
                let payment = Payment {
                    intent: intent.clone(),
                    entity: entity.clone(),
                    amount_minor: *amount_minor,
                    forwarded: false,
                    outcome: None,
                };
                if payments.insert((*eid, *rid), payment).is_some() {
                    return Err(inconsistent());
                }
            }
            Record::Forwarded { eid, rid } => {
                let payment = payments
                    .get_mut(&(*eid, *rid))
                    .filter(|payment| !payment.forwarded && payment.outcome.is_none())
                    .ok_or_else(inconsistent)?;
                payment.forwarded = true;
            }
            Record::Outcome { eid, rid, result } => {
                let payment = payments
                    .get_mut(&(*eid, *rid))
                    .filter(|payment| payment.outcome.is_none())
                    .filter(|payment| payment.forwarded != (*result == OutcomeKind::Released))
                    .ok_or_else(inconsistent)?;
                payment.outcome = Some(*result);
            }
            Record::Taint {
                writer,
                label,
                indexes,
            } => state.taint.push((
                indexes.clone(),
                LabelEntry {
                    label: *label,
                    writer_episode: *writer,
                },
            )),
            Record::Ratchet { intent, conf } => {
                let ledger = ledger(&mut state.ledgers, intent);
                ledger.context_conf = ledger.context_conf.max(*conf);
            }
            Record::Quarantine {
                server_id,
                lockfile_digest,
            } => {
                state
                    .quarantined
                    .insert((server_id.clone(), lockfile_digest.clone()));
            }
        }
    }
    let overflow = || JournalError::Inconsistent {
        line: records.len(),
    };
    for ((eid, rid), payment) in payments {
        let ledger = ledger(&mut state.ledgers, &payment.intent);
        ledger.calls = ledger.calls.checked_add(1).ok_or_else(overflow)?;
        let unresolved = match payment.outcome {
            Some(OutcomeKind::Executed) => {
                ledger.committed_minor = ledger
                    .committed_minor
                    .checked_add(payment.amount_minor)
                    .ok_or_else(overflow)?;
                false
            }
            Some(OutcomeKind::Declined) => {
                ledger.declined = ledger.declined.checked_add(1).ok_or_else(overflow)?;
                continue;
            }
            Some(OutcomeKind::Unknown) => true,
            None if payment.forwarded => true,
            // Never forwarded, refused or released: the use was released with it.
            None | Some(OutcomeKind::Refused | OutcomeKind::Released) => continue,
        };
        let uses = ledger
            .entity_uses
            .entry(payment.entity.clone())
            .or_insert(0);
        *uses = uses.checked_add(1).ok_or_else(overflow)?;
        if unresolved {
            state.unresolved.insert(payment.entity.clone());
            ledger.unresolved.insert(
                (eid, rid),
                RestoredReservation {
                    entity: payment.entity,
                    amount_minor: payment.amount_minor,
                },
            );
        }
    }
    Ok(state)
}

fn ledger<'a>(ledgers: &'a mut BTreeMap<String, Ledger>, intent: &str) -> &'a mut Ledger {
    ledgers
        .entry(intent.to_owned())
        .or_insert_with(Ledger::empty)
}

/// The open journal file, held under its lock.
#[derive(Debug)]
pub struct Journal {
    file: File,
    _lock: File,
}

impl Journal {
    /// Takes the lock at `lock`, opens or creates the journal at `path`, truncates a torn
    /// tail, fsyncs, and parses every record.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::Lock`] if another instance holds the lock or the lock file
    /// fails its checks, [`JournalError::UnsafeFile`] if the journal file does, and
    /// [`JournalError::Malformed`] for a complete line that is not a record.
    pub fn open(path: &Path, lock: &Path) -> Result<(Self, Vec<Record>), JournalError> {
        let euid = nix::unistd::geteuid().as_raw();
        let lock = take_lock(lock, euid)?;
        let mut file = open_journal_file(path, euid)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let complete = match bytes.iter().rposition(|&byte| byte == b'\n') {
            Some(last) => last.checked_add(1).ok_or(JournalError::Encoding)?,
            None => 0,
        };
        if complete != bytes.len() {
            file.set_len(u64::try_from(complete).map_err(|_| JournalError::Encoding)?)?;
            file.sync_all()?;
        }
        let mut records = Vec::new();
        for (index, line) in bytes
            .get(..complete)
            .unwrap_or_default()
            .split_inclusive(|&byte| byte == b'\n')
            .enumerate()
        {
            // Line numbers only label errors, so saturating cannot change a decision.
            let malformed = JournalError::Malformed {
                line: index.saturating_add(1),
            };
            // Every line here ends with its newline; a blank one is malformed.
            let line = line.strip_suffix(b"\n").unwrap_or(line);
            if line.is_empty() {
                return Err(malformed);
            }
            records.push(Record::parse(line).ok_or(malformed)?);
        }
        file.seek(SeekFrom::End(0))?;
        Ok((Self { file, _lock: lock }, records))
    }
}

/// Where the writer thread puts its batches: the journal, or a test double.
trait Sink: Send + 'static {
    /// Writes `bytes` at the end, then fsyncs if `sync`.
    fn write_batch(&mut self, bytes: &[u8], sync: bool) -> io::Result<()>;
}

impl Sink for Journal {
    fn write_batch(&mut self, bytes: &[u8], sync: bool) -> io::Result<()> {
        self.file.write_all(bytes)?;
        if sync {
            self.file.sync_data()?;
        }
        Ok(())
    }
}

/// Opens the journal file: `O_NOFOLLOW`, `O_NONBLOCK`, created mode 0600 if absent, and
/// checked by fstat like the lock file.
fn open_journal_file(path: &Path, euid: u32) -> Result<File, JournalError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .mode(JOURNAL_MODE)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    let file = match options.clone().create_new(true).open(path) {
        Ok(file) => {
            file.set_permissions(Permissions::from_mode(JOURNAL_MODE))?;
            // The file's fsyncs do not cover its name: without this, a crash could take the
            // whole new journal, and with it every budget (R1).
            if let Some(parent) = path.parent() {
                File::open(parent)?.sync_all()?;
            }
            file
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            options.open(path).map_err(|error| {
                if error.raw_os_error() == Some(nix::libc::ELOOP) {
                    JournalError::UnsafeFile
                } else {
                    JournalError::Io(error)
                }
            })?
        }
        Err(error) if error.raw_os_error() == Some(nix::libc::ELOOP) => {
            return Err(JournalError::UnsafeFile);
        }
        Err(error) => return Err(JournalError::Io(error)),
    };
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.uid() != euid
        || metadata.mode() & 0o7777 != JOURNAL_MODE
        || metadata.nlink() != 1
    {
        return Err(JournalError::UnsafeFile);
    }
    Ok(file)
}

/// One append for the writer: encoded lines, whether they need an fsync, and where to answer.
struct Append {
    lines: Vec<u8>,
    sync: bool,
    done: SyncSender<Result<(), JournalError>>,
}

/// A handle every episode's actor uses to append. Cloning it is cheap.
#[derive(Debug, Clone)]
pub struct JournalHandle {
    queue: SyncSender<Append>,
}

impl JournalHandle {
    /// Appends `records` and waits until they are written, not necessarily fsynced: for
    /// `reserve` and `outcome`, which a later fsync, or none, covers (R1).
    ///
    /// # Errors
    ///
    /// Returns a [`JournalError`] if the journal failed, now or earlier.
    pub fn append(&self, records: &[Record]) -> Result<(), JournalError> {
        self.send(records, false)
    }

    /// Appends `records` and waits until they are fsynced: for `forwarded`, `taint`,
    /// `ratchet` and `quarantine`.
    ///
    /// # Errors
    ///
    /// Returns a [`JournalError`] if the journal failed, now or earlier.
    pub fn commit(&self, records: &[Record]) -> Result<(), JournalError> {
        self.send(records, true)
    }

    fn send(&self, records: &[Record], sync: bool) -> Result<(), JournalError> {
        let mut lines = Vec::new();
        for record in records {
            lines.extend(record.to_line()?);
        }
        let (done, answer) = mpsc::sync_channel(1);
        match self.queue.try_send(Append { lines, sync, done }) {
            Ok(()) => {}
            // A full queue fails closed rather than stalling the caller unboundedly.
            Err(TrySendError::Full(_)) => return Err(JournalError::Failed),
            Err(TrySendError::Disconnected(_)) => return Err(JournalError::Stopped),
        }
        answer.recv().map_err(|_| JournalError::Stopped)?
    }
}

/// Starts the writer thread that owns `journal`.
///
/// # Errors
///
/// Returns the error of spawning the thread.
pub fn spawn_writer(journal: Journal) -> io::Result<(JournalHandle, JoinHandle<()>)> {
    spawn_sink(journal)
}

fn spawn_sink<S: Sink>(sink: S) -> io::Result<(JournalHandle, JoinHandle<()>)> {
    let (queue, appends) = mpsc::sync_channel(WRITER_QUEUE);
    let thread = thread::Builder::new()
        .name("journal-writer".to_owned())
        .spawn(move || run_writer(sink, &appends))?;
    Ok((JournalHandle { queue }, thread))
}

/// Writes every append waiting together in one write and at most one fsync, then answers
/// them all. After an error, every later append gets [`JournalError::Failed`].
fn run_writer<S: Sink>(mut sink: S, appends: &Receiver<Append>) {
    let mut failed = false;
    while let Ok(first) = appends.recv() {
        let mut batch = vec![first];
        batch.extend(appends.try_iter());
        let result = if failed {
            Err(JournalError::Failed)
        } else {
            let bytes: Vec<u8> = batch
                .iter()
                .flat_map(|append| append.lines.iter().copied())
                .collect();
            let sync = batch.iter().any(|append| append.sync);
            sink.write_batch(&bytes, sync).map_err(JournalError::Io)
        };
        if let (false, Err(error)) = (failed, &result) {
            // Once: the PEP keeps running, refusing what needs the journal, so say why.
            drop(writeln!(
                io::stderr().lock(),
                "pep-sidecar: the journal failed, refusing every later append: {error}"
            ));
        }
        failed |= result.is_err();
        for append in batch {
            let answer = match &result {
                Ok(()) => Ok(()),
                Err(_) => Err(JournalError::Failed),
            };
            // A caller that stopped waiting has nothing to learn.
            drop(append.done.send(answer));
        }
    }
}

/// The journal-backed [`LabelStore`] (R1): each call's entries are applied, which checks the
/// store's capacity, and then go in one fsynced `taint` record, which `record_all` waits for.
/// So a replay can never overflow the store, concurrent writers share an fsync, and a failed
/// fsync leaves only extra taint in memory, which fails closed; the journal then refuses
/// everything else anyway.
#[derive(Debug)]
pub struct JournaledLabels {
    inner: InMemoryLabelStore,
    journal: JournalHandle,
}

impl JournaledLabels {
    /// A store of `capacity` entries, loaded with the replayed `taint` rebuilt against
    /// `stores`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::CapacityExceeded`] if the replayed taint no longer fits.
    pub fn restore(
        capacity: usize,
        journal: JournalHandle,
        taint: &[(Vec<JournaledIndex>, LabelEntry)],
        stores: &BTreeMap<String, KeyPolicy>,
    ) -> Result<Arc<Self>, StoreError> {
        let inner = InMemoryLabelStore::with_capacity(capacity);
        for (indexes, entry) in taint {
            let rebuilt: Vec<TaintIndex> = indexes
                .iter()
                .filter_map(|index| index.rebuild(stores))
                .collect();
            inner.record_all(&rebuilt, *entry)?;
        }
        Ok(Arc::new(Self { inner, journal }))
    }
}

impl LabelStore for JournaledLabels {
    fn record_all(&self, indexes: &[TaintIndex], entry: LabelEntry) -> Result<(), StoreError> {
        if indexes.is_empty() {
            // Nothing to taint, so nothing to make durable: reads pay no fsync.
            return Ok(());
        }
        self.inner.record_all(indexes, entry)?;
        let record = Record::Taint {
            writer: entry.writer_episode,
            label: entry.label,
            indexes: indexes.iter().map(JournaledIndex::from).collect(),
        };
        self.journal
            .commit(&[record])
            .map_err(|_| StoreError::Unavailable)
    }

    fn lookup(&self, index: &TaintIndex) -> Result<Option<Label>, StoreError> {
        self.inner.lookup(index)
    }
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
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let path = std::env::temp_dir().join(format!("pep-journal-{}-{n}", std::process::id()));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, Permissions::from_mode(0o700)).unwrap();
            Self { path }
        }

        fn journal(&self) -> PathBuf {
            self.path.join("journal.jsonl")
        }

        fn lock(&self) -> PathBuf {
            self.path.join("journal.lock")
        }

        fn open(&self) -> Result<(Journal, Vec<Record>), JournalError> {
            Journal::open(&self.journal(), &self.lock())
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            drop(fs::remove_dir_all(&self.path));
        }
    }

    const EID: u128 = 0x0192_7a3c_0000_0000_0000_0000_0000_0001;
    const OTHER: u128 = 0x0192_7a3c_0000_0000_0000_0000_0000_0002;

    fn reserve(eid: u128, rid: u64, intent: &str, entity: &str, amount_minor: u64) -> Record {
        Record::Reserve {
            intent: intent.to_owned(),
            eid,
            rid,
            entity: entity.to_owned(),
            amount_minor,
            currency: "USD".to_owned(),
            action_digest: "sha-256:j3XfycsYi2G8jSVocXUTiPN2JWbcwQfOK1L4pLAdI1E".to_owned(),
            idempotency_key: "pep-key".to_owned(),
        }
    }

    const fn forwarded(eid: u128, rid: u64) -> Record {
        Record::Forwarded { eid, rid }
    }

    const fn outcome(eid: u128, rid: u64, result: OutcomeKind) -> Record {
        Record::Outcome { eid, rid, result }
    }

    fn stores() -> BTreeMap<String, KeyPolicy> {
        BTreeMap::from([(
            "notes://agent".to_owned(),
            KeyPolicy {
                case_insensitive: false,
            },
        )])
    }

    fn location(key: &str) -> TaintIndex {
        TaintIndex::Location(StoreKey::new("notes://agent", key, &stores()).unwrap())
    }

    fn content() -> TaintIndex {
        TaintIndex::Content(
            ContentDigest::of(&JcsValue::string(
                "a value long enough to be content-indexed",
            ))
            .unwrap(),
        )
    }

    const SECRET_WRITE: Label = Label::new(Confidentiality::Secret, Integrity::UntrustedAgentWrite);

    fn every_kind() -> Vec<Record> {
        vec![
            reserve(EID, 1, "pay-invoices", "INV-1001", 30_000),
            forwarded(EID, 1),
            outcome(EID, 1, OutcomeKind::Executed),
            outcome(EID, 2, OutcomeKind::Refused),
            outcome(EID, 3, OutcomeKind::Unknown),
            outcome(EID, 4, OutcomeKind::Released),
            Record::Taint {
                writer: EID,
                label: SECRET_WRITE,
                indexes: vec![
                    JournaledIndex::from(&location("k1")),
                    JournaledIndex::from(&TaintIndex::Below(
                        StoreKey::new("notes://agent", "a", &stores()).unwrap(),
                    )),
                    JournaledIndex::from(&content()),
                ],
            },
            Record::Ratchet {
                intent: "pay-invoices".to_owned(),
                conf: Confidentiality::Confidential,
            },
            Record::Quarantine {
                server_id: "a".to_owned(),
                lockfile_digest: "sha-256:lock".to_owned(),
            },
        ]
    }

    #[test]
    fn records_round_trip_as_canonical_lines() {
        for record in every_kind() {
            let line = record.to_line().unwrap();
            assert_eq!(line.last(), Some(&b'\n'));
            let body = &line[..line.len() - 1];
            assert_eq!(jcs::canonicalize(body).unwrap(), body);
            assert_eq!(
                Record::parse(body),
                Some(record.clone()),
                "{}",
                String::from_utf8_lossy(body)
            );
        }
        assert_eq!(
            String::from_utf8(forwarded(EID, 7).to_line().unwrap()).unwrap(),
            format!(
                "{{\"eid\":\"{}\",\"rid\":7,\"type\":\"forwarded\"}}\n",
                encode_ulid(EID)
            )
        );
    }

    #[test]
    fn only_exact_records_parse() {
        let eid = encode_ulid(EID);
        for line in [
            format!(r#"{{"eid": "{eid}","rid":7,"type":"forwarded"}}"#),
            format!(r#"{{"eid":"{eid}","extra":1,"rid":7,"type":"forwarded"}}"#),
            format!(r#"{{"eid":"{eid}","type":"forwarded"}}"#),
            format!(
                r#"{{"eid":"{}","rid":7,"type":"forwarded"}}"#,
                eid.to_lowercase()
            ),
            format!(r#"{{"eid":"{eid}","rid":-7,"type":"forwarded"}}"#),
            format!(r#"{{"eid":"{eid}","rid":7,"type":"forward"}}"#),
            format!(r#"{{"eid":"{eid}","result":"lost","rid":7,"type":"outcome"}}"#),
            r#"{"conf":"top","intent":"i","type":"ratchet"}"#.to_owned(),
            format!(
                r#"{{"indexes":[{{"content":"sha-256:short"}}],"label":{{"conf":"secret","integ":"trusted"}},"type":"taint","writer":"{eid}"}}"#
            ),
            format!(
                r#"{{"indexes":[{{"content":"x","location":{{}}}}],"label":{{"conf":"secret","integ":"trusted"}},"type":"taint","writer":"{eid}"}}"#
            ),
            "[]".to_owned(),
            String::new(),
        ] {
            let parsed = Record::parse(line.as_bytes());
            // A content digest is checked when it is rebuilt, not when it is parsed.
            if line.contains("sha-256:short") {
                let Some(Record::Taint { indexes, .. }) = parsed else {
                    panic!("{line}");
                };
                assert_eq!(indexes[0].rebuild(&stores()), None);
                continue;
            }
            assert_eq!(parsed, None, "{line}");
        }
        assert!(matches!(
            reserve(EID, 1, "i", "e", 1 << 53).to_line(),
            Err(JournalError::Encoding)
        ));
    }

    #[test]
    fn the_largest_taint_record_reads_back() {
        // 4,096 indexes (the episode's label quota), each with a 1 KiB key: beyond the request
        // profile, within the journal's.
        let indexes: Vec<JournaledIndex> = (0..4096)
            .map(|n| JournaledIndex::Location {
                uri: "notes://agent".to_owned(),
                key: format!("{n:04}{}", "k".repeat(1020)),
            })
            .collect();
        let record = Record::Taint {
            writer: EID,
            label: SECRET_WRITE,
            indexes,
        };
        let line = record.to_line().unwrap();
        assert!(line.len() > jcs::MAX_REQUEST_BYTES);
        assert_eq!(Record::parse(&line[..line.len() - 1]), Some(record));
        let too_big = Record::Taint {
            writer: EID,
            label: SECRET_WRITE,
            indexes: vec![JournaledIndex::Content("x".repeat(MAX_LINE_BYTES)); 1],
        };
        assert!(matches!(too_big.to_line(), Err(JournalError::Encoding)));
    }

    fn ledger_of<'a>(replay: &'a Replay, intent: &str) -> &'a Ledger {
        replay.ledgers.get(intent).unwrap()
    }

    #[test]
    fn replay_counts_declines_but_not_refusals() {
        let records = vec![
            reserve(EID, 1, "pay", "INV-1", 100),
            forwarded(EID, 1),
            outcome(EID, 1, OutcomeKind::Declined),
            reserve(EID, 2, "pay", "INV-1", 100),
            forwarded(EID, 2),
            outcome(EID, 2, OutcomeKind::Refused),
        ];
        let replay = replay(&records).unwrap();
        let pay = ledger_of(&replay, "pay");
        assert_eq!((pay.calls, pay.declined), (2, 1));
        assert!(pay.entity_uses.is_empty(), "a decline gives its use back");
        let line = outcome(EID, 1, OutcomeKind::Declined).to_line().unwrap();
        assert_eq!(
            Record::parse(line.trim_ascii_end()).unwrap(),
            outcome(EID, 1, OutcomeKind::Declined)
        );
    }

    #[test]
    fn replay_rebuilds_each_ledger() {
        let records = vec![
            // Executed: committed, a call and a use.
            reserve(EID, 1, "pay", "INV-1", 100),
            forwarded(EID, 1),
            outcome(EID, 1, OutcomeKind::Executed),
            // Refused, released, and never forwarded: a call each, nothing else.
            reserve(EID, 2, "pay", "INV-2", 200),
            forwarded(EID, 2),
            outcome(EID, 2, OutcomeKind::Refused),
            reserve(EID, 3, "pay", "INV-3", 300),
            outcome(EID, 3, OutcomeKind::Released),
            reserve(EID, 4, "pay", "INV-4", 400),
            // Forwarded with no outcome, and unknown: unresolved.
            reserve(EID, 5, "pay", "INV-5", 500),
            forwarded(EID, 5),
            reserve(OTHER, 1, "other", "INV-6", 600),
            forwarded(OTHER, 1),
            outcome(OTHER, 1, OutcomeKind::Unknown),
            // Ratchet rises keep the highest.
            Record::Ratchet {
                intent: "pay".to_owned(),
                conf: Confidentiality::Confidential,
            },
            Record::Ratchet {
                intent: "pay".to_owned(),
                conf: Confidentiality::Internal,
            },
            Record::Quarantine {
                server_id: "a".to_owned(),
                lockfile_digest: "sha-256:lock".to_owned(),
            },
            Record::Taint {
                writer: EID,
                label: SECRET_WRITE,
                indexes: vec![JournaledIndex::from(&location("k1"))],
            },
        ];
        let replay = replay(&records).unwrap();
        let pay = ledger_of(&replay, "pay");
        assert_eq!(pay.committed_minor, 100);
        assert_eq!(pay.calls, 5);
        assert_eq!(
            pay.entity_uses,
            BTreeMap::from([("INV-1".to_owned(), 1), ("INV-5".to_owned(), 1)])
        );
        assert_eq!(
            pay.unresolved,
            BTreeMap::from([(
                (EID, 5),
                RestoredReservation {
                    entity: "INV-5".to_owned(),
                    amount_minor: 500
                }
            )])
        );
        assert_eq!(pay.context_conf, Confidentiality::Confidential);
        let other = ledger_of(&replay, "other");
        assert_eq!(other.calls, 1);
        assert_eq!(other.committed_minor, 0);
        assert_eq!(
            other.unresolved.keys().copied().collect::<Vec<_>>(),
            vec![(OTHER, 1)]
        );
        assert_eq!(other.context_conf, Confidentiality::Public);
        // Unresolved entities block in every intent (RV4 #1).
        assert_eq!(
            replay.unresolved,
            BTreeSet::from(["INV-5".to_owned(), "INV-6".to_owned()])
        );
        assert_eq!(
            replay.quarantined,
            BTreeSet::from([("a".to_owned(), "sha-256:lock".to_owned())])
        );
        assert_eq!(replay.taint.len(), 1);
        assert_eq!(
            replay.taint[0].1,
            LabelEntry {
                label: SECRET_WRITE,
                writer_episode: EID
            }
        );
    }

    #[test]
    fn replay_refuses_inconsistent_histories() {
        let r = || reserve(EID, 1, "pay", "INV-1", 100);
        for (records, line) in [
            (vec![r(), r()], 2),
            (vec![forwarded(EID, 1)], 1),
            (vec![outcome(EID, 1, OutcomeKind::Executed)], 1),
            (vec![r(), forwarded(EID, 1), forwarded(EID, 1)], 3),
            (
                vec![
                    r(),
                    outcome(EID, 1, OutcomeKind::Released),
                    forwarded(EID, 1),
                ],
                3,
            ),
            (
                vec![
                    r(),
                    forwarded(EID, 1),
                    outcome(EID, 1, OutcomeKind::Released),
                ],
                3,
            ),
            (vec![r(), outcome(EID, 1, OutcomeKind::Executed)], 2),
            (vec![r(), outcome(EID, 1, OutcomeKind::Unknown)], 2),
            (
                vec![
                    r(),
                    forwarded(EID, 1),
                    outcome(EID, 1, OutcomeKind::Unknown),
                    outcome(EID, 1, OutcomeKind::Executed),
                ],
                4,
            ),
        ] {
            assert!(
                matches!(replay(&records), Err(JournalError::Inconsistent { line: found }) if found == line),
                "{records:?}"
            );
        }
    }

    #[test]
    fn open_creates_a_private_journal_and_reads_it_back() {
        let dir = TempDir::new();
        let (journal, records) = dir.open().unwrap();
        assert!(records.is_empty());
        let metadata = fs::metadata(dir.journal()).unwrap();
        assert_eq!(metadata.mode() & 0o7777, JOURNAL_MODE);
        let (handle, writer) = spawn_writer(journal).unwrap();
        handle.append(&every_kind()[..3]).unwrap();
        handle.commit(&every_kind()[3..]).unwrap();
        drop(handle);
        writer.join().unwrap();
        let (_journal, records) = dir.open().unwrap();
        assert_eq!(records, every_kind());
    }

    #[test]
    fn a_torn_tail_is_truncated_and_other_bad_lines_stop_boot() {
        let dir = TempDir::new();
        drop(dir.open().unwrap());
        let complete = forwarded(EID, 1).to_line().unwrap();
        let torn = &reserve(EID, 2, "pay", "INV-2", 1).to_line().unwrap()[..20];
        fs::write(dir.journal(), [complete.as_slice(), torn].concat()).unwrap();
        let (journal, records) = dir.open().unwrap();
        assert_eq!(records, vec![forwarded(EID, 1)]);
        assert_eq!(fs::read(dir.journal()).unwrap(), complete);
        drop(journal);
        // A complete line that is not a record, or a blank line, stops the PEP.
        for (bytes, line) in [
            ([complete.as_slice(), b"{\"type\":\"nope\"}\n"].concat(), 2),
            (
                [complete.as_slice(), b"\n", complete.as_slice()].concat(),
                2,
            ),
            (b"\n".to_vec(), 1),
        ] {
            fs::write(dir.journal(), &bytes).unwrap();
            assert!(
                matches!(dir.open(), Err(JournalError::Malformed { line: found }) if found == line),
                "{:?}",
                String::from_utf8_lossy(&bytes)
            );
        }
    }

    #[test]
    fn a_second_instance_is_locked_out() {
        let dir = TempDir::new();
        let first = dir.open().unwrap();
        assert!(matches!(
            dir.open(),
            Err(JournalError::Lock(PeerError::LockHeld))
        ));
        drop(first);
        assert!(dir.open().is_ok());
    }

    #[test]
    fn unsafe_journal_files_are_refused() {
        let dir = TempDir::new();
        // A symlink.
        let target = dir.path.join("elsewhere");
        fs::write(&target, b"").unwrap();
        fs::set_permissions(&target, Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&target, dir.journal()).unwrap();
        assert!(matches!(dir.open(), Err(JournalError::UnsafeFile)));
        fs::remove_file(dir.journal()).unwrap();
        // A second link.
        fs::hard_link(&target, dir.journal()).unwrap();
        assert!(matches!(dir.open(), Err(JournalError::UnsafeFile)));
        fs::remove_file(&target).unwrap();
        // Another mode.
        fs::set_permissions(dir.journal(), Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(dir.open(), Err(JournalError::UnsafeFile)));
        fs::set_permissions(dir.journal(), Permissions::from_mode(0o600)).unwrap();
        assert!(dir.open().is_ok());
    }

    #[test]
    fn appends_from_many_threads_keep_their_order() {
        let dir = TempDir::new();
        let (journal, _) = dir.open().unwrap();
        let (handle, writer) = spawn_writer(journal).unwrap();
        let threads: Vec<_> = (0..8u128)
            .map(|worker| {
                let handle = handle.clone();
                thread::spawn(move || {
                    for rid in 1..=50u64 {
                        let record = reserve(EID + worker, rid, "pay", "INV-1", rid);
                        if rid % 2 == 0 {
                            handle.commit(&[record]).unwrap();
                        } else {
                            handle.append(&[record]).unwrap();
                        }
                    }
                })
            })
            .collect();
        for worker in threads {
            worker.join().unwrap();
        }
        drop(handle);
        writer.join().unwrap();
        let (_journal, records) = dir.open().unwrap();
        assert_eq!(records.len(), 400);
        for worker in 0..8u128 {
            let rids: Vec<u64> = records
                .iter()
                .filter_map(|record| match record {
                    Record::Reserve { eid, rid, .. } if *eid == EID + worker => Some(*rid),
                    _ => None,
                })
                .collect();
            assert_eq!(rids, (1..=50).collect::<Vec<_>>());
        }
    }

    #[test]
    fn a_failed_write_fails_every_later_append() {
        let dir = TempDir::new();
        let (mut journal, _) = dir.open().unwrap();
        // A read-only handle: the next write fails.
        journal.file = File::open(dir.journal()).unwrap();
        let (handle, writer) = spawn_writer(journal).unwrap();
        assert!(matches!(
            handle.commit(&[forwarded(EID, 1)]),
            Err(JournalError::Failed)
        ));
        assert!(matches!(
            handle.append(&[forwarded(EID, 2)]),
            Err(JournalError::Failed)
        ));
        drop(handle);
        writer.join().unwrap();
        assert!(fs::read(dir.journal()).unwrap().is_empty());
    }

    /// Fails its first batch, then accepts every other.
    struct FailsOnce {
        calls: Arc<Mutex<Vec<(usize, bool)>>>,
    }

    impl Sink for FailsOnce {
        fn write_batch(&mut self, bytes: &[u8], sync: bool) -> io::Result<()> {
            let mut calls = self
                .calls
                .lock()
                .map_err(|_| io::Error::other("poisoned"))?;
            calls.push((bytes.len(), sync));
            if calls.len() == 1 {
                Err(io::Error::other("injected"))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn the_writer_never_recovers_from_a_failure() {
        // After a failed fsync the file's state is unknown, so a sink that would accept the
        // next write must not get it.
        let calls = Arc::new(Mutex::new(Vec::new()));
        let (handle, writer) = spawn_sink(FailsOnce {
            calls: calls.clone(),
        })
        .unwrap();
        assert!(matches!(
            handle.commit(&[forwarded(EID, 1)]),
            Err(JournalError::Failed)
        ));
        assert!(matches!(
            handle.commit(&[forwarded(EID, 2)]),
            Err(JournalError::Failed)
        ));
        drop(handle);
        writer.join().unwrap();
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].1, "a commit asks for an fsync");
    }

    fn labels(
        dir: &TempDir,
        capacity: usize,
    ) -> (Arc<JournaledLabels>, JournalHandle, JoinHandle<()>) {
        let (journal, records) = dir.open().unwrap();
        let replayed = replay(&records).unwrap();
        let (handle, writer) = spawn_writer(journal).unwrap();
        let store =
            JournaledLabels::restore(capacity, handle.clone(), &replayed.taint, &stores()).unwrap();
        (store, handle, writer)
    }

    #[test]
    fn journaled_taint_survives_a_restart() {
        let dir = TempDir::new();
        let (store, handle, writer) = labels(&dir, 10);
        let entry = LabelEntry {
            label: SECRET_WRITE,
            writer_episode: EID,
        };
        store
            .record_all(&[location("k1"), content()], entry)
            .unwrap();
        // A call with nothing to taint writes nothing.
        store.record_all(&[], entry).unwrap();
        drop((store, handle));
        writer.join().unwrap();
        let text = fs::read_to_string(dir.journal()).unwrap();
        assert_eq!(text.lines().count(), 1);
        let (store, handle, writer) = labels(&dir, 10);
        assert_eq!(store.lookup(&location("k1")).unwrap(), Some(SECRET_WRITE));
        assert_eq!(store.lookup(&content()).unwrap(), Some(SECRET_WRITE));
        assert_eq!(store.lookup(&location("k2")).unwrap(), None);
        drop((store, handle));
        writer.join().unwrap();
    }

    #[test]
    fn capacity_is_checked_before_the_append() {
        let dir = TempDir::new();
        let (store, handle, writer) = labels(&dir, 1);
        let entry = LabelEntry {
            label: SECRET_WRITE,
            writer_episode: EID,
        };
        assert_eq!(
            store.record_all(&[location("k1"), location("k2")], entry),
            Err(StoreError::CapacityExceeded)
        );
        assert_eq!(store.lookup(&location("k1")).unwrap(), None);
        drop((store, handle));
        writer.join().unwrap();
        assert!(fs::read(dir.journal()).unwrap().is_empty());
    }

    #[test]
    fn a_journal_that_failed_refuses_taint() {
        let dir = TempDir::new();
        let (mut journal, _) = dir.open().unwrap();
        journal.file = File::open(dir.journal()).unwrap();
        let (handle, writer) = spawn_writer(journal).unwrap();
        let store = JournaledLabels::restore(10, handle.clone(), &[], &stores()).unwrap();
        let entry = LabelEntry {
            label: SECRET_WRITE,
            writer_episode: EID,
        };
        assert_eq!(
            store.record_all(&[location("k1")], entry),
            Err(StoreError::Unavailable)
        );
        // The entry was applied first, so writers can share an fsync. Extra taint fails closed,
        // and the failed journal now refuses everything else.
        assert_eq!(store.lookup(&location("k1")).unwrap(), Some(SECRET_WRITE));
        drop((store, handle));
        writer.join().unwrap();
    }

    #[test]
    fn taint_for_an_unpinned_store_is_skipped_at_replay() {
        let entry = LabelEntry {
            label: SECRET_WRITE,
            writer_episode: EID,
        };
        let gone = JournaledIndex::Location {
            uri: "files://gone".to_owned(),
            key: "k".to_owned(),
        };
        let kept = JournaledIndex::from(&location("k1"));
        assert_eq!(gone.rebuild(&stores()), None);
        let dir = TempDir::new();
        let (journal, _) = dir.open().unwrap();
        let (handle, writer) = spawn_writer(journal).unwrap();
        let store =
            JournaledLabels::restore(1, handle.clone(), &[(vec![gone, kept], entry)], &stores())
                .unwrap();
        assert_eq!(store.lookup(&location("k1")).unwrap(), Some(SECRET_WRITE));
        drop((store, handle));
        writer.join().unwrap();
    }
}
