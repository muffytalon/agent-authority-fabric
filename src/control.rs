//! Control-socket messages (H1, E1).
//!
//! The control socket speaks the same HTTP subset as the agent socket ([`crate::http`]), one
//! JSON request per connection, to one peer: the operator (uid and gid 20004 in Compose,
//! checked by [`crate::peercred::require_peer`]). Each request names its `call`:
//!
//! | `call` | Members | Result |
//! |---|---|---|
//! | `start_episode` | `intent` | `eid`, `episode_token`, `exp` |
//! | `end_episode` | `eid` | `{}` |
//! | `trusted_input` | `eid`, `input_id`, `value`, `conf` | `{}` |
//! | `pending` | — | `approvals`: `eid`, `rid`, `tool`, `arguments`, `action_digest`, `amount_minor` |
//! | `approve`, `decline` | `eid`, `rid`, `action_digest`, `amount_minor` | `{}` |
//!
//! A reply is `{"result": …}`, or `{"error": code}` with one of [`ControlError`]'s codes. The
//! operator is trusted, so errors say what went wrong; the agent never sees them.

use crate::config::{Fields, LoadError};
use crate::engine::{Confidentiality, decode_ulid, encode_ulid};
use crate::http::Status;
use crate::jcs::{self, JcsValue};

/// The control socket's request target.
pub const CONTROL_ENDPOINT: &str = "/control";

/// An approval or a decline: everything is matched against the `AwaitingStepUp` reservation
/// before [`crate::engine::PepEngine::approve_step_up`], which takes only the rid (H1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    /// The episode.
    pub eid: u128,
    /// The reservation.
    pub rid: u64,
    /// The payment's `action_digest`.
    pub action_digest: String,
    /// The reserved amount in minor units.
    pub amount_minor: u64,
}

/// One control request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlRequest {
    /// Start an episode of the named intent (E1).
    StartEpisode {
        /// The intent's config name.
        intent: String,
    },
    /// End an episode (E1).
    EndEpisode {
        /// The episode.
        eid: u128,
    },
    /// Record a trusted input (F-13).
    TrustedInput {
        /// The episode.
        eid: u128,
        /// The input's id, unique in the episode.
        input_id: String,
        /// The value, as canonical JSON.
        value: Vec<u8>,
        /// Its confidentiality.
        conf: Confidentiality,
    },
    /// List the payments awaiting approval.
    Pending,
    /// Approve a payment awaiting step-up (F-15).
    Approve(Approval),
    /// Decline it.
    Decline(Approval),
}

/// Why a control request failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ControlError {
    /// The request is not a valid control request; the message says where.
    #[error("bad request: {0}")]
    BadRequest(String),
    /// No intent of that name is configured.
    #[error("unknown intent")]
    UnknownIntent,
    /// The intent already has a live episode (E1).
    #[error("intent has a live episode")]
    IntentBusy,
    /// `limits.episodes` episodes are live (E1).
    #[error("too many live episodes")]
    EpisodesFull,
    /// No live episode has that eid.
    #[error("unknown episode")]
    UnknownEpisode,
    /// No reservation of that rid awaits approval.
    #[error("no such payment awaits approval")]
    NotAwaiting,
    /// The reservation awaits approval, but its digest or amount differ (H1).
    #[error("approval does not match the payment")]
    Mismatch,
    /// The engine refused the request.
    #[error("refused by the engine")]
    Refused,
    /// The PEP could not carry it out, such as a failed journal write.
    #[error("unavailable")]
    Unavailable,
}

impl ControlError {
    /// The error's code in a reply.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::BadRequest(_) => "bad_request",
            Self::UnknownIntent => "unknown_intent",
            Self::IntentBusy => "intent_busy",
            Self::EpisodesFull => "episodes_full",
            Self::UnknownEpisode => "unknown_episode",
            Self::NotAwaiting => "not_awaiting",
            Self::Mismatch => "mismatch",
            Self::Refused => "refused",
            Self::Unavailable => "unavailable",
        }
    }
}

impl From<LoadError> for ControlError {
    fn from(error: LoadError) -> Self {
        Self::BadRequest(error.to_string())
    }
}

/// Parses a control request body.
///
/// # Errors
///
/// Returns [`ControlError::BadRequest`] for anything that is not exactly one control request.
pub fn parse(body: &[u8]) -> Result<ControlRequest, ControlError> {
    let value =
        jcs::parse(body).map_err(|error| ControlError::BadRequest(format!("not JSON: {error}")))?;
    let mut fields = Fields::of(&value, "")?;
    let call = fields.string("call")?;
    let request = match call {
        "start_episode" => ControlRequest::StartEpisode {
            intent: fields.string("intent")?.to_owned(),
        },
        "end_episode" => ControlRequest::EndEpisode {
            eid: eid(&mut fields)?,
        },
        "trusted_input" => {
            let eid = eid(&mut fields)?;
            let input_id = fields.string("input_id")?.to_owned();
            let value = fields.value("value")?.to_canonical_bytes();
            let conf_path = fields.path_of("conf");
            let conf = Confidentiality::from_name(fields.string("conf")?).ok_or_else(|| {
                ControlError::BadRequest(format!("{conf_path}: unknown confidentiality"))
            })?;
            ControlRequest::TrustedInput {
                eid,
                input_id,
                value,
                conf,
            }
        }
        "pending" => ControlRequest::Pending,
        "approve" | "decline" => {
            let approval = Approval {
                eid: eid(&mut fields)?,
                rid: fields.u64("rid")?,
                action_digest: fields.string("action_digest")?.to_owned(),
                amount_minor: fields.u64("amount_minor")?,
            };
            if call == "approve" {
                ControlRequest::Approve(approval)
            } else {
                ControlRequest::Decline(approval)
            }
        }
        _ => return Err(ControlError::BadRequest("call: unknown call".to_owned())),
    };
    fields.done()?;
    Ok(request)
}

/// The `eid` member: a canonical ULID.
fn eid(fields: &mut Fields<'_>) -> Result<u128, ControlError> {
    let path = fields.path_of("eid");
    let text = fields.string("eid")?;
    decode_ulid(text)
        .filter(|eid| encode_ulid(*eid) == text)
        .ok_or_else(|| ControlError::BadRequest(format!("{path}: not a ULID")))
}

/// One payment awaiting approval, as `pending` lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingPayment {
    /// The episode.
    pub eid: u128,
    /// The reservation.
    pub rid: u64,
    /// The payment tool.
    pub tool: String,
    /// Its canonical arguments.
    pub arguments: JcsValue,
    /// Its `action_digest`.
    pub action_digest: String,
    /// The amount in minor units.
    pub amount_minor: u64,
}

/// A reply: its HTTP status, and its JSON body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlReply {
    /// 200, or 400 for a bad request.
    pub status: Status,
    /// `{"result": …}` or `{"error": code}`.
    pub body: Vec<u8>,
}

impl ControlReply {
    /// The HTTP response bytes.
    #[must_use]
    pub fn to_http(&self) -> Vec<u8> {
        crate::http::response(self.status, Some(("application/json", &self.body)))
    }
}

/// A successful reply around `result`, canonical JSON.
#[must_use]
pub fn ok(result: &[u8]) -> ControlReply {
    let mut body = br#"{"result":"#.to_vec();
    body.extend_from_slice(result);
    body.push(b'}');
    ControlReply {
        status: Status::Ok,
        body,
    }
}

/// The empty successful result.
#[must_use]
pub fn done() -> ControlReply {
    ok(b"{}")
}

/// An error reply: 400 for a bad request, 200 otherwise.
#[must_use]
pub fn error(error: &ControlError) -> ControlReply {
    let mut body = br#"{"error":"#.to_vec();
    body.extend_from_slice(&JcsValue::string(error.code()).to_canonical_bytes());
    body.push(b'}');
    let status = match error {
        ControlError::BadRequest(_) => Status::BadRequest,
        _ => Status::Ok,
    };
    ControlReply { status, body }
}

/// The `start_episode` result.
///
/// # Errors
///
/// Returns [`ControlError::Unavailable`] if `exp` is beyond the safe-integer range.
pub fn started(eid: u128, token: &str, exp: u64) -> Result<ControlReply, ControlError> {
    let exp = i64::try_from(exp)
        .ok()
        .and_then(JcsValue::int)
        .ok_or(ControlError::Unavailable)?;
    let mut result = br#"{"eid":"#.to_vec();
    result.extend(JcsValue::string(encode_ulid(eid)).to_canonical_bytes());
    result.extend_from_slice(br#","episode_token":"#);
    result.extend(JcsValue::string(token).to_canonical_bytes());
    result.extend_from_slice(br#","exp":"#);
    result.extend(exp.to_canonical_bytes());
    result.push(b'}');
    Ok(ok(&result))
}

/// The `pending` result.
///
/// # Errors
///
/// Returns [`ControlError::Unavailable`] if a number is beyond the safe-integer range.
pub fn pending(payments: &[PendingPayment]) -> Result<ControlReply, ControlError> {
    let int = |value: u64| {
        i64::try_from(value)
            .ok()
            .and_then(JcsValue::int)
            .ok_or(ControlError::Unavailable)
    };
    let mut result = br#"{"approvals":["#.to_vec();
    for (index, payment) in payments.iter().enumerate() {
        if index > 0 {
            result.push(b',');
        }
        result.extend_from_slice(br#"{"action_digest":"#);
        result.extend(JcsValue::string(payment.action_digest.as_str()).to_canonical_bytes());
        result.extend_from_slice(br#","amount_minor":"#);
        result.extend(int(payment.amount_minor)?.to_canonical_bytes());
        result.extend_from_slice(br#","arguments":"#);
        result.extend(payment.arguments.to_canonical_bytes());
        result.extend_from_slice(br#","eid":"#);
        result.extend(JcsValue::string(encode_ulid(payment.eid)).to_canonical_bytes());
        result.extend_from_slice(br#","rid":"#);
        result.extend(int(payment.rid)?.to_canonical_bytes());
        result.extend_from_slice(br#","tool":"#);
        result.extend(JcsValue::string(payment.tool.as_str()).to_canonical_bytes());
        result.push(b'}');
    }
    result.extend_from_slice(b"]}");
    Ok(ok(&result))
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

    const EID: u128 = 0x0192_7a3c_0000_0000_0000_0000_0000_0001;

    fn eid() -> String {
        encode_ulid(EID)
    }

    fn request(body: &str) -> Result<ControlRequest, ControlError> {
        parse(body.as_bytes())
    }

    fn bad(body: &str) -> String {
        match request(body) {
            Err(ControlError::BadRequest(why)) => why,
            other => panic!("expected a bad request, got {other:?}"),
        }
    }

    #[test]
    fn every_call_parses() {
        let eid = eid();
        assert_eq!(
            request(r#"{"call":"start_episode","intent":"pay-invoices"}"#),
            Ok(ControlRequest::StartEpisode {
                intent: "pay-invoices".to_owned()
            })
        );
        assert_eq!(
            request(&format!(r#"{{"call":"end_episode","eid":"{eid}"}}"#)),
            Ok(ControlRequest::EndEpisode { eid: EID })
        );
        assert_eq!(
            request(r#"{"call":"pending"}"#),
            Ok(ControlRequest::Pending)
        );
        assert_eq!(
            request(&format!(
                r#"{{"call":"trusted_input","eid":"{eid}","input_id":"u1","value":{{ "entity" : "rcpt_A", "amount_minor": 100 }},"conf":"internal"}}"#
            )),
            Ok(ControlRequest::TrustedInput {
                eid: EID,
                input_id: "u1".to_owned(),
                value: br#"{"amount_minor":100,"entity":"rcpt_A"}"#.to_vec(),
                conf: Confidentiality::Internal,
            })
        );
        let approval = Approval {
            eid: EID,
            rid: 2,
            action_digest: "sha-256:d".to_owned(),
            amount_minor: 60_000,
        };
        for (call, expected) in [
            ("approve", ControlRequest::Approve(approval.clone())),
            ("decline", ControlRequest::Decline(approval.clone())),
        ] {
            assert_eq!(
                request(&format!(
                    r#"{{"call":"{call}","eid":"{eid}","rid":2,"action_digest":"sha-256:d","amount_minor":60000}}"#
                )),
                Ok(expected)
            );
        }
    }

    #[test]
    fn anything_else_is_a_bad_request() {
        let eid = eid();
        assert_eq!(bad(r#"{"call":"restart"}"#), "call: unknown call");
        assert_eq!(bad(r#"{"call":"pending","x":1}"#), "x: unexpected field");
        assert_eq!(bad(r#"{"intent":"pay"}"#), "call: missing");
        assert_eq!(bad(r#"{"call":"start_episode"}"#), "intent: missing");
        assert_eq!(
            bad(&format!(
                r#"{{"call":"end_episode","eid":"{}"}}"#,
                eid.to_lowercase()
            )),
            "eid: not a ULID"
        );
        assert_eq!(
            bad(r#"{"call":"end_episode","eid":7}"#),
            "eid: expected a string"
        );
        assert_eq!(
            bad(&format!(
                r#"{{"call":"approve","eid":"{eid}","rid":-2,"action_digest":"d","amount_minor":1}}"#
            )),
            "rid: expected a safe non-negative integer"
        );
        assert_eq!(
            bad(&format!(
                r#"{{"call":"trusted_input","eid":"{eid}","input_id":"u1","value":1,"conf":"top"}}"#
            )),
            "conf: unknown confidentiality"
        );
        assert!(bad(r#"{"call":"pending","call":"pending"}"#).starts_with("not JSON"));
        assert!(bad("[]").contains("expected an object"));
    }

    #[test]
    fn replies_are_canonical() {
        let started = started(EID, "eyJ.t", 1_800_000_000).unwrap();
        assert_eq!(started.status, Status::Ok);
        assert_eq!(
            String::from_utf8(started.body.clone()).unwrap(),
            format!(
                r#"{{"result":{{"eid":"{}","episode_token":"eyJ.t","exp":1800000000}}}}"#,
                eid()
            )
        );
        let pending = pending(&[PendingPayment {
            eid: EID,
            rid: 2,
            tool: "pay_invoice".to_owned(),
            arguments: jcs::parse(br#"{"amount":60000,"invoice_id":"INV-1"}"#).unwrap(),
            action_digest: "sha-256:d".to_owned(),
            amount_minor: 60_000,
        }])
        .unwrap();
        let empty = super::pending(&[]).unwrap();
        for body in [&started.body, &pending.body, &empty.body, &done().body] {
            assert_eq!(jcs::canonicalize(body).unwrap(), *body);
        }
        assert_eq!(empty.body, br#"{"result":{"approvals":[]}}"#);
        let refused = error(&ControlError::IntentBusy);
        assert_eq!(
            (refused.status, refused.body),
            (Status::Ok, br#"{"error":"intent_busy"}"#.to_vec())
        );
        assert_eq!(
            error(&ControlError::BadRequest("x".to_owned())).status,
            Status::BadRequest
        );
        assert!(super::started(EID, "t", u64::MAX).is_err());
    }
}
