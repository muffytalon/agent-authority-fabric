//! The only bytes the PEP sends upstream (F-16).
//!
//! [`tools_call_request`] builds a `tools/call` body from the engine's canonical tool name and
//! arguments ([`crate::engine::Allowed`]), with an id and a `_meta` the PEP makes itself, and
//! derives the MCP 2026-07-28 headers from that body. Nothing the agent sent is copied: not its
//! JSON-RPC id, not its `_meta` (so never the Episode Token, `progressToken` or `logLevel`), and
//! none of its headers. The PEP is an MCP endpoint to the agent and an MCP client to the
//! broker, never an HTTP intermediary.
//!
//! The body is JCS-canonical, so the broker's `action_digest`, recomputed from the forwarded
//! `name` and `arguments`, equals the engine's.

use crate::engine::{decode_ulid, encode_ulid};
use crate::jcs::{self, JcsObject, JcsString, JcsValue, ParseOptions};

/// The MCP revision the PEP speaks upstream.
pub const PROTOCOL_VERSION: &str = "2026-07-28";
/// `_meta` key of the Call Proof (SPEC §3.4).
pub const CALL_PROOF_META_KEY: &str = "dev.pep-sidecar/call-proof";
/// The PEP's `clientInfo.name`.
pub const CLIENT_NAME: &str = "pep-sidecar";
/// The PEP's `clientInfo.version`.
pub const CLIENT_VERSION: &str = env!("CARGO_PKG_VERSION");
/// Longest tool name MCP recommends, and the lockfile allows (L1).
pub const MAX_TOOL_NAME: usize = 128;
/// `_meta` key, in a result or an error's `data`, of the broker's payment outcome (P1). The
/// broker strips any `dev.pep-sidecar/*` key a tool server sent, so a present key is its own.
pub const OUTCOME_META_KEY: &str = "dev.pep-sidecar/outcome";

/// One upstream request: the body, and the headers derived from it. The HTTP layer adds
/// `Content-Length` and `Connection: close`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamRequest {
    /// The JCS-canonical JSON-RPC request.
    pub body: Vec<u8>,
    /// Header names and values, in a fixed order.
    pub headers: Vec<(&'static str, String)>,
}

/// Why an upstream request could not be built. Each is a PEP fault, never something the
/// agent can cause past the engine's guards.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ForwardError {
    /// The tool name is not 1 to 128 characters of `[A-Za-z0-9_.-]`, so it cannot go in
    /// `Mcp-Name` as is.
    #[error("tool name is not header-safe")]
    ToolNameNotHeaderSafe,
    /// The upstream id is not a canonical ULID.
    #[error("upstream id is not a ULID")]
    InvalidUpstreamId,
    /// The arguments are not a JSON object.
    #[error("arguments are not an object")]
    ArgumentsNotObject,
    /// The body could not be encoded.
    #[error("request could not be encoded")]
    Encoding,
    /// The broker's reply is not one JSON-RPC response to this request: not JSON, a batch,
    /// another id, both or neither of `result` and `error`, or a result that is not an object.
    #[error("ambiguous upstream reply")]
    Ambiguous,
}

/// The broker's explicit outcome for a payment (P1, RV3 B6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrokerOutcome {
    /// The tool server executed the payment.
    Executed,
    /// It did not: declined, or the broker refused the Call Proof.
    Refused,
    /// No one knows. Any value the PEP does not recognize reads as this.
    Unknown,
}

/// What the broker answered: its outcome, when it gave one, and the tool's result, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamReply {
    /// The outcome, from the result's `_meta` or the error's `data`.
    pub outcome: Option<BrokerOutcome>,
    /// The result object's canonical bytes, for
    /// [`crate::engine::PepEngine::record_result_raw`], which drops its `_meta`. `None` for an
    /// error reply.
    pub result: Option<Vec<u8>>,
}

/// Reads the broker's JSON-only reply to the request whose id was `upstream_id` (M1). The
/// caller has already checked that the reply came from the broker's uid, and was 200 with
/// `Content-Type: application/json`.
///
/// # Errors
///
/// Returns [`ForwardError::Ambiguous`] for anything but one JSON-RPC response to this
/// request; the caller treats it as an unknown outcome.
pub fn read_upstream_reply(body: &[u8], upstream_id: &str) -> Result<UpstreamReply, ForwardError> {
    let value = jcs::parse_with(body, &ParseOptions::definition())
        .map_err(|_| ForwardError::Ambiguous)?
        .value;
    let object = value.as_object().ok_or(ForwardError::Ambiguous)?;
    let known = object
        .entries()
        .iter()
        .all(|(key, _)| matches!(key.as_str(), "jsonrpc" | "id" | "result" | "error"));
    if !known
        || object.get("jsonrpc").and_then(JcsValue::as_str) != Some("2.0")
        || object.get("id").and_then(JcsValue::as_str) != Some(upstream_id)
    {
        return Err(ForwardError::Ambiguous);
    }
    let outcome_in = |holder: Option<&JcsValue>| {
        holder
            .and_then(|holder| holder.get(OUTCOME_META_KEY))
            .map(|outcome| match outcome.as_str() {
                Some("executed") => BrokerOutcome::Executed,
                Some("refused") => BrokerOutcome::Refused,
                _ => BrokerOutcome::Unknown,
            })
    };
    match (object.get("result"), object.get("error")) {
        (Some(result), None) => {
            if result.as_object().is_none() {
                return Err(ForwardError::Ambiguous);
            }
            Ok(UpstreamReply {
                outcome: outcome_in(result.get("_meta")),
                result: Some(result.to_canonical_bytes()),
            })
        }
        (None, Some(error)) => {
            if error.as_object().is_none() {
                return Err(ForwardError::Ambiguous);
            }
            Ok(UpstreamReply {
                outcome: outcome_in(error.get("data")),
                result: None,
            })
        }
        _ => Err(ForwardError::Ambiguous),
    }
}

/// Builds the upstream `tools/call` for an allowed call.
/// - `upstream_id` is the PEP-assigned ULID the engine saw as the call's id (M1).
/// - `tool` and `arguments` are the engine's canonical name and arguments, the same pair that
///   `action_digest` hashes.
/// - `call_proof` is the Call Proof for this call (T1).
///
/// # Errors
///
/// Returns a [`ForwardError`] for a tool name that is not header-safe, an upstream id that is
/// not a canonical ULID, or arguments that are not an object.
pub fn tools_call_request(
    upstream_id: &str,
    tool: &str,
    arguments: &JcsValue,
    call_proof: &str,
) -> Result<UpstreamRequest, ForwardError> {
    if !is_header_safe_tool_name(tool) {
        return Err(ForwardError::ToolNameNotHeaderSafe);
    }
    if decode_ulid(upstream_id).is_none_or(|id| encode_ulid(id) != upstream_id) {
        return Err(ForwardError::InvalidUpstreamId);
    }
    if arguments.as_object().is_none() {
        return Err(ForwardError::ArgumentsNotObject);
    }
    let client_info = object(vec![
        ("name", JcsValue::string(CLIENT_NAME)),
        ("version", JcsValue::string(CLIENT_VERSION)),
    ])?;
    let meta = object(vec![
        (CALL_PROOF_META_KEY, JcsValue::string(call_proof)),
        (
            "io.modelcontextprotocol/clientCapabilities",
            JcsValue::Object(object(Vec::new())?),
        ),
        (
            "io.modelcontextprotocol/clientInfo",
            JcsValue::Object(client_info),
        ),
        (
            "io.modelcontextprotocol/protocolVersion",
            JcsValue::string(PROTOCOL_VERSION),
        ),
    ])?;
    let params = object(vec![
        ("_meta", JcsValue::Object(meta)),
        ("arguments", arguments.clone()),
        ("name", JcsValue::string(tool)),
    ])?;
    let request = object(vec![
        ("id", JcsValue::string(upstream_id)),
        ("jsonrpc", JcsValue::string("2.0")),
        ("method", JcsValue::string("tools/call")),
        ("params", JcsValue::Object(params)),
    ])?;
    Ok(UpstreamRequest {
        body: JcsValue::Object(request).to_canonical_bytes(),
        headers: vec![
            ("Content-Type", "application/json".to_owned()),
            ("Accept", "application/json, text/event-stream".to_owned()),
            ("MCP-Protocol-Version", PROTOCOL_VERSION.to_owned()),
            ("Mcp-Method", "tools/call".to_owned()),
            ("Mcp-Name", tool.to_owned()),
        ],
    })
}

/// Whether `name` is 1 to [`MAX_TOOL_NAME`] characters of `[A-Za-z0-9_.-]`.
#[must_use]
pub fn is_header_safe_tool_name(name: &str) -> bool {
    (1..=MAX_TOOL_NAME).contains(&name.len())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

fn object(entries: Vec<(&str, JcsValue)>) -> Result<JcsObject, ForwardError> {
    JcsObject::from_entries(
        entries
            .into_iter()
            .map(|(key, value)| (JcsString::new(key), value))
            .collect(),
    )
    .map_err(|_| ForwardError::Encoding)
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

    const ID: &str = "01JBAE0Z1TFCQ9Y41W9NF6YYMB";

    fn arguments() -> JcsValue {
        jcs::parse(br#"{"amount":5000,"currency":"USD","recipient_id":"rcpt_123"}"#).unwrap()
    }

    #[test]
    fn body_is_canonical_and_built_by_the_pep() {
        let request = tools_call_request(ID, "pay_invoice", &arguments(), "eyJ.proof").unwrap();
        let expected = format!(
            concat!(
                r#"{{"id":"{id}","jsonrpc":"2.0","method":"tools/call","params":{{"_meta":{{"#,
                r#""dev.pep-sidecar/call-proof":"eyJ.proof","#,
                r#""io.modelcontextprotocol/clientCapabilities":{{}},"#,
                r#""io.modelcontextprotocol/clientInfo":{{"name":"pep-sidecar","version":"{version}"}},"#,
                r#""io.modelcontextprotocol/protocolVersion":"2026-07-28"}},"#,
                r#""arguments":{{"amount":5000,"currency":"USD","recipient_id":"rcpt_123"}},"#,
                r#""name":"pay_invoice"}}}}"#
            ),
            id = ID,
            version = CLIENT_VERSION
        );
        assert_eq!(String::from_utf8(request.body.clone()).unwrap(), expected);
        assert_eq!(jcs::canonicalize(&request.body).unwrap(), request.body);
    }

    #[test]
    fn headers_follow_the_body() {
        let request = tools_call_request(ID, "get_invoice", &arguments(), "p").unwrap();
        assert_eq!(
            request.headers,
            vec![
                ("Content-Type", "application/json".to_owned()),
                ("Accept", "application/json, text/event-stream".to_owned()),
                ("MCP-Protocol-Version", "2026-07-28".to_owned()),
                ("Mcp-Method", "tools/call".to_owned()),
                ("Mcp-Name", "get_invoice".to_owned()),
            ]
        );
    }

    #[test]
    fn the_broker_recomputes_the_same_action_digest() {
        // SPEC §2's vector, recomputed the way the broker does: from the forwarded body.
        let request = tools_call_request(ID, "pay_invoice", &arguments(), "p").unwrap();
        let body = jcs::parse(&request.body).unwrap();
        let params = body.get("params").unwrap();
        let digest = jcs::action_digest(
            params.get("name").unwrap().as_str().unwrap(),
            params.get("arguments").unwrap(),
        );
        assert_eq!(
            digest,
            "sha-256:j3XfycsYi2G8jSVocXUTiPN2JWbcwQfOK1L4pLAdI1E"
        );
    }

    #[test]
    fn upstream_replies() {
        let reply = |body: &str| read_upstream_reply(body.as_bytes(), ID);
        // A payment result with the broker's outcome; big integers keep their digits (J1).
        let executed = reply(&format!(
            r#"{{"jsonrpc":"2.0","id":"{ID}","result":{{"resultType":"complete","content":[],"structuredContent":{{"n":18446744073709551615}},"_meta":{{"dev.pep-sidecar/outcome":"executed"}}}}}}"#
        ))
        .unwrap();
        assert_eq!(executed.outcome, Some(BrokerOutcome::Executed));
        let result = String::from_utf8(executed.result.unwrap()).unwrap();
        assert!(result.contains("18446744073709551615"));
        let reparsed = jcs::parse_with(result.as_bytes(), &ParseOptions::definition()).unwrap();
        assert_eq!(reparsed.value.to_canonical_bytes(), result.as_bytes());
        // No outcome: a non-payment result.
        let plain = reply(&format!(
            r#"{{"jsonrpc":"2.0","id":"{ID}","result":{{"resultType":"complete"}}}}"#
        ))
        .unwrap();
        assert_eq!(plain.outcome, None);
        // A refused Call Proof: an error with the outcome in `data`, and no result.
        let refused = reply(&format!(
            r#"{{"jsonrpc":"2.0","id":"{ID}","error":{{"code":-31403,"message":"refused","data":{{"dev.pep-sidecar/outcome":"refused"}}}}}}"#
        ))
        .unwrap();
        assert_eq!(
            refused,
            UpstreamReply {
                outcome: Some(BrokerOutcome::Refused),
                result: None
            }
        );
        // An outcome the PEP does not know is unknown.
        for outcome in [r#""pending""#, "1", r#""Executed""#] {
            let odd = reply(&format!(
                r#"{{"jsonrpc":"2.0","id":"{ID}","result":{{"_meta":{{"dev.pep-sidecar/outcome":{outcome}}}}}}}"#
            ))
            .unwrap();
            assert_eq!(odd.outcome, Some(BrokerOutcome::Unknown), "{outcome}");
        }
        // Anything but one response to this request is ambiguous.
        for body in [
            String::new(),
            "{".to_owned(),
            format!(r#"[{{"jsonrpc":"2.0","id":"{ID}","result":{{}}}}]"#),
            r#"{"jsonrpc":"2.0","id":"01JBAE0Z1TFCQ9Y41W9NF6YYMC","result":{}}"#.to_owned(),
            format!(r#"{{"jsonrpc":"2.0","id":"{ID}"}}"#),
            format!(r#"{{"jsonrpc":"2.0","id":"{ID}","result":{{}},"error":{{}}}}"#),
            format!(r#"{{"jsonrpc":"2.0","id":"{ID}","result":[]}}"#),
            format!(r#"{{"jsonrpc":"2.0","id":"{ID}","error":"x"}}"#),
            format!(r#"{{"jsonrpc":"1.0","id":"{ID}","result":{{}}}}"#),
            format!(r#"{{"jsonrpc":"2.0","id":"{ID}","result":{{}},"extra":1}}"#),
            format!(r#"{{"jsonrpc":"2.0","id":"{ID}","result":{{}},"result":{{}}}}"#),
        ] {
            assert_eq!(reply(&body), Err(ForwardError::Ambiguous), "{body}");
        }
    }

    #[test]
    fn bad_inputs_rejected() {
        let args = arguments();
        for tool in ["", "bad name", "pay\u{430}", "a/b", &"x".repeat(129)] {
            assert_eq!(
                tools_call_request(ID, tool, &args, "p"),
                Err(ForwardError::ToolNameNotHeaderSafe),
                "{tool:?}"
            );
        }
        assert!(tools_call_request(ID, &"x".repeat(128), &args, "p").is_ok());
        for id in [
            "",
            "7",
            "01jbae0z1tfcq9y41w9nf6yymb",
            "81JBAE0Z1TFCQ9Y41W9NF6YYMB",
        ] {
            assert_eq!(
                tools_call_request(id, "t", &args, "p"),
                Err(ForwardError::InvalidUpstreamId),
                "{id:?}"
            );
        }
        assert_eq!(
            tools_call_request(ID, "t", &JcsValue::Array(vec![]), "p"),
            Err(ForwardError::ArgumentsNotObject)
        );
    }
}
