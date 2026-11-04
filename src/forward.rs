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
use crate::jcs::{JcsObject, JcsString, JcsValue};

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
