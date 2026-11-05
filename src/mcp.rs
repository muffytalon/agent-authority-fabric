//! The PEP's MCP 2026-07-28 surface to the agent (M1, U1).
//!
//! [`check`] runs steps 2 to 13 of U1's reply order on a framed request ([`crate::http`] is
//! step 1), and either routes it or gives the only reply. Steps 14 to 16 (the Episode Token,
//! the rate limit and the engine) belong to the episode's actor, which builds its replies with
//! the functions here. Every body this module writes is JCS-canonical JSON.
//!
//! | Step | Check | Reply |
//! |---|---|---|
//! | 2 | Not POST | 405 |
//! | 3 | An `Origin` header | 403 |
//! | 4 | `Content-Type` not JSON, or `Accept` without JSON and SSE | 400 |
//! | 5 | Not JSON under the request profile | 400, -32700 |
//! | 6 | Not one JSON-RPC request or notification | 400, -32600 |
//! | 7 | `notifications/cancelled` | 202, ignored |
//! | 8 | Any other notification | 400 |
//! | 9 | A missing standard header | 400, -32020 |
//! | 10 | A missing `_meta` field | 400, -32602 |
//! | 11 | A header that differs from the body or `_meta`, or any `Mcp-Param-*` | 400, -32020 |
//! | 12 | A version other than 2026-07-28 | 400, -32022 |
//! | 13 | An unknown method | 404, -32601 |

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use crate::engine::EPISODE_META_KEY;
use crate::forward::PROTOCOL_VERSION;
use crate::http::{self, RequestHead, Status};
use crate::jcs::{self, JcsObject, JcsString, JcsValue};

/// `_meta` key of the request's protocol version.
pub const PROTOCOL_VERSION_META_KEY: &str = "io.modelcontextprotocol/protocolVersion";
/// `_meta` key of the client's capabilities.
pub const CLIENT_CAPABILITIES_META_KEY: &str = "io.modelcontextprotocol/clientCapabilities";
/// `_meta` key of a subscription's id.
pub const SUBSCRIPTION_ID_META_KEY: &str = "io.modelcontextprotocol/subscriptionId";
/// The header that may carry the Episode Token (SPEC §3.3).
pub const EPISODE_HEADER: &str = "pep-episode";
/// Longest string id the PEP accepts from the agent (M1).
pub const MAX_AGENT_ID_CHARS: usize = 64;

/// JSON-RPC parse error.
pub const PARSE_ERROR: i64 = -32700;
/// JSON-RPC invalid request.
pub const INVALID_REQUEST: i64 = -32600;
/// JSON-RPC method not found.
pub const METHOD_NOT_FOUND: i64 = -32601;
/// JSON-RPC invalid params, for a missing `_meta` field.
pub const INVALID_PARAMS: i64 = -32602;
/// MCP header mismatch, for a missing standard header or one that differs from the body.
pub const HEADER_MISMATCH: i64 = -32020;
/// MCP unsupported protocol version.
pub const UNSUPPORTED_VERSION: i64 = -32022;
/// `PEP_DENIED` (U1): every policy and token denial.
pub const PEP_DENIED_CODE: i64 = -31403;
/// `PEP_UNAVAILABLE` (U1): a PEP fault or a rate-limited call.
pub const PEP_UNAVAILABLE_CODE: i64 = -31503;

/// The message for each code. One message per code, so the code says no more than the
/// message (F-09).
const fn message(code: i64) -> &'static str {
    match code {
        PARSE_ERROR => "Parse error",
        INVALID_REQUEST => "Invalid Request",
        METHOD_NOT_FOUND => "Method not found",
        INVALID_PARAMS => "Invalid params",
        HEADER_MISMATCH => "Header mismatch",
        UNSUPPORTED_VERSION => "Unsupported protocol version",
        PEP_DENIED_CODE => crate::engine::PEP_DENIED,
        _ => crate::engine::PEP_UNAVAILABLE,
    }
}

/// The methods the PEP serves (M1's router).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// `server/discover`, answered by the PEP; no token.
    Discover,
    /// `tools/list`, served from the pins; token in `_meta` or `Pep-Episode`.
    ToolsList,
    /// `tools/call`, through the engine; token in `_meta`.
    ToolsCall,
    /// `subscriptions/listen`, the one SSE reply; no token.
    Listen,
}

impl Method {
    fn parse(name: &str) -> Option<Self> {
        match name {
            "server/discover" => Some(Self::Discover),
            "tools/list" => Some(Self::ToolsList),
            "tools/call" => Some(Self::ToolsCall),
            "subscriptions/listen" => Some(Self::Listen),
            _ => None,
        }
    }

    /// Whether the method needs a valid Episode Token (U1 step 14).
    #[must_use]
    pub const fn needs_token(self) -> bool {
        matches!(self, Self::ToolsList | Self::ToolsCall)
    }
}

/// A request that passed steps 2 to 13.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentRequest {
    /// The agent's id: a safe integer, or 1 to 64 printable ASCII characters. It goes back on
    /// the reply and nowhere else (RV3 F6).
    pub id: JcsValue,
    /// The method.
    pub method: Method,
    /// The params, `_meta` included.
    pub params: JcsObject,
    header_token: Option<String>,
}

impl AgentRequest {
    /// The Episode Token under the method's rule (M1, RV4 #11): for `tools/call` only
    /// `_meta["dev.pep-sidecar/episode"]`; for `tools/list` that, or else the `Pep-Episode`
    /// header alone; for the others none. Step 11 already refused a header that differs from
    /// `_meta`. `None` on a method that needs a token is a denial (step 14).
    #[must_use]
    pub fn episode_token(&self) -> Option<&str> {
        let in_meta = self
            .params
            .get("_meta")
            .and_then(|meta| meta.get(EPISODE_META_KEY));
        match self.method {
            Method::ToolsCall => in_meta.and_then(JcsValue::as_str),
            Method::ToolsList => match in_meta {
                Some(value) => value.as_str(),
                None => self.header_token.as_deref(),
            },
            Method::Discover | Method::Listen => None,
        }
    }

    /// The engine's view of a `tools/call`: the agent's params under the PEP-assigned id
    /// `pep_id`, as canonical bytes for [`crate::engine::PepEngine::evaluate_raw`]. The engine
    /// then keys the call by [`engine_call_id`] of `pep_id`.
    #[must_use]
    pub fn engine_request(&self, pep_id: &str) -> Vec<u8> {
        let mut out = br#"{"id":"#.to_vec();
        out.extend_from_slice(&JcsValue::string(pep_id).to_canonical_bytes());
        out.extend_from_slice(br#","jsonrpc":"2.0","method":"tools/call","params":"#);
        out.extend_from_slice(&JcsValue::Object(self.params.clone()).to_canonical_bytes());
        out.push(b'}');
        out
    }
}

/// What a request that passed [`check`] asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Inbound {
    /// A `notifications/cancelled`: reply 202 ([`accepted`]) and do nothing (M1). Cancellation
    /// is the closing of the connection, so the notification never touches a reservation.
    Ignored,
    /// A request for the actor.
    Request(AgentRequest),
}

/// A complete reply: a status and, unless the status says it all, a JSON body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// The HTTP status.
    pub status: Status,
    /// The JSON-RPC body, if any.
    pub body: Option<Vec<u8>>,
}

impl Reply {
    const fn bare(status: Status) -> Self {
        Self { status, body: None }
    }

    fn error(status: Status, id: Option<&JcsValue>, code: i64) -> Self {
        Self {
            status,
            body: Some(error_body(id, code)),
        }
    }

    /// The HTTP response bytes.
    #[must_use]
    pub fn to_http(&self) -> Vec<u8> {
        http::response(
            self.status,
            self.body.as_deref().map(|body| ("application/json", body)),
        )
    }
}

/// The reply to a notification the PEP ignores: 202.
#[must_use]
pub const fn accepted() -> Reply {
    Reply::bare(Status::Accepted)
}

/// Runs steps 2 to 13 of U1 on a framed request.
///
/// # Errors
///
/// Returns the only reply for a request that fails a step.
pub fn check(head: &RequestHead, body: &[u8]) -> Result<Inbound, Reply> {
    let headers = &head.headers;
    // 2-4: transport.
    if !head.is_post() {
        return Err(Reply::bare(Status::MethodNotAllowed));
    }
    if headers.contains("origin") {
        return Err(Reply::bare(Status::Forbidden));
    }
    if !headers
        .get("content-type")
        .is_some_and(is_json_content_type)
        || !accepts_json_and_sse(head)
    {
        return Err(Reply::bare(Status::BadRequest));
    }
    // 5: JSON under the request profile.
    let message =
        jcs::parse(body).map_err(|_| Reply::error(Status::BadRequest, None, PARSE_ERROR))?;
    // 6: one JSON-RPC request or notification.
    let (id, method, params) = json_rpc_parts(&message)?;
    let Some(id) = id else {
        // 7, 8: notifications.
        return if method == "notifications/cancelled" {
            Ok(Inbound::Ignored)
        } else {
            Err(Reply::bare(Status::BadRequest))
        };
    };
    let fail = |status, code| Reply::error(status, Some(id), code);
    // 9: the standard headers.
    let version_header = headers.get("mcp-protocol-version");
    let method_header = headers.get("mcp-method");
    let name_header = headers.get("mcp-name");
    let (Some(version_header), Some(method_header)) = (version_header, method_header) else {
        return Err(fail(Status::BadRequest, HEADER_MISMATCH));
    };
    if method == "tools/call" && name_header.is_none() {
        return Err(fail(Status::BadRequest, HEADER_MISMATCH));
    }
    // 10: `_meta`, which needs params that are an object.
    let meta = params.and_then(|params| params.get("_meta"));
    let version = meta
        .and_then(|meta| meta.get(PROTOCOL_VERSION_META_KEY))
        .and_then(JcsValue::as_str);
    let capabilities = meta
        .and_then(|meta| meta.get(CLIENT_CAPABILITIES_META_KEY))
        .and_then(JcsValue::as_object);
    let (Some(params), Some(meta), Some(version), Some(_)) = (params, meta, version, capabilities)
    else {
        return Err(fail(Status::BadRequest, INVALID_PARAMS));
    };
    // 11: headers against the body and `_meta`.
    let name_in_body = params.get("name").and_then(JcsValue::as_str);
    let name_matches = match (method == "tools/call", name_header) {
        (true, Some(header)) => {
            name_in_body.is_some_and(|name| decode_header(header).as_deref() == Some(name))
        }
        (false, None) => true,
        _ => false,
    };
    let header_token = headers.get(EPISODE_HEADER);
    let token_matches = match (header_token, meta.get(EPISODE_META_KEY)) {
        (Some(header), Some(in_meta)) => in_meta.as_str() == Some(header),
        _ => true,
    };
    let has_param_header = headers.names().any(|name| name.starts_with("mcp-param-"));
    if decode_header(method_header).as_deref() != Some(method)
        || version_header != version
        || !name_matches
        || !token_matches
        || has_param_header
    {
        return Err(fail(Status::BadRequest, HEADER_MISMATCH));
    }
    // 12: the version.
    if version != PROTOCOL_VERSION {
        return Err(fail(Status::BadRequest, UNSUPPORTED_VERSION));
    }
    // 13: the router.
    let method = Method::parse(method).ok_or_else(|| fail(Status::NotFound, METHOD_NOT_FOUND))?;
    Ok(Inbound::Request(AgentRequest {
        id: id.clone(),
        method,
        params: params.clone(),
        header_token: header_token.map(str::to_owned),
    }))
}

type Parts<'a> = (Option<&'a JcsValue>, &'a str, Option<&'a JcsObject>);

/// Step 6: the id (absent for a notification), the method and the params of one JSON-RPC
/// request or notification. Params that are not an object count as absent, so a request gets
/// -32602 at step 10.
fn json_rpc_parts(message: &JcsValue) -> Result<Parts<'_>, Reply> {
    let invalid = |id: Option<&JcsValue>| {
        Reply::error(
            Status::BadRequest,
            id.filter(|id| is_valid_id(id)),
            INVALID_REQUEST,
        )
    };
    // A batch is an array, so not an object.
    let object = message.as_object().ok_or_else(|| invalid(None))?;
    let id = object.get("id");
    let known = object
        .entries()
        .iter()
        .all(|(key, _)| matches!(key.as_str(), "id" | "jsonrpc" | "method" | "params"));
    let method = object.get("method").and_then(JcsValue::as_str);
    let (true, Some("2.0"), Some(method)) = (
        known,
        object.get("jsonrpc").and_then(JcsValue::as_str),
        method,
    ) else {
        // A response has `result` or `error` and no `method`.
        return Err(invalid(id));
    };
    if id.is_some_and(|id| !is_valid_id(id)) {
        return Err(invalid(None));
    }
    let params = object.get("params").and_then(JcsValue::as_object);
    Ok((id, method, params))
}

/// A safe integer, or 1 to [`MAX_AGENT_ID_CHARS`] printable ASCII characters (M1). Such a
/// string has no NFC form other than itself.
fn is_valid_id(id: &JcsValue) -> bool {
    match id {
        // The request profile admits only integers within ±(2^53 - 1) (F-04); a fraction
        // (the lenient-numbers test profile) has no `i64` value.
        JcsValue::Number(number) => number.as_i64().is_some(),
        JcsValue::String(text) => {
            let text = text.as_str();
            (1..=MAX_AGENT_ID_CHARS).contains(&text.len())
                && text.bytes().all(|byte| matches!(byte, b' '..=b'~'))
        }
        JcsValue::Null | JcsValue::Bool(_) | JcsValue::Array(_) | JcsValue::Object(_) => false,
    }
}

/// A header value as the body would have it: `=?base64?…?=` decoded (standard alphabet,
/// padded), and NFC-normalized like every parsed string. `None` if the encoding is invalid.
fn decode_header(value: &str) -> Option<String> {
    let Some(encoded) = value
        .strip_prefix("=?base64?")
        .and_then(|rest| rest.strip_suffix("?="))
    else {
        return Some(JcsString::new(value).into_string());
    };
    let bytes = STANDARD.decode(encoded).ok()?;
    let text = String::from_utf8(bytes).ok()?;
    Some(JcsString::new(text).into_string())
}

/// `application/json`, optionally with `charset=utf-8`; case-insensitive.
fn is_json_content_type(value: &str) -> bool {
    let mut parts = value.split(';').map(|part| part.trim_matches([' ', '\t']));
    parts
        .next()
        .is_some_and(|media| media.eq_ignore_ascii_case("application/json"))
        && parts.all(|parameter| parameter.eq_ignore_ascii_case("charset=utf-8"))
}

/// Whether the `Accept` values, together, list both `application/json` and
/// `text/event-stream`, as MCP requires of clients.
fn accepts_json_and_sse(head: &RequestHead) -> bool {
    let mut json = false;
    let mut sse = false;
    for range in head
        .headers
        .all("accept")
        .flat_map(|value| value.split(','))
    {
        let media = range
            .split(';')
            .next()
            .unwrap_or_default()
            .trim_matches([' ', '\t']);
        json |= media.eq_ignore_ascii_case("application/json");
        sse |= media.eq_ignore_ascii_case("text/event-stream");
    }
    json && sse
}

/// The id as the engine keys the call: the canonical JSON of `pep_id`, quotes included.
#[must_use]
pub fn engine_call_id(pep_id: &str) -> String {
    JcsValue::string(pep_id).to_canonical_string()
}

/// A JSON-RPC error body with `code`'s one message and no `data` (U1). An absent `id` is
/// written as `null`.
#[must_use]
pub fn error_body(id: Option<&JcsValue>, code: i64) -> Vec<u8> {
    let mut out = format!(r#"{{"error":{{"code":{code},"message":"#).into_bytes();
    out.extend_from_slice(&JcsValue::string(message(code)).to_canonical_bytes());
    out.extend_from_slice(br#"},"id":"#);
    out.extend_from_slice(&id.map_or_else(|| b"null".to_vec(), JcsValue::to_canonical_bytes));
    out.extend_from_slice(br#","jsonrpc":"2.0"}"#);
    out
}

/// A JSON-RPC result body around `result`, which must be canonical JSON: the bytes the engine
/// recorded, or a result built here.
#[must_use]
pub fn result_body(id: &JcsValue, result: &[u8]) -> Vec<u8> {
    let mut out = br#"{"id":"#.to_vec();
    out.extend_from_slice(&id.to_canonical_bytes());
    out.extend_from_slice(br#","jsonrpc":"2.0","result":"#);
    out.extend_from_slice(result);
    out.push(b'}');
    out
}

/// The 200 reply carrying `result`.
#[must_use]
pub fn result_reply(id: &JcsValue, result: &[u8]) -> Reply {
    Reply {
        status: Status::Ok,
        body: Some(result_body(id, result)),
    }
}

/// The reply to any policy or token denial: 200, `PEP_DENIED` (U1).
#[must_use]
pub fn denied(id: &JcsValue) -> Reply {
    Reply::error(Status::Ok, Some(id), PEP_DENIED_CODE)
}

/// The reply to a PEP fault or a rate-limited call: 200, `PEP_UNAVAILABLE` (U1).
#[must_use]
pub fn unavailable(id: &JcsValue) -> Reply {
    Reply::error(Status::Ok, Some(id), PEP_UNAVAILABLE_CODE)
}

/// The `server/discover` result (M1): this version only, the tools capability, never cached,
/// and `instructions` only when the lockfile pins their text.
#[must_use]
pub fn discover_result(instructions: Option<&str>) -> Vec<u8> {
    let mut out = br#"{"cacheScope":"public","capabilities":{"tools":{}},"#.to_vec();
    if let Some(text) = instructions {
        out.extend_from_slice(br#""instructions":"#);
        out.extend_from_slice(&JcsValue::string(text).to_canonical_bytes());
        out.push(b',');
    }
    out.extend_from_slice(br#""resultType":"complete","supportedVersions":["#);
    out.extend_from_slice(&JcsValue::string(PROTOCOL_VERSION).to_canonical_bytes());
    out.extend_from_slice(br#"],"ttlMs":0}"#);
    out
}

/// The `tools/list` result (M1): `tools`, the pinned definitions of every serving server, in
/// one page, private and never cached, since a quarantine can change it at any moment.
#[must_use]
pub fn tools_list_result(tools: &[JcsValue]) -> Vec<u8> {
    let mut out = br#"{"cacheScope":"private","resultType":"complete","tools":["#.to_vec();
    for (index, tool) in tools.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        out.extend_from_slice(&tool.to_canonical_bytes());
    }
    out.extend_from_slice(br#"],"ttlMs":0}"#);
    out
}

/// The whole `subscriptions/listen` reply (M1): the SSE head, the acknowledgement with no
/// notification types, then the completion result, after which the PEP closes the
/// connection. No `notifications/cancelled`: both SDKs treat it as an unexpected close.
#[must_use]
pub fn listen_reply(id: &JcsValue) -> Vec<u8> {
    let mut subscription = br#"{""#.to_vec();
    subscription.extend_from_slice(SUBSCRIPTION_ID_META_KEY.as_bytes());
    subscription.extend_from_slice(br#"":"#);
    subscription.extend_from_slice(&id.to_canonical_bytes());
    subscription.push(b'}');

    let mut acknowledged = br#"{"jsonrpc":"2.0","method":"notifications/subscriptions/acknowledged","params":{"_meta":"#.to_vec();
    acknowledged.extend_from_slice(&subscription);
    acknowledged.extend_from_slice(br#","notifications":{}}}"#);

    let mut complete = br#"{"_meta":"#.to_vec();
    complete.extend_from_slice(&subscription);
    complete.extend_from_slice(br#","resultType":"complete"}"#);

    let mut out = http::stream_head("text/event-stream");
    out.extend_from_slice(&sse_event(&acknowledged));
    out.extend_from_slice(&sse_event(&result_body(id, &complete)));
    out
}

/// One SSE event. Canonical JSON has no raw CR or LF, so one `data` line holds it.
fn sse_event(json: &[u8]) -> Vec<u8> {
    let mut out = b"event: message\ndata: ".to_vec();
    out.extend_from_slice(json);
    out.extend_from_slice(b"\n\n");
    out
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
    use crate::http::{Deadlines, parse_head};
    use std::time::{Duration, Instant};

    const TOKEN: &str = "eyJ.spike.token";
    const META: &str = r#"{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}"#;

    fn meta_with_token(token: &str) -> String {
        format!(
            r#"{{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{{}},"dev.pep-sidecar/episode":"{token}"}}"#
        )
    }

    /// The headers a pinned SDK sends for `method` (D2 spike).
    fn sdk_headers(method: &str, name: Option<&str>) -> String {
        let mut headers = format!(
            "Host: pep.local\r\nAccept: application/json, text/event-stream\r\nContent-Type: application/json\r\nMCP-Protocol-Version: 2026-07-28\r\nMcp-Method: {method}\r\n"
        );
        if let Some(name) = name {
            headers = format!("{headers}Mcp-Name: {name}\r\n");
        }
        headers
    }

    fn head(headers: &str, body: &str) -> RequestHead {
        let raw = format!(
            "POST /mcp HTTP/1.1\r\n{headers}Content-Length: {}\r\n\r\n",
            body.len()
        );
        parse_head(raw.as_bytes(), "/mcp").unwrap()
    }

    fn run(headers: &str, body: &str) -> Result<Inbound, Reply> {
        check(&head(headers, body), body.as_bytes())
    }

    fn call_body(id: &str, name: &str, meta: &str) -> String {
        format!(
            r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"{name}","arguments":{{"invoice_id":"INV-1"}},"_meta":{meta}}}}}"#
        )
    }

    fn list_body(id: &str, meta: &str) -> String {
        format!(
            r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/list","params":{{"_meta":{meta}}}}}"#
        )
    }

    fn request(result: Result<Inbound, Reply>) -> AgentRequest {
        match result {
            Ok(Inbound::Request(request)) => request,
            other => panic!("expected a request, got {other:?}"),
        }
    }

    /// The reply's status, and its JSON-RPC error code and id, if any.
    fn refused(result: Result<Inbound, Reply>) -> (u16, Option<i64>, Option<String>) {
        let Err(reply) = result else {
            panic!("expected a reply, got {result:?}");
        };
        let Some(body) = reply.body else {
            return (reply.status.code(), None, None);
        };
        let value = jcs::parse(&body).unwrap();
        assert_eq!(jcs::canonicalize(&body).unwrap(), body, "not canonical");
        let error = value.get("error").unwrap();
        assert_eq!(
            error.get("message").unwrap().as_str(),
            Some(message(error.get("code").unwrap().as_i64().unwrap()))
        );
        assert!(error.get("data").is_none());
        (
            reply.status.code(),
            error.get("code").unwrap().as_i64(),
            Some(value.get("id").unwrap().to_canonical_string()),
        )
    }

    #[test]
    fn sdk_requests_route() {
        let call = request(run(
            &sdk_headers("tools/call", Some("get_invoice")),
            &call_body("0", "get_invoice", &meta_with_token(TOKEN)),
        ));
        assert_eq!(call.method, Method::ToolsCall);
        assert_eq!(call.id.to_canonical_string(), "0");
        assert_eq!(call.episode_token(), Some(TOKEN));
        for (method, body) in [
            ("server/discover", r#"{"jsonrpc":"2.0","id":"server-discover-probe-1","method":"server/discover","params":{"_meta":META}}"#.replace("META", META)),
            ("tools/list", list_body("1", META)),
            ("subscriptions/listen", r#"{"jsonrpc":"2.0","id":"listen:0","method":"subscriptions/listen","params":{"_meta":META}}"#.replace("META", META)),
        ] {
            let routed = request(run(&sdk_headers(method, None), &body));
            assert_eq!(Some(routed.method), Method::parse(method));
        }
    }

    #[test]
    fn episode_token_rules() {
        let with_header =
            |method: &str, name| format!("{}Pep-Episode: {TOKEN}\r\n", sdk_headers(method, name));
        // tools/call: `_meta` only.
        let call = request(run(
            &with_header("tools/call", Some("t")),
            &call_body("1", "t", META),
        ));
        assert_eq!(call.episode_token(), None);
        // tools/list: `_meta`, or the header alone (RV4 #11).
        let list = request(run(&with_header("tools/list", None), &list_body("1", META)));
        assert_eq!(list.episode_token(), Some(TOKEN));
        let list = request(run(&sdk_headers("tools/list", None), &list_body("1", META)));
        assert_eq!(list.episode_token(), None);
        let list = request(run(
            &sdk_headers("tools/list", None),
            &list_body("1", &meta_with_token("other")),
        ));
        assert_eq!(list.episode_token(), Some("other"));
        // A token that is not a string is none.
        let meta = META.replace("}}", r#"},"dev.pep-sidecar/episode":7}"#);
        let list = request(run(
            &sdk_headers("tools/list", None),
            &list_body("1", &meta),
        ));
        assert_eq!(list.episode_token(), None);
        // Discover and listen need none, and get none.
        let discover = request(run(
            &with_header("server/discover", None),
            &format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{{"_meta":{META}}}}}"#
            ),
        ));
        assert_eq!(discover.episode_token(), None);
        assert!(!Method::Discover.needs_token() && !Method::Listen.needs_token());
        assert!(Method::ToolsList.needs_token() && Method::ToolsCall.needs_token());
    }

    #[test]
    fn transport_steps() {
        let body = list_body("1", META);
        let ok = sdk_headers("tools/list", None);
        // 2: not POST.
        let get = parse_head(b"GET /mcp HTTP/1.1\r\nHost: x\r\n\r\n", "/mcp").unwrap();
        assert_eq!(refused(check(&get, b"")), (405, None, None));
        // 3: Origin, even with everything else right.
        assert_eq!(
            refused(run(&format!("{ok}Origin: http://evil.example\r\n"), &body)),
            (403, None, None)
        );
        // 4: Content-Type and Accept.
        for (from, to) in [
            ("Content-Type: application/json", "Content-Type: text/plain"),
            (
                "Content-Type: application/json",
                "Content-Type: application/json; charset=latin1",
            ),
            ("Content-Type: application/json\r\n", ""),
            (
                "Accept: application/json, text/event-stream",
                "Accept: application/json",
            ),
            (
                "Accept: application/json, text/event-stream",
                "Accept: text/event-stream",
            ),
            ("Accept: application/json, text/event-stream", "Accept: */*"),
            ("Accept: application/json, text/event-stream\r\n", ""),
        ] {
            assert_eq!(
                refused(run(&ok.replace(from, to), &body)),
                (400, None, None),
                "{to}"
            );
        }
        for (from, to) in [
            (
                "Content-Type: application/json",
                "content-type: Application/JSON; Charset=UTF-8",
            ),
            (
                "Accept: application/json, text/event-stream",
                "Accept: text/event-stream;q=0.5\r\nAccept: application/json",
            ),
        ] {
            request(run(&ok.replace(from, to), &body));
        }
    }

    #[test]
    fn json_rpc_steps() {
        let ok = sdk_headers("tools/list", None);
        // 5: not JSON under the request profile: duplicate keys, 2^53, malformed.
        for body in [
            r#"{"jsonrpc":"2.0","jsonrpc":"2.0"}"#,
            r#"{"jsonrpc":"2.0","id":9007199254740992,"method":"tools/list"}"#,
            "{",
            "",
        ] {
            assert_eq!(
                refused(run(&ok, body)),
                (400, Some(PARSE_ERROR), Some("null".to_owned())),
                "{body}"
            );
        }
        // 6: not one request or notification.
        for (body, id) in [
            (format!("[{}]", list_body("1", META)), "null"),
            (r#"{"jsonrpc":"2.0","id":1,"result":{}}"#.to_owned(), "1"),
            (
                r#"{"jsonrpc":"1.0","id":1,"method":"tools/list"}"#.to_owned(),
                "1",
            ),
            (r#"{"id":1,"method":"tools/list"}"#.to_owned(), "1"),
            (r#"{"jsonrpc":"2.0","id":1}"#.to_owned(), "1"),
            (r#"{"jsonrpc":"2.0","id":1,"method":7}"#.to_owned(), "1"),
            (
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","extra":1}"#.to_owned(),
                "1",
            ),
            (
                r#"{"jsonrpc":"2.0","id":null,"method":"tools/list"}"#.to_owned(),
                "null",
            ),
            (
                r#"{"jsonrpc":"2.0","id":true,"method":"tools/list"}"#.to_owned(),
                "null",
            ),
            (
                r#"{"jsonrpc":"2.0","id":"","method":"tools/list"}"#.to_owned(),
                "null",
            ),
            (
                format!(
                    r#"{{"jsonrpc":"2.0","id":"{}","method":"tools/list"}}"#,
                    "x".repeat(65)
                ),
                "null",
            ),
            (
                r#"{"jsonrpc":"2.0","id":"café","method":"tools/list"}"#.to_owned(),
                "null",
            ),
            (
                r#"{"jsonrpc":"2.0","id":"a\nb","method":"tools/list"}"#.to_owned(),
                "null",
            ),
            (
                r#"{"jsonrpc":"2.0","id":{},"method":"tools/list"}"#.to_owned(),
                "null",
            ),
            ("7".to_owned(), "null"),
            // A malformed message never echoes an id that is itself invalid.
            (
                r#"{"jsonrpc":"1.0","id":true,"method":"tools/list"}"#.to_owned(),
                "null",
            ),
            (r#"{"id":{"a":1},"result":{}}"#.to_owned(), "null"),
        ] {
            assert_eq!(
                refused(run(&ok, &body)),
                (400, Some(INVALID_REQUEST), Some(id.to_owned())),
                "{body}"
            );
        }
        // The id limits: 64 printable characters, and ±(2^53 - 1).
        for id in [
            format!(r#""{}""#, "~".repeat(64)),
            r#"" x ""#.to_owned(),
            "9007199254740991".to_owned(),
            "-9007199254740991".to_owned(),
        ] {
            let routed = request(run(&ok, &list_body(&id, META)));
            assert_eq!(routed.id.to_canonical_string(), id);
        }
    }

    #[test]
    fn notifications() {
        // 7: cancelled is ignored before any header check: the TypeScript SDK sends it with
        // no Mcp-Method (D2 spike).
        let bare = "Host: pep.local\r\nAccept: application/json, text/event-stream\r\nContent-Type: application/json\r\n";
        let cancelled = r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"listen-1"}}"#;
        assert_eq!(run(bare, cancelled), Ok(Inbound::Ignored));
        assert_eq!(accepted().to_http(), http::response(Status::Accepted, None));
        // 8: any other notification.
        let other = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        assert_eq!(refused(run(bare, other)), (400, None, None));
    }

    #[test]
    fn header_and_meta_steps() {
        let call =
            |headers: &str, meta: &str| run(headers, &call_body(r#""c1""#, "get_invoice", meta));
        let ok = sdk_headers("tools/call", Some("get_invoice"));
        let err = |code| (400, Some(code), Some(r#""c1""#.to_owned()));
        // 9: a missing standard header.
        for missing in [
            "MCP-Protocol-Version: 2026-07-28\r\n",
            "Mcp-Method: tools/call\r\n",
            "Mcp-Name: get_invoice\r\n",
        ] {
            assert_eq!(
                refused(call(&ok.replace(missing, ""), META)),
                err(HEADER_MISMATCH),
                "{missing}"
            );
        }
        // 10: a missing `_meta` field, checked after the headers are present.
        for meta in [
            r#"{"io.modelcontextprotocol/clientCapabilities":{}}"#,
            r#"{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}"#,
            r#"{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":[]}"#,
            r#"{"io.modelcontextprotocol/protocolVersion":20260728,"io.modelcontextprotocol/clientCapabilities":{}}"#,
            "[]",
        ] {
            assert_eq!(refused(call(&ok, meta)), err(INVALID_PARAMS), "{meta}");
        }
        let no_meta =
            r#"{"jsonrpc":"2.0","id":"c1","method":"tools/call","params":{"name":"get_invoice"}}"#;
        assert_eq!(refused(run(&ok, no_meta)), err(INVALID_PARAMS));
        let array_params = r#"{"jsonrpc":"2.0","id":"c1","method":"tools/call","params":[]}"#;
        assert_eq!(refused(run(&ok, array_params)), err(INVALID_PARAMS));
        // 11: headers that differ from the body or `_meta`.
        for headers in [
            ok.replace("Mcp-Method: tools/call", "Mcp-Method: tools/list"),
            ok.replace("Mcp-Name: get_invoice", "Mcp-Name: pay_invoice"),
            ok.replace("Mcp-Name: get_invoice", "Mcp-Name: Get_Invoice"),
            ok.replace("Mcp-Name: get_invoice", "Mcp-Name: =?base64?not base64?="),
            ok.replace(
                "Mcp-Name: get_invoice",
                "Mcp-Name: =?base64?Z2V0X2ludm9pY2U?=",
            ),
            ok.replace("2026-07-28", "2025-11-25"),
            format!("{ok}Pep-Episode: other\r\n"),
            format!("{ok}Mcp-Param-Region: eu\r\n"),
            format!("{ok}mcp-param-x: 1\r\n"),
        ] {
            assert_eq!(
                refused(call(&headers, &meta_with_token(TOKEN))),
                err(HEADER_MISMATCH),
                "{headers}"
            );
        }
        // A header token beside a non-string `_meta` token differs too.
        let meta = META.replace("}}", r#"},"dev.pep-sidecar/episode":7}"#);
        assert_eq!(
            refused(call(&format!("{ok}Pep-Episode: 7\r\n"), &meta)),
            err(HEADER_MISMATCH)
        );
        // Mcp-Name on a method that has no name.
        let list = format!("{}Mcp-Name: x\r\n", sdk_headers("tools/list", None));
        assert_eq!(
            refused(run(&list, &list_body(r#""c1""#, META))),
            err(HEADER_MISMATCH)
        );
        // Matching values pass, a base64 Mcp-Name decoded and NFC-normalized.
        request(call(
            &format!("{ok}Pep-Episode: {TOKEN}\r\n"),
            &meta_with_token(TOKEN),
        ));
        let encoded = format!("=?base64?{}?=", STANDARD.encode("cafe\u{301}"));
        let headers = sdk_headers("tools/call", Some(&encoded));
        let body = call_body(r#""c1""#, "caf\u{e9}", META);
        assert_eq!(
            request(run(&headers, &body))
                .params
                .get("name")
                .unwrap()
                .as_str(),
            Some("caf\u{e9}")
        );
        // 12: a version that is present and consistent but unsupported.
        let old = ok.replace("2026-07-28", "2025-11-25");
        assert_eq!(
            refused(call(&old, &META.replace("2026-07-28", "2025-11-25"))),
            err(UNSUPPORTED_VERSION)
        );
        // 13: an unknown method, `ping` included.
        for method in ["ping", "resources/list", "logging/setLevel"] {
            let body = format!(
                r#"{{"jsonrpc":"2.0","id":"c1","method":"{method}","params":{{"_meta":{META}}}}}"#
            );
            assert_eq!(
                refused(run(&sdk_headers(method, None), &body)),
                (404, Some(METHOD_NOT_FOUND), Some(r#""c1""#.to_owned())),
                "{method}"
            );
        }
    }

    #[test]
    fn steps_run_in_order() {
        // Each request fails two steps; the earlier one gives the reply.
        let list = sdk_headers("tools/list", None);
        let bad_json = "{";
        let origin = format!("{list}Origin: x\r\n");
        assert_eq!(refused(run(&origin, bad_json)), (403, None, None));
        let text = list.replace("application/json\r\n", "text/plain\r\n");
        assert_eq!(refused(run(&text, bad_json)), (400, None, None));
        // A missing header (9) before a missing `_meta` (10).
        let no_version = list.replace("MCP-Protocol-Version: 2026-07-28\r\n", "");
        let no_meta = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
        assert_eq!(refused(run(&no_version, no_meta)).1, Some(HEADER_MISMATCH));
        // A tools/call missing Mcp-Name is step 9 too, before its missing `_meta`.
        let no_name = sdk_headers("tools/call", None);
        let call_no_meta =
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t"}}"#;
        assert_eq!(
            refused(run(&no_name, call_no_meta)).1,
            Some(HEADER_MISMATCH)
        );
        // A mismatch (11) before an unsupported version (12) and an unknown method (13).
        let old = list.replace("2026-07-28", "2025-11-25");
        assert_eq!(
            refused(run(&old, &list_body("1", META))).1,
            Some(HEADER_MISMATCH)
        );
        let ping = r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-11-25","io.modelcontextprotocol/clientCapabilities":{}}}}"#;
        let ping_headers = sdk_headers("ping", None).replace("2026-07-28", "2025-11-25");
        assert_eq!(
            refused(run(&ping_headers, ping)).1,
            Some(UNSUPPORTED_VERSION)
        );
    }

    #[test]
    fn a_legacy_initialize_gets_header_mismatch() {
        // The TypeScript SDK's default 'legacy' mode (D2 spike): no version header, no
        // Mcp-Method, no `_meta`. U1 step 9 answers before the router could say 404.
        let headers = "Host: pep.local\r\nAccept: application/json, text/event-stream\r\nContent-Type: application/json\r\n";
        let body = r#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"pep-d2-spike","version":"0.0.1"}}}"#;
        assert_eq!(
            refused(run(headers, body)),
            (400, Some(HEADER_MISMATCH), Some("0".to_owned()))
        );
    }

    #[test]
    fn the_engine_sees_the_pep_id_and_the_agent_params() {
        let body = call_body(r#""agent-7""#, "get_invoice", &meta_with_token(TOKEN));
        let call = request(run(&sdk_headers("tools/call", Some("get_invoice")), &body));
        let pep_id = "01JBAE0Z1TFCQ9Y41W9NF6YYMB";
        let engine_request = call.engine_request(pep_id);
        assert_eq!(jcs::canonicalize(&engine_request).unwrap(), engine_request);
        let value = jcs::parse(&engine_request).unwrap();
        assert_eq!(value.get("id").unwrap().as_str(), Some(pep_id));
        assert_eq!(value.get("method").unwrap().as_str(), Some("tools/call"));
        assert_eq!(
            value.get("params"),
            Some(&JcsValue::Object(call.params.clone()))
        );
        assert_eq!(engine_call_id(pep_id), format!("\"{pep_id}\""));
    }

    #[test]
    fn reply_bodies_are_canonical() {
        let id = JcsValue::string("listen-1");
        for body in [
            error_body(None, PARSE_ERROR),
            error_body(Some(&id), HEADER_MISMATCH),
            denied(&id).body.unwrap(),
            unavailable(&JcsValue::int(3).unwrap()).body.unwrap(),
            result_body(&id, br#"{"resultType":"complete"}"#),
            discover_result(None),
            discover_result(Some("Use \"get_invoice\" first.\n")),
            tools_list_result(&[]),
            tools_list_result(&[
                jcs::parse(br#"{"name":"b","inputSchema":{"type":"object"}}"#).unwrap(),
                jcs::parse(br#"{"name":"a"}"#).unwrap(),
            ]),
        ] {
            assert_eq!(
                jcs::canonicalize(&body).unwrap(),
                body,
                "{}",
                String::from_utf8_lossy(&body)
            );
        }
        assert_eq!(
            String::from_utf8(denied(&id).body.unwrap()).unwrap(),
            r#"{"error":{"code":-31403,"message":"PEP_DENIED"},"id":"listen-1","jsonrpc":"2.0"}"#
        );
        assert_eq!(
            String::from_utf8(unavailable(&id).body.unwrap()).unwrap(),
            r#"{"error":{"code":-31503,"message":"PEP_UNAVAILABLE"},"id":"listen-1","jsonrpc":"2.0"}"#
        );
        assert_eq!(denied(&id).status, Status::Ok);
        assert_eq!(
            String::from_utf8(discover_result(None)).unwrap(),
            r#"{"cacheScope":"public","capabilities":{"tools":{}},"resultType":"complete","supportedVersions":["2026-07-28"],"ttlMs":0}"#
        );
        assert_eq!(
            String::from_utf8(tools_list_result(
                &[jcs::parse(br#"{"name":"a"}"#).unwrap()]
            ))
            .unwrap(),
            r#"{"cacheScope":"private","resultType":"complete","tools":[{"name":"a"}],"ttlMs":0}"#
        );
    }

    #[test]
    fn listen_reply_acknowledges_then_completes() {
        let id = JcsValue::string("listen-1");
        let reply = String::from_utf8(listen_reply(&id)).unwrap();
        let (head, events) = reply.split_once("\r\n\r\n").unwrap();
        assert!(head.contains("Content-Type: text/event-stream"));
        assert!(!head.contains("Content-Length"));
        let data: Vec<&str> = events
            .split("\n\n")
            .filter(|event| !event.is_empty())
            .map(|event| event.strip_prefix("event: message\ndata: ").unwrap())
            .collect();
        assert_eq!(
            data,
            vec![
                r#"{"jsonrpc":"2.0","method":"notifications/subscriptions/acknowledged","params":{"_meta":{"io.modelcontextprotocol/subscriptionId":"listen-1"},"notifications":{}}}"#,
                r#"{"id":"listen-1","jsonrpc":"2.0","result":{"_meta":{"io.modelcontextprotocol/subscriptionId":"listen-1"},"resultType":"complete"}}"#,
            ]
        );
        for json in data {
            assert_eq!(jcs::canonicalize(json.as_bytes()).unwrap(), json.as_bytes());
        }
        assert!(!reply.contains("notifications/cancelled"));
    }

    /// RV3 E4: every request the SDKs sent in the D2 spike, rebuilt from its log line, framed
    /// by `http`, and checked here. The logs hold the parsed params and headers, so each body
    /// is rebuilt from them: the wire spelling (whitespace, key order) is not replayed.
    #[test]
    fn the_d2_spike_requests_are_accepted() {
        let dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("spikes/d2-transport/results");
        let mut seen = 0;
        let mut routed = 0;
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("log") {
                continue;
            }
            for line in std::fs::read_to_string(&path).unwrap().lines() {
                let record = jcs::parse_with(line.as_bytes(), &jcs::ParseOptions::definition())
                    .unwrap()
                    .value;
                if record.get("kind").and_then(JcsValue::as_str) != Some("request") {
                    continue;
                }
                seen += 1;
                let method = record.get("method").unwrap().as_str().unwrap();
                let mut members = vec![
                    (JcsString::new("jsonrpc"), JcsValue::string("2.0")),
                    (JcsString::new("method"), JcsValue::string(method)),
                ];
                for key in ["id", "params"] {
                    match record.get(key) {
                        None | Some(JcsValue::Null) => {}
                        Some(value) => members.push((JcsString::new(key), value.clone())),
                    }
                }
                let body = JcsValue::Object(JcsObject::from_entries(members).unwrap())
                    .to_canonical_bytes();
                let mut raw = b"POST /mcp HTTP/1.1\r\n".to_vec();
                for (name, value) in record
                    .get("headers")
                    .unwrap()
                    .as_object()
                    .unwrap()
                    .entries()
                {
                    if name.as_str() != "content-length" {
                        raw.extend_from_slice(
                            format!("{}: {}\r\n", name.as_str(), value.as_str().unwrap())
                                .as_bytes(),
                        );
                    }
                }
                raw.extend_from_slice(format!("content-length: {}\r\n\r\n", body.len()).as_bytes());
                raw.extend_from_slice(&body);
                let at = Instant::now() + Duration::from_secs(5);
                let framed = http::read_request(
                    &mut Replay(std::io::Cursor::new(raw)),
                    "/mcp",
                    Deadlines { head: at, body: at },
                )
                .unwrap_or_else(|error| panic!("{}: {method}: {error}", path.display()));
                let outcome = check(&framed.head, &framed.body);
                match method {
                    "initialize" => assert_eq!(refused(outcome).1, Some(HEADER_MISMATCH)),
                    "notifications/cancelled" => assert_eq!(outcome, Ok(Inbound::Ignored)),
                    _ => {
                        let request = request(outcome);
                        routed += 1;
                        assert_eq!(Method::parse(method), Some(request.method));
                        if request.method == Method::ToolsCall {
                            let engine_request =
                                request.engine_request("01JBAE0Z1TFCQ9Y41W9NF6YYMB");
                            jcs::parse(&engine_request).unwrap();
                        }
                        // With the client-wide header, every request that needs a token has one
                        // (RV4 #11). The `_meta`-only runs are the failing case that rule fixes.
                        if path.to_string_lossy().contains("enforce-header")
                            && request.method.needs_token()
                        {
                            assert_eq!(request.episode_token(), Some(TOKEN), "{}", path.display());
                        }
                    }
                }
            }
        }
        assert_eq!(seen, 73);
        assert_eq!(routed, 70);
    }

    struct Replay(std::io::Cursor<Vec<u8>>);

    impl std::io::Read for Replay {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.0.read(buf)
        }
    }

    impl http::TimedRead for Replay {
        fn set_read_timeout(&mut self, _: Option<Duration>) -> std::io::Result<()> {
            Ok(())
        }
    }
}
