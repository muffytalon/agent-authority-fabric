//! `stub-agent SOCKET METHOD [NAME] [PARAMS-JSON]`: a minimal agent for Compose tests. It reads
//! its Episode Token from the first line of stdin (E1), sends one MCP request with the headers
//! a pinned SDK sends, the token as a client-wide `Pep-Episode` header and in `_meta`, and
//! writes the reply's body to stdout. Exits 0 for a result, 1 for an error reply, 2 for a usage
//! or transport failure. The Gate 1 agents are the SDK clients (step 9).

use std::io::{self, BufRead, Write};
use std::os::unix::net::UnixStream;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use pep_sidecar::http;
use pep_sidecar::jcs::{self, JcsValue, ParseOptions};

/// The deadline for the PEP's answer: a step-up can wait up to 55 seconds (P1).
const TIMEOUT: Duration = Duration::from_mins(1);

fn log(message: &str) {
    let stderr = io::stderr();
    drop(writeln!(stderr.lock(), "stub-agent: {message}"));
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (socket, method, name, params) = match args.as_slice() {
        [socket, method] => (socket, method, None, "{}"),
        [socket, method, params] => (socket, method, None, params.as_str()),
        [socket, method, name, params] => (socket, method, Some(name.as_str()), params.as_str()),
        _ => {
            log("usage: stub-agent SOCKET METHOD [NAME] [PARAMS-JSON]");
            return ExitCode::from(2);
        }
    };
    let mut token = String::new();
    drop(io::stdin().lock().read_line(&mut token));
    let token = token.trim();
    match exchange(socket, method, name, params, token) {
        Ok(body) => {
            let stdout = io::stdout();
            let mut out = stdout.lock();
            drop(out.write_all(&body).and_then(|()| out.write_all(b"\n")));
            let is_result = jcs::parse_with(&body, &ParseOptions::definition())
                .ok()
                .is_some_and(|parsed| parsed.value.get("result").is_some());
            if is_result {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(error) => {
            log(&error);
            ExitCode::from(2)
        }
    }
}

fn exchange(
    socket: &str,
    method: &str,
    name: Option<&str>,
    params: &str,
    token: &str,
) -> Result<Vec<u8>, String> {
    let params = jcs::parse(params.as_bytes()).map_err(|error| format!("params: {error}"))?;
    let params = params.as_object().ok_or("params must be an object")?;
    // The agent's `_meta`: the version, capabilities and the token.
    let meta = format!(
        r#"{{"io.modelcontextprotocol/clientCapabilities":{{}},"io.modelcontextprotocol/protocolVersion":"2026-07-28"{}}}"#,
        if token.is_empty() {
            String::new()
        } else {
            format!(
                r#","dev.pep-sidecar/episode":{}"#,
                JcsValue::string(token).to_canonical_string()
            )
        }
    );
    let mut members: Vec<String> = params
        .entries()
        .iter()
        .map(|(key, value)| {
            format!(
                "{}:{}",
                JcsValue::string(key.as_str()).to_canonical_string(),
                value.to_canonical_string()
            )
        })
        .collect();
    members.push(format!(r#""_meta":{meta}"#));
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":"stub-agent-1","method":{},"params":{{{}}}}}"#,
        JcsValue::string(method).to_canonical_string(),
        members.join(",")
    );
    let mut request = format!(
        "POST /mcp HTTP/1.1\r\nHost: pep.local\r\nAccept: application/json, text/event-stream\r\nContent-Type: application/json\r\nMCP-Protocol-Version: 2026-07-28\r\nMcp-Method: {method}\r\n"
    );
    if let Some(name) = name {
        request.push_str("Mcp-Name: ");
        request.push_str(name);
        request.push_str("\r\n");
    }
    if !token.is_empty() {
        request.push_str("Pep-Episode: ");
        request.push_str(token);
        request.push_str("\r\n");
    }
    request.push_str("Content-Length: ");
    request.push_str(&body.len().to_string());
    request.push_str("\r\nConnection: close\r\n\r\n");
    request.push_str(&body);
    let mut stream = UnixStream::connect(socket).map_err(|error| error.to_string())?;
    stream
        .write_all(request.as_bytes())
        .map_err(|error| error.to_string())?;
    let deadline = Instant::now()
        .checked_add(TIMEOUT)
        .ok_or("clock overflow")?;
    let response = http::read_response(&mut stream, deadline, jcs::MAX_DEFINITION_BYTES)
        .map_err(|error| error.to_string())?;
    Ok(response.body)
}
