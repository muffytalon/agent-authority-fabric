//! `stub-injector SOCKET UID GID CAPTURE-FILE`: G3's replay harness (RV3 D2). It sends every
//! request `stub-broker-capture` wrote down back to the broker, as the PEP's uid and over the
//! PEP's socket, which is the most an attacker holding a captured proof could do.
//!
//! One line per attempt, then `{"accepted":N,"attempts":M}`. A proof the broker honours is the
//! failure: it exits 0 only if none was accepted and at least one was tried. Test images only.
//! The oracle judges the run as well, because an accepted replay reaches a tool with no `allow`.

use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use pep_sidecar::forward::UpstreamRequest;
use pep_sidecar::http::MAX_BODY_BYTES;
use pep_sidecar::jcs::{self, JcsValue, ParseOptions};
use pep_sidecar::upstream::BrokerClient;

/// The deadline for one replay.
const TIMEOUT: Duration = Duration::from_secs(10);

fn log(message: &str) {
    let stderr = io::stderr();
    drop(writeln!(stderr.lock(), "stub-injector: {message}"));
}

fn print(line: &str) {
    let stdout = io::stdout();
    drop(writeln!(stdout.lock(), "{line}"));
}

/// The request one capture line holds.
fn request(line: &str) -> Option<UpstreamRequest> {
    let captured = jcs::parse_with(line.as_bytes(), &ParseOptions::definition())
        .ok()?
        .value;
    Some(UpstreamRequest {
        server_id: captured.get("server_id")?.as_str()?.to_owned(),
        body: captured.get("body")?.as_str()?.as_bytes().to_vec(),
        headers: vec![
            ("Content-Type", "application/json".to_owned()),
            ("Accept", "application/json".to_owned()),
        ],
    })
}

/// Whether the broker honoured the request: a JSON-RPC result, not an error or a status.
fn accepted(client: &BrokerClient, request: &UpstreamRequest) -> bool {
    client.exchange(request, TIMEOUT).is_ok_and(|body| {
        jcs::parse_with(&body, &ParseOptions::definition())
            .is_ok_and(|reply| reply.value.get("result").is_some())
    })
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [socket, uid, gid, capture] = args.as_slice() else {
        log("usage: stub-injector SOCKET UID GID CAPTURE-FILE");
        return ExitCode::from(2);
    };
    let (Ok(uid), Ok(gid)) = (uid.parse(), gid.parse()) else {
        log("UID and GID are numbers");
        return ExitCode::from(2);
    };
    let text = match fs::read_to_string(capture) {
        Ok(text) => text,
        Err(error) => {
            log(&format!("{capture}: {error}"));
            return ExitCode::from(2);
        }
    };
    let client = BrokerClient::new(PathBuf::from(socket), uid, gid, MAX_BODY_BYTES);
    let mut attempts = 0usize;
    let mut honoured = 0usize;
    for line in text.lines() {
        let Some(request) = request(line) else {
            log("a capture line cannot be read");
            return ExitCode::from(2);
        };
        // Bounded by the capture file, and only counted for the report.
        attempts = attempts.saturating_add(1);
        let was_accepted = accepted(&client, &request);
        if was_accepted {
            honoured = honoured.saturating_add(1);
        }
        print(&format!(
            r#"{{"accepted":{was_accepted},"server_id":{}}}"#,
            JcsValue::string(request.server_id.as_str()).to_canonical_string()
        ));
    }
    print(&format!(
        r#"{{"accepted":{honoured},"attempts":{attempts}}}"#
    ));
    if attempts > 0 && honoured == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
