//! `stub-injector`: G3's replay harness (RV3 D2), and the kit's way of sending what `stub-agent`
//! will not. Test images only.
//!
//! `stub-injector broker SOCKET UID GID FILE`: sends every request in `FILE`, as
//! `stub-broker-capture` wrote them or as the kit mutated them, to the broker, over the PEP's
//! socket and as the PEP's uid, the most an attacker holding a proof could do. One line per
//! attempt, then `{"accepted":N,"attempts":M}`. It exits 0 only if none was accepted and at
//! least one was tried. The oracle judges the run as well, because an accepted replay reaches a
//! tool with no `allow`.
//!
//! `stub-injector pep SOCKET FILE`: sends each line's raw request to the agent socket, one
//! connection each. A line is `{"request":TEXT}`, with an optional `delay_ms` to wait first and
//! an optional `drop_after_ms`, to hang up that long after sending instead of reading the reply.
//! One line per attempt, then a count of each kind of reply.
//!
//! `FILE` may be `-`, for stdin.

use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

use pep_sidecar::forward::UpstreamRequest;
use pep_sidecar::http::MAX_BODY_BYTES;
use pep_sidecar::jcs::{self, JcsValue, ParseOptions};
use pep_sidecar::stubs::raw_call;
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

fn parsed(line: &str) -> Option<JcsValue> {
    jcs::parse_with(line.as_bytes(), &ParseOptions::definition())
        .ok()
        .map(|parsed| parsed.value)
}

/// The request one capture line holds.
fn broker_request(line: &str) -> Option<UpstreamRequest> {
    let captured = parsed(line)?;
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

fn replay_to_broker(socket: &str, uid: u32, gid: u32, text: &str) -> ExitCode {
    let client = BrokerClient::new(PathBuf::from(socket), uid, gid, MAX_BODY_BYTES);
    let mut attempts = 0usize;
    let mut honoured = 0usize;
    for line in text.lines() {
        let Some(request) = broker_request(line) else {
            log("a capture line cannot be read");
            return ExitCode::from(2);
        };
        // Bounded by the file, and only counted for the report.
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

fn send_to_pep(socket: &str, text: &str) -> ExitCode {
    let kinds = [
        "accepted",
        "denied",
        "unavailable",
        "closed",
        "dropped",
        "other",
        "refused",
    ];
    let mut counts = [0usize; 7];
    for line in text.lines() {
        let Some(item) = parsed(line) else {
            log("a line cannot be read");
            return ExitCode::from(2);
        };
        let Some(request) = item.get("request").and_then(JcsValue::as_str) else {
            log("a line has no request");
            return ExitCode::from(2);
        };
        let millis = |key: &str| {
            item.get(key)
                .and_then(JcsValue::as_i64)
                .and_then(|ms| u64::try_from(ms).ok())
                .map(Duration::from_millis)
        };
        if let Some(wait) = millis("delay_ms") {
            thread::sleep(wait);
        }
        let kind = raw_call(socket, request, millis("drop_after_ms"));
        print(&format!(r#"{{"reply":"{kind}"}}"#));
        for (name, count) in kinds.iter().zip(counts.iter_mut()) {
            if *name == kind {
                // Bounded by the file, and only counted for the report.
                *count = count.saturating_add(1);
            }
        }
    }
    let summary: Vec<String> = kinds
        .iter()
        .zip(counts.iter())
        .map(|(name, count)| format!(r#""{name}":{count}"#))
        .collect();
    print(&format!("{{{}}}", summary.join(",")));
    ExitCode::SUCCESS
}

fn read_input(path: &str) -> Option<String> {
    if path == "-" {
        let mut text = String::new();
        io::stdin().read_to_string(&mut text).ok().map(|_| text)
    } else {
        fs::read_to_string(path).ok()
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let usage = || {
        log("usage: stub-injector broker SOCKET UID GID FILE | pep SOCKET FILE");
        ExitCode::from(2)
    };
    match refs.as_slice() {
        ["broker", socket, uid, gid, file] => {
            let (Ok(uid), Ok(gid), Some(text)) = (uid.parse(), gid.parse(), read_input(file))
            else {
                return usage();
            };
            replay_to_broker(socket, uid, gid, &text)
        }
        ["pep", socket, file] => match read_input(file) {
            Some(text) => send_to_pep(socket, &text),
            None => usage(),
        },
        _ => usage(),
    }
}
