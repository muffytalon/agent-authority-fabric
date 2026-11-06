//! `stub-broker-capture CAPTURE-FILE CONFIG`: the stub broker in G3's test-only mode. It runs as
//! `stub-broker` does, and also writes each `tools/call` it receives, Call Proof included, to
//! `CAPTURE-FILE`, one JSON line each, for `stub-injector` to replay (RV3 D2).
//!
//! Writing proofs down is what this binary is for, and what the logs must never do, so it is its
//! own binary: only the `broker-capture` test image holds it, never a release image (RV4 #20).

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;
use std::sync::Mutex;

use pep_sidecar::http::Request;
use pep_sidecar::jcs::{self, JcsValue};
use pep_sidecar::stubs::broker;

fn log(message: &str) {
    let stderr = io::stderr();
    drop(writeln!(stderr.lock(), "{message}"));
}

/// One capture line, if `request` is a `tools/call`.
fn capture_line(request: &Request) -> Option<String> {
    let server_id = request.head.target.strip_prefix("/mcp/")?;
    let message = jcs::parse(&request.body).ok()?;
    if message.get("method").and_then(JcsValue::as_str) != Some("tools/call") {
        return None;
    }
    let body = std::str::from_utf8(&request.body).ok()?;
    Some(format!(
        r#"{{"body":{},"server_id":{}}}"#,
        JcsValue::string(body).to_canonical_string(),
        JcsValue::string(server_id).to_canonical_string(),
    ))
}

fn run(capture: &Path, config: &Path) -> Result<(), String> {
    let file: File = OpenOptions::new()
        .create(true)
        .append(true)
        .open(capture)
        .map_err(|error| format!("{}: {error}", capture.display()))?;
    let file = Mutex::new(file);
    let observe = move |request: &Request| {
        if let (Some(line), Ok(mut file)) = (capture_line(request), file.lock()) {
            drop(writeln!(file, "{line}"));
        }
    };
    broker::serve(config, observe, || log("stub-broker-capture: serving"))
}

fn main() -> ExitCode {
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let [capture, config] = args.as_slice() else {
        log("usage: stub-broker-capture CAPTURE-FILE CONFIG");
        return ExitCode::from(2);
    };
    match run(Path::new(capture), Path::new(config)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            log(&format!("stub-broker-capture: {error}"));
            ExitCode::FAILURE
        }
    }
}
