//! `stub-operator SOCKET REQUEST`: the scripted operator. Sends one control request (a JSON
//! object, [`pep_sidecar::control`]) to the PEP's control socket and writes the reply's body
//! to stdout: for `start_episode`, the Episode Token the harness hands to a fresh agent on
//! its stdin (E1). Exits 0 for a result, 1 for an error reply, 2 for a usage or transport
//! failure.

use std::io::{self, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use pep_sidecar::http;
use pep_sidecar::jcs;

/// The deadline for the PEP's answer: an approval waits for the actor.
const TIMEOUT: Duration = Duration::from_secs(30);

fn log(message: &str) {
    let stderr = io::stderr();
    drop(writeln!(stderr.lock(), "stub-operator: {message}"));
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [socket, request] = args.as_slice() else {
        log("usage: stub-operator SOCKET REQUEST-JSON");
        return ExitCode::from(2);
    };
    match exchange(&PathBuf::from(socket), request.as_bytes()) {
        Ok((status, body)) => {
            let stdout = io::stdout();
            let mut out = stdout.lock();
            drop(out.write_all(&body).and_then(|()| out.write_all(b"\n")));
            let is_result = jcs::parse(&body)
                .ok()
                .is_some_and(|value| value.get("result").is_some());
            if status == 200 && is_result {
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

fn exchange(socket: &PathBuf, body: &[u8]) -> Result<(u16, Vec<u8>), String> {
    let mut stream = UnixStream::connect(socket).map_err(|error| error.to_string())?;
    let mut request = format!(
        "POST /control HTTP/1.1\r\nHost: pep\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    request.extend_from_slice(body);
    stream
        .write_all(&request)
        .map_err(|error| error.to_string())?;
    let deadline = Instant::now()
        .checked_add(TIMEOUT)
        .ok_or("clock overflow")?;
    let response = http::read_response(&mut stream, deadline, jcs::MAX_REQUEST_BYTES)
        .map_err(|error| error.to_string())?;
    Ok((response.status, response.body))
}
