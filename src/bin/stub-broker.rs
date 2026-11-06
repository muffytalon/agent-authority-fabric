//! `stub-broker CONFIG`: the stub broker ([`pep_sidecar::stubs::broker`]).

use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use pep_sidecar::peercred::{bind_safe_listener, require_peer};
use pep_sidecar::serve::accept_loop;
use pep_sidecar::stubs::broker::{self, Broker};
use pep_sidecar::stubs::{answer, now_ms};
use pep_sidecar::tokens::unix_now;

/// The deadline for one request.
const READ_TIMEOUT: Duration = Duration::from_secs(10);

fn log(message: &str) {
    let stderr = io::stderr();
    drop(writeln!(stderr.lock(), "{message}"));
}

fn main() -> ExitCode {
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let (check, path) = match args.as_slice() {
        [path] => (false, path),
        [flag, path] if flag == "--check" => (true, path),
        _ => {
            log("usage: stub-broker [--check] CONFIG");
            return ExitCode::from(2);
        }
    };
    if check {
        // A container healthcheck: is the server accepting connections?
        return if check_ready(Path::new(path)) {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        };
    }
    match run(Path::new(path)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            log(&format!("stub-broker: {error}"));
            ExitCode::FAILURE
        }
    }
}

fn run(path: &Path) -> Result<(), String> {
    let bytes = std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let config = broker::load(&bytes, &|path| std::fs::read(path).ok())
        .map_err(|error| error.to_string())?;
    let boot_second = unix_now().map_err(|error| error.to_string())?;
    let socket = config.socket.clone();
    let connections = config.connections;
    let pep = config.pep;
    let broker = Arc::new(Broker::open(config, boot_second)?);
    let bound = bind_safe_listener(&socket).map_err(|error| error.to_string())?;
    log("stub-broker: serving");
    accept_loop(bound.listener(), connections, move |mut stream| {
        // The PEP, and only the PEP (RV3 F7).
        if require_peer(&stream, pep.0, pep.1).is_err() {
            return;
        }
        let routes = |target: &str| broker.routes(target);
        answer(&mut stream, &routes, READ_TIMEOUT, |request| {
            let now = unix_now().unwrap_or(0);
            broker.handle(request, now, now_ms())
        });
    });
    Err("stopped accepting".to_owned())
}

/// Whether the broker socket named in the config at `path` accepts a connection.
fn check_ready(path: &Path) -> bool {
    std::fs::read(path)
        .ok()
        .and_then(|bytes| broker::load(&bytes, &|path| std::fs::read(path).ok()).ok())
        .is_some_and(|config| std::os::unix::net::UnixStream::connect(&config.socket).is_ok())
}
