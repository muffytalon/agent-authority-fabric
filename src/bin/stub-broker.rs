//! `stub-broker CONFIG`: the stub broker ([`pep_sidecar::stubs::broker`]).

use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

use pep_sidecar::stubs::broker;

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
    let ready = || log("stub-broker: serving");
    match broker::serve(Path::new(path), |_| {}, ready) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            log(&format!("stub-broker: {error}"));
            ExitCode::FAILURE
        }
    }
}

/// Whether the broker socket named in the config at `path` accepts a connection.
fn check_ready(path: &Path) -> bool {
    std::fs::read(path)
        .ok()
        .and_then(|bytes| broker::load(&bytes, &|path| std::fs::read(path).ok()).ok())
        .is_some_and(|config| std::os::unix::net::UnixStream::connect(&config.socket).is_ok())
}
