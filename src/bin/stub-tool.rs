//! `stub-tool CONFIG`: one stub tool server ([`pep_sidecar::stubs::tool`]).

use std::io::{self, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use pep_sidecar::peercred::bind_safe_listener;
use pep_sidecar::serve::accept_loop;
use pep_sidecar::stubs::tool::{self, TOOL_ENDPOINT, ToolServer};
use pep_sidecar::stubs::{answer, now_ms};
use pep_sidecar::upstream::Endpoint;

/// The deadline for one request.
const READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Connections served at once.
const CONNECTIONS: usize = 64;

fn log(message: &str) {
    let stderr = io::stderr();
    drop(writeln!(stderr.lock(), "{message}"));
}

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let (Some(path), None) = (args.next(), args.next()) else {
        log("usage: stub-tool CONFIG");
        return ExitCode::from(2);
    };
    match run(Path::new(&path)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            log(&format!("stub-tool: {error}"));
            ExitCode::FAILURE
        }
    }
}

fn run(path: &Path) -> Result<(), String> {
    let bytes = std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let config = tool::load(&bytes, &tool::read_file).map_err(|error| error.to_string())?;
    let endpoint = Endpoint::parse(&config.listen).ok_or("listen: unix:/path or tcp:host:port")?;
    let server_id = config.server_id.clone();
    let server = Arc::new(ToolServer::open(config)?);
    let accept = |target: &str| target == TOOL_ENDPOINT;
    match endpoint {
        Endpoint::Unix(socket) => {
            let bound = bind_safe_listener(&socket).map_err(|error| error.to_string())?;
            log(&format!("stub-tool {server_id}: serving"));
            accept_loop(bound.listener(), CONNECTIONS, move |mut stream| {
                answer(&mut stream, &accept, READ_TIMEOUT, |request| {
                    server.handle(request, now_ms())
                });
            });
        }
        Endpoint::Tcp(address) => {
            let listener = TcpListener::bind(&address).map_err(|error| error.to_string())?;
            log(&format!("stub-tool {server_id}: serving"));
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let server = Arc::clone(&server);
                drop(thread::Builder::new().spawn(move || {
                    answer(&mut stream, &accept, READ_TIMEOUT, |request| {
                        server.handle(request, now_ms())
                    });
                }));
            }
        }
    }
    Err("stopped accepting".to_owned())
}
