//! Test stand-ins for the components around the PEP (`WEEK2_PLAN` step 7): the broker, the
//! tool servers and the scripted operator, and the Gate 1 oracle. They run under the same lints,
//! but are never part of the PEP's own image; their binaries are `stub-broker`, `stub-tool`,
//! `stub-operator` and `stub-oracle`.

pub mod broker;
pub mod oracle;
pub mod tool;

use std::io::Write;
use std::net::Shutdown;
use std::time::{Duration, Instant};

use crate::http::{self, Deadlines, Request, TimedRead};

/// Unix milliseconds, for logs.
#[must_use]
pub fn now_ms() -> u64 {
    crate::decision_log::unix_ms()
}

/// A connected stream a stub serves.
pub trait Connection: TimedRead + Write {
    /// Closes both directions.
    fn close(&mut self);
}

impl Connection for std::os::unix::net::UnixStream {
    fn close(&mut self) {
        drop(self.shutdown(Shutdown::Both));
    }
}

impl Connection for std::net::TcpStream {
    fn close(&mut self) {
        drop(self.shutdown(Shutdown::Both));
    }
}

/// Reads one request whose target `accept` admits, answers it with `handle`, and closes: the
/// same HTTP subset as the PEP's.
pub fn answer<S: Connection>(
    stream: &mut S,
    accept: &dyn Fn(&str) -> bool,
    timeout: Duration,
    handle: impl FnOnce(&Request) -> Vec<u8>,
) {
    let at = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);
    let reply = match http::read_request_matching(stream, accept, Deadlines { head: at, body: at })
    {
        Ok(request) => handle(&request),
        Err(error) => {
            let Some(status) = error.reply() else {
                stream.close();
                return;
            };
            http::response(status, None)
        }
    };
    drop(stream.set_read_timeout(Some(Duration::from_millis(50))));
    drop(stream.write_all(&reply));
    // Drain what the client still sent, so a close cannot reset it before it reads.
    let mut sink = [0u8; 1024];
    drop(stream.read(&mut sink));
    stream.close();
}
