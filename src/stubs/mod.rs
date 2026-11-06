//! Test stand-ins for the components around the PEP (`WEEK2_PLAN` step 7): the broker, the
//! tool servers and the scripted operator, and the Gate 1 oracle. They run under the same lints,
//! but are never part of the PEP's own image; their binaries are `stub-broker`, `stub-tool`,
//! `stub-operator` and `stub-oracle`.

pub mod broker;
pub mod oracle;
pub mod tool;

use std::io::{Read as _, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::thread;
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

impl Connection for UnixStream {
    fn close(&mut self) {
        drop(self.shutdown(Shutdown::Both));
    }
}

impl Connection for std::net::TcpStream {
    fn close(&mut self) {
        drop(self.shutdown(Shutdown::Both));
    }
}

/// The longest a dripped reply runs: past any upstream deadline, so the reader gives up first.
const DRIP_LIMIT: Duration = Duration::from_mins(1);

/// Reads one request whose target `accept` admits, answers it with `handle`, and closes: the
/// same HTTP subset as the PEP's.
pub fn answer<S: Connection>(
    stream: &mut S,
    accept: &dyn Fn(&str) -> bool,
    timeout: Duration,
    handle: impl FnOnce(&Request) -> Vec<u8>,
) {
    answer_with(stream, accept, timeout, |request| (handle(request), None));
}

/// [`answer`], except that `handle` also says how to send its reply: all at once, or one byte per
/// the given interval, for as long as the reader lasts (a tool server's slow drip).
pub fn answer_with<S: Connection>(
    stream: &mut S,
    accept: &dyn Fn(&str) -> bool,
    timeout: Duration,
    handle: impl FnOnce(&Request) -> (Vec<u8>, Option<Duration>),
) {
    answer_finally(
        stream,
        accept,
        timeout,
        |request| {
            let (reply, drip) = handle(request);
            (reply, drip, ())
        },
        |()| {},
    );
}

/// [`answer_with`], calling `done` with what `handle` left for it once the reply has been
/// written: what a residence measured to the last byte needs (O1). A request that could not be
/// read has no `done`.
pub fn answer_finally<S: Connection, T>(
    stream: &mut S,
    accept: &dyn Fn(&str) -> bool,
    timeout: Duration,
    handle: impl FnOnce(&Request) -> (Vec<u8>, Option<Duration>, T),
    done: impl FnOnce(T),
) {
    let at = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);
    let deadlines = Deadlines { head: at, body: at };
    let (reply, drip, left) = match http::read_request_matching(stream, accept, deadlines) {
        Ok(request) => {
            let (reply, drip, left) = handle(&request);
            (reply, drip, Some(left))
        }
        Err(error) => {
            let Some(status) = error.reply() else {
                stream.close();
                return;
            };
            (http::response(status, None), None, None)
        }
    };
    drop(stream.set_read_timeout(Some(Duration::from_millis(50))));
    match drip {
        Some(interval) => drip_out(stream, &reply, interval),
        None => drop(stream.write_all(&reply)),
    }
    if let Some(left) = left {
        done(left);
    }
    // Drain what the client still sent, so a close cannot reset it before it reads.
    let mut sink = [0u8; 1024];
    drop(stream.read(&mut sink));
    stream.close();
}

/// The deadline for one [`raw_call`].
const RAW_CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// Sends raw `request` on a connection of its own to the PEP's agent socket, for the test clients
/// `stub-injector` and `stub-load`, and sorts what comes back: `accepted`, `denied`, `unavailable`,
/// `closed` with no reply, `refused` with no connection, or `other`. With `drop_after`, it hangs
/// up that long after sending instead of reading, and says `dropped`.
#[must_use]
pub fn raw_call(socket: &str, request: &str, drop_after: Option<Duration>) -> &'static str {
    let Ok(mut stream) = UnixStream::connect(socket) else {
        return "refused";
    };
    if stream.write_all(request.as_bytes()).is_err() {
        return "closed";
    }
    if let Some(wait) = drop_after {
        thread::sleep(wait);
        return "dropped";
    }
    drop(stream.set_read_timeout(Some(RAW_CALL_TIMEOUT)));
    let mut reply = Vec::new();
    drop(stream.read_to_end(&mut reply));
    let text = String::from_utf8_lossy(&reply);
    if text.is_empty() {
        "closed"
    } else if text.contains("PEP_DENIED") {
        "denied"
    } else if text.contains("PEP_UNAVAILABLE") {
        "unavailable"
    } else if text.contains(r#""result":"#) {
        "accepted"
    } else {
        "other"
    }
}

/// Writes `bytes` one at a time, until the reader goes away or [`DRIP_LIMIT`] passes.
fn drip_out<S: Connection>(stream: &mut S, bytes: &[u8], interval: Duration) {
    let until = Instant::now().checked_add(DRIP_LIMIT);
    for byte in bytes {
        if stream.write_all(&[*byte]).is_err() || until.is_none_or(|until| Instant::now() >= until)
        {
            return;
        }
        thread::sleep(interval);
    }
}
