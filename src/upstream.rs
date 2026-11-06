//! The PEP's client to the broker (§2a, PEP↔broker).
//!
//! One request per connection over the broker's Unix socket, JSON in both directions. The
//! connection's peer must have the broker's uid and gid (RV3 F7), because the payment outcome
//! in a reply is trusted only from the broker (M1, P1). A reply counts only if it is 200 with
//! `Content-Type: application/json` and arrives whole by the deadline; anything else is no
//! reply, which the actor treats as an unknown outcome.

use std::io;
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use crate::actor::{Upstream, UpstreamFailure};
use crate::forward::UpstreamRequest;
use crate::http::{self, HttpError};
use crate::mcp::is_json_content_type;
use crate::peercred::{PeerError, require_peer};

/// Why an exchange with the broker produced no usable reply.
#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    /// The socket could not be reached.
    #[error("connect: {0}")]
    Connect(io::Error),
    /// The connection was not made by the deadline.
    #[error("connect deadline passed")]
    ConnectTimeout,
    /// The peer is not the broker.
    #[error("peer: {0}")]
    Peer(#[from] PeerError),
    /// The request could not be written.
    #[error("write: {0}")]
    Write(io::Error),
    /// The request was not fully written by the deadline.
    #[error("write deadline passed")]
    WriteTimeout,
    /// The deadline passed after the whole request was written.
    #[error("deadline passed")]
    Timeout,
    /// The reply was not a response in the HTTP subset.
    #[error("response: {0}")]
    Response(HttpError),
    /// The status was not 200.
    #[error("status {0}")]
    Status(u16),
    /// The content type was not JSON.
    #[error("not JSON")]
    ContentType,
}

impl UpstreamError {
    /// Whether the server cannot have acted on the request: no connection, the wrong peer, or
    /// a request cut short, which the subset's exact `Content-Length` makes it refuse.
    #[must_use]
    pub const fn not_delivered(&self) -> bool {
        matches!(
            self,
            Self::Connect(_)
                | Self::ConnectTimeout
                | Self::Peer(_)
                | Self::Write(_)
                | Self::WriteTimeout
        )
    }
}

/// When an upstream leg's first byte left and its last byte came back: what O1's residence
/// subtracts from a hop's time, so a hop is not charged for the time spent upstream.
#[derive(Debug, Default)]
pub struct LegTimer {
    marks: Mutex<(Option<Instant>, Option<Instant>)>,
}

impl LegTimer {
    /// The first byte is going upstream.
    pub fn wrote(&self) {
        if let Ok(mut marks) = self.marks.lock() {
            marks.0.get_or_insert_with(Instant::now);
        }
    }

    /// The last byte came back.
    pub fn read(&self) {
        if let Ok(mut marks) = self.marks.lock() {
            marks.1 = Some(Instant::now());
        }
    }

    /// How long the leg took, once it has ended.
    #[must_use]
    pub fn duration(&self) -> Option<Duration> {
        let marks = self.marks.lock().ok()?;
        let (wrote, read) = (marks.0?, marks.1?);
        read.checked_duration_since(wrote)
    }
}

/// A hop's residence (O1): `since` to now, less the upstream leg. Saturating, as only a
/// measurement; `None` if the call went upstream and that leg has not ended.
#[must_use]
pub fn residence_us(since: Instant, leg: Option<Duration>) -> u64 {
    let total = since.elapsed().saturating_sub(leg.unwrap_or_default());
    u64::try_from(total.as_micros()).unwrap_or(u64::MAX)
}

/// The broker client: its socket, the uid and gid its peer must have, and the largest reply
/// body it reads.
#[derive(Debug, Clone)]
pub struct BrokerClient {
    socket: PathBuf,
    uid: u32,
    gid: u32,
    max_body: usize,
}

impl BrokerClient {
    /// A client for the broker at `socket`, whose peer must be `uid` and `gid`.
    #[must_use]
    pub const fn new(socket: PathBuf, uid: u32, gid: u32, max_body: usize) -> Self {
        Self {
            socket,
            uid,
            gid,
            max_body,
        }
    }

    /// Sends `request` to `/mcp/{server_id}` and returns the body of a 200 JSON reply that
    /// arrives within `timeout`.
    ///
    /// # Errors
    ///
    /// Returns an [`UpstreamError`] for every other end of the exchange.
    pub fn exchange(
        &self,
        request: &UpstreamRequest,
        timeout: Duration,
    ) -> Result<Vec<u8>, UpstreamError> {
        self.exchange_timed(request, timeout, None)
    }

    /// [`BrokerClient::exchange`], with `timer` marking the leg's ends.
    ///
    /// # Errors
    ///
    /// As [`BrokerClient::exchange`].
    pub fn exchange_timed(
        &self,
        request: &UpstreamRequest,
        timeout: Duration,
        timer: Option<&LegTimer>,
    ) -> Result<Vec<u8>, UpstreamError> {
        let headers: Vec<(&str, String)> = request
            .headers
            .iter()
            .map(|(name, value)| (*name, value.clone()))
            .collect();
        post(&Post {
            endpoint: &Endpoint::Unix(self.socket.clone()),
            path: &format!("/mcp/{}", request.server_id),
            host: "broker",
            headers: &headers,
            body: &request.body,
            timeout,
            max_body: self.max_body,
            peer: Some((self.uid, self.gid)),
            timer,
        })
    }
}

/// Where an HTTP server listens: a Unix socket, or a TCP address (the broker reaches each
/// tool server on its own network, N1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    /// `unix:/path`.
    Unix(PathBuf),
    /// `tcp:host:port`.
    Tcp(String),
}

impl Endpoint {
    /// Parses `unix:/absolute/path` or `tcp:host:port`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        if let Some(path) = text.strip_prefix("unix:") {
            return path
                .starts_with('/')
                .then(|| Self::Unix(PathBuf::from(path)));
        }
        let address = text.strip_prefix("tcp:")?;
        let (host, port) = address.rsplit_once(':')?;
        (!host.is_empty() && port.parse::<u16>().is_ok()).then(|| Self::Tcp(address.to_owned()))
    }
}

/// A connected stream of either kind.
enum Connection {
    Unix(UnixStream),
    Tcp(TcpStream),
}

/// One POST of a JSON body.
#[derive(Debug, Clone, Copy)]
pub struct Post<'a> {
    /// Where the server listens.
    pub endpoint: &'a Endpoint,
    /// The request target.
    pub path: &'a str,
    /// The `Host` header.
    pub host: &'a str,
    /// The other headers; `Content-Length` and `Connection: close` are added.
    pub headers: &'a [(&'a str, String)],
    /// The body.
    pub body: &'a [u8],
    /// The deadline for the whole exchange, from now.
    pub timeout: Duration,
    /// The largest reply body read.
    pub max_body: usize,
    /// Over a Unix socket, the uid and gid the server must have (RV3 F7). Over TCP no peer
    /// check is possible, and the caller authenticates otherwise (the broker's per-server
    /// credential).
    pub peer: Option<(u32, u32)>,
    /// Marks the leg's first byte written and last byte read (O1).
    pub timer: Option<&'a LegTimer>,
}

/// Sends `request` and returns the body of a 200 JSON reply that arrives whole within its
/// timeout.
///
/// # Errors
///
/// Returns an [`UpstreamError`] for every other end of the exchange.
pub fn post(request: &Post<'_>) -> Result<Vec<u8>, UpstreamError> {
    let Post {
        endpoint,
        path,
        host,
        headers,
        body,
        timeout,
        max_body,
        peer,
        timer,
    } = *request;
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(UpstreamError::ConnectTimeout)?;
    let mut connection = match endpoint {
        Endpoint::Unix(socket) => {
            let socket = socket.clone();
            let stream = connect_by(deadline, move || UnixStream::connect(socket))?;
            if let Some((uid, gid)) = peer {
                require_peer(&stream, uid, gid)?;
            }
            Connection::Unix(stream)
        }
        Endpoint::Tcp(address) => {
            let address = address.clone();
            Connection::Tcp(connect_by(deadline, move || TcpStream::connect(address))?)
        }
    };
    let bytes = request_bytes(path, host, headers, body);
    if let Some(timer) = timer {
        timer.wrote();
    }
    let written = match &mut connection {
        Connection::Unix(stream) => http::write_by(stream, &bytes, deadline),
        Connection::Tcp(stream) => http::write_by(stream, &bytes, deadline),
    };
    written.map_err(|error| match error.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => UpstreamError::WriteTimeout,
        _ => UpstreamError::Write(error),
    })?;
    let response = match &mut connection {
        Connection::Unix(stream) => http::read_response(stream, deadline, max_body),
        Connection::Tcp(stream) => http::read_response(stream, deadline, max_body),
    }
    .map_err(|error| match error {
        HttpError::Timeout => UpstreamError::Timeout,
        other => UpstreamError::Response(other),
    })?;
    if let Some(timer) = timer {
        timer.read();
    }
    if response.status != 200 {
        return Err(UpstreamError::Status(response.status));
    }
    if !response
        .headers
        .get("content-type")
        .is_some_and(is_json_content_type)
    {
        return Err(UpstreamError::ContentType);
    }
    Ok(response.body)
}

/// Connects in a helper thread, so `deadline` holds: `connect` has no timeout of its own, and
/// on a Unix socket whose backlog is full it blocks for as long as the server does not accept
/// (RV5 V13). A connection that comes after the deadline is closed unused. Past
/// [`MAX_PENDING_CONNECTS`] blocked helpers, a new call fails at once, so a hung server cannot
/// pile up threads.
fn connect_by<T, F>(deadline: Instant, connect: F) -> Result<T, UpstreamError>
where
    T: Send + 'static,
    F: FnOnce() -> io::Result<T> + Send + 'static,
{
    let left = deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
        .ok_or(UpstreamError::ConnectTimeout)?;
    let taken = PENDING_CONNECTS.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
        (count < MAX_PENDING_CONNECTS).then(|| count.saturating_add(1))
    });
    if taken.is_err() {
        return Err(UpstreamError::ConnectTimeout);
    }
    let (done, result) = mpsc::sync_channel(1);
    let spawned = thread::Builder::new()
        .name("upstream-connect".to_owned())
        .spawn(move || {
            let connected = connect();
            PENDING_CONNECTS.fetch_sub(1, Ordering::SeqCst);
            // Past the deadline no one is waiting, and the stream closes here.
            drop(done.send(connected));
        });
    if let Err(error) = spawned {
        PENDING_CONNECTS.fetch_sub(1, Ordering::SeqCst);
        return Err(UpstreamError::Connect(error));
    }
    match result.recv_timeout(left) {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(error)) => Err(UpstreamError::Connect(error)),
        Err(_) => Err(UpstreamError::ConnectTimeout),
    }
}

/// Connect helpers blocked at once.
static PENDING_CONNECTS: AtomicUsize = AtomicUsize::new(0);
/// The most connects that may block at once. Each holds a file descriptor, so the PEP's budget
/// counts them.
pub const MAX_PENDING_CONNECTS: usize = 64;

impl Upstream for BrokerClient {
    fn call(
        &self,
        request: &UpstreamRequest,
        timeout: Duration,
    ) -> Result<Vec<u8>, UpstreamFailure> {
        self.call_marked(request, timeout, None)
    }

    fn call_timed(
        &self,
        request: &UpstreamRequest,
        timeout: Duration,
        timer: &LegTimer,
    ) -> Result<Vec<u8>, UpstreamFailure> {
        self.call_marked(request, timeout, Some(timer))
    }
}

impl BrokerClient {
    fn call_marked(
        &self,
        request: &UpstreamRequest,
        timeout: Duration,
        timer: Option<&LegTimer>,
    ) -> Result<Vec<u8>, UpstreamFailure> {
        self.exchange_timed(request, timeout, timer)
            .map_err(|error| {
                // The broker forwards a call only on its way to a 200, so any other status from it
                // means nothing was forwarded (SPEC §3.4).
                if error.not_delivered() || matches!(error, UpstreamError::Status(_)) {
                    UpstreamFailure::NotSent
                } else {
                    UpstreamFailure::Lost
                }
            })
    }
}

/// The request on the wire.
fn request_bytes(path: &str, host: &str, headers: &[(&str, String)], body: &[u8]) -> Vec<u8> {
    let mut out = format!("POST {path} HTTP/1.1\r\nHost: {host}\r\n").into_bytes();
    for (name, value) in headers {
        out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    out.extend_from_slice(
        format!(
            "Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .as_bytes(),
    );
    out.extend_from_slice(body);
    out
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use crate::forward::tools_call_request;
    use crate::http::{Deadlines, read_request};
    use crate::jcs::JcsValue;
    use std::io::{Read as _, Write as _};
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    const ID: &str = "01JBAE0Z1TFCQ9Y41W9NF6YYMB";

    /// A one-shot broker on a fresh socket: it reads one request, checks it, and writes
    /// `reply` (or nothing).
    fn broker(reply: Option<&'static [u8]>) -> (PathBuf, thread::JoinHandle<Vec<u8>>) {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let path =
            std::env::temp_dir().join(format!("pep-upstream-{}-{n}.sock", std::process::id()));
        drop(std::fs::remove_file(&path));
        let listener = UnixListener::bind(&path).unwrap();
        let thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let at = Instant::now() + Duration::from_secs(5);
            let request =
                read_request(&mut stream, "/mcp/a", Deadlines { head: at, body: at }).unwrap();
            if let Some(reply) = reply {
                stream.write_all(reply).unwrap();
            } else {
                thread::sleep(Duration::from_millis(500));
            }
            request.body
        });
        (path, thread)
    }

    fn me() -> (u32, u32) {
        (
            nix::unistd::geteuid().as_raw(),
            nix::unistd::getegid().as_raw(),
        )
    }

    fn request() -> UpstreamRequest {
        let arguments = crate::jcs::parse(br#"{"invoice_id":"INV-1"}"#).unwrap();
        tools_call_request(ID, "a", "get_invoice", &arguments, "eyJ.proof").unwrap()
    }

    fn exchange(path: &std::path::Path, timeout: Duration) -> Result<Vec<u8>, UpstreamError> {
        let (uid, gid) = me();
        BrokerClient::new(path.to_path_buf(), uid, gid, 1024).exchange(&request(), timeout)
    }

    #[test]
    fn a_json_reply_is_returned() {
        let (path, broker) = broker(Some(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
        ));
        assert_eq!(exchange(&path, Duration::from_secs(5)).unwrap(), b"{}");
        // The broker got the PEP's request, routed to the tool's server.
        let body = broker.join().unwrap();
        assert_eq!(body, request().body);
        assert_eq!(
            crate::jcs::parse(&body).unwrap().pointer("/params/name"),
            Some(&JcsValue::string("get_invoice"))
        );
    }

    #[test]
    fn a_failure_says_whether_anything_was_sent() {
        let (uid, gid) = me();
        let call = |path: PathBuf| {
            BrokerClient::new(path, uid, gid, 1024).call(&request(), Duration::from_secs(5))
        };
        // Nobody there: no byte left the PEP.
        let missing = std::env::temp_dir().join(format!("pep-none-{}.sock", std::process::id()));
        assert_eq!(call(missing), Err(UpstreamFailure::NotSent));
        // A status: the broker's own contract says it forwarded nothing.
        for reply in [
            &b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"[..],
            b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n",
        ] {
            let (path, server) = broker(Some(reply));
            assert_eq!(call(path), Err(UpstreamFailure::NotSent));
            server.join().unwrap();
        }
        // Read and then closed with no reply: it may have gone upstream.
        let (path, server) = broker(None);
        assert_eq!(call(path), Err(UpstreamFailure::Lost));
        server.join().unwrap();
        // A reply that stops short: the same.
        let (path, server) = broker(Some(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 4\r\n\r\n{}",
        ));
        assert_eq!(call(path), Err(UpstreamFailure::Lost));
        server.join().unwrap();
    }

    #[test]
    fn a_server_that_reads_slowly_cannot_stretch_the_deadline() {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let path =
            std::env::temp_dir().join(format!("pep-upstream-{}-{n}.sock", std::process::id()));
        drop(std::fs::remove_file(&path));
        let listener = UnixListener::bind(&path).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = vec![0u8; 64 * 1024];
            while matches!(stream.read(&mut buffer), Ok(read) if read > 0) {
                thread::sleep(Duration::from_millis(5));
            }
        });
        let body = vec![b'x'; 8 << 20];
        let started = Instant::now();
        let error = post(&Post {
            timer: None,
            endpoint: &Endpoint::Unix(path),
            path: "/mcp",
            host: "tool",
            headers: &[],
            body: &body,
            timeout: Duration::from_millis(50),
            max_body: 1024,
            peer: None,
        })
        .unwrap_err();
        assert!(matches!(error, UpstreamError::WriteTimeout), "{error}");
        assert!(error.not_delivered());
        assert!(started.elapsed() < Duration::from_secs(2));
        server.join().unwrap();
    }

    #[test]
    fn a_residence_leaves_the_upstream_leg_out() {
        let timer = LegTimer::default();
        assert_eq!(timer.duration(), None, "not started");
        timer.wrote();
        assert_eq!(timer.duration(), None, "not ended");
        thread::sleep(Duration::from_millis(30));
        timer.read();
        let leg = timer.duration().unwrap();
        assert!(leg >= Duration::from_millis(30));
        let since = Instant::now()
            .checked_sub(leg + Duration::from_millis(5))
            .unwrap();
        assert!(residence_us(since, Some(leg)) >= 5_000);
        assert!(
            residence_us(since, Some(leg)) < 30_000,
            "the leg is left out"
        );
        // A later first write does not move the start.
        timer.wrote();
        assert_eq!(timer.duration(), Some(leg));
    }

    #[test]
    fn connect_keeps_the_deadline() {
        let started = Instant::now();
        let result: Result<(), UpstreamError> =
            connect_by(started + Duration::from_millis(30), || {
                thread::sleep(Duration::from_secs(1));
                Ok(())
            });
        assert!(matches!(result, Err(UpstreamError::ConnectTimeout)));
        assert!(started.elapsed() < Duration::from_millis(900));
        let immediate: Result<u8, UpstreamError> =
            connect_by(Instant::now() + Duration::from_secs(1), || Ok(7));
        assert_eq!(immediate.unwrap(), 7);
        let refused: Result<u8, UpstreamError> =
            connect_by(Instant::now() + Duration::from_secs(1), || {
                Err(io::ErrorKind::ConnectionRefused.into())
            });
        assert!(refused.unwrap_err().not_delivered());
    }

    #[test]
    fn anything_else_is_no_reply() {
        for (reply, expected) in [
            (&b"HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}"[..], "status 500"),
            (b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 2\r\n\r\n{}", "not JSON"),
            (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n", "response: malformed request: transfer-encoding not supported"),
            (b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}", "response: malformed request: unsupported HTTP version"),
            (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2048\r\n\r\n{}", "response: malformed request: body too large"),
            (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 4\r\n\r\n{}", "response: connection closed early"),
        ] {
            let (path, broker) = broker(Some(reply));
            let error = exchange(&path, Duration::from_secs(5)).unwrap_err();
            assert_eq!(error.to_string(), expected);
            broker.join().unwrap();
        }
    }

    #[test]
    fn a_silent_broker_times_out() {
        let (path, broker) = broker(None);
        let start = Instant::now();
        assert!(matches!(
            exchange(&path, Duration::from_millis(100)),
            Err(UpstreamError::Timeout)
        ));
        assert!(start.elapsed() < Duration::from_millis(450));
        broker.join().unwrap();
    }

    #[test]
    fn the_peer_must_be_the_broker() {
        let (path, _broker) = broker(None);
        let (uid, gid) = me();
        let error = BrokerClient::new(path, uid.wrapping_add(1), gid, 1024)
            .exchange(&request(), Duration::from_secs(1))
            .unwrap_err();
        assert!(matches!(error, UpstreamError::Peer(_)), "{error}");
        // No broker at all.
        let missing = std::env::temp_dir().join("pep-upstream-missing.sock");
        assert!(matches!(
            BrokerClient::new(missing, uid, gid, 1024).exchange(&request(), Duration::from_secs(1)),
            Err(UpstreamError::Connect(_))
        ));
    }
}
