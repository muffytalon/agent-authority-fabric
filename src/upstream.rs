//! The PEP's client to the broker (§2a, PEP↔broker).
//!
//! One request per connection over the broker's Unix socket, JSON in both directions. The
//! connection's peer must have the broker's uid and gid (RV3 F7), because the payment outcome
//! in a reply is trusted only from the broker (M1, P1). A reply counts only if it is 200 with
//! `Content-Type: application/json` and arrives whole by the deadline; anything else is no
//! reply, which the actor treats as an unknown outcome.

use std::io::{self, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::actor::Upstream;
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
    /// The peer is not the broker.
    #[error("peer: {0}")]
    Peer(#[from] PeerError),
    /// The request could not be written.
    #[error("write: {0}")]
    Write(io::Error),
    /// The deadline passed.
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
    } = *request;
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(UpstreamError::Timeout)?;
    let mut connection = match endpoint {
        Endpoint::Unix(socket) => {
            let stream = UnixStream::connect(socket).map_err(UpstreamError::Connect)?;
            if let Some((uid, gid)) = peer {
                require_peer(&stream, uid, gid)?;
            }
            Connection::Unix(stream)
        }
        Endpoint::Tcp(address) => {
            Connection::Tcp(TcpStream::connect(address).map_err(UpstreamError::Connect)?)
        }
    };
    let left = deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
        .ok_or(UpstreamError::Timeout)?;
    let bytes = request_bytes(path, host, headers, body);
    let written = match &mut connection {
        Connection::Unix(stream) => stream
            .set_write_timeout(Some(left))
            .and_then(|()| stream.write_all(&bytes)),
        Connection::Tcp(stream) => stream
            .set_write_timeout(Some(left))
            .and_then(|()| stream.write_all(&bytes)),
    };
    written.map_err(|error| match error.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => UpstreamError::Timeout,
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

impl Upstream for BrokerClient {
    fn call(&self, request: &UpstreamRequest, timeout: Duration) -> Option<Vec<u8>> {
        self.exchange(request, timeout).ok()
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
