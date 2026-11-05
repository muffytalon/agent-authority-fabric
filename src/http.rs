//! The strict HTTP/1.1 subset the PEP serves on its Unix sockets (D2, `WEEK2_PLAN` §2a).
//!
//! One request per connection, always answered with `Connection: close`. A request is a
//! request line and header block of at most [`MAX_HEAD_BYTES`] and [`MAX_FIELDS`] fields, then
//! a body of exactly `Content-Length` bytes, at most [`MAX_BODY_BYTES`]. Everything else that
//! HTTP/1.1 allows and the PEP does not need is refused (U1 step 1): `Transfer-Encoding`,
//! `Content-Encoding`, a repeated `Content-Length`, obs-fold, bare CR or LF, whitespace before
//! a colon, bytes outside visible ASCII, any version but `HTTP/1.1` (so HTTP/1.0 and the HTTP/2
//! preface too), any target but the endpoint's plain path, and a repeat of a header the MCP
//! checks compare (RV3 F5). Header names compare case-insensitively.
//!
//! [`parse_head`] is sans-IO. [`read_request`] drives it over a stream with absolute deadlines:
//! before each read the timeout is set to the time left, so a peer that trickles one byte per
//! interval cannot hold a connection open past its deadline (RV3 F1).

use std::io::{self, Read};
use std::time::{Duration, Instant};

/// Longest request line plus header block, the final empty line included.
pub const MAX_HEAD_BYTES: usize = 16 * 1024;
/// Most header fields in one request.
pub const MAX_FIELDS: usize = 64;
/// Largest request body.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Bytes asked of the stream per read.
const READ_CHUNK: usize = 4096;

/// Headers that may appear at most once, because the MCP checks compare them with the body
/// (RV3 F5). `Content-Length` is checked on its own.
const SINGLETON_FIELDS: [&str; 6] = [
    "content-type",
    "host",
    "mcp-method",
    "mcp-name",
    "mcp-protocol-version",
    "pep-episode",
];

/// Why a request got no further than HTTP framing (U1 step 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HttpError {
    /// A deadline passed. The connection is closed with no reply.
    #[error("deadline passed")]
    Timeout,
    /// The peer closed the connection before a whole request arrived. No reply.
    #[error("connection closed early")]
    Closed,
    /// A read failed. No reply.
    #[error("read failed")]
    Io,
    /// The request is malformed. The reply is 400.
    #[error("malformed request: {0}")]
    Malformed(Malformed),
}

impl HttpError {
    /// The status to reply with, or `None` to close the connection with no reply.
    #[must_use]
    pub const fn reply(self) -> Option<Status> {
        match self {
            Self::Malformed(_) => Some(Status::BadRequest),
            Self::Timeout | Self::Closed | Self::Io => None,
        }
    }
}

/// What made a request malformed. Each gets 400; the variant is for the decision log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Malformed {
    /// The request line and headers exceed [`MAX_HEAD_BYTES`].
    #[error("head too large")]
    HeadTooLarge,
    /// More than [`MAX_FIELDS`] header fields.
    #[error("too many header fields")]
    TooManyFields,
    /// A CR not followed by LF, or an LF not preceded by CR.
    #[error("bare CR or LF")]
    BareLineEnding,
    /// A byte outside visible ASCII, space and tab.
    #[error("byte outside visible ASCII")]
    NonAscii,
    /// Not `method SP target SP version`, or a method that is not a token.
    #[error("malformed request line")]
    RequestLine,
    /// A version other than `HTTP/1.1`.
    #[error("unsupported HTTP version")]
    Version,
    /// A target other than the endpoint's path.
    #[error("unexpected request target")]
    Target,
    /// A header line that is obs-fold, has no colon, has whitespace before the colon, or has a
    /// name that is not a token.
    #[error("malformed header field")]
    FieldSyntax,
    /// A repeat of a header the MCP checks compare.
    #[error("repeated header field")]
    DuplicateField,
    /// A `Transfer-Encoding` header.
    #[error("transfer-encoding not supported")]
    TransferEncoding,
    /// A `Content-Encoding` header.
    #[error("content-encoding not supported")]
    ContentEncoding,
    /// A `Content-Length` that is repeated or not plain digits.
    #[error("invalid content-length")]
    ContentLength,
    /// A `Content-Length` above [`MAX_BODY_BYTES`].
    #[error("body too large")]
    BodyTooLarge,
    /// No `Host` header (RFC 9112 §3.2).
    #[error("missing host")]
    MissingHost,
    /// A POST with no `Content-Length`.
    #[error("missing content-length")]
    MissingContentLength,
}

impl From<Malformed> for HttpError {
    fn from(reason: Malformed) -> Self {
        Self::Malformed(reason)
    }
}

/// A request's header fields: names lower-cased, values with surrounding spaces and tabs
/// removed, in arrival order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Headers {
    fields: Vec<(String, String)>,
}

impl Headers {
    /// The first value of `name`, compared case-insensitively.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(field, _)| field.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// Every value of `name`, compared case-insensitively.
    pub fn all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.fields
            .iter()
            .filter(move |(field, _)| field.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// Whether `name` is present, compared case-insensitively.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    /// Every field name, lower-cased, in arrival order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.fields.iter().map(|(name, _)| name.as_str())
    }
}

/// A parsed request line and header block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHead {
    /// The method, case-sensitive.
    pub method: String,
    /// The request target, which the reader's predicate accepted.
    pub target: String,
    /// The header fields.
    pub headers: Headers,
    /// The body length, when `Content-Length` is present.
    pub content_length: Option<usize>,
}

impl RequestHead {
    /// Whether the method is `POST`, the only one the PEP serves.
    #[must_use]
    pub fn is_post(&self) -> bool {
        self.method == "POST"
    }
}

/// A whole request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The request line and headers.
    pub head: RequestHead,
    /// The body: exactly `Content-Length` bytes for a POST, and empty for any other method,
    /// whose body is never read (it gets 405).
    pub body: Vec<u8>,
}

/// Absolute deadlines for one request, usually measured from `accept`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deadlines {
    /// The whole head must have arrived by then.
    pub head: Instant,
    /// The whole body must have arrived by then.
    pub body: Instant,
}

/// A byte stream whose read timeout can be set: a `UnixStream`, or a test double.
pub trait TimedRead: Read {
    /// Sets the timeout for the next reads. `None` blocks.
    ///
    /// # Errors
    ///
    /// Returns the stream's error.
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()>;
}

#[cfg(unix)]
impl TimedRead for std::os::unix::net::UnixStream {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        std::os::unix::net::UnixStream::set_read_timeout(self, timeout)
    }
}

impl TimedRead for std::net::TcpStream {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        std::net::TcpStream::set_read_timeout(self, timeout)
    }
}

/// Reads one request for `endpoint` from `stream`, within `deadlines`.
///
/// # Errors
///
/// Returns [`HttpError::Malformed`] for a request to refuse with 400, and
/// [`HttpError::Timeout`], [`HttpError::Closed`] or [`HttpError::Io`] when the connection is
/// to be closed with no reply.
pub fn read_request<S: TimedRead + ?Sized>(
    stream: &mut S,
    endpoint: &str,
    deadlines: Deadlines,
) -> Result<Request, HttpError> {
    read_request_matching(stream, &|target| target == endpoint, deadlines)
}

/// [`read_request`] for a server with several targets, such as the broker's
/// `/mcp/{server_id}`: any target `accept` admits.
///
/// # Errors
///
/// As [`read_request`].
pub fn read_request_matching<S: TimedRead + ?Sized>(
    stream: &mut S,
    accept: &dyn Fn(&str) -> bool,
    deadlines: Deadlines,
) -> Result<Request, HttpError> {
    let (buf, head_end) = read_head(stream, deadlines.head)?;
    let (head_bytes, rest) = buf.split_at_checked(head_end).ok_or(HttpError::Io)?;
    let head = parse_head_matching(head_bytes, accept)?;
    if !head.is_post() {
        return Ok(Request {
            head,
            body: Vec::new(),
        });
    }
    let length = head.content_length.ok_or(Malformed::MissingContentLength)?;
    let body = read_body(stream, rest, length, deadlines.body)?;
    Ok(Request { head, body })
}

/// Reads until a whole head has arrived. Returns the bytes read and the head's length.
fn read_head<S: TimedRead + ?Sized>(
    stream: &mut S,
    deadline: Instant,
) -> Result<(Vec<u8>, usize), HttpError> {
    let mut buf = Vec::with_capacity(READ_CHUNK);
    let mut scanned = 0;
    loop {
        if let Some(end) = scan_head(&buf, &mut scanned)? {
            return Ok((buf, end));
        }
        let room = MAX_HEAD_BYTES
            .checked_add(1)
            .and_then(|cap| cap.checked_sub(buf.len()))
            .ok_or(Malformed::HeadTooLarge)?;
        read_some(stream, &mut buf, deadline, room)?;
    }
}

/// The `length` body bytes: those already read in `rest`, then the rest from the stream. One
/// message per connection, so bytes past the body are never parsed.
fn read_body<S: TimedRead + ?Sized>(
    stream: &mut S,
    rest: &[u8],
    length: usize,
    deadline: Instant,
) -> Result<Vec<u8>, HttpError> {
    let mut body = rest
        .get(..length.min(rest.len()))
        .unwrap_or_default()
        .to_vec();
    while body.len() < length {
        let room = length.checked_sub(body.len()).ok_or(HttpError::Io)?;
        read_some(stream, &mut body, deadline, room)?;
    }
    Ok(body)
}

/// Reads up to `room` bytes into `buf`, after setting the timeout to the time left until
/// `deadline`.
fn read_some<S: TimedRead + ?Sized>(
    stream: &mut S,
    buf: &mut Vec<u8>,
    deadline: Instant,
    room: usize,
) -> Result<(), HttpError> {
    let mut chunk = [0u8; READ_CHUNK];
    let slot = chunk
        .get_mut(..room.clamp(1, READ_CHUNK))
        .ok_or(HttpError::Io)?;
    loop {
        let left = deadline
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
            .ok_or(HttpError::Timeout)?;
        stream
            .set_read_timeout(Some(left))
            .map_err(|_| HttpError::Io)?;
        match stream.read(slot) {
            Ok(0) => return Err(HttpError::Closed),
            Ok(read) => {
                buf.extend_from_slice(slot.get(..read).ok_or(HttpError::Io)?);
                return Ok(());
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Err(HttpError::Timeout);
            }
            Err(_) => return Err(HttpError::Io),
        }
    }
}

/// Looks for the end of the head in `buf`, past the `scanned` bytes already checked. Returns
/// the length of the head, the final CRLF CRLF included, once it has arrived.
///
/// # Errors
///
/// Returns [`Malformed::BareLineEnding`] as soon as one arrives, and
/// [`Malformed::HeadTooLarge`] once more than [`MAX_HEAD_BYTES`] arrive with no end.
fn scan_head(buf: &[u8], scanned: &mut usize) -> Result<Option<usize>, Malformed> {
    // Back up three bytes, so a terminator split across reads is still seen.
    let start = scanned.saturating_sub(3);
    let window = buf.get(start..).unwrap_or_default();
    let found = window
        .windows(4)
        .position(|four| four == b"\r\n\r\n")
        .and_then(|at| start.checked_add(at)?.checked_add(4));
    let checked = buf.get(..found.unwrap_or(buf.len())).unwrap_or_default();
    if has_bare_line_ending(checked) {
        return Err(Malformed::BareLineEnding);
    }
    match found {
        // `parse_head` refuses a head longer than the cap.
        Some(end) => Ok(Some(end)),
        None if buf.len() > MAX_HEAD_BYTES => Err(Malformed::HeadTooLarge),
        None => {
            *scanned = buf.len();
            Ok(None)
        }
    }
}

/// Whether `bytes` holds an LF not preceded by CR, or a CR followed by anything but LF. A CR
/// at the very end may still be followed by its LF.
fn has_bare_line_ending(bytes: &[u8]) -> bool {
    bytes.first() == Some(&b'\n')
        || bytes.windows(2).any(|pair| match pair {
            [b'\r', next] => *next != b'\n',
            [prev, b'\n'] => *prev != b'\r',
            _ => false,
        })
}

/// Parses a request line and header block for `endpoint`. `head` ends with the empty line
/// (CRLF CRLF).
///
/// # Errors
///
/// Returns the [`Malformed`] reason for a head to refuse with 400.
pub fn parse_head(head: &[u8], endpoint: &str) -> Result<RequestHead, Malformed> {
    parse_head_matching(head, &|target| target == endpoint)
}

/// [`parse_head`] for any target `accept` admits.
///
/// # Errors
///
/// As [`parse_head`].
pub fn parse_head_matching(
    head: &[u8],
    accept: &dyn Fn(&str) -> bool,
) -> Result<RequestHead, Malformed> {
    let ((method, target), headers) = head_lines(head, |line| parse_request_line(line, accept))?;
    if !headers.contains("host") {
        return Err(Malformed::MissingHost);
    }
    let content_length = content_length(&headers, MAX_BODY_BYTES)?;
    Ok(RequestHead {
        method,
        target,
        headers,
        content_length,
    })
}

/// The first line of `head`, as `first_line` reads it, and its header fields, after the
/// checks requests and responses share: size, line endings, visible ASCII, field syntax and
/// count, repeated MCP headers, and no transfer or content coding. `head` ends with the
/// empty line (CRLF CRLF). The first line is checked before any field.
fn head_lines<T>(
    head: &[u8],
    first_line: impl FnOnce(&str) -> Result<T, Malformed>,
) -> Result<(T, Headers), Malformed> {
    if head.len() > MAX_HEAD_BYTES {
        return Err(Malformed::HeadTooLarge);
    }
    let text = head
        .strip_suffix(b"\r\n\r\n")
        .ok_or(Malformed::BareLineEnding)?;
    if has_bare_line_ending(text) {
        return Err(Malformed::BareLineEnding);
    }
    if !text
        .iter()
        .all(|&byte| matches!(byte, b'\t' | b'\r' | b'\n' | b' '..=b'~'))
    {
        return Err(Malformed::NonAscii);
    }
    let text = std::str::from_utf8(text).map_err(|_| Malformed::NonAscii)?;
    let mut lines = text.split("\r\n");
    let first = first_line(lines.next().ok_or(Malformed::RequestLine)?)?;
    let mut fields = Vec::new();
    for line in lines {
        if fields.len() >= MAX_FIELDS {
            return Err(Malformed::TooManyFields);
        }
        fields.push(parse_field(line)?);
    }
    let headers = Headers { fields };
    for name in SINGLETON_FIELDS {
        if headers.all(name).nth(1).is_some() {
            return Err(Malformed::DuplicateField);
        }
    }
    if headers.contains("transfer-encoding") {
        return Err(Malformed::TransferEncoding);
    }
    if headers.contains("content-encoding") {
        return Err(Malformed::ContentEncoding);
    }
    Ok((first, headers))
}

/// The one `Content-Length`, if present: plain digits, at most `cap`.
fn content_length(headers: &Headers, cap: usize) -> Result<Option<usize>, Malformed> {
    let mut lengths = headers.all("content-length");
    let first = lengths
        .next()
        .map(|value| parse_content_length(value, cap))
        .transpose()?;
    if lengths.next().is_some() {
        return Err(Malformed::ContentLength);
    }
    Ok(first)
}

/// Checks `method SP target SP HTTP/1.1` and returns the method.
fn parse_request_line(
    line: &str,
    accept: &dyn Fn(&str) -> bool,
) -> Result<(String, String), Malformed> {
    let mut parts = line.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Malformed::RequestLine);
    };
    if !is_token(method) {
        return Err(Malformed::RequestLine);
    }
    if version != "HTTP/1.1" {
        return Err(Malformed::Version);
    }
    if !accept(target) {
        return Err(Malformed::Target);
    }
    Ok((method.to_owned(), target.to_owned()))
}

/// Parses `name ":" OWS value OWS`.
fn parse_field(line: &str) -> Result<(String, String), Malformed> {
    let (name, value) = line.split_once(':').ok_or(Malformed::FieldSyntax)?;
    if !is_token(name) {
        // A token has no whitespace, so this refuses obs-fold (a line that starts with a space
        // or tab) and whitespace before the colon.
        return Err(Malformed::FieldSyntax);
    }
    let value = value.trim_matches([' ', '\t']);
    Ok((name.to_ascii_lowercase(), value.to_owned()))
}

/// Whether `text` is a non-empty RFC 9110 token.
fn is_token(text: &str) -> bool {
    !text.is_empty()
        && text.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

/// Parses a `Content-Length` of plain digits, at most `cap`.
fn parse_content_length(value: &str, cap: usize) -> Result<usize, Malformed> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Malformed::ContentLength);
    }
    let mut length: usize = 0;
    for digit in value.bytes() {
        length = length
            .checked_mul(10)
            .and_then(|tens| tens.checked_add(usize::from(digit.wrapping_sub(b'0'))))
            .filter(|length| *length <= cap)
            .ok_or(Malformed::BodyTooLarge)?;
    }
    Ok(length)
}

/// A whole response, read by the PEP as a client of the broker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// The status code.
    pub status: u16,
    /// The header fields.
    pub headers: Headers,
    /// The body: exactly `Content-Length` bytes.
    pub body: Vec<u8>,
}

/// Reads one response from `stream` by `deadline`, with a body of at most `max_body` bytes.
/// The subset is the request side's: `HTTP/1.1` only, an exact `Content-Length`, no transfer
/// or content coding, and the same header rules.
///
/// # Errors
///
/// Returns [`HttpError::Malformed`] for a response outside the subset, and
/// [`HttpError::Timeout`], [`HttpError::Closed`] or [`HttpError::Io`] when it did not arrive.
pub fn read_response<S: TimedRead + ?Sized>(
    stream: &mut S,
    deadline: Instant,
    max_body: usize,
) -> Result<Response, HttpError> {
    let (buf, head_end) = read_head(stream, deadline)?;
    let (head, rest) = buf.split_at_checked(head_end).ok_or(HttpError::Io)?;
    let (status, headers) = head_lines(head, parse_status_line)?;
    let length = content_length(&headers, max_body)?.ok_or(Malformed::MissingContentLength)?;
    let body = read_body(stream, rest, length, deadline)?;
    Ok(Response {
        status,
        headers,
        body,
    })
}

/// Checks `HTTP/1.1 SP 3DIGIT SP reason` and returns the code.
fn parse_status_line(line: &str) -> Result<u16, Malformed> {
    let mut parts = line.splitn(3, ' ');
    let (Some(version), Some(code), Some(_reason)) = (parts.next(), parts.next(), parts.next())
    else {
        return Err(Malformed::RequestLine);
    };
    if version != "HTTP/1.1" {
        return Err(Malformed::Version);
    }
    if code.len() != 3 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Malformed::RequestLine);
    }
    code.parse().map_err(|_| Malformed::RequestLine)
}

/// The statuses the PEP sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// 200.
    Ok,
    /// 202, for an ignored notification.
    Accepted,
    /// 400.
    BadRequest,
    /// 403, for a request with an `Origin` header.
    Forbidden,
    /// 404, for an unknown method.
    NotFound,
    /// 405, for any method but POST.
    MethodNotAllowed,
}

impl Status {
    /// The status code.
    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            Self::Ok => 200,
            Self::Accepted => 202,
            Self::BadRequest => 400,
            Self::Forbidden => 403,
            Self::NotFound => 404,
            Self::MethodNotAllowed => 405,
        }
    }

    const fn reason(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::Accepted => "Accepted",
            Self::BadRequest => "Bad Request",
            Self::Forbidden => "Forbidden",
            Self::NotFound => "Not Found",
            Self::MethodNotAllowed => "Method Not Allowed",
        }
    }
}

/// A whole response: `body`, if any, with its content type, then `Content-Length` and
/// `Connection: close`. A 405 also carries `Allow: POST`.
#[must_use]
pub fn response(status: Status, body: Option<(&str, &[u8])>) -> Vec<u8> {
    let mut out = status_line(status);
    if status == Status::MethodNotAllowed {
        out.extend_from_slice(b"Allow: POST\r\n");
    }
    let bytes = body.map_or(&[][..], |(content_type, bytes)| {
        out.extend_from_slice(format!("Content-Type: {content_type}\r\n").as_bytes());
        bytes
    });
    out.extend_from_slice(format!("Content-Length: {}\r\n", bytes.len()).as_bytes());
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    out.extend_from_slice(bytes);
    out
}

/// The head of a 200 response whose body ends when the connection closes: the one SSE reply
/// (`subscriptions/listen`). It has no `Content-Length`.
#[must_use]
pub fn stream_head(content_type: &str) -> Vec<u8> {
    let mut out = status_line(Status::Ok);
    out.extend_from_slice(format!("Content-Type: {content_type}\r\n").as_bytes());
    out.extend_from_slice(b"Cache-Control: no-store\r\nConnection: close\r\n\r\n");
    out
}

fn status_line(status: Status) -> Vec<u8> {
    format!("HTTP/1.1 {} {}\r\n", status.code(), status.reason()).into_bytes()
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
    use std::collections::VecDeque;

    const ENDPOINT: &str = "/mcp";

    /// A stream that hands out scripted chunks, then reports a timeout or end of stream.
    struct Script {
        chunks: VecDeque<Vec<u8>>,
        /// Sleep before each chunk.
        delay: Duration,
        /// What happens once the chunks run out: `true` is a timeout, `false` end of stream.
        then_timeout: bool,
        timeouts: Vec<Option<Duration>>,
    }

    impl Script {
        fn new(chunks: &[&[u8]]) -> Self {
            Self {
                chunks: chunks.iter().map(|chunk| chunk.to_vec()).collect(),
                delay: Duration::ZERO,
                then_timeout: false,
                timeouts: Vec::new(),
            }
        }
    }

    impl Read for Script {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            std::thread::sleep(self.delay);
            let Some(mut chunk) = self.chunks.pop_front() else {
                return if self.then_timeout {
                    Err(io::ErrorKind::WouldBlock.into())
                } else {
                    Ok(0)
                };
            };
            let read = chunk.len().min(buf.len());
            buf[..read].copy_from_slice(&chunk[..read]);
            if read < chunk.len() {
                self.chunks.push_front(chunk.split_off(read));
            }
            Ok(read)
        }
    }

    impl TimedRead for Script {
        fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
            self.timeouts.push(timeout);
            Ok(())
        }
    }

    fn deadlines(secs: u64) -> Deadlines {
        let at = Instant::now() + Duration::from_secs(secs);
        Deadlines { head: at, body: at }
    }

    fn read(chunks: &[&[u8]]) -> Result<Request, HttpError> {
        read_request(&mut Script::new(chunks), ENDPOINT, deadlines(5))
    }

    fn post(headers: &str, body: &str) -> Vec<u8> {
        format!(
            "POST /mcp HTTP/1.1\r\nHost: pep.local\r\nContent-Length: {}\r\n{headers}\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    fn malformed(raw: &[u8]) -> Malformed {
        match read(&[raw]) {
            Err(HttpError::Malformed(reason)) => reason,
            other => panic!("expected a malformed request, got {other:?}"),
        }
    }

    /// What the TypeScript SDK sent in the D2 spike, apart from the body.
    const UNDICI: &str = "host: pep.local\r\nconnection: keep-alive\r\naccept: application/json, text/event-stream\r\ncontent-type: application/json\r\nmcp-method: tools/list\r\nmcp-protocol-version: 2026-07-28\r\npep-episode: eyJ.spike.token\r\naccept-language: *\r\nuser-agent: undici\r\naccept-encoding: gzip, deflate\r\n";

    #[test]
    fn an_sdk_request_parses() {
        let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
        let raw = format!(
            "POST /mcp HTTP/1.1\r\n{UNDICI}content-length: {}\r\n\r\n{body}",
            body.len()
        );
        let request = read(&[raw.as_bytes()]).unwrap();
        assert!(request.head.is_post());
        assert_eq!(request.body, body.as_bytes());
        let headers = &request.head.headers;
        assert_eq!(headers.get("MCP-Method"), Some("tools/list"));
        assert_eq!(headers.get("Pep-Episode"), Some("eyJ.spike.token"));
        assert_eq!(
            headers.get("accept"),
            Some("application/json, text/event-stream")
        );
        assert_eq!(headers.names().count(), 11);
    }

    #[test]
    fn requests_arrive_in_any_chunks() {
        let raw = post("", r#"{"a":1}"#);
        // One byte per read, and a terminator split across reads.
        let bytes: Vec<&[u8]> = raw.chunks(1).collect();
        assert_eq!(read(&bytes).unwrap().body, br#"{"a":1}"#);
        let split = raw.len() - 9;
        assert_eq!(
            read(&[&raw[..split], &raw[split..]]).unwrap().body,
            br#"{"a":1}"#
        );
    }

    #[test]
    fn bytes_past_the_body_are_ignored() {
        let mut raw = post("", "{}");
        raw.extend_from_slice(b"POST /mcp HTTP/1.1\r\n");
        assert_eq!(read(&[&raw]).unwrap().body, b"{}");
    }

    #[test]
    fn other_methods_parse_and_their_body_is_never_read() {
        let request = read(&[b"GET /mcp HTTP/1.1\r\nHost: pep.local\r\n\r\n"]).unwrap();
        assert!(!request.head.is_post());
        assert!(request.body.is_empty());
        // A DELETE that announces a body still gets no further than its head.
        let request =
            read(&[b"DELETE /mcp HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\n"]).unwrap();
        assert_eq!(request.head.method, "DELETE");
        assert!(request.body.is_empty());
        // Methods are case-sensitive.
        assert!(
            !read(&[&post("", "{}").replacen(b"POST", b"post", 1)])
                .unwrap()
                .head
                .is_post()
        );
    }

    trait ReplaceN {
        fn replacen(&self, from: &[u8], to: &[u8], n: usize) -> Vec<u8>;
    }

    impl ReplaceN for Vec<u8> {
        fn replacen(&self, from: &[u8], to: &[u8], n: usize) -> Vec<u8> {
            let text = String::from_utf8(self.clone()).unwrap();
            let from = std::str::from_utf8(from).unwrap();
            let to = std::str::from_utf8(to).unwrap();
            text.replacen(from, to, n).into_bytes()
        }
    }

    #[test]
    fn framing_rejects() {
        let cases: Vec<(Vec<u8>, Malformed)> = vec![
            (
                b"POST /mcp HTTP/1.0\r\nHost: x\r\nContent-Length: 0\r\n\r\n".to_vec(),
                Malformed::Version,
            ),
            (
                b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec(),
                Malformed::Version,
            ),
            (
                b"POST /mcp HTTP/1.1 \r\nHost: x\r\n\r\n".to_vec(),
                Malformed::RequestLine,
            ),
            (
                b"POST  /mcp HTTP/1.1\r\nHost: x\r\n\r\n".to_vec(),
                Malformed::RequestLine,
            ),
            (
                b"\r\nPOST /mcp HTTP/1.1\r\nHost: x\r\n\r\n".to_vec(),
                Malformed::RequestLine,
            ),
            (
                b"PO(ST /mcp HTTP/1.1\r\nHost: x\r\n\r\n".to_vec(),
                Malformed::RequestLine,
            ),
            (
                post("", "{}").replacen(b"/mcp", b"/mcp?x=1", 1),
                Malformed::Target,
            ),
            (
                post("", "{}").replacen(b"/mcp", b"/mcp/", 1),
                Malformed::Target,
            ),
            (
                post("", "{}").replacen(b"/mcp", b"http://pep.local/mcp", 1),
                Malformed::Target,
            ),
            (
                post("", "{}").replacen(b"/mcp", b"/MCP", 1),
                Malformed::Target,
            ),
            (
                post("Transfer-Encoding: chunked\r\n", "{}"),
                Malformed::TransferEncoding,
            ),
            (
                post("Content-Encoding: gzip\r\n", "{}"),
                Malformed::ContentEncoding,
            ),
            (
                post("Content-Length: 2\r\n", "{}"),
                Malformed::ContentLength,
            ),
            (
                post("content-length: 3\r\n", "{}"),
                Malformed::ContentLength,
            ),
            (
                post("", "{}").replacen(b"Content-Length: 2", b"Content-Length: +2", 1),
                Malformed::ContentLength,
            ),
            (
                post("", "{}").replacen(b"Content-Length: 2", b"Content-Length: 2, 2", 1),
                Malformed::ContentLength,
            ),
            (
                post("", "{}").replacen(b"Content-Length: 2", b"Content-Length:", 1),
                Malformed::ContentLength,
            ),
            (
                post("", "{}").replacen(b"Content-Length: 2", b"Content-Length: 1048577", 1),
                Malformed::BodyTooLarge,
            ),
            (
                post("", "{}").replacen(
                    b"Content-Length: 2",
                    b"Content-Length: 99999999999999999999999",
                    1,
                ),
                Malformed::BodyTooLarge,
            ),
            (
                post("", "{}").replacen(b"Content-Length: 2\r\n", b"", 1),
                Malformed::MissingContentLength,
            ),
            (
                post("", "{}").replacen(b"Host: pep.local\r\n", b"", 1),
                Malformed::MissingHost,
            ),
            (post("Host: other\r\n", "{}"), Malformed::DuplicateField),
            (
                post("X-A: 1\r\n continued\r\n", "{}"),
                Malformed::FieldSyntax,
            ),
            (
                post("X-A: 1\r\n\tcontinued\r\n", "{}"),
                Malformed::FieldSyntax,
            ),
            (
                post("X-A: 1\r\n Mcp-Method: tools/list\r\n", "{}"),
                Malformed::FieldSyntax,
            ),
            (
                post("Mcp-Method : tools/list\r\n", "{}"),
                Malformed::FieldSyntax,
            ),
            (
                post("Mcp-Method\t: tools/list\r\n", "{}"),
                Malformed::FieldSyntax,
            ),
            (post("no colon here\r\n", "{}"), Malformed::FieldSyntax),
            (post(": empty name\r\n", "{}"), Malformed::FieldSyntax),
            (post("X(A): 1\r\n", "{}"), Malformed::FieldSyntax),
            (post("X-A: caf\u{e9}\r\n", "{}"), Malformed::NonAscii),
            (post("X-A: a\u{0}b\r\n", "{}"), Malformed::NonAscii),
            (post("X-A: a\u{7f}b\r\n", "{}"), Malformed::NonAscii),
            (post("X-A: a\rb\r\n", "{}"), Malformed::BareLineEnding),
            (post("X-A: a\nb\r\n", "{}"), Malformed::BareLineEnding),
            (
                b"POST /mcp HTTP/1.1\nHost: x\n\n".to_vec(),
                Malformed::BareLineEnding,
            ),
            (
                b"\nPOST /mcp HTTP/1.1\r\n".to_vec(),
                Malformed::BareLineEnding,
            ),
        ];
        for (raw, reason) in cases {
            assert_eq!(
                malformed(&raw),
                reason,
                "{:?}",
                String::from_utf8_lossy(&raw)
            );
        }
    }

    #[test]
    fn repeated_mcp_headers_rejected_in_any_case() {
        for (first, second) in [
            (
                "MCP-Protocol-Version: 2026-07-28",
                "mcp-protocol-version: 2026-07-28",
            ),
            ("Mcp-Method: tools/call", "MCP-METHOD: tools/list"),
            ("Mcp-Name: a", "mcp-name: a"),
            ("Pep-Episode: t", "pep-episode: t"),
            (
                "Content-Type: application/json",
                "content-type: application/json",
            ),
        ] {
            let raw = post(&format!("{first}\r\n{second}\r\n"), "{}");
            assert_eq!(malformed(&raw), Malformed::DuplicateField, "{first}");
        }
        // A list-valued header may repeat.
        let request = read(&[&post(
            "Accept: application/json\r\nAccept: text/event-stream\r\n",
            "{}",
        )])
        .unwrap();
        assert_eq!(
            request.head.headers.all("accept").collect::<Vec<_>>(),
            vec!["application/json", "text/event-stream"]
        );
    }

    #[test]
    fn parse_head_checks_line_endings_itself() {
        // Without the reader's scan in front of it.
        for head in [
            &b"POST /mcp HTTP/1.1\r\nHost: x\nX-A: 1\r\n\r\n"[..],
            b"POST /mcp HTTP/1.1\r\nHost: x\rX-A: 1\r\n\r\n",
            b"POST /mcp HTTP/1.1\r\nHost: x\r\n",
        ] {
            assert_eq!(
                parse_head(head, ENDPOINT),
                Err(Malformed::BareLineEnding),
                "{:?}",
                String::from_utf8_lossy(head)
            );
        }
        let long = vec![b'a'; MAX_HEAD_BYTES + 1];
        assert_eq!(parse_head(&long, ENDPOINT), Err(Malformed::HeadTooLarge));
    }

    #[test]
    fn values_are_trimmed_and_names_folded() {
        let request = read(&[&post("MCP-Method: \t tools/list \t\r\nX-Empty:\r\n", "{}")]).unwrap();
        let headers = &request.head.headers;
        assert_eq!(headers.get("mcp-method"), Some("tools/list"));
        assert_eq!(headers.get("x-empty"), Some(""));
        assert!(
            headers
                .names()
                .all(|name| name == name.to_ascii_lowercase())
        );
    }

    #[test]
    fn head_size_and_field_limits() {
        let filler = |bytes: usize| format!("X-F: {}\r\n", "a".repeat(bytes));
        // Exactly MAX_HEAD_BYTES is accepted, one more is not.
        let base = post("", "").len();
        let fits = post(&filler(MAX_HEAD_BYTES - base - 7), "");
        assert_eq!(fits.len(), MAX_HEAD_BYTES);
        assert!(read(&[&fits]).is_ok());
        let over = post(&filler(MAX_HEAD_BYTES - base - 6), "");
        assert_eq!(malformed(&over), Malformed::HeadTooLarge);
        // A head that never ends is refused once it passes the cap.
        let endless = vec![b'a'; MAX_HEAD_BYTES + 1];
        assert_eq!(malformed(&endless), Malformed::HeadTooLarge);
        // Fields: Host and Content-Length are two of the 64.
        let fields = |n: usize| {
            let mut out = String::new();
            for i in 0..n {
                out.push_str("X-");
                out.push_str(&i.to_string());
                out.push_str(": v\r\n");
            }
            out
        };
        assert!(read(&[&post(&fields(MAX_FIELDS - 2), "")]).is_ok());
        assert_eq!(
            malformed(&post(&fields(MAX_FIELDS - 1), "")),
            Malformed::TooManyFields
        );
    }

    #[test]
    fn body_limit() {
        let body = "a".repeat(MAX_BODY_BYTES);
        assert_eq!(
            read(&[&post("", &body)]).unwrap().body.len(),
            MAX_BODY_BYTES
        );
    }

    #[test]
    fn early_close_and_read_errors_get_no_reply() {
        let raw = post("", "{}");
        assert_eq!(read(&[&raw[..10]]), Err(HttpError::Closed));
        assert_eq!(read(&[&raw[..raw.len() - 1]]), Err(HttpError::Closed));
        assert_eq!(HttpError::Closed.reply(), None);
        assert_eq!(HttpError::Timeout.reply(), None);
        assert_eq!(HttpError::Io.reply(), None);
        assert_eq!(
            HttpError::Malformed(Malformed::Target).reply(),
            Some(Status::BadRequest)
        );
    }

    #[test]
    fn a_trickling_peer_meets_the_absolute_deadline() {
        // RV3 F1: one byte every 20 ms never resets the clock.
        let raw = post("", "{}");
        let mut stream = Script::new(&raw.chunks(1).collect::<Vec<_>>());
        stream.delay = Duration::from_millis(20);
        let start = Instant::now();
        let at = start + Duration::from_millis(300);
        let result = read_request(&mut stream, ENDPOINT, Deadlines { head: at, body: at });
        assert_eq!(result, Err(HttpError::Timeout));
        assert!(start.elapsed() < Duration::from_millis(400));
        // Each timeout was the time left, never more.
        let timeouts: Vec<Duration> = stream.timeouts.iter().map(|t| t.unwrap()).collect();
        assert!(timeouts.windows(2).all(|pair| pair[1] < pair[0]));
        assert!(timeouts[0] <= Duration::from_millis(300));
    }

    #[test]
    fn head_and_body_deadlines_apply_separately() {
        let raw = post("", r#"{"a":1}"#);
        let split = raw.len() - 3;
        let now = Instant::now();
        // The head is on time, the body is not.
        let mut stream = Script::new(&[&raw[..split]]);
        stream.then_timeout = true;
        let result = read_request(
            &mut stream,
            ENDPOINT,
            Deadlines {
                head: now + Duration::from_secs(5),
                body: now + Duration::from_millis(50),
            },
        );
        assert_eq!(result, Err(HttpError::Timeout));
        // A deadline already passed refuses before reading.
        let mut stream = Script::new(&[&raw]);
        let past = Deadlines {
            head: now,
            body: now,
        };
        assert_eq!(
            read_request(&mut stream, ENDPOINT, past),
            Err(HttpError::Timeout)
        );
        assert!(stream.timeouts.is_empty());
    }

    #[test]
    fn responses_carry_length_and_close() {
        assert_eq!(
            response(Status::Ok, Some(("application/json", b"{}"))),
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"
        );
        assert_eq!(
            response(Status::MethodNotAllowed, None),
            b"HTTP/1.1 405 Method Not Allowed\r\nAllow: POST\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        assert_eq!(
            response(Status::Accepted, None),
            b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        assert_eq!(
            stream_head("text/event-stream"),
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n"
        );
        for (status, code) in [
            (Status::Ok, 200),
            (Status::Accepted, 202),
            (Status::BadRequest, 400),
            (Status::Forbidden, 403),
            (Status::NotFound, 404),
            (Status::MethodNotAllowed, 405),
        ] {
            assert_eq!(status.code(), code);
        }
    }

    #[cfg(unix)]
    #[test]
    fn reads_from_a_unix_stream() {
        use std::io::Write;
        use std::os::unix::net::UnixStream;
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let raw = post("", "{}");
        client.write_all(&raw).unwrap();
        assert_eq!(
            read_request(&mut server, ENDPOINT, deadlines(5))
                .unwrap()
                .body,
            b"{}"
        );
        // Nothing more arrives: the real timeout fires.
        client.write_all(&raw[..5]).unwrap();
        let at = Instant::now() + Duration::from_millis(50);
        assert_eq!(
            read_request(&mut server, ENDPOINT, Deadlines { head: at, body: at }),
            Err(HttpError::Timeout)
        );
    }
}
