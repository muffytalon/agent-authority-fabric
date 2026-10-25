//! JCS-strict-NFC: a byte-cursor implementation of RFC 8785 JSON canonicalization that also
//! normalizes every string and key to Unicode NFC.
//!
//! Wire bytes are parsed directly, never through `serde_json`, so duplicate keys, lone
//! surrogates, leading zeros and out-of-range integers are rejected instead of being silently
//! repaired. `WEEK1_PLAN.md` §3 documents the state machine and the error-offset rules.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest as _, Sha256};
use unicode_normalization::{IsNormalized, UnicodeNormalization as _, is_nfc_quick};

/// Largest integer magnitude accepted in requests: 2^53 - 1.
pub const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
/// Smallest integer accepted in requests: -(2^53 - 1).
pub const MIN_SAFE_INTEGER: i64 = -9_007_199_254_740_991;
/// Default maximum request size in bytes (1 MiB).
pub const MAX_REQUEST_BYTES: usize = 1_048_576;
/// Default maximum container nesting depth.
pub const MAX_DEPTH: usize = 64;
/// Default maximum number of values in a request.
pub const MAX_REQUEST_NODES: usize = 8192;
/// Prefix of every digest string.
pub const DIGEST_PREFIX: &str = "sha-256:";

const MAX_SAFE_U64: u64 = 9_007_199_254_740_991;
const NEG_ZERO_BITS: u64 = 0x8000_0000_0000_0000;

#[cfg(not(feature = "lenient-numbers"))]
const REQUEST_NUMBERS: NumberMode = NumberMode::SafeInteger;
#[cfg(feature = "lenient-numbers")]
const REQUEST_NUMBERS: NumberMode = NumberMode::EcmaSafe;

/// Errors produced while parsing JSON wire bytes.
///
/// Every variant carries only the byte offset where parsing failed, never input bytes, so an
/// error cannot leak request contents into logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum JcsError {
    /// Input ended before a complete value was read.
    #[error("unexpected end of input at byte {offset}")]
    UnexpectedEof {
        /// Byte offset of the error.
        offset: usize,
    },
    /// A byte that the grammar does not allow at this position.
    #[error("unexpected byte at offset {offset}")]
    UnexpectedByte {
        /// Byte offset of the error.
        offset: usize,
    },
    /// Non-whitespace bytes after the top-level value.
    #[error("trailing data at byte {offset}")]
    TrailingData {
        /// Byte offset of the error.
        offset: usize,
    },
    /// The input starts with a UTF-8 byte order mark.
    #[error("byte order mark at byte {offset}")]
    ByteOrderMark {
        /// Byte offset of the error.
        offset: usize,
    },
    /// A string contains bytes that are not valid UTF-8.
    #[error("invalid UTF-8 at byte {offset}")]
    InvalidUtf8 {
        /// Byte offset of the error.
        offset: usize,
    },
    /// A string contains an unescaped control character below U+0020.
    #[error("unescaped control character at byte {offset}")]
    ControlCharInString {
        /// Byte offset of the error.
        offset: usize,
    },
    /// An escape sequence that JSON does not define, or a malformed `\u` escape.
    #[error("invalid escape at byte {offset}")]
    InvalidEscape {
        /// Byte offset of the backslash that starts the escape.
        offset: usize,
    },
    /// A UTF-16 surrogate escape without its partner.
    #[error("lone surrogate at byte {offset}")]
    LoneSurrogate {
        /// Byte offset of the backslash that starts the escape.
        offset: usize,
    },
    /// A number with a leading zero, such as `00` or `-01`.
    #[error("leading zero at byte {offset}")]
    LeadingZero {
        /// Byte offset of the error.
        offset: usize,
    },
    /// A number whose magnitude exceeds 2^53 - 1.
    #[error("number out of range at byte {offset}")]
    NumberOutOfRange {
        /// Byte offset of the first byte of the number.
        offset: usize,
    },
    /// A fraction or exponent where only integers are allowed.
    #[error("non-integer number at byte {offset}")]
    NonIntegerNumber {
        /// Byte offset of the `.`, `e` or `E`.
        offset: usize,
    },
    /// A number that does not fit in a finite IEEE-754 double.
    #[error("non-finite number at byte {offset}")]
    NumberNotFinite {
        /// Byte offset of the first byte of the number.
        offset: usize,
    },
    /// Two object keys that are equal after NFC normalization.
    #[error("duplicate key at byte {offset}")]
    DuplicateKey {
        /// Byte offset of the opening quote of the later key (0 for in-memory objects).
        offset: usize,
    },
    /// Containers nested deeper than the configured limit.
    #[error("nesting too deep at byte {offset}")]
    DepthExceeded {
        /// Byte offset of the bracket that exceeds the limit.
        offset: usize,
    },
    /// Input larger than the configured limit.
    #[error("input too large at byte {offset}")]
    InputTooLarge {
        /// The configured limit.
        offset: usize,
    },
    /// More values than the configured limit.
    #[error("too many values at byte {offset}")]
    NodeLimitExceeded {
        /// Byte offset of the first value over the limit.
        offset: usize,
    },
}

impl JcsError {
    /// Byte offset at which the error was detected.
    #[must_use]
    pub const fn offset(self) -> usize {
        match self {
            Self::UnexpectedEof { offset }
            | Self::UnexpectedByte { offset }
            | Self::TrailingData { offset }
            | Self::ByteOrderMark { offset }
            | Self::InvalidUtf8 { offset }
            | Self::ControlCharInString { offset }
            | Self::InvalidEscape { offset }
            | Self::LoneSurrogate { offset }
            | Self::LeadingZero { offset }
            | Self::NumberOutOfRange { offset }
            | Self::NonIntegerNumber { offset }
            | Self::NumberNotFinite { offset }
            | Self::DuplicateKey { offset }
            | Self::DepthExceeded { offset }
            | Self::InputTooLarge { offset }
            | Self::NodeLimitExceeded { offset } => offset,
        }
    }
}

/// How number tokens are accepted and canonicalized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumberMode {
    /// Integers only, with magnitude at most 2^53 - 1 (the F-04 request profile).
    SafeInteger,
    /// RFC 8785 fractions and exponents, with magnitude at most 2^53 - 1.
    EcmaSafe,
    /// Any finite IEEE-754 double (tool results). `int` is set only for safe integers.
    EcmaAny,
}

/// Limits and number rules for one parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseOptions {
    /// Number profile.
    pub numbers: NumberMode,
    /// Maximum input size in bytes.
    pub max_bytes: usize,
    /// Maximum container nesting depth.
    pub max_depth: usize,
    /// Maximum number of values, containers included.
    pub max_nodes: usize,
}

impl ParseOptions {
    /// The request profile: safe integers only (fractions too with `lenient-numbers`), 1 MiB,
    /// depth 64 and 8192 values.
    #[must_use]
    pub const fn request() -> Self {
        Self {
            numbers: REQUEST_NUMBERS,
            max_bytes: MAX_REQUEST_BYTES,
            max_depth: MAX_DEPTH,
            max_nodes: MAX_REQUEST_NODES,
        }
    }

    /// The tool-result profile: any finite number, depth 64, and the given size limits.
    #[must_use]
    pub const fn result(max_bytes: usize, max_nodes: usize) -> Self {
        Self {
            numbers: NumberMode::EcmaAny,
            max_bytes,
            max_depth: MAX_DEPTH,
            max_nodes,
        }
    }
}

/// A string guaranteed to be in Unicode Normalization Form C.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JcsString(String);

impl JcsString {
    /// Builds a string, normalizing it to NFC.
    #[must_use]
    pub fn new(text: impl Into<String>) -> Self {
        Self(nfc(text.into()))
    }

    /// The NFC text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the wrapper and returns the NFC text.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

/// A JSON number in canonical form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JcsNumber {
    canonical: String,
    int: Option<i64>,
}

impl JcsNumber {
    /// Builds a number from a safe integer. Returns `None` outside ±(2^53 - 1).
    #[must_use]
    pub fn from_i64(value: i64) -> Option<Self> {
        (MIN_SAFE_INTEGER..=MAX_SAFE_INTEGER)
            .contains(&value)
            .then(|| Self {
                canonical: value.to_string(),
                int: Some(value),
            })
    }

    /// The value as an integer, if it is a safe integer.
    #[must_use]
    pub const fn as_i64(&self) -> Option<i64> {
        self.int
    }

    /// The canonical text of the number.
    #[must_use]
    pub fn canonical(&self) -> &str {
        &self.canonical
    }
}

/// A JSON object whose members are kept sorted by UTF-16 code units.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JcsObject {
    entries: Vec<(JcsString, JcsValue)>,
}

impl JcsObject {
    /// Builds an object from members, sorting them by UTF-16 code units.
    ///
    /// # Errors
    ///
    /// Returns [`JcsError::DuplicateKey`] with offset 0 if two keys are equal.
    pub fn from_entries(mut entries: Vec<(JcsString, JcsValue)>) -> Result<Self, JcsError> {
        entries.sort_by(|a, b| a.0.as_str().encode_utf16().cmp(b.0.as_str().encode_utf16()));
        if entries
            .iter()
            .zip(entries.iter().skip(1))
            .any(|(a, b)| a.0 == b.0)
        {
            return Err(JcsError::DuplicateKey { offset: 0 });
        }
        Ok(Self { entries })
    }

    /// The member named `key`, compared after NFC normalization of `key`.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&JcsValue> {
        let key = nfc(key.to_owned());
        self.entries
            .binary_search_by(|(k, _)| k.as_str().encode_utf16().cmp(key.encode_utf16()))
            .ok()
            .and_then(|index| self.entries.get(index))
            .map(|(_, value)| value)
    }

    /// Whether the object has a member named `key`.
    #[must_use]
    pub fn contains_key(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    /// The members in canonical order.
    #[must_use]
    pub fn entries(&self) -> &[(JcsString, JcsValue)] {
        &self.entries
    }

    /// Number of members.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the object has no members.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// A parsed JSON value in canonical form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JcsValue {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// A number.
    Number(JcsNumber),
    /// A string.
    String(JcsString),
    /// An array.
    Array(Vec<JcsValue>),
    /// An object.
    Object(JcsObject),
}

/// One value inside a tree, as yielded by [`JcsValue::nodes`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node<'a> {
    /// RFC 6901 pointer from the root.
    pub pointer: String,
    /// Nesting depth; the root is 0.
    pub depth: usize,
    /// The value at `pointer`.
    pub value: &'a JcsValue,
}

impl JcsValue {
    /// Builds a string value, normalizing it to NFC.
    #[must_use]
    pub fn string(text: impl Into<String>) -> Self {
        Self::String(JcsString::new(text))
    }

    /// Builds a number value from a safe integer.
    #[must_use]
    pub fn int(value: i64) -> Option<Self> {
        JcsNumber::from_i64(value).map(Self::Number)
    }

    /// The text, if this is a string.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        if let Self::String(text) = self {
            Some(text.as_str())
        } else {
            None
        }
    }

    /// The integer, if this is a safe integer.
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        if let Self::Number(number) = self {
            number.as_i64()
        } else {
            None
        }
    }

    /// The boolean, if this is `true` or `false`.
    #[must_use]
    pub fn as_bool(&self) -> Option<bool> {
        if let Self::Bool(flag) = self {
            Some(*flag)
        } else {
            None
        }
    }

    /// The object, if this is an object.
    #[must_use]
    pub fn as_object(&self) -> Option<&JcsObject> {
        if let Self::Object(object) = self {
            Some(object)
        } else {
            None
        }
    }

    /// The items, if this is an array.
    #[must_use]
    pub fn as_array(&self) -> Option<&[JcsValue]> {
        if let Self::Array(items) = self {
            Some(items)
        } else {
            None
        }
    }

    /// Whether this is neither an array nor an object.
    #[must_use]
    pub const fn is_scalar(&self) -> bool {
        !matches!(self, Self::Array(_) | Self::Object(_))
    }

    /// The object member named `key`, if this is an object.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&JcsValue> {
        self.as_object().and_then(|object| object.get(key))
    }

    /// Resolves an RFC 6901 JSON pointer. Array indices with leading zeros are rejected.
    #[must_use]
    pub fn pointer(&self, pointer: &str) -> Option<&JcsValue> {
        if pointer.is_empty() {
            return Some(self);
        }
        let rest = pointer.strip_prefix('/')?;
        let mut current = self;
        for raw in rest.split('/') {
            let token = unescape_pointer_token(raw)?;
            current = match current {
                Self::Object(object) => object.get(&token)?,
                Self::Array(items) => items.get(parse_array_index(&token)?)?,
                Self::Null | Self::Bool(_) | Self::Number(_) | Self::String(_) => return None,
            };
        }
        Some(current)
    }

    /// Every value in the tree, in pre-order, with its pointer and depth.
    #[must_use]
    pub fn nodes(&self) -> Vec<Node<'_>> {
        let mut out = Vec::new();
        collect_nodes(self, "", 0, &mut out);
        out
    }

    /// Every scalar value in the tree, in pre-order, with its pointer and depth.
    #[must_use]
    pub fn leaves(&self) -> Vec<Node<'_>> {
        self.nodes()
            .into_iter()
            .filter(|node| node.value.is_scalar())
            .collect()
    }

    /// The RFC 8785 canonical serialization as text.
    #[must_use]
    pub fn to_canonical_string(&self) -> String {
        let mut out = String::new();
        write_value(&mut out, self);
        out
    }

    /// The RFC 8785 canonical serialization as UTF-8 bytes.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        self.to_canonical_string().into_bytes()
    }
}

/// A parsed value and the number of values it contains (containers included).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    /// The parsed value.
    pub value: JcsValue,
    /// Number of values in `value`, the root included.
    pub nodes: usize,
}

/// The inputs of an `origin_hash` (SPEC §2).
#[derive(Debug, Clone, Copy)]
pub struct OriginRef<'a> {
    /// Canonical JSON-RPC id of the call that produced the value.
    pub source_call_id: &'a str,
    /// Tool that produced the value.
    pub tool: &'a str,
    /// `action_digest` of the producing call.
    pub query_digest: &'a str,
    /// RFC 6901 pointer to the value inside the result.
    pub result_pointer: &'a str,
    /// The value itself.
    pub value: &'a JcsValue,
}

/// Parses wire bytes with the request profile.
///
/// # Errors
///
/// Returns a [`JcsError`] for any input that is not valid JCS-strict-NFC JSON.
pub fn parse(input: &[u8]) -> Result<JcsValue, JcsError> {
    parse_with(input, &ParseOptions::request()).map(|parsed| parsed.value)
}

/// Parses wire bytes with the given options.
///
/// # Errors
///
/// Returns a [`JcsError`] for invalid JSON or when a limit in `options` is exceeded.
pub fn parse_with(input: &[u8], options: &ParseOptions) -> Result<Parsed, JcsError> {
    if input.len() > options.max_bytes {
        return Err(JcsError::InputTooLarge {
            offset: options.max_bytes,
        });
    }
    if input.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return Err(JcsError::ByteOrderMark { offset: 0 });
    }
    let mut cursor = Cursor {
        buf: input,
        pos: 0,
        depth: 0,
        nodes: 0,
        options: *options,
    };
    cursor.skip_ws()?;
    let value = cursor.value()?;
    cursor.skip_ws()?;
    if cursor.pos != input.len() {
        return Err(JcsError::TrailingData { offset: cursor.pos });
    }
    Ok(Parsed {
        value,
        nodes: cursor.nodes,
    })
}

/// Parses wire bytes with the request profile and returns their canonical serialization.
///
/// # Errors
///
/// Returns a [`JcsError`] for any input that [`parse`] rejects.
pub fn canonicalize(input: &[u8]) -> Result<Vec<u8>, JcsError> {
    parse(input).map(|value| value.to_canonical_bytes())
}

/// `"sha-256:" + base64url_no_pad(SHA-256(JCS_strict_NFC(input)))`.
///
/// # Errors
///
/// Returns a [`JcsError`] for any input that [`parse`] rejects.
pub fn digest(input: &[u8]) -> Result<String, JcsError> {
    parse(input).map(|value| digest_value(&value))
}

/// The digest of an in-memory value.
#[must_use]
pub fn digest_value(value: &JcsValue) -> String {
    let mut out = String::from(DIGEST_PREFIX);
    out.push_str(&sha256_b64url(&value.to_canonical_bytes()));
    out
}

/// Unpadded base64url of SHA-256 over raw bytes.
#[must_use]
pub fn sha256_b64url(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(data))
}

/// `digest({"method": "tools/call", "name": name, "arguments": arguments})`.
#[must_use]
pub fn action_digest(name: &str, arguments: &JcsValue) -> String {
    // Keys are listed in canonical (UTF-16) order.
    let object = JcsObject {
        entries: vec![
            (JcsString::new("arguments"), arguments.clone()),
            (JcsString::new("method"), JcsValue::string("tools/call")),
            (JcsString::new("name"), JcsValue::string(name)),
        ],
    };
    digest_value(&JcsValue::Object(object))
}

/// `digest({"source_call_id", "tool", "query_digest", "result_pointer", "value"})`.
#[must_use]
pub fn origin_hash(origin: &OriginRef<'_>) -> String {
    // Keys are listed in canonical (UTF-16) order.
    let object = JcsObject {
        entries: vec![
            (
                JcsString::new("query_digest"),
                JcsValue::string(origin.query_digest),
            ),
            (
                JcsString::new("result_pointer"),
                JcsValue::string(origin.result_pointer),
            ),
            (
                JcsString::new("source_call_id"),
                JcsValue::string(origin.source_call_id),
            ),
            (JcsString::new("tool"), JcsValue::string(origin.tool)),
            (JcsString::new("value"), origin.value.clone()),
        ],
    };
    digest_value(&JcsValue::Object(object))
}

fn nfc(text: String) -> String {
    if matches!(is_nfc_quick(text.chars()), IsNormalized::Yes) {
        text
    } else {
        text.nfc().collect()
    }
}

fn unescape_pointer_token(raw: &str) -> Option<String> {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c == '~' {
            match chars.next() {
                Some('0') => out.push('~'),
                Some('1') => out.push('/'),
                _ => return None,
            }
        } else {
            out.push(c);
        }
    }
    Some(out)
}

/// Escapes one RFC 6901 reference token (`~` becomes `~0`, `/` becomes `~1`).
#[must_use]
pub fn escape_pointer_token(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

fn parse_array_index(token: &str) -> Option<usize> {
    if token == "0" {
        return Some(0);
    }
    let first = token.bytes().next()?;
    if !(b'1'..=b'9').contains(&first) || !token.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    token.parse().ok()
}

fn collect_nodes<'a>(value: &'a JcsValue, pointer: &str, depth: usize, out: &mut Vec<Node<'a>>) {
    let child_depth = depth.saturating_add(1);
    out.push(Node {
        pointer: pointer.to_owned(),
        depth,
        value,
    });
    match value {
        JcsValue::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                collect_nodes(item, &format!("{pointer}/{index}"), child_depth, out);
            }
        }
        JcsValue::Object(object) => {
            for (key, item) in &object.entries {
                let child = format!("{pointer}/{}", escape_pointer_token(key.as_str()));
                collect_nodes(item, &child, child_depth, out);
            }
        }
        JcsValue::Null | JcsValue::Bool(_) | JcsValue::Number(_) | JcsValue::String(_) => {}
    }
}

fn write_value(out: &mut String, value: &JcsValue) {
    match value {
        JcsValue::Null => out.push_str("null"),
        JcsValue::Bool(true) => out.push_str("true"),
        JcsValue::Bool(false) => out.push_str("false"),
        JcsValue::Number(number) => out.push_str(&number.canonical),
        JcsValue::String(text) => write_string(out, text.as_str()),
        JcsValue::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_value(out, item);
            }
            out.push(']');
        }
        JcsValue::Object(object) => {
            out.push('{');
            for (index, (key, item)) in object.entries.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_string(out, key.as_str());
                out.push(':');
                write_value(out, item);
            }
            out.push('}');
        }
    }
}

fn write_string(out: &mut String, text: &str) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if u32::from(c) < 0x20 => push_control_escape(out, u32::from(c)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Writes a lowercase six-character escape for a control character below U+0020.
fn push_control_escape(out: &mut String, code: u32) {
    out.push_str("\\u00");
    out.push(if code < 0x10 { '0' } else { '1' });
    out.push(char::from_digit(code & 0x0F, 16).unwrap_or('0'));
}

struct Member {
    utf16: Vec<u16>,
    offset: usize,
    key: JcsString,
    value: JcsValue,
}

fn finish_object(mut members: Vec<Member>) -> Result<JcsValue, JcsError> {
    members.sort_by(|a, b| a.utf16.cmp(&b.utf16));
    for (a, b) in members.iter().zip(members.iter().skip(1)) {
        if a.utf16 == b.utf16 {
            return Err(JcsError::DuplicateKey {
                offset: a.offset.max(b.offset),
            });
        }
    }
    Ok(JcsValue::Object(JcsObject {
        entries: members
            .into_iter()
            .map(|member| (member.key, member.value))
            .collect(),
    }))
}

fn safe_integer(negative: bool, magnitude: u64, start: usize) -> Result<JcsNumber, JcsError> {
    let out_of_range = JcsError::NumberOutOfRange { offset: start };
    let value = i64::try_from(magnitude).map_err(|_| out_of_range)?;
    let value = if negative {
        value.checked_neg().ok_or(out_of_range)?
    } else {
        value
    };
    Ok(JcsNumber {
        canonical: value.to_string(),
        int: Some(value),
    })
}

fn ecma_number(token: &[u8], start: usize, mode: NumberMode) -> Result<JcsNumber, JcsError> {
    let malformed = JcsError::UnexpectedByte { offset: start };
    let text = core::str::from_utf8(token).map_err(|_| malformed)?;
    let parsed: f64 = text.parse().map_err(|_| malformed)?;
    if !parsed.is_finite() {
        return Err(JcsError::NumberNotFinite { offset: start });
    }
    if mode == NumberMode::EcmaSafe
        && !(-9_007_199_254_740_991.0_f64..=9_007_199_254_740_991.0_f64).contains(&parsed)
    {
        return Err(JcsError::NumberOutOfRange { offset: start });
    }
    let value = if parsed.to_bits() == NEG_ZERO_BITS {
        0.0
    } else {
        parsed
    };
    let mut buffer = ryu_js::Buffer::new();
    let canonical = buffer.format_finite(value).to_owned();
    let int = canonical
        .parse::<i64>()
        .ok()
        .filter(|i| (MIN_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(i));
    Ok(JcsNumber { canonical, int })
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
    depth: usize,
    nodes: usize,
    options: ParseOptions,
}

impl Cursor<'_> {
    fn peek(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }

    fn eof(&self) -> JcsError {
        JcsError::UnexpectedEof {
            offset: self.buf.len(),
        }
    }

    fn unexpected(&self) -> JcsError {
        if self.peek().is_some() {
            JcsError::UnexpectedByte { offset: self.pos }
        } else {
            self.eof()
        }
    }

    fn bump(&mut self) -> Result<(), JcsError> {
        self.pos = self
            .pos
            .checked_add(1)
            .ok_or(JcsError::InputTooLarge { offset: self.pos })?;
        Ok(())
    }

    fn skip_ws(&mut self) -> Result<(), JcsError> {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.bump()?;
        }
        Ok(())
    }

    fn expect_byte(&mut self, want: u8) -> Result<(), JcsError> {
        if self.peek() == Some(want) {
            self.bump()
        } else {
            Err(self.unexpected())
        }
    }

    fn value(&mut self) -> Result<JcsValue, JcsError> {
        let start = self.pos;
        let over_limit = JcsError::NodeLimitExceeded { offset: start };
        self.nodes = self.nodes.checked_add(1).ok_or(over_limit)?;
        if self.nodes > self.options.max_nodes {
            return Err(over_limit);
        }
        match self.peek() {
            None => Err(self.eof()),
            Some(b'{') => {
                self.enter(start)?;
                let value = self.object();
                self.leave();
                value
            }
            Some(b'[') => {
                self.enter(start)?;
                let value = self.array();
                self.leave();
                value
            }
            Some(b'"') => self.string().map(JcsValue::String),
            Some(b'-' | b'0'..=b'9') => self.number().map(JcsValue::Number),
            Some(b't') => self.literal(b"true").map(|()| JcsValue::Bool(true)),
            Some(b'f') => self.literal(b"false").map(|()| JcsValue::Bool(false)),
            Some(b'n') => self.literal(b"null").map(|()| JcsValue::Null),
            Some(_) => Err(JcsError::UnexpectedByte { offset: start }),
        }
    }

    fn enter(&mut self, start: usize) -> Result<(), JcsError> {
        let too_deep = JcsError::DepthExceeded { offset: start };
        let depth = self.depth.checked_add(1).ok_or(too_deep)?;
        if depth > self.options.max_depth {
            return Err(too_deep);
        }
        self.depth = depth;
        self.bump()
    }

    fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn object(&mut self) -> Result<JcsValue, JcsError> {
        let mut members = Vec::new();
        self.skip_ws()?;
        match self.peek() {
            Some(b'}') => {
                self.bump()?;
                return Ok(JcsValue::Object(JcsObject {
                    entries: Vec::new(),
                }));
            }
            Some(b'"') => {}
            _ => return Err(self.unexpected()),
        }
        loop {
            let offset = self.pos;
            let key = self.string()?;
            self.skip_ws()?;
            self.expect_byte(b':')?;
            self.skip_ws()?;
            let value = self.value()?;
            members.push(Member {
                utf16: key.as_str().encode_utf16().collect(),
                offset,
                key,
                value,
            });
            self.skip_ws()?;
            match self.peek() {
                Some(b',') => {
                    self.bump()?;
                    self.skip_ws()?;
                    if self.peek() != Some(b'"') {
                        return Err(self.unexpected());
                    }
                }
                Some(b'}') => {
                    self.bump()?;
                    break;
                }
                _ => return Err(self.unexpected()),
            }
        }
        finish_object(members)
    }

    fn array(&mut self) -> Result<JcsValue, JcsError> {
        let mut items = Vec::new();
        self.skip_ws()?;
        if self.peek() == Some(b']') {
            self.bump()?;
            return Ok(JcsValue::Array(items));
        }
        loop {
            items.push(self.value()?);
            self.skip_ws()?;
            match self.peek() {
                Some(b',') => {
                    self.bump()?;
                    self.skip_ws()?;
                }
                Some(b']') => {
                    self.bump()?;
                    return Ok(JcsValue::Array(items));
                }
                _ => return Err(self.unexpected()),
            }
        }
    }

    fn string(&mut self) -> Result<JcsString, JcsError> {
        self.expect_byte(b'"')?;
        let mut out = String::new();
        loop {
            let Some(byte) = self.peek() else {
                return Err(self.eof());
            };
            match byte {
                b'"' => {
                    self.bump()?;
                    return Ok(JcsString::new(out));
                }
                b'\\' => self.escape(&mut out)?,
                0x00..=0x1F => return Err(JcsError::ControlCharInString { offset: self.pos }),
                0x20..=0x21 | 0x23..=0x5B | 0x5D..=0x7F => {
                    out.push(char::from(byte));
                    self.bump()?;
                }
                0xC2..=0xDF => self.utf8_sequence(&mut out, 2)?,
                0xE0..=0xEF => self.utf8_sequence(&mut out, 3)?,
                0xF0..=0xF4 => self.utf8_sequence(&mut out, 4)?,
                _ => return Err(JcsError::InvalidUtf8 { offset: self.pos }),
            }
        }
    }

    fn utf8_sequence(&mut self, out: &mut String, width: usize) -> Result<(), JcsError> {
        let start = self.pos;
        let invalid = JcsError::InvalidUtf8 { offset: start };
        let end = start.checked_add(width).ok_or(invalid)?;
        let bytes = self.buf.get(start..end).ok_or(invalid)?;
        let text = core::str::from_utf8(bytes).map_err(|_| invalid)?;
        out.push_str(text);
        self.pos = end;
        Ok(())
    }

    fn escape(&mut self, out: &mut String) -> Result<(), JcsError> {
        let start = self.pos;
        self.bump()?;
        let Some(byte) = self.peek() else {
            return Err(self.eof());
        };
        let decoded = match byte {
            b'"' => '"',
            b'\\' => '\\',
            b'/' => '/',
            b'b' => '\u{8}',
            b'f' => '\u{c}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => {
                self.bump()?;
                return self.unicode_escape(start, out);
            }
            _ => return Err(JcsError::InvalidEscape { offset: start }),
        };
        out.push(decoded);
        self.bump()
    }

    fn unicode_escape(&mut self, start: usize, out: &mut String) -> Result<(), JcsError> {
        let unit = self.hex4(start)?;
        let lone = JcsError::LoneSurrogate { offset: start };
        if (0xD800..=0xDBFF).contains(&unit) {
            let second = self.pos;
            if self.peek() != Some(b'\\') {
                return Err(lone);
            }
            self.bump()?;
            if self.peek() != Some(b'u') {
                return Err(lone);
            }
            self.bump()?;
            let low = self.hex4(second)?;
            if !(0xDC00..=0xDFFF).contains(&low) {
                return Err(lone);
            }
            let decoded = char::decode_utf16([unit, low])
                .next()
                .and_then(Result::ok)
                .ok_or(lone)?;
            out.push(decoded);
        } else if (0xDC00..=0xDFFF).contains(&unit) {
            return Err(lone);
        } else {
            let decoded =
                char::from_u32(u32::from(unit)).ok_or(JcsError::InvalidEscape { offset: start })?;
            out.push(decoded);
        }
        Ok(())
    }

    /// Reads exactly four hex digits, checking each one (`from_str_radix` would accept `+`).
    fn hex4(&mut self, start: usize) -> Result<u16, JcsError> {
        let invalid = JcsError::InvalidEscape { offset: start };
        let mut unit: u16 = 0;
        for _ in 0..4 {
            let Some(byte) = self.peek() else {
                return Err(self.eof());
            };
            let digit = char::from(byte)
                .to_digit(16)
                .and_then(|d| u16::try_from(d).ok())
                .ok_or(invalid)?;
            unit = unit
                .checked_mul(16)
                .and_then(|u| u.checked_add(digit))
                .ok_or(invalid)?;
            self.bump()?;
        }
        Ok(unit)
    }

    fn number(&mut self) -> Result<JcsNumber, JcsError> {
        let start = self.pos;
        let negative = self.peek() == Some(b'-');
        if negative {
            self.bump()?;
        }
        let safe_only = self.options.numbers == NumberMode::SafeInteger;
        let mut magnitude: u64 = 0;
        match self.peek() {
            Some(b'0') => {
                self.bump()?;
                if matches!(self.peek(), Some(b'0'..=b'9')) {
                    return Err(JcsError::LeadingZero { offset: self.pos });
                }
            }
            Some(b'1'..=b'9') => {
                while let Some(byte @ b'0'..=b'9') = self.peek() {
                    if safe_only {
                        let digit = u64::from(char::from(byte).to_digit(10).unwrap_or(0));
                        magnitude = magnitude
                            .checked_mul(10)
                            .and_then(|m| m.checked_add(digit))
                            .filter(|m| *m <= MAX_SAFE_U64)
                            .ok_or(JcsError::NumberOutOfRange { offset: start })?;
                    }
                    self.bump()?;
                }
            }
            _ => return Err(self.unexpected()),
        }
        let has_fraction_or_exponent = matches!(self.peek(), Some(b'.' | b'e' | b'E'));
        if safe_only {
            if has_fraction_or_exponent {
                return Err(JcsError::NonIntegerNumber { offset: self.pos });
            }
            return safe_integer(negative, magnitude, start);
        }
        if has_fraction_or_exponent {
            self.fraction_and_exponent()?;
        }
        let token = self
            .buf
            .get(start..self.pos)
            .ok_or(JcsError::UnexpectedByte { offset: start })?;
        ecma_number(token, start, self.options.numbers)
    }

    fn fraction_and_exponent(&mut self) -> Result<(), JcsError> {
        if self.peek() == Some(b'.') {
            self.bump()?;
            self.digits()?;
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.bump()?;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.bump()?;
            }
            self.digits()?;
        }
        Ok(())
    }

    /// Consumes one or more ASCII digits.
    fn digits(&mut self) -> Result<(), JcsError> {
        if !matches!(self.peek(), Some(b'0'..=b'9')) {
            return Err(self.unexpected());
        }
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.bump()?;
        }
        Ok(())
    }

    fn literal(&mut self, word: &[u8]) -> Result<(), JcsError> {
        for &expected in word {
            if self.peek() == Some(expected) {
                self.bump()?;
            } else {
                return Err(self.unexpected());
            }
        }
        Ok(())
    }
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

    /// The six-character JSON escape for a UTF-16 code unit given in hex.
    fn u(hex: &str) -> String {
        format!("\\u{hex}")
    }

    fn err(input: &[u8]) -> JcsError {
        parse(input).unwrap_err()
    }

    fn canon(input: &[u8]) -> String {
        String::from_utf8(canonicalize(input).unwrap()).unwrap()
    }

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut out, b| {
            write!(out, "{b:02x}").unwrap();
            out
        })
    }

    #[test]
    fn known_answer_digest() {
        assert_eq!(
            digest(b"{}").unwrap(),
            "sha-256:RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o"
        );
    }

    #[test]
    fn error_offsets() {
        let cases: Vec<(Vec<u8>, JcsError)> = vec![
            (b"".to_vec(), JcsError::UnexpectedEof { offset: 0 }),
            (b"   ".to_vec(), JcsError::UnexpectedEof { offset: 3 }),
            (
                vec![0xEF, 0xBB, 0xBF, b'{', b'}'],
                JcsError::ByteOrderMark { offset: 0 },
            ),
            (b"{} x".to_vec(), JcsError::TrailingData { offset: 3 }),
            (
                br#"{"a":1,}"#.to_vec(),
                JcsError::UnexpectedByte { offset: 7 },
            ),
            (b"[1,]".to_vec(), JcsError::UnexpectedByte { offset: 3 }),
            (
                br#"{"a" 1}"#.to_vec(),
                JcsError::UnexpectedByte { offset: 5 },
            ),
            (
                br#"{"a":1 "b":2}"#.to_vec(),
                JcsError::UnexpectedByte { offset: 7 },
            ),
            (
                br#"{"a":1,"a":2}"#.to_vec(),
                JcsError::DuplicateKey { offset: 7 },
            ),
            (
                format!(r#"{{"e{}":1,"{}":2}}"#, u("0301"), u("00e9")).into_bytes(),
                JcsError::DuplicateKey { offset: 13 },
            ),
            (br#""\u12""#.to_vec(), JcsError::InvalidEscape { offset: 1 }),
            (
                br#""\u+123""#.to_vec(),
                JcsError::InvalidEscape { offset: 1 },
            ),
            (br#""\x""#.to_vec(), JcsError::InvalidEscape { offset: 1 }),
            (
                format!("\"{}\"", u("d800")).into_bytes(),
                JcsError::LoneSurrogate { offset: 1 },
            ),
            (
                format!("\"{}{}\"", u("d800"), u("0041")).into_bytes(),
                JcsError::LoneSurrogate { offset: 1 },
            ),
            (
                format!("\"{}\"", u("dc00")).into_bytes(),
                JcsError::LoneSurrogate { offset: 1 },
            ),
            (
                b"\"a\x01\"".to_vec(),
                JcsError::ControlCharInString { offset: 2 },
            ),
            (
                vec![b'"', 0xC0, 0xAF, b'"'],
                JcsError::InvalidUtf8 { offset: 1 },
            ),
            (
                vec![b'"', 0xED, 0xA0, 0x80, b'"'],
                JcsError::InvalidUtf8 { offset: 1 },
            ),
            (
                vec![b'"', 0xF4, 0x90, 0x80, 0x80, b'"'],
                JcsError::InvalidUtf8 { offset: 1 },
            ),
            (vec![b'"', 0x80, b'"'], JcsError::InvalidUtf8 { offset: 1 }),
            (b"\"abc".to_vec(), JcsError::UnexpectedEof { offset: 4 }),
            (b"00".to_vec(), JcsError::LeadingZero { offset: 1 }),
            (b"-01".to_vec(), JcsError::LeadingZero { offset: 2 }),
            (b"-".to_vec(), JcsError::UnexpectedEof { offset: 1 }),
            (b"+1".to_vec(), JcsError::UnexpectedByte { offset: 0 }),
            (b".5".to_vec(), JcsError::UnexpectedByte { offset: 0 }),
            (
                b"9007199254740992".to_vec(),
                JcsError::NumberOutOfRange { offset: 0 },
            ),
            (
                b"-9007199254740992".to_vec(),
                JcsError::NumberOutOfRange { offset: 0 },
            ),
            (
                "[".repeat(65).into_bytes(),
                JcsError::DepthExceeded { offset: 64 },
            ),
            (b"tru".to_vec(), JcsError::UnexpectedEof { offset: 3 }),
            (b"trux".to_vec(), JcsError::UnexpectedByte { offset: 3 }),
        ];
        for (input, expected) in cases {
            assert_eq!(
                parse(&input).unwrap_err(),
                expected,
                "input {:?}",
                String::from_utf8_lossy(&input)
            );
        }
    }

    #[cfg(not(feature = "lenient-numbers"))]
    #[test]
    fn strict_rejects_fractions_and_exponents() {
        assert_eq!(err(b"1.5"), JcsError::NonIntegerNumber { offset: 1 });
        assert_eq!(err(b"1e2"), JcsError::NonIntegerNumber { offset: 1 });
        assert_eq!(err(b"1.0"), JcsError::NonIntegerNumber { offset: 1 });
        assert_eq!(
            err("1".repeat(400).as_bytes()),
            JcsError::NumberOutOfRange { offset: 0 }
        );
    }

    #[cfg(feature = "lenient-numbers")]
    #[test]
    fn lenient_request_numbers() {
        for (input, expected) in [
            ("1.0", "1"),
            ("1e2", "100"),
            ("1E-7", "1e-7"),
            ("-0.0", "0"),
            ("123.456e2", "12345.6"),
            ("0.1", "0.1"),
        ] {
            assert_eq!(canon(input.as_bytes()), expected, "input {input}");
        }
        assert_eq!(err(b"1e400"), JcsError::NumberNotFinite { offset: 0 });
        assert_eq!(err(b"1e16"), JcsError::NumberOutOfRange { offset: 0 });
        assert_eq!(err(b"1."), JcsError::UnexpectedEof { offset: 2 });
        assert_eq!(
            err("1".repeat(400).as_bytes()),
            JcsError::NumberNotFinite { offset: 0 }
        );
    }

    #[test]
    fn accepted_values() {
        assert_eq!(canon(b"-0"), "0");
        assert_eq!(canon(br#"[-0,{"a":-0}]"#), r#"[0,{"a":0}]"#);
        let deep = format!("{}{}", "[".repeat(64), "]".repeat(64));
        assert_eq!(canon(deep.as_bytes()), deep);
        assert_eq!(canon(b"9007199254740991"), "9007199254740991");
        assert_eq!(canon(b"-9007199254740991"), "-9007199254740991");
        assert_eq!(
            canon(b" \t\r\n{ \"b\" : [ true , false , null ] , \"a\" : 1 } \n"),
            r#"{"a":1,"b":[true,false,null]}"#
        );
        assert_eq!(canon(b"\"/\""), "\"/\"");
    }

    #[test]
    fn nfc_equivalent_strings_serialize_identically() {
        let expected = vec![0x22, 0xC3, 0xA9, 0x22];
        let composed = format!("\"{}\"", u("00E9"));
        let decomposed = format!("\"e{}\"", u("0301"));
        assert_eq!(canonicalize(composed.as_bytes()).unwrap(), expected);
        assert_eq!(canonicalize(decomposed.as_bytes()).unwrap(), expected);
        assert_eq!(canonicalize(b"\"e\xCC\x81\"").unwrap(), expected);
    }

    #[test]
    fn in_memory_string_is_nfc() {
        assert_eq!(JcsString::new("e\u{301}").as_str(), "\u{e9}");
        assert_eq!(
            JcsValue::string("e\u{301}").to_canonical_bytes(),
            vec![0x22, 0xC3, 0xA9, 0x22]
        );
        let duplicate = JcsObject::from_entries(vec![
            (JcsString::new("e\u{301}"), JcsValue::Null),
            (JcsString::new("\u{e9}"), JcsValue::Null),
        ]);
        assert_eq!(duplicate, Err(JcsError::DuplicateKey { offset: 0 }));
    }

    #[test]
    fn surrogate_pair_round_trips() {
        let input = format!("\"{}{}\"", u("d83d"), u("de00"));
        assert_eq!(
            canonicalize(input.as_bytes()).unwrap(),
            vec![0x22, 0xF0, 0x9F, 0x98, 0x80, 0x22]
        );
    }

    #[test]
    fn control_characters_are_escaped() {
        let value = JcsValue::string("\u{1}\u{1f}\u{8}\t\n\u{c}\r\"\\/\u{7f}\u{2028}");
        let expected = format!(
            "\"{e}0001{e}001f\\b\\t\\n\\f\\r\\\"\\\\/\u{7f}\u{2028}\"",
            e = "\\u"
        );
        assert_eq!(value.to_canonical_string(), expected);
        assert_eq!(parse(expected.as_bytes()).unwrap(), value);
    }

    #[test]
    fn rfc8785_sort_vector_nfc() {
        let input = format!(
            r#"{{"{}":"Euro Sign","\r":"Carriage Return","{}":"Hebrew Letter Dalet With Dagesh","1":"One","{}{}":"Emoji: Grinning Face","{}":"Control","{}":"Latin Small Letter O With Diaeresis"}}"#,
            u("20ac"),
            u("fb33"),
            u("d83d"),
            u("de00"),
            u("0080"),
            u("00f6")
        );
        let bytes = canonicalize(input.as_bytes()).unwrap();
        assert_eq!(bytes.len(), 181);
        assert_eq!(
            hex(&bytes),
            "7b225c72223a2243617272696167652052657475726e222c2231223a224f6e65222c22c280223a22436f6e74726f6c222c22c3b6223a224c6174696e20536d616c6c204c6574746572204f205769746820446961657265736973222c22d793d6bc223a22486562726577204c65747465722044616c6574205769746820446167657368222c22e282ac223a224575726f205369676e222c22f09f9880223a22456d6f6a693a204772696e6e696e672046616365227d"
        );
        assert_eq!(
            digest(input.as_bytes()).unwrap(),
            "sha-256:mgPbgbBjohAvazT5LBgyJA_w6YmlxvrHDvBHwIx3EZ8"
        );
    }

    #[test]
    fn utf16_vs_codepoint_order() {
        let input = format!(
            r#"{{"{}":"PUA","{}{}":"Emoji","{}":"Euro"}}"#,
            u("e000"),
            u("d83d"),
            u("de00"),
            u("20ac")
        );
        let bytes = canonicalize(input.as_bytes()).unwrap();
        assert_eq!(
            hex(&bytes),
            "7b22e282ac223a224575726f222c22f09f9880223a22456d6f6a69222c22ee8080223a22505541227d"
        );
        assert_eq!(
            digest(input.as_bytes()).unwrap(),
            "sha-256:jNh0WYS4ffXX2aXqkhvL-ODli8yRoW9Hl5cJkVcLwgU"
        );
    }

    #[test]
    fn action_and_origin_digests() {
        let a = parse(br#"{"recipient_id":"rcpt_123","currency":"USD","amount":5000}"#).unwrap();
        let b =
            parse(b" { \"amount\" : 5000 , \"recipient_id\":\"rcpt_123\",\"currency\":\"USD\"}")
                .unwrap();
        assert_eq!(
            action_digest("pay_invoice", &a),
            "sha-256:j3XfycsYi2G8jSVocXUTiPN2JWbcwQfOK1L4pLAdI1E"
        );
        assert_eq!(
            action_digest("pay_invoice", &a),
            action_digest("pay_invoice", &b)
        );
        let query = parse(br#"{"invoice_id":"inv_42"}"#).unwrap();
        let query_digest = action_digest("get_invoice", &query);
        assert_eq!(
            query_digest,
            "sha-256:bdmNQo66RS-48sR_0n8pP5jmbo0a0Sh00gUWv8nEDNU"
        );
        let value = parse(b"5000").unwrap();
        let origin = OriginRef {
            source_call_id: "7",
            tool: "get_invoice",
            query_digest: &query_digest,
            result_pointer: "/total_minor",
            value: &value,
        };
        assert_eq!(
            origin_hash(&origin),
            "sha-256:2pEVfWny8jku05UQCRDDarGnSs_F2tZB7_YtsC-7SYU"
        );
    }

    #[test]
    fn json_pointer() {
        let value = parse(br#"{"a/b":{"~x":[10,20]},"":1}"#).unwrap();
        assert_eq!(
            value.pointer("/a~1b/~0x/1").and_then(JcsValue::as_i64),
            Some(20)
        );
        assert_eq!(value.pointer("/a~1b/~0x/01"), None);
        assert_eq!(value.pointer("/a~1b/~0x/-"), None);
        assert_eq!(value.pointer("/a~2"), None);
        assert_eq!(value.pointer("/").and_then(JcsValue::as_i64), Some(1));
        assert_eq!(value.pointer(""), Some(&value));
        assert_eq!(value.pointer("a"), None);
    }

    #[test]
    fn nodes_and_leaves() {
        let value = parse(br#"{"a":[1,{"b":"x"}],"c/d":null}"#).unwrap();
        let leaves: Vec<(String, usize)> = value
            .leaves()
            .into_iter()
            .map(|node| (node.pointer, node.depth))
            .collect();
        assert_eq!(
            leaves,
            vec![
                ("/a/0".to_owned(), 2),
                ("/a/1/b".to_owned(), 3),
                ("/c~1d".to_owned(), 1)
            ]
        );
        assert_eq!(value.nodes().len(), 6);
    }

    #[test]
    fn node_and_size_limits() {
        let options = ParseOptions {
            max_nodes: 3,
            ..ParseOptions::request()
        };
        assert_eq!(
            parse_with(b"[1,2,3]", &options).unwrap_err(),
            JcsError::NodeLimitExceeded { offset: 5 }
        );
        assert_eq!(parse_with(b"[1,2]", &options).unwrap().nodes, 3);
        let small = ParseOptions {
            max_bytes: 4,
            ..ParseOptions::request()
        };
        assert_eq!(
            parse_with(b"[1,2]", &small).unwrap_err(),
            JcsError::InputTooLarge { offset: 4 }
        );
    }

    #[test]
    fn result_profile_numbers() {
        let options = ParseOptions::result(1024, 64);
        let fraction = parse_with(b"12.5", &options).unwrap().value;
        assert_eq!(fraction.to_canonical_string(), "12.5");
        assert_eq!(fraction.as_i64(), None);
        let big = parse_with(b"18446744073709551615", &options).unwrap().value;
        assert_eq!(big.to_canonical_string(), "18446744073709552000");
        assert_eq!(big.as_i64(), None);
        let nanos = parse_with(b"1729771234123456789", &options).unwrap().value;
        assert_eq!(nanos.as_i64(), None);
        let safe = parse_with(b"30000.0", &options).unwrap().value;
        assert_eq!(safe, JcsValue::int(30_000).unwrap());
        assert_eq!(
            parse_with(b"1e400", &options).unwrap_err(),
            JcsError::NumberNotFinite { offset: 0 }
        );
        assert_eq!(
            parse_with(b"-0", &options)
                .unwrap()
                .value
                .to_canonical_string(),
            "0"
        );
    }

    #[test]
    fn safe_integer_constructor_bounds() {
        assert!(JcsNumber::from_i64(MAX_SAFE_INTEGER).is_some());
        assert!(JcsNumber::from_i64(MIN_SAFE_INTEGER).is_some());
        assert!(JcsNumber::from_i64(MAX_SAFE_INTEGER + 1).is_none());
        assert!(JcsNumber::from_i64(MIN_SAFE_INTEGER - 1).is_none());
    }

    #[test]
    fn error_offset_accessor() {
        assert_eq!(err(b"[1,]").offset(), 3);
    }
}
