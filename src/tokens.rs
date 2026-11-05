//! ES256 compact JWS for the Episode Token (SPEC §3.3) and the per-call Call Proof (SPEC §3.4),
//! and the broker's bounded replay cache (`WEEK2_PLAN.md` T1).
//!
//! Both token types follow the same JOSE rules (rfc8725bis-10):
//! - ES256 only. The two token types never share a key, and their `typ`s differ, so the two
//!   validations are mutually exclusive.
//! - The protected header is exactly `alg`, `typ` and `kid`. `kid` is the RFC 7638 thumbprint
//!   of the current boot's key, and it is checked before the signature, so a token from an
//!   earlier boot fails on `kid`.
//! - A compact token uses only `[A-Za-z0-9_.-]`, has three parts, and each part is strict
//!   unpadded base64url with zero trailing bits. Header and claims must be JCS-canonical JSON,
//!   parsed with `jcs` (duplicate members rejected). So each token has exactly one encoding.
//! - The signature is a 64-byte r‖s. The signer makes it low-S, and both verifiers reject
//!   high-S, so each token also has exactly one valid signature (`p256` itself accepts high-S).
//! - Claims are an exact set: a missing or an extra member rejects.
//!
//! Time checks run against a high-water mark that never decreases, so a backward clock step
//! cannot re-admit an expired token or proof. Clock readings are injected as whole Unix
//! seconds ([`unix_now`] in production). Keys and `jti`s come from an injected entropy source,
//! `/dev/urandom` in production ([`os_entropy`]), so the crate needs no `getrandom`.

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};

use crate::engine::{Budget, PEP_DENIED, PEP_UNAVAILABLE, ResState, Reservation};
use crate::engine::{decode_ulid, encode_ulid};
use crate::jcs::{self, JcsObject, JcsString, JcsValue, NumberMode, ParseOptions};

/// The only signature algorithm.
pub const ALG: &str = "ES256";
/// `typ` of the Episode Token (SPEC §3.3).
pub const EPISODE_TYP: &str = "pep-episode+jwt";
/// `typ` of the Call Proof (SPEC §3.4).
pub const CALL_PROOF_TYP: &str = "pep-callproof+jwt";
/// `iss` of every Call Proof: the PEP.
pub const CALL_PROOF_ISS: &str = "spiffe://corp.example/pep";
/// `aud` of every Call Proof: the broker, its only verifier.
pub const CALL_PROOF_AUD: &str = "spiffe://corp.example/broker";
/// Longest Call Proof lifetime, `exp - iat`.
pub const CALL_PROOF_TTL_SECS: u64 = 60;
/// Longest Episode Token lifetime, `exp - iat` (8 hours).
pub const EPISODE_MAX_LIFETIME_SECS: u64 = 28_800;
/// The episode idle timeout of E1 (30 minutes).
pub const EPISODE_IDLE_SECS: u64 = 1_800;
/// The clock skew T1 allows on `iat` and `exp`.
pub const CLOCK_SKEW_SECS: u64 = 2;
/// The replay cache capacity T1 sizes from the rate limit and the episode cap.
pub const REPLAY_CACHE_ENTRIES: usize = 32_768;
/// Longest compact token accepted or issued.
pub const MAX_TOKEN_BYTES: usize = 8_192;

const SIGNATURE_BYTES: usize = 64;
const SCALAR_BYTES: usize = 32;
const JTI_BYTES: usize = 16;
const MAX_JTI_CHARS: usize = 64;
const KEY_ATTEMPTS: usize = 8;
const DIGEST_PREFIX: &str = "sha-256:";
const DIGEST_CHARS: usize = 43;
const MAX_PROV: usize = 2;

/// JSON limits for one token segment. Claims are safe integers whatever the cargo features,
/// and a segment is small and shallow.
const SEGMENT_OPTIONS: ParseOptions = ParseOptions {
    numbers: NumberMode::SafeInteger,
    max_bytes: MAX_TOKEN_BYTES,
    max_depth: 4,
    max_nodes: 64,
    reject_noncharacters: true,
};

const HEADER_MEMBERS: [&str; 3] = ["alg", "kid", "typ"];
const EPISODE_MEMBERS: [&str; 10] = [
    "client_id",
    "eid",
    "exp",
    "iat",
    "intent_digest",
    "peer_uid",
    "rar_digest",
    "release_epoch",
    "sub",
    "txn",
];
const CALL_PROOF_MEMBERS: [&str; 10] = [
    "action_digest",
    "aud",
    "eid",
    "exp",
    "iat",
    "iss",
    "jti",
    "release_epoch",
    "server_id",
    "tool_schema_digest",
];
const PAYMENT_MEMBERS: [&str; 3] = ["budget", "prov", "rid"];
const BUDGET_MEMBERS: [&str; 4] = [
    "amount_minor",
    "committed_minor",
    "currency",
    "reserved_minor",
];

/// Why a token was refused, or could not be made.
#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    /// Not three strict base64url parts of canonical JSON within the size limit.
    #[error("malformed token")]
    Malformed,
    /// The protected header lacks `alg`, `typ` or `kid`, or has any other member.
    #[error("header member not allowed")]
    HeaderNotAllowed,
    /// `alg` is not ES256.
    #[error("algorithm not allowed")]
    AlgNotAllowed,
    /// `typ` is not the expected token type.
    #[error("wrong token type")]
    TypMismatch,
    /// `kid` is not the current boot's key.
    #[error("unknown key id")]
    KidMismatch,
    /// The signature is not a 64-byte r‖s of two valid non-zero scalars.
    #[error("malformed signature")]
    SignatureEncoding,
    /// The signature is high-S.
    #[error("high-S signature")]
    HighS,
    /// The signature does not verify.
    #[error("bad signature")]
    BadSignature,
    /// A claim is missing or extra, or has the wrong type or range.
    #[error("invalid claims")]
    InvalidClaims,
    /// `exp` is not after `iat`, or `exp - iat` is longer than the token type allows.
    #[error("token lifetime not allowed")]
    LifetimeNotAllowed,
    /// `iat` is more than the allowed skew in the future.
    #[error("token issued in the future")]
    NotYetValid,
    /// `exp` is more than the allowed skew in the past.
    #[error("token expired")]
    Expired,
    /// A Call Proof issued in or before the broker's boot second.
    #[error("proof predates the verifier's boot")]
    BeforeBoot,
    /// The proof's `jti` was already admitted.
    #[error("replayed proof")]
    Replayed,
    /// The replay cache is full of live entries. Nothing is evicted early (fail closed).
    #[error("replay cache full")]
    ReplayCacheFull,
    /// `iss` or `aud` is not the expected value.
    #[error("issuer or audience mismatch")]
    IssuerOrAudience,
    /// `server_id` is not the route's server.
    #[error("server mismatch")]
    ServerMismatch,
    /// `release_epoch` is not the verifier's.
    #[error("release epoch mismatch")]
    EpochMismatch,
    /// `tool_schema_digest` is not the pinned digest.
    #[error("tool schema digest mismatch")]
    SchemaDigestMismatch,
    /// `action_digest` is not the digest the verifier recomputed.
    #[error("action digest mismatch")]
    ActionDigestMismatch,
    /// `rid`, `prov` and `budget` are present on a non-payment proof, or absent on a payment.
    #[error("payment claims mismatch")]
    PaymentClaimsMismatch,
    /// `budget`'s amount or currency differs from the forwarded arguments.
    #[error("budget mismatch")]
    BudgetMismatch,
    /// The Episode Token's `peer_uid` is not the connection's uid.
    #[error("peer mismatch")]
    PeerMismatch,
    /// The Episode Token's `intent_digest` is not the configured intent's.
    #[error("intent mismatch")]
    IntentMismatch,
    /// The episode was never started in this boot.
    #[error("unknown episode")]
    UnknownEpisode,
    /// The episode was ended.
    #[error("episode ended")]
    EpisodeEnded,
    /// The episode went idle, which ends it for good.
    #[error("episode idle")]
    EpisodeIdle,
    /// The episode was already started.
    #[error("episode already started")]
    EpisodeExists,
    /// The episode table is full.
    #[error("too many episodes")]
    TooManyEpisodes,
    /// The reservation is not `Held`, so it gets no payment proof (F-15).
    #[error("reservation is not held")]
    NotHeld,
    /// No valid signing key could be made from the entropy source.
    #[error("key generation failed")]
    KeyGeneration,
    /// Signing failed.
    #[error("signing failed")]
    Signing,
    /// The public key is not a valid P-256 point.
    #[error("invalid public key")]
    InvalidKey,
    /// Reading the entropy source failed.
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
    /// The system clock reads before the Unix epoch.
    #[error("clock before the Unix epoch")]
    Clock,
    /// A lock was poisoned by a panicking thread.
    #[error("internal lock poisoned")]
    Poisoned,
}

impl TokenError {
    /// The only text an agent may see (U1): a refused token is [`PEP_DENIED`], and a fault of
    /// the PEP itself, a full replay cache included, is [`PEP_UNAVAILABLE`].
    #[must_use]
    pub const fn to_agent_code(&self) -> &'static str {
        match self {
            Self::ReplayCacheFull
            | Self::KeyGeneration
            | Self::Signing
            | Self::Io(_)
            | Self::Clock
            | Self::Poisoned => PEP_UNAVAILABLE,
            _ => PEP_DENIED,
        }
    }
}

/// Opens `/dev/urandom`, the production entropy source for keys and `jti`s.
///
/// # Errors
///
/// Returns [`TokenError::Io`] if it cannot be opened.
pub fn os_entropy() -> Result<File, TokenError> {
    Ok(File::open("/dev/urandom")?)
}

/// The current Unix time in whole seconds.
///
/// # Errors
///
/// Returns [`TokenError::Clock`] if the system clock reads before the Unix epoch.
pub fn unix_now() -> Result<u64, TokenError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .map_err(|_| TokenError::Clock)
}

/// A fresh `jti`: 16 bytes from `entropy`, as unpadded base64url.
///
/// # Errors
///
/// Returns [`TokenError::Io`] if `entropy` cannot supply 16 bytes.
pub fn new_jti<R: Read>(entropy: &mut R) -> Result<String, TokenError> {
    let mut bytes = [0_u8; JTI_BYTES];
    entropy.read_exact(&mut bytes)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// A per-boot ES256 signing key and its `kid`. Each token type gets its own key.
pub struct Es256Signer {
    key: SigningKey,
    verifier: Es256Verifier,
}

impl fmt::Debug for Es256Signer {
    /// Prints the `kid` only, never the secret.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Es256Signer")
            .field("kid", &self.verifier.kid)
            .finish_non_exhaustive()
    }
}

impl Es256Signer {
    /// Makes a key from `entropy`, drawing 32 bytes until they form a valid non-zero scalar
    /// below the group order (at most eight draws; one almost always suffices).
    ///
    /// # Errors
    ///
    /// Returns [`TokenError::Io`] if `entropy` runs dry, or [`TokenError::KeyGeneration`] if
    /// no draw forms a valid key.
    pub fn generate<R: Read>(entropy: &mut R) -> Result<Self, TokenError> {
        for _ in 0..KEY_ATTEMPTS {
            let mut bytes = [0_u8; SCALAR_BYTES];
            entropy.read_exact(&mut bytes)?;
            if let Ok(key) = SigningKey::from_slice(&bytes) {
                return Self::from_key(key);
            }
        }
        Err(TokenError::KeyGeneration)
    }

    /// Makes a key from a 32-byte big-endian secret scalar (fixed test vectors).
    ///
    /// # Errors
    ///
    /// Returns [`TokenError::KeyGeneration`] if the bytes are not a valid secret scalar.
    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self, TokenError> {
        Self::from_key(SigningKey::from_slice(bytes).map_err(|_| TokenError::KeyGeneration)?)
    }

    fn from_key(key: SigningKey) -> Result<Self, TokenError> {
        let verifier = Es256Verifier::new(*key.verifying_key())?;
        Ok(Self { key, verifier })
    }

    /// The key's `kid`, its RFC 7638 thumbprint.
    #[must_use]
    pub fn kid(&self) -> &str {
        &self.verifier.kid
    }

    /// The matching verifier, to hand to the other side (the broker reads the Call Proof key
    /// from `/run/pep-pub`).
    #[must_use]
    pub fn verifier(&self) -> Es256Verifier {
        self.verifier.clone()
    }

    /// Signs `claims` as a compact JWS of type `typ`, with a low-S signature.
    fn sign(&self, typ: &str, claims: JcsObject) -> Result<String, TokenError> {
        let header = object(vec![
            ("alg", JcsValue::string(ALG)),
            ("kid", JcsValue::string(self.kid())),
            ("typ", JcsValue::string(typ)),
        ])?;
        let mut token = URL_SAFE_NO_PAD.encode(JcsValue::Object(header).to_canonical_bytes());
        token.push('.');
        token.push_str(&URL_SAFE_NO_PAD.encode(JcsValue::Object(claims).to_canonical_bytes()));
        let signature: Signature = self
            .key
            .try_sign(token.as_bytes())
            .map_err(|_| TokenError::Signing)?;
        let bytes = signature.normalize_s().to_bytes();
        let bytes: &[u8] = bytes.as_ref();
        token.push('.');
        token.push_str(&URL_SAFE_NO_PAD.encode(bytes));
        if token.len() > MAX_TOKEN_BYTES {
            return Err(TokenError::Malformed);
        }
        Ok(token)
    }
}

/// An ES256 verifying key and its `kid`.
#[derive(Debug, Clone)]
pub struct Es256Verifier {
    key: VerifyingKey,
    kid: String,
}

impl Es256Verifier {
    fn new(key: VerifyingKey) -> Result<Self, TokenError> {
        let kid = thumbprint(&key)?;
        Ok(Self { key, kid })
    }

    /// A verifier from a SEC1-encoded public key, such as the uncompressed key the PEP writes
    /// to `/run/pep-pub`.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError::InvalidKey`] for an encoding that is not a point on P-256.
    pub fn from_sec1(bytes: &[u8]) -> Result<Self, TokenError> {
        Self::new(VerifyingKey::from_sec1_bytes(bytes).map_err(|_| TokenError::InvalidKey)?)
    }

    /// A verifier from the base64url `x` and `y` of an EC JWK. Each must decode strictly to
    /// 32 bytes, and the point must be on the curve (`elliptic-curve` 0.14 has no JWK support,
    /// so this builds SEC1 `04‖x‖y`).
    ///
    /// # Errors
    ///
    /// Returns [`TokenError::InvalidKey`] for a bad coordinate or a point off the curve.
    pub fn from_jwk(x: &str, y: &str) -> Result<Self, TokenError> {
        let coordinate = |text: &str| {
            URL_SAFE_NO_PAD
                .decode(text)
                .ok()
                .filter(|bytes| bytes.len() == SCALAR_BYTES)
                .ok_or(TokenError::InvalidKey)
        };
        let mut sec1 = vec![0x04];
        sec1.extend(coordinate(x)?);
        sec1.extend(coordinate(y)?);
        Self::from_sec1(&sec1)
    }

    /// The uncompressed SEC1 encoding (`04‖x‖y`, 65 bytes).
    #[must_use]
    pub fn to_sec1_uncompressed(&self) -> Vec<u8> {
        self.key.to_sec1_point(false).as_bytes().to_vec()
    }

    /// The key's `kid`, its RFC 7638 thumbprint.
    #[must_use]
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Checks a compact JWS of type `typ` against this key and returns its claims. The order
    /// is fixed: size and charset, header (`alg`, `typ`, then `kid`), signature encoding and
    /// low-S, the signature itself, and only then the claims.
    fn verify(&self, token: &str, typ: &str) -> Result<JcsObject, TokenError> {
        if token.len() > MAX_TOKEN_BYTES || !token.bytes().all(is_compact_byte) {
            return Err(TokenError::Malformed);
        }
        let (signing_input, signature) = token.rsplit_once('.').ok_or(TokenError::Malformed)?;
        let (header, claims) = signing_input.split_once('.').ok_or(TokenError::Malformed)?;
        if claims.contains('.')
            || [header, claims, signature]
                .iter()
                .any(|part| part.is_empty())
        {
            return Err(TokenError::Malformed);
        }
        check_header(&decode_object(header)?, typ, &self.kid)?;
        let signature = URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| TokenError::Malformed)?;
        if signature.len() != SIGNATURE_BYTES {
            return Err(TokenError::SignatureEncoding);
        }
        let signature =
            Signature::from_slice(&signature).map_err(|_| TokenError::SignatureEncoding)?;
        if signature.normalize_s() != signature {
            return Err(TokenError::HighS);
        }
        self.key
            .verify(signing_input.as_bytes(), &signature)
            .map_err(|_| TokenError::BadSignature)?;
        decode_object(claims)
    }
}

/// The RFC 7638 thumbprint of a P-256 key: unpadded base64url of SHA-256 over
/// `{"crv":"P-256","kty":"EC","x":…,"y":…}`, which JCS already emits in the required order.
fn thumbprint(key: &VerifyingKey) -> Result<String, TokenError> {
    let point = key.to_sec1_point(false);
    let x: &[u8] = point.x().ok_or(TokenError::InvalidKey)?.as_ref();
    let y: &[u8] = point.y().ok_or(TokenError::InvalidKey)?.as_ref();
    let jwk = object(vec![
        ("crv", JcsValue::string("P-256")),
        ("kty", JcsValue::string("EC")),
        ("x", JcsValue::string(URL_SAFE_NO_PAD.encode(x))),
        ("y", JcsValue::string(URL_SAFE_NO_PAD.encode(y))),
    ])?;
    Ok(jcs::sha256_b64url(
        &JcsValue::Object(jwk).to_canonical_bytes(),
    ))
}

const fn is_compact_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')
}

const fn is_b64url_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
}

/// Decodes one segment: strict base64url, then JSON that must be an object and must already
/// be in canonical form.
fn decode_object(segment: &str) -> Result<JcsObject, TokenError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| TokenError::Malformed)?;
    let parsed = jcs::parse_with(&bytes, &SEGMENT_OPTIONS).map_err(|_| TokenError::Malformed)?;
    if parsed.value.to_canonical_bytes() != bytes {
        return Err(TokenError::Malformed);
    }
    match parsed.value {
        JcsValue::Object(object) => Ok(object),
        _ => Err(TokenError::Malformed),
    }
}

fn check_header(header: &JcsObject, typ: &str, kid: &str) -> Result<(), TokenError> {
    if !has_exactly(header, &HEADER_MEMBERS) {
        return Err(TokenError::HeaderNotAllowed);
    }
    let member = |key: &str| {
        header
            .get(key)
            .and_then(JcsValue::as_str)
            .ok_or(TokenError::HeaderNotAllowed)
    };
    if member("alg")? != ALG {
        return Err(TokenError::AlgNotAllowed);
    }
    if member("typ")? != typ {
        return Err(TokenError::TypMismatch);
    }
    if member("kid")? != kid {
        return Err(TokenError::KidMismatch);
    }
    Ok(())
}

fn has_exactly(object: &JcsObject, members: &[&str]) -> bool {
    object.len() == members.len() && members.iter().all(|member| object.contains_key(member))
}

fn object(entries: Vec<(&str, JcsValue)>) -> Result<JcsObject, TokenError> {
    JcsObject::from_entries(
        entries
            .into_iter()
            .map(|(key, value)| (JcsString::new(key), value))
            .collect(),
    )
    .map_err(|_| TokenError::InvalidClaims)
}

fn uint(value: u64) -> Result<JcsValue, TokenError> {
    i64::try_from(value)
        .ok()
        .and_then(JcsValue::int)
        .ok_or(TokenError::InvalidClaims)
}

fn text<'a>(object: &'a JcsObject, key: &str) -> Result<&'a str, TokenError> {
    object
        .get(key)
        .and_then(JcsValue::as_str)
        .ok_or(TokenError::InvalidClaims)
}

fn unsigned(object: &JcsObject, key: &str) -> Result<u64, TokenError> {
    object
        .get(key)
        .and_then(JcsValue::as_i64)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(TokenError::InvalidClaims)
}

/// A ULID `eid` in its one canonical spelling.
fn parse_eid(text: &str) -> Result<u128, TokenError> {
    decode_ulid(text)
        .filter(|eid| encode_ulid(*eid) == text)
        .ok_or(TokenError::InvalidClaims)
}

fn is_digest(text: &str) -> bool {
    text.strip_prefix(DIGEST_PREFIX)
        .is_some_and(|encoded| encoded.len() == DIGEST_CHARS && encoded.bytes().all(is_b64url_byte))
}

fn is_jti(text: &str) -> bool {
    !text.is_empty() && text.len() <= MAX_JTI_CHARS && text.bytes().all(is_b64url_byte)
}

fn is_currency(text: &str) -> bool {
    text.len() == 3 && text.bytes().all(|byte| byte.is_ascii_uppercase())
}

/// `exp` must be after `iat`, by at most `max` seconds.
fn check_lifetime(iat: u64, exp: u64, max: u64) -> Result<(), TokenError> {
    exp.checked_sub(iat)
        .filter(|lifetime| (1..=max).contains(lifetime))
        .map(drop)
        .ok_or(TokenError::LifetimeNotAllowed)
}

/// `iat` may be at most `skew` seconds in the future of `now`, and `exp` at most `skew`
/// seconds in its past. An overflow fails closed.
fn check_window(iat: u64, exp: u64, now: u64, skew: u64) -> Result<(), TokenError> {
    if now.checked_add(skew).is_none_or(|latest| iat > latest) {
        return Err(TokenError::NotYetValid);
    }
    if exp.checked_add(skew).is_none_or(|deadline| now > deadline) {
        return Err(TokenError::Expired);
    }
    Ok(())
}

fn lock<T>(mutex: &Mutex<T>) -> Result<MutexGuard<'_, T>, TokenError> {
    mutex.lock().map_err(|_| TokenError::Poisoned)
}

// ---- Episode Token (SPEC §3.3) ----

/// The claims of an Episode Token. `txn` is not stored: it always equals `eid`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpisodeClaims {
    /// The episode id, also `txn` and the engine's `episode_id`.
    pub eid: u128,
    /// Digest of the configured intent.
    pub intent_digest: String,
    /// Subject.
    pub sub: String,
    /// OAuth client id.
    pub client_id: String,
    /// The uid the token is bound to; it must equal the connection's peer uid.
    pub peer_uid: u32,
    /// Release epoch of the lockfile the episode was started under.
    pub release_epoch: u64,
    /// Digest of the RAR `authorization_details` (the configured intent's, until Week 5).
    pub rar_digest: String,
    /// Issued at, in Unix seconds.
    pub iat: u64,
    /// Expires at, in Unix seconds; `exp - iat` is at most [`EPISODE_MAX_LIFETIME_SECS`].
    pub exp: u64,
}

impl EpisodeClaims {
    fn to_object(&self) -> Result<JcsObject, TokenError> {
        let eid = encode_ulid(self.eid);
        object(vec![
            ("client_id", JcsValue::string(self.client_id.as_str())),
            ("eid", JcsValue::string(eid.as_str())),
            ("exp", uint(self.exp)?),
            ("iat", uint(self.iat)?),
            (
                "intent_digest",
                JcsValue::string(self.intent_digest.as_str()),
            ),
            ("peer_uid", uint(u64::from(self.peer_uid))?),
            ("rar_digest", JcsValue::string(self.rar_digest.as_str())),
            ("release_epoch", uint(self.release_epoch)?),
            ("sub", JcsValue::string(self.sub.as_str())),
            ("txn", JcsValue::string(eid)),
        ])
    }

    fn from_object(object: &JcsObject) -> Result<Self, TokenError> {
        if !has_exactly(object, &EPISODE_MEMBERS) {
            return Err(TokenError::InvalidClaims);
        }
        let eid_text = text(object, "eid")?;
        let eid = parse_eid(eid_text)?;
        if text(object, "txn")? != eid_text {
            return Err(TokenError::InvalidClaims);
        }
        let claims = Self {
            eid,
            intent_digest: text(object, "intent_digest")?.to_owned(),
            sub: text(object, "sub")?.to_owned(),
            client_id: text(object, "client_id")?.to_owned(),
            peer_uid: u32::try_from(unsigned(object, "peer_uid")?)
                .map_err(|_| TokenError::InvalidClaims)?,
            release_epoch: unsigned(object, "release_epoch")?,
            rar_digest: text(object, "rar_digest")?.to_owned(),
            iat: unsigned(object, "iat")?,
            exp: unsigned(object, "exp")?,
        };
        check_lifetime(claims.iat, claims.exp, EPISODE_MAX_LIFETIME_SECS)?;
        Ok(claims)
    }
}

/// What the PEP requires of an Episode Token on one connection (M1).
#[derive(Debug, Clone, Copy)]
pub struct EpisodeExpectations<'a> {
    /// The connection's peer uid.
    pub peer_uid: u32,
    /// The loaded lockfile's release epoch.
    pub release_epoch: u64,
    /// The configured intent's digest.
    pub intent_digest: &'a str,
}

/// Mints an Episode Token. The caller also registers the episode with
/// [`EpisodeStates::start`].
///
/// # Errors
///
/// Returns [`TokenError::LifetimeNotAllowed`] unless `exp - iat` is between 1 and
/// [`EPISODE_MAX_LIFETIME_SECS`], or an error from encoding or signing.
pub fn mint_episode_token(
    signer: &Es256Signer,
    claims: &EpisodeClaims,
) -> Result<String, TokenError> {
    check_lifetime(claims.iat, claims.exp, EPISODE_MAX_LIFETIME_SECS)?;
    signer.sign(EPISODE_TYP, claims.to_object()?)
}

/// Verifies an Episode Token presented on a connection, and records the use against its
/// episode (which resets the idle timer).
///
/// # Errors
///
/// Returns the [`TokenError`] of the first failing check: the JOSE rules, the claims, the
/// expectations (`peer_uid`, `release_epoch`, `intent_digest`), then the time window and the
/// episode's state.
pub fn verify_episode_token(
    token: &str,
    verifier: &Es256Verifier,
    expect: &EpisodeExpectations<'_>,
    episodes: &EpisodeStates,
    now: u64,
) -> Result<EpisodeClaims, TokenError> {
    verify_episode_token_with(
        token,
        verifier,
        expect.peer_uid,
        expect.release_epoch,
        |_| Some(expect.intent_digest.to_owned()),
        episodes,
        now,
    )
}

/// [`verify_episode_token`] for a PEP with several intents: the digest the token must carry is
/// that of its own episode's intent, found by `intent_digest_of` from the token's `eid` once
/// the signature, peer and epoch checks pass. An `eid` it does not know is
/// [`TokenError::IntentMismatch`].
///
/// # Errors
///
/// As [`verify_episode_token`].
pub fn verify_episode_token_with(
    token: &str,
    verifier: &Es256Verifier,
    peer_uid: u32,
    release_epoch: u64,
    intent_digest_of: impl FnOnce(u128) -> Option<String>,
    episodes: &EpisodeStates,
    now: u64,
) -> Result<EpisodeClaims, TokenError> {
    let claims = EpisodeClaims::from_object(&verifier.verify(token, EPISODE_TYP)?)?;
    if claims.peer_uid != peer_uid {
        return Err(TokenError::PeerMismatch);
    }
    if claims.release_epoch != release_epoch {
        return Err(TokenError::EpochMismatch);
    }
    if intent_digest_of(claims.eid).as_deref() != Some(claims.intent_digest.as_str()) {
        return Err(TokenError::IntentMismatch);
    }
    episodes.admit(&claims, now)?;
    Ok(claims)
}

/// End and idle state of this boot's episodes, keyed by `eid`, never by token bytes: every
/// token of an ended episode stays refused, however it is encoded.
#[derive(Debug)]
pub struct EpisodeStates {
    table: Mutex<EpisodeTable>,
    capacity: usize,
    idle_secs: u64,
    skew_secs: u64,
}

#[derive(Debug, Default)]
struct EpisodeTable {
    /// High-water mark of every clock reading seen; it never decreases.
    clock: u64,
    episodes: HashMap<u128, Liveness>,
}

#[derive(Debug, Clone, Copy)]
struct Liveness {
    ended: bool,
    last_active: u64,
    expires: u64,
}

impl EpisodeStates {
    /// An empty table for at most `capacity` episodes whose tokens may still be valid.
    #[must_use]
    pub fn new(capacity: usize, idle_secs: u64, skew_secs: u64) -> Self {
        Self {
            table: Mutex::new(EpisodeTable::default()),
            capacity,
            idle_secs,
            skew_secs,
        }
    }

    /// Registers a started episode whose token expires at `expires`. Entries whose tokens can
    /// no longer be valid are dropped first.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError::EpisodeExists`] for an `eid` already registered, or
    /// [`TokenError::TooManyEpisodes`] when the table is full.
    pub fn start(&self, eid: u128, expires: u64, now: u64) -> Result<(), TokenError> {
        let mut table = lock(&self.table)?;
        table.clock = table.clock.max(now);
        let clock = table.clock;
        let skew = self.skew_secs;
        table.episodes.retain(|_, entry| {
            entry
                .expires
                .checked_add(skew)
                .is_none_or(|end| end >= clock)
        });
        if table.episodes.contains_key(&eid) {
            return Err(TokenError::EpisodeExists);
        }
        if table.episodes.len() >= self.capacity {
            return Err(TokenError::TooManyEpisodes);
        }
        table.episodes.insert(
            eid,
            Liveness {
                ended: false,
                last_active: clock,
                expires,
            },
        );
        Ok(())
    }

    /// Ends an episode (`end_episode`): every later use of any of its tokens is refused.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError::UnknownEpisode`] if the episode is not registered.
    pub fn end(&self, eid: u128) -> Result<(), TokenError> {
        let mut table = lock(&self.table)?;
        let entry = table
            .episodes
            .get_mut(&eid)
            .ok_or(TokenError::UnknownEpisode)?;
        entry.ended = true;
        Ok(())
    }

    /// Whether the episode `eid` can take no more calls: unknown, ended, idle or expired. The
    /// registry ends such an episode, so its intent can start another (E1). A poisoned table
    /// reads as over (fail closed); going idle ends the episode for good.
    #[must_use]
    pub fn is_over(&self, eid: u128, now: u64) -> bool {
        let Ok(mut table) = lock(&self.table) else {
            return true;
        };
        let clock = table.clock.max(now);
        let Some(entry) = table.episodes.get_mut(&eid) else {
            return true;
        };
        let idle = entry
            .last_active
            .checked_add(self.idle_secs)
            .is_none_or(|deadline| clock > deadline);
        let expired = entry
            .expires
            .checked_add(self.skew_secs)
            .is_none_or(|limit| clock > limit);
        if idle {
            entry.ended = true;
        }
        entry.ended || expired
    }

    /// Admits one use of a verified token: the time window against the high-water clock, then
    /// the episode's end and idle state. A use resets the idle timer; going idle ends the
    /// episode for good.
    fn admit(&self, claims: &EpisodeClaims, now: u64) -> Result<(), TokenError> {
        let mut table = lock(&self.table)?;
        table.clock = table.clock.max(now);
        let clock = table.clock;
        check_window(claims.iat, claims.exp, clock, self.skew_secs)?;
        let entry = table
            .episodes
            .get_mut(&claims.eid)
            .ok_or(TokenError::UnknownEpisode)?;
        if entry.ended {
            return Err(TokenError::EpisodeEnded);
        }
        if entry
            .last_active
            .checked_add(self.idle_secs)
            .is_none_or(|deadline| clock > deadline)
        {
            entry.ended = true;
            return Err(TokenError::EpisodeIdle);
        }
        entry.last_active = clock;
        Ok(())
    }
}

// ---- Call Proof (SPEC §3.4) ----

/// The `budget` claim of a payment proof: the reserved amount, and the intent's totals right
/// after this reservation (`reserved_minor` includes it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetClaim {
    /// ISO 4217 currency of the payment.
    pub currency: String,
    /// The reserved amount, in minor units.
    pub amount_minor: u64,
    /// Total reserved, this reservation included.
    pub reserved_minor: u64,
    /// Total committed.
    pub committed_minor: u64,
}

/// The claims only a payment proof carries. They can be built only from a `Held`
/// reservation ([`PaymentClaims::for_held`]), so no other reservation gets a proof (F-15).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentClaims {
    rid: u64,
    prov: Vec<String>,
    budget: BudgetClaim,
}

impl PaymentClaims {
    /// The payment claims of a `Held` reservation. `prov` is the engine's `Allowed.prov`: the
    /// origin hashes of the witness leaves (the amount, and the currency when bound).
    ///
    /// # Errors
    ///
    /// Returns [`TokenError::NotHeld`] unless the reservation is `Held`, or
    /// [`TokenError::InvalidClaims`] unless `prov` holds one or two digests and the amounts
    /// and currency are valid.
    pub fn for_held(
        reservation: &Reservation,
        budget: &Budget,
        currency: &str,
        prov: Vec<String>,
    ) -> Result<Self, TokenError> {
        if reservation.state != ResState::Held {
            return Err(TokenError::NotHeld);
        }
        let claims = Self {
            rid: reservation.id,
            prov,
            budget: BudgetClaim {
                currency: currency.to_owned(),
                amount_minor: reservation.amount_minor,
                reserved_minor: budget.reserved,
                committed_minor: budget.committed,
            },
        };
        claims.check()?;
        Ok(claims)
    }

    /// The reservation id.
    #[must_use]
    pub const fn rid(&self) -> u64 {
        self.rid
    }

    /// The witness origin hashes.
    #[must_use]
    pub fn prov(&self) -> &[String] {
        &self.prov
    }

    /// The `budget` claim.
    #[must_use]
    pub const fn budget(&self) -> &BudgetClaim {
        &self.budget
    }

    fn check(&self) -> Result<(), TokenError> {
        let budget = &self.budget;
        let valid = self.rid >= 1
            && (1..=MAX_PROV).contains(&self.prov.len())
            && self.prov.iter().all(|hash| is_digest(hash))
            && is_currency(&budget.currency)
            && budget.amount_minor >= 1
            && budget.reserved_minor >= budget.amount_minor;
        if valid {
            Ok(())
        } else {
            Err(TokenError::InvalidClaims)
        }
    }

    fn members(&self) -> Result<Vec<(&'static str, JcsValue)>, TokenError> {
        let budget = object(vec![
            ("amount_minor", uint(self.budget.amount_minor)?),
            ("committed_minor", uint(self.budget.committed_minor)?),
            ("currency", JcsValue::string(self.budget.currency.as_str())),
            ("reserved_minor", uint(self.budget.reserved_minor)?),
        ])?;
        let prov = self
            .prov
            .iter()
            .map(|hash| JcsValue::string(hash.as_str()))
            .collect();
        Ok(vec![
            ("budget", JcsValue::Object(budget)),
            ("prov", JcsValue::Array(prov)),
            ("rid", uint(self.rid)?),
        ])
    }

    fn from_object(object: &JcsObject) -> Result<Self, TokenError> {
        let budget = object
            .get("budget")
            .and_then(JcsValue::as_object)
            .filter(|budget| has_exactly(budget, &BUDGET_MEMBERS))
            .ok_or(TokenError::InvalidClaims)?;
        let prov = object
            .get("prov")
            .and_then(JcsValue::as_array)
            .ok_or(TokenError::InvalidClaims)?
            .iter()
            .map(|hash| {
                hash.as_str()
                    .map(str::to_owned)
                    .ok_or(TokenError::InvalidClaims)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let claims = Self {
            rid: unsigned(object, "rid")?,
            prov,
            budget: BudgetClaim {
                currency: text(budget, "currency")?.to_owned(),
                amount_minor: unsigned(budget, "amount_minor")?,
                reserved_minor: unsigned(budget, "reserved_minor")?,
                committed_minor: unsigned(budget, "committed_minor")?,
            },
        };
        claims.check()?;
        Ok(claims)
    }
}

/// The claims of a Call Proof. `iss` and `aud` are fixed ([`CALL_PROOF_ISS`],
/// [`CALL_PROOF_AUD`]). `tth` is added in Week 5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallProofClaims {
    /// Unique proof id ([`new_jti`]); the replay cache key.
    pub jti: String,
    /// Issued at, in Unix seconds.
    pub iat: u64,
    /// Expires at; `exp - iat` is at most [`CALL_PROOF_TTL_SECS`].
    pub exp: u64,
    /// The episode the call belongs to.
    pub eid: u128,
    /// The target server's `server_id` in the lockfile.
    pub server_id: String,
    /// `action_digest` of the forwarded call.
    pub action_digest: String,
    /// Release epoch of the PEP's lockfile.
    pub release_epoch: u64,
    /// The lockfile's pinned digest of the tool's upstream definition.
    pub tool_schema_digest: String,
    /// Present exactly on payment proofs.
    pub payment: Option<PaymentClaims>,
}

impl CallProofClaims {
    fn check(&self) -> Result<(), TokenError> {
        if !is_jti(&self.jti) {
            return Err(TokenError::InvalidClaims);
        }
        check_lifetime(self.iat, self.exp, CALL_PROOF_TTL_SECS)
    }

    fn to_object(&self) -> Result<JcsObject, TokenError> {
        let mut members = vec![
            (
                "action_digest",
                JcsValue::string(self.action_digest.as_str()),
            ),
            ("aud", JcsValue::string(CALL_PROOF_AUD)),
            ("eid", JcsValue::string(encode_ulid(self.eid))),
            ("exp", uint(self.exp)?),
            ("iat", uint(self.iat)?),
            ("iss", JcsValue::string(CALL_PROOF_ISS)),
            ("jti", JcsValue::string(self.jti.as_str())),
            ("release_epoch", uint(self.release_epoch)?),
            ("server_id", JcsValue::string(self.server_id.as_str())),
            (
                "tool_schema_digest",
                JcsValue::string(self.tool_schema_digest.as_str()),
            ),
        ];
        if let Some(payment) = &self.payment {
            members.extend(payment.members()?);
        }
        object(members)
    }

    fn from_object(object: &JcsObject) -> Result<Self, TokenError> {
        let is_payment = PAYMENT_MEMBERS
            .iter()
            .any(|member| object.contains_key(member));
        let exact = if is_payment {
            object.len()
                == CALL_PROOF_MEMBERS
                    .len()
                    .saturating_add(PAYMENT_MEMBERS.len())
                && CALL_PROOF_MEMBERS
                    .iter()
                    .chain(&PAYMENT_MEMBERS)
                    .all(|member| object.contains_key(member))
        } else {
            has_exactly(object, &CALL_PROOF_MEMBERS)
        };
        if !exact {
            return Err(TokenError::InvalidClaims);
        }
        if text(object, "iss")? != CALL_PROOF_ISS || text(object, "aud")? != CALL_PROOF_AUD {
            return Err(TokenError::IssuerOrAudience);
        }
        let claims = Self {
            jti: text(object, "jti")?.to_owned(),
            iat: unsigned(object, "iat")?,
            exp: unsigned(object, "exp")?,
            eid: parse_eid(text(object, "eid")?)?,
            server_id: text(object, "server_id")?.to_owned(),
            action_digest: text(object, "action_digest")?.to_owned(),
            release_epoch: unsigned(object, "release_epoch")?,
            tool_schema_digest: text(object, "tool_schema_digest")?.to_owned(),
            payment: if is_payment {
                Some(PaymentClaims::from_object(object)?)
            } else {
                None
            },
        };
        claims.check()?;
        Ok(claims)
    }
}

/// Issues a Call Proof for a forwarded `tools/call`.
///
/// # Errors
///
/// Returns [`TokenError::InvalidClaims`] for a malformed `jti`,
/// [`TokenError::LifetimeNotAllowed`] unless `exp - iat` is between 1 and
/// [`CALL_PROOF_TTL_SECS`], or an error from encoding or signing.
pub fn issue_call_proof(
    signer: &Es256Signer,
    claims: &CallProofClaims,
) -> Result<String, TokenError> {
    claims.check()?;
    signer.sign(CALL_PROOF_TYP, claims.to_object()?)
}

/// The payment facts the broker reads from the forwarded arguments.
#[derive(Debug, Clone, Copy)]
pub struct ExpectedPayment<'a> {
    /// The forwarded amount, in minor units.
    pub amount_minor: u64,
    /// The forwarded currency.
    pub currency: &'a str,
}

/// What the broker requires of a Call Proof for one forwarded call.
#[derive(Debug, Clone, Copy)]
pub struct CallProofExpectations<'a> {
    /// The server the request is routed to (`/mcp/{server_id}`).
    pub server_id: &'a str,
    /// The broker's lockfile release epoch.
    pub release_epoch: u64,
    /// The pinned digest of the called tool on that server.
    pub tool_schema_digest: &'a str,
    /// `action_digest` recomputed from the forwarded body.
    pub action_digest: &'a str,
    /// Present exactly when the lockfile marks the tool as a payment.
    pub payment: Option<ExpectedPayment<'a>>,
}

/// Verifies a Call Proof at the broker (SPEC §3.4's broker checks), and admits its `jti`.
/// Nothing is admitted unless every other check passes, so an invalid proof cannot fill the
/// cache.
///
/// # Errors
///
/// Returns the [`TokenError`] of the first failing check: the JOSE rules, the claims (with
/// `iss`, `aud` and the lifetime), the expectations, then the boot cutoff, the time window and
/// the replay cache.
pub fn verify_call_proof(
    token: &str,
    verifier: &Es256Verifier,
    expect: &CallProofExpectations<'_>,
    cache: &ReplayCache,
    now: u64,
) -> Result<CallProofClaims, TokenError> {
    let claims = CallProofClaims::from_object(&verifier.verify(token, CALL_PROOF_TYP)?)?;
    if claims.server_id != expect.server_id {
        return Err(TokenError::ServerMismatch);
    }
    if claims.release_epoch != expect.release_epoch {
        return Err(TokenError::EpochMismatch);
    }
    if claims.tool_schema_digest != expect.tool_schema_digest {
        return Err(TokenError::SchemaDigestMismatch);
    }
    if claims.action_digest != expect.action_digest {
        return Err(TokenError::ActionDigestMismatch);
    }
    match (&claims.payment, &expect.payment) {
        (None, None) => {}
        (Some(payment), Some(expected)) => {
            let budget = payment.budget();
            if budget.amount_minor != expected.amount_minor || budget.currency != expected.currency
            {
                return Err(TokenError::BudgetMismatch);
            }
        }
        _ => return Err(TokenError::PaymentClaimsMismatch),
    }
    cache.admit(&claims.jti, claims.iat, claims.exp, now)?;
    Ok(claims)
}

/// The broker's bounded replay cache of admitted `jti`s (T1). A full cache with live entries
/// rejects rather than evicting; an entry is dropped only once its proof can no longer pass
/// the time window.
#[derive(Debug)]
pub struct ReplayCache {
    table: Mutex<ReplayTable>,
    capacity: usize,
    boot_second: u64,
    skew_secs: u64,
}

#[derive(Debug, Default)]
struct ReplayTable {
    /// High-water mark of every clock reading seen; it never decreases.
    clock: u64,
    seen: HashMap<String, u64>,
    by_expiry: BTreeSet<(u64, String)>,
}

impl ReplayTable {
    /// Drops every entry whose proof is now outside the time window for good.
    fn evict(&mut self, skew: u64) {
        while let Some(&(exp, _)) = self.by_expiry.first() {
            if exp
                .checked_add(skew)
                .is_none_or(|deadline| deadline >= self.clock)
            {
                break;
            }
            if let Some((_, jti)) = self.by_expiry.pop_first() {
                self.seen.remove(&jti);
            }
        }
    }
}

impl ReplayCache {
    /// An empty cache for at most `capacity` live `jti`s. Proofs issued in or before
    /// `boot_second` are refused, so a proof minted in the broker's boot second, just before
    /// a restart, cannot be replayed once.
    #[must_use]
    pub fn new(capacity: usize, boot_second: u64, skew_secs: u64) -> Self {
        Self {
            table: Mutex::new(ReplayTable::default()),
            capacity,
            boot_second,
            skew_secs,
        }
    }

    /// Admits a `jti` once, atomically: of two identical proofs checked at the same moment,
    /// exactly one passes.
    fn admit(&self, jti: &str, iat: u64, exp: u64, now: u64) -> Result<(), TokenError> {
        if iat <= self.boot_second {
            return Err(TokenError::BeforeBoot);
        }
        let mut table = lock(&self.table)?;
        table.clock = table.clock.max(now);
        check_window(iat, exp, table.clock, self.skew_secs)?;
        table.evict(self.skew_secs);
        if table.seen.contains_key(jti) {
            return Err(TokenError::Replayed);
        }
        if table.seen.len() >= self.capacity {
            return Err(TokenError::ReplayCacheFull);
        }
        table.seen.insert(jti.to_owned(), exp);
        table.by_expiry.insert((exp, jti.to_owned()));
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
    use std::thread;

    /// RFC 6979 A.2.5's P-256 secret key.
    const RFC6979_SECRET: &str = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";
    // Vectors from spikes/token-vectors/jws_vectors.py (pyca/cryptography, deterministic
    // RFC 6979, low-S), computed independently of this module.
    const KID: &str = "DOvxvJiAdIqVWIkFt5hDtCunXLF0BV4-JGv4f-ALSm0";
    const SEC1: &str = "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";
    const EPISODE_VECTOR: &str = "eyJhbGciOiJFUzI1NiIsImtpZCI6IkRPdnh2SmlBZElxVldJa0Z0NWhEdEN1blhMRjBCVjQtSkd2NGYtQUxTbTAiLCJ0eXAiOiJwZXAtZXBpc29kZStqd3QifQ.eyJjbGllbnRfaWQiOiJnYXRlMS1oYXJuZXNzIiwiZWlkIjoiMDFKQkFFMFoxVEZDUTlZNDFXOU5GNllZTUIiLCJleHAiOjE4MDAwMjg4MDAsImlhdCI6MTgwMDAwMDAwMCwiaW50ZW50X2RpZ2VzdCI6InNoYS0yNTY6ajNYZnljc1lpMkc4alNWb2NYVVRpUE4ySldiY3dRZk9LMUw0cExBZEkxRSIsInBlZXJfdWlkIjoyMDAwMSwicmFyX2RpZ2VzdCI6InNoYS0yNTY6UkJOdm8xV3paNG9SUnEwVzktaGtucFQ3VDhJZjUzNkRFTUJnOWh5cV80byIsInJlbGVhc2VfZXBvY2giOjcsInN1YiI6Im9wZXJhdG9yQGNvcnAuZXhhbXBsZSIsInR4biI6IjAxSkJBRTBaMVRGQ1E5WTQxVzlORjZZWU1CIn0.5DzfX4-LVXZM3v0eDROQB1R1hrSJg19pQCLIBCnJugEVFIGFaitgPknHj-LJjDcZkA9cH9j4vs8484ADDwzMUg";
    const PROOF_VECTOR: &str = "eyJhbGciOiJFUzI1NiIsImtpZCI6IkRPdnh2SmlBZElxVldJa0Z0NWhEdEN1blhMRjBCVjQtSkd2NGYtQUxTbTAiLCJ0eXAiOiJwZXAtY2FsbHByb29mK2p3dCJ9.eyJhY3Rpb25fZGlnZXN0Ijoic2hhLTI1NjpqM1hmeWNzWWkyRzhqU1ZvY1hVVGlQTjJKV2Jjd1FmT0sxTDRwTEFkSTFFIiwiYXVkIjoic3BpZmZlOi8vY29ycC5leGFtcGxlL2Jyb2tlciIsImJ1ZGdldCI6eyJhbW91bnRfbWlub3IiOjUwMDAsImNvbW1pdHRlZF9taW5vciI6MCwiY3VycmVuY3kiOiJVU0QiLCJyZXNlcnZlZF9taW5vciI6NTAwMH0sImVpZCI6IjAxSkJBRTBaMVRGQ1E5WTQxVzlORjZZWU1CIiwiZXhwIjoxODAwMDAwMDYwLCJpYXQiOjE4MDAwMDAwMDAsImlzcyI6InNwaWZmZTovL2NvcnAuZXhhbXBsZS9wZXAiLCJqdGkiOiJBQUFBQUFBQUFBQUFBQUFBQUFBQUFBIiwicHJvdiI6WyJzaGEtMjU2OjJwRVZmV255OGprdTA1VVFDUkREYXJHblNzX0YydFpCN19ZdHNDLTdTWVUiXSwicmVsZWFzZV9lcG9jaCI6NywicmlkIjoxLCJzZXJ2ZXJfaWQiOiJhIiwidG9vbF9zY2hlbWFfZGlnZXN0Ijoic2hhLTI1NjpiZG1OUW82NlJTLTQ4c1JfMG44cFA1am1ibzBhMFNoMDBnVVd2OG5FRE5VIn0.4H1YcN2_1k3rK7XLVwKpiEizCqnrLbZNWSXCdWGa4wlRBG8q_fIHButvwSGPIDSZQQ3u1un_qkxbO-dzUb1ChA";
    /// The P-256 group order n, big-endian.
    const ORDER: &str = "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551";
    const B64URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const EID: u128 = 0x0192_d4e0_7c3a_7b2e_9f10_3c4d_5e6f_7a8b;
    const T0: u64 = 1_800_000_000;
    const ACTION: &str = "sha-256:j3XfycsYi2G8jSVocXUTiPN2JWbcwQfOK1L4pLAdI1E";
    const SCHEMA: &str = "sha-256:bdmNQo66RS-48sR_0n8pP5jmbo0a0Sh00gUWv8nEDNU";
    const PROV: &str = "sha-256:2pEVfWny8jku05UQCRDDarGnSs_F2tZB7_YtsC-7SYU";

    fn hex(text: &str) -> Vec<u8> {
        text.as_bytes()
            .chunks(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    fn rfc_signer() -> Es256Signer {
        Es256Signer::from_secret_bytes(&hex(RFC6979_SECRET)).unwrap()
    }

    /// A second key, standing in for the other token type's key or an earlier boot's.
    fn other_signer() -> Es256Signer {
        Es256Signer::from_secret_bytes(&[7; 32]).unwrap()
    }

    fn episode_claims() -> EpisodeClaims {
        EpisodeClaims {
            eid: EID,
            intent_digest: ACTION.to_owned(),
            sub: "operator@corp.example".to_owned(),
            client_id: "gate1-harness".to_owned(),
            peer_uid: 20_001,
            release_epoch: 7,
            rar_digest: "sha-256:RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o".to_owned(),
            iat: T0,
            exp: T0 + EPISODE_MAX_LIFETIME_SECS,
        }
    }

    fn episode_expect() -> EpisodeExpectations<'static> {
        EpisodeExpectations {
            peer_uid: 20_001,
            release_epoch: 7,
            intent_digest: ACTION,
        }
    }

    /// An episode table with EID started at T0.
    fn episodes() -> EpisodeStates {
        let states = EpisodeStates::new(64, EPISODE_IDLE_SECS, CLOCK_SKEW_SECS);
        states
            .start(EID, T0 + EPISODE_MAX_LIFETIME_SECS, T0)
            .unwrap();
        states
    }

    fn payment() -> PaymentClaims {
        PaymentClaims {
            rid: 1,
            prov: vec![PROV.to_owned()],
            budget: BudgetClaim {
                currency: "USD".to_owned(),
                amount_minor: 5000,
                reserved_minor: 5000,
                committed_minor: 0,
            },
        }
    }

    fn proof_claims(jti: &str, iat: u64) -> CallProofClaims {
        CallProofClaims {
            jti: jti.to_owned(),
            iat,
            exp: iat + CALL_PROOF_TTL_SECS,
            eid: EID,
            server_id: "a".to_owned(),
            action_digest: ACTION.to_owned(),
            release_epoch: 7,
            tool_schema_digest: SCHEMA.to_owned(),
            payment: Some(payment()),
        }
    }

    fn read_claims(jti: &str, iat: u64) -> CallProofClaims {
        CallProofClaims {
            payment: None,
            ..proof_claims(jti, iat)
        }
    }

    fn proof_expect() -> CallProofExpectations<'static> {
        CallProofExpectations {
            server_id: "a",
            release_epoch: 7,
            tool_schema_digest: SCHEMA,
            action_digest: ACTION,
            payment: Some(ExpectedPayment {
                amount_minor: 5000,
                currency: "USD",
            }),
        }
    }

    fn read_expect() -> CallProofExpectations<'static> {
        CallProofExpectations {
            payment: None,
            ..proof_expect()
        }
    }

    /// A broker that booted ten seconds before T0.
    fn cache() -> ReplayCache {
        ReplayCache::new(REPLAY_CACHE_ENTRIES, T0 - 10, CLOCK_SKEW_SECS)
    }

    fn verify_proof(token: &str, signer: &Es256Signer) -> Result<CallProofClaims, TokenError> {
        verify_call_proof(token, &signer.verifier(), &proof_expect(), &cache(), T0)
    }

    fn verify_episode(token: &str, signer: &Es256Signer) -> Result<EpisodeClaims, TokenError> {
        verify_episode_token(
            token,
            &signer.verifier(),
            &episode_expect(),
            &episodes(),
            T0,
        )
    }

    /// Signs arbitrary header and claims text with `signer`, low-S.
    fn forge(signer: &Es256Signer, header: &str, claims: &str) -> String {
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(claims)
        );
        let signature: Signature = signer.key.try_sign(input.as_bytes()).unwrap();
        let bytes = signature.normalize_s().to_bytes();
        let bytes: &[u8] = bytes.as_ref();
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(bytes))
    }

    fn header(typ: &str, kid: &str) -> String {
        format!(r#"{{"alg":"ES256","kid":"{kid}","typ":"{typ}"}}"#)
    }

    /// The canonical claims of `token` with `key` set to `value`, or removed when `None`.
    fn edited_claims(token: &str, key: &str, value: Option<JcsValue>) -> String {
        let claims = token.split('.').nth(1).unwrap();
        let parsed = jcs::parse(&URL_SAFE_NO_PAD.decode(claims).unwrap()).unwrap();
        let mut entries: Vec<_> = parsed
            .as_object()
            .unwrap()
            .entries()
            .iter()
            .filter(|(name, _)| name.as_str() != key)
            .cloned()
            .collect();
        if let Some(value) = value {
            entries.push((JcsString::new(key), value));
        }
        JcsValue::Object(JcsObject::from_entries(entries).unwrap()).to_canonical_string()
    }

    /// The same token with `s` replaced by `n - s`: an equally valid, high-S signature.
    fn high_s(token: &str) -> String {
        let (input, signature) = token.rsplit_once('.').unwrap();
        let mut bytes = URL_SAFE_NO_PAD.decode(signature).unwrap();
        let order = hex(ORDER);
        let mut borrow = 0_u16;
        for i in (0..SCALAR_BYTES).rev() {
            let minuend = u16::from(order[i]);
            let subtrahend = u16::from(bytes[SCALAR_BYTES + i]) + borrow;
            let (digit, next) = if minuend >= subtrahend {
                (minuend - subtrahend, 0)
            } else {
                (minuend + 256 - subtrahend, 1)
            };
            bytes[SCALAR_BYTES + i] = u8::try_from(digit).unwrap();
            borrow = next;
        }
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(&bytes))
    }

    // ---- Keys and the independent vectors ----

    #[test]
    fn kid_is_the_rfc7638_thumbprint() {
        let signer = rfc_signer();
        assert_eq!(signer.kid(), KID);
        let verifier = signer.verifier();
        assert_eq!(verifier.to_sec1_uncompressed(), hex(SEC1));
        assert_eq!(Es256Verifier::from_sec1(&hex(SEC1)).unwrap().kid(), KID);
        let sec1 = hex(SEC1);
        let jwk = Es256Verifier::from_jwk(
            &URL_SAFE_NO_PAD.encode(&sec1[1..33]),
            &URL_SAFE_NO_PAD.encode(&sec1[33..65]),
        )
        .unwrap();
        assert_eq!(jwk.kid(), KID);
        assert_ne!(other_signer().kid(), KID);
    }

    #[test]
    fn bad_public_keys_rejected() {
        let mut off_curve = hex(SEC1);
        off_curve[64] ^= 1;
        assert!(matches!(
            Es256Verifier::from_sec1(&off_curve),
            Err(TokenError::InvalidKey)
        ));
        let sec1 = hex(SEC1);
        let x = URL_SAFE_NO_PAD.encode(&sec1[1..33]);
        assert!(matches!(
            Es256Verifier::from_jwk(&x, &URL_SAFE_NO_PAD.encode(&off_curve[33..65])),
            Err(TokenError::InvalidKey)
        ));
        assert!(matches!(
            Es256Verifier::from_jwk(&x, &URL_SAFE_NO_PAD.encode(&sec1[33..64])),
            Err(TokenError::InvalidKey)
        ));
    }

    #[test]
    fn episode_token_matches_the_independent_vector() {
        let signer = rfc_signer();
        let token = mint_episode_token(&signer, &episode_claims()).unwrap();
        assert_eq!(token, EPISODE_VECTOR);
        assert_eq!(verify_episode(&token, &signer).unwrap(), episode_claims());
    }

    #[test]
    fn call_proof_matches_the_independent_vector() {
        let signer = rfc_signer();
        let claims = proof_claims("AAAAAAAAAAAAAAAAAAAAAA", T0);
        let token = issue_call_proof(&signer, &claims).unwrap();
        assert_eq!(token, PROOF_VECTOR);
        assert_eq!(verify_proof(&token, &signer).unwrap(), claims);
    }

    #[test]
    fn signatures_are_low_s() {
        let signer = rfc_signer();
        let mut saw_high_raw = false;
        for iat in T0..T0 + 32 {
            let token = issue_call_proof(&signer, &read_claims("j", iat)).unwrap();
            let (input, signature) = token.rsplit_once('.').unwrap();
            let signature =
                Signature::from_slice(&URL_SAFE_NO_PAD.decode(signature).unwrap()).unwrap();
            assert_eq!(signature.normalize_s(), signature);
            // p256's own signer emits high-S as it comes, so the normalization matters.
            let raw: Signature = signer.key.try_sign(input.as_bytes()).unwrap();
            saw_high_raw |= raw.normalize_s() != raw;
        }
        assert!(saw_high_raw);
    }

    #[test]
    fn high_s_rejected_by_both_verifiers() {
        let signer = rfc_signer();
        let proof = high_s(PROOF_VECTOR);
        // The high-S twin is a valid ECDSA signature: p256 alone accepts it.
        let (input, signature) = proof.rsplit_once('.').unwrap();
        let signature = Signature::from_slice(&URL_SAFE_NO_PAD.decode(signature).unwrap()).unwrap();
        assert!(
            signer
                .verifier()
                .key
                .verify(input.as_bytes(), &signature)
                .is_ok()
        );
        assert!(matches!(
            verify_proof(&proof, &signer),
            Err(TokenError::HighS)
        ));
        assert!(matches!(
            verify_episode(&high_s(EPISODE_VECTOR), &signer),
            Err(TokenError::HighS)
        ));
    }

    #[test]
    fn key_generation_draws_until_a_valid_scalar() {
        // Zero is not a valid scalar, nor is n - 1 + 1 = n; the third draw is.
        let mut entropy = Vec::new();
        entropy.extend([0_u8; 32]);
        entropy.extend(hex(ORDER));
        entropy.extend(hex(RFC6979_SECRET));
        let signer = Es256Signer::generate(&mut entropy.as_slice()).unwrap();
        assert_eq!(signer.kid(), KID);
        assert!(matches!(
            Es256Signer::generate(&mut [0_u8; 32 * KEY_ATTEMPTS].as_slice()),
            Err(TokenError::KeyGeneration)
        ));
        assert!(matches!(
            Es256Signer::generate(&mut [1_u8; 31].as_slice()),
            Err(TokenError::Io(_))
        ));
        let mut os = os_entropy().unwrap();
        let first = Es256Signer::generate(&mut os).unwrap();
        let second = Es256Signer::generate(&mut os).unwrap();
        assert_ne!(first.kid(), second.kid());
        assert!(!format!("{first:?}").contains(&format!("{:?}", first.key.to_bytes())));
    }

    #[test]
    fn jti_comes_from_entropy() {
        assert_eq!(
            new_jti(&mut [0_u8; 16].as_slice()).unwrap(),
            "AAAAAAAAAAAAAAAAAAAAAA"
        );
        let mut os = os_entropy().unwrap();
        let a = new_jti(&mut os).unwrap();
        assert_eq!(a.len(), 22);
        assert_ne!(a, new_jti(&mut os).unwrap());
        assert!(unix_now().unwrap() > T0 - 100_000_000);
    }

    // ---- JOSE rules ----

    #[test]
    fn alg_confusion_rejected() {
        let signer = rfc_signer();
        let claims = edited_claims(PROOF_VECTOR, "x-none", None);
        for alg in ["none", "HS256", "ES384", "RS256", "ES256K", "es256"] {
            let header = format!(r#"{{"alg":"{alg}","kid":"{KID}","typ":"{CALL_PROOF_TYP}"}}"#);
            let token = forge(&signer, &header, &claims);
            assert!(
                matches!(
                    verify_proof(&token, &signer),
                    Err(TokenError::AlgNotAllowed)
                ),
                "{alg}"
            );
        }
        // The unsigned form (`header.claims.`) is refused by its shape, before any decoding.
        let header = format!(r#"{{"alg":"none","kid":"{KID}","typ":"{CALL_PROOF_TYP}"}}"#);
        let forged = forge(&signer, &header, &claims);
        let (input, _) = forged.rsplit_once('.').unwrap();
        assert!(matches!(
            verify_proof(&format!("{input}."), &signer),
            Err(TokenError::Malformed)
        ));
    }

    #[test]
    fn typ_swap_rejected() {
        let signer = rfc_signer();
        // Same key, wrong type, both ways.
        assert!(matches!(
            verify_proof(EPISODE_VECTOR, &signer),
            Err(TokenError::TypMismatch)
        ));
        assert!(matches!(
            verify_episode(PROOF_VECTOR, &signer),
            Err(TokenError::TypMismatch)
        ));
        let claims = edited_claims(PROOF_VECTOR, "x-none", None);
        for typ in [
            "JWT",
            "jwt",
            "pep-callproof+JWT",
            "urn:pep-sidecar:evidence:jws-callproof:v1",
        ] {
            let token = forge(&signer, &header(typ, KID), &claims);
            assert!(matches!(
                verify_proof(&token, &signer),
                Err(TokenError::TypMismatch)
            ));
        }
        // In production the types also use different keys: the episode key's token, given to
        // the broker, fails on typ before kid is even compared.
        let episode_key = other_signer();
        let token = mint_episode_token(&episode_key, &episode_claims()).unwrap();
        assert!(matches!(
            verify_proof(&token, &signer),
            Err(TokenError::TypMismatch)
        ));
    }

    #[test]
    fn header_members_outside_the_allowlist_rejected() {
        let signer = rfc_signer();
        let claims = edited_claims(PROOF_VECTOR, "x-none", None);
        for extra in [
            "jku", "jwk", "x5u", "x5c", "crit", "cty", "b64", "zip", "nonce",
        ] {
            let header = JcsValue::Object(
                object(vec![
                    ("alg", JcsValue::string(ALG)),
                    (extra, JcsValue::string("x")),
                    ("kid", JcsValue::string(KID)),
                    ("typ", JcsValue::string(CALL_PROOF_TYP)),
                ])
                .unwrap(),
            )
            .to_canonical_string();
            let token = forge(&signer, &header, &claims);
            assert!(
                matches!(
                    verify_proof(&token, &signer),
                    Err(TokenError::HeaderNotAllowed)
                ),
                "{extra}"
            );
        }
        let missing = format!(r#"{{"alg":"ES256","typ":"{CALL_PROOF_TYP}"}}"#);
        assert!(matches!(
            verify_proof(&forge(&signer, &missing, &claims), &signer),
            Err(TokenError::HeaderNotAllowed)
        ));
        let not_text = format!(r#"{{"alg":"ES256","kid":7,"typ":"{CALL_PROOF_TYP}"}}"#);
        assert!(matches!(
            verify_proof(&forge(&signer, &not_text, &claims), &signer),
            Err(TokenError::HeaderNotAllowed)
        ));
    }

    #[test]
    fn kid_from_another_boot_rejected_before_the_signature() {
        let signer = rfc_signer();
        let earlier_boot = other_signer();
        let token = issue_call_proof(&earlier_boot, &proof_claims("j", T0)).unwrap();
        assert!(matches!(
            verify_proof(&token, &signer),
            Err(TokenError::KidMismatch)
        ));
        // The current kid with another key's signature fails on the signature.
        let claims = edited_claims(PROOF_VECTOR, "x-none", None);
        let token = forge(&earlier_boot, &header(CALL_PROOF_TYP, KID), &claims);
        assert!(matches!(
            verify_proof(&token, &signer),
            Err(TokenError::BadSignature)
        ));
    }

    #[test]
    fn charset_and_shape_rejected() {
        let signer = rfc_signer();
        let (head, rest) = PROOF_VECTOR.split_once('.').unwrap();
        let malformed = [
            format!("{PROOF_VECTOR}=="),
            format!("{PROOF_VECTOR} "),
            format!(" {PROOF_VECTOR}"),
            PROOF_VECTOR.replacen('-', "+", 1),
            PROOF_VECTOR.replacen('_', "/", 1),
            format!("{head}é.{rest}"),
            format!("{head}.{rest}.e30"),
            head.to_owned(),
            format!("{head}.{}", rest.split_once('.').unwrap().0),
            format!(".{rest}"),
            format!("{head}..{}", rest.split_once('.').unwrap().1),
            "a".repeat(MAX_TOKEN_BYTES + 1),
            String::new(),
        ];
        for token in malformed {
            assert!(
                matches!(verify_proof(&token, &signer), Err(TokenError::Malformed)),
                "{token}"
            );
        }
    }

    #[test]
    fn non_zero_trailing_bits_rejected() {
        let signer = rfc_signer();
        // A 64-byte signature is 86 characters; the last carries 2 bits and 4 zero bits.
        let (input, signature) = PROOF_VECTOR.rsplit_once('.').unwrap();
        let last = *signature.as_bytes().last().unwrap();
        let index = B64URL.iter().position(|&c| c == last).unwrap();
        assert_eq!(index % 16, 0);
        let mut tampered = signature.as_bytes().to_vec();
        *tampered.last_mut().unwrap() = B64URL[index + 1];
        let token = format!("{input}.{}", String::from_utf8(tampered).unwrap());
        assert!(matches!(
            verify_proof(&token, &signer),
            Err(TokenError::Malformed)
        ));
    }

    #[test]
    fn non_canonical_json_rejected() {
        let signer = rfc_signer();
        let claims = edited_claims(PROOF_VECTOR, "x-none", None);
        let headers = [
            format!(r#"{{"alg": "ES256","kid":"{KID}","typ":"{CALL_PROOF_TYP}"}}"#),
            format!(r#"{{"kid":"{KID}","alg":"ES256","typ":"{CALL_PROOF_TYP}"}}"#),
            format!(r#"{{"alg":"ES256","alg":"ES256","kid":"{KID}","typ":"{CALL_PROOF_TYP}"}}"#),
            format!("{} ", header(CALL_PROOF_TYP, KID)),
        ];
        for header in headers {
            assert!(
                matches!(
                    verify_proof(&forge(&signer, &header, &claims), &signer),
                    Err(TokenError::Malformed)
                ),
                "{header}"
            );
        }
        let spaced = claims.replacen(':', ": ", 1);
        assert!(matches!(
            verify_proof(
                &forge(&signer, &header(CALL_PROOF_TYP, KID), &spaced),
                &signer
            ),
            Err(TokenError::Malformed)
        ));
    }

    #[test]
    fn signature_must_be_64_bytes_of_valid_scalars() {
        let signer = rfc_signer();
        let (input, signature) = PROOF_VECTOR.rsplit_once('.').unwrap();
        let bytes = URL_SAFE_NO_PAD.decode(signature).unwrap();
        let short = format!("{input}.{}", URL_SAFE_NO_PAD.encode(&bytes[..63]));
        let zero_r = [vec![0; 32], bytes[32..].to_vec()].concat();
        let zero_r = format!("{input}.{}", URL_SAFE_NO_PAD.encode(&zero_r));
        for token in [short, zero_r] {
            assert!(matches!(
                verify_proof(&token, &signer),
                Err(TokenError::SignatureEncoding)
            ));
        }
    }

    #[test]
    fn tampered_claims_rejected() {
        let signer = rfc_signer();
        let (head, rest) = PROOF_VECTOR.split_once('.').unwrap();
        let signature = rest.rsplit_once('.').unwrap().1;
        let claims = edited_claims(PROOF_VECTOR, "server_id", Some(JcsValue::string("b")));
        let token = format!("{head}.{}.{signature}", URL_SAFE_NO_PAD.encode(claims));
        assert!(matches!(
            verify_proof(&token, &signer),
            Err(TokenError::BadSignature)
        ));
    }

    // ---- Episode Token ----

    #[test]
    fn episode_claims_are_an_exact_set() {
        let signer = rfc_signer();
        let head = header(EPISODE_TYP, KID);
        let edits: [(&str, Option<JcsValue>); 7] = [
            ("nbf", JcsValue::int(i64::try_from(T0).unwrap())),
            ("jti", Some(JcsValue::string("x"))),
            ("sub", None),
            ("txn", Some(JcsValue::string("01JBAE0Z1TFCQ9Y41W9NF6YYMC"))),
            ("eid", Some(JcsValue::string("01jbae0z1tfcq9y41w9nf6yymb"))),
            ("peer_uid", JcsValue::int(i64::from(u32::MAX) + 1)),
            ("release_epoch", JcsValue::int(-1)),
        ];
        for (key, value) in edits {
            let claims = edited_claims(EPISODE_VECTOR, key, value);
            assert!(
                matches!(
                    verify_episode(&forge(&signer, &head, &claims), &signer),
                    Err(TokenError::InvalidClaims)
                ),
                "{key}"
            );
        }
    }

    #[test]
    fn episode_lifetime_is_capped() {
        let signer = rfc_signer();
        let too_long = EpisodeClaims {
            exp: T0 + EPISODE_MAX_LIFETIME_SECS + 1,
            ..episode_claims()
        };
        assert!(matches!(
            mint_episode_token(&signer, &too_long),
            Err(TokenError::LifetimeNotAllowed)
        ));
        let instant = EpisodeClaims {
            exp: T0,
            ..episode_claims()
        };
        assert!(matches!(
            mint_episode_token(&signer, &instant),
            Err(TokenError::LifetimeNotAllowed)
        ));
        let claims = edited_claims(EPISODE_VECTOR, "exp", JcsValue::int(1_800_028_801));
        let token = forge(&signer, &header(EPISODE_TYP, KID), &claims);
        assert!(matches!(
            verify_episode(&token, &signer),
            Err(TokenError::LifetimeNotAllowed)
        ));
    }

    #[test]
    fn episode_bindings_checked() {
        let signer = rfc_signer();
        let check = |expect: EpisodeExpectations<'_>| {
            verify_episode_token(EPISODE_VECTOR, &signer.verifier(), &expect, &episodes(), T0)
        };
        assert!(matches!(
            check(EpisodeExpectations {
                peer_uid: 20_009,
                ..episode_expect()
            }),
            Err(TokenError::PeerMismatch)
        ));
        assert!(matches!(
            check(EpisodeExpectations {
                release_epoch: 8,
                ..episode_expect()
            }),
            Err(TokenError::EpochMismatch)
        ));
        assert!(matches!(
            check(EpisodeExpectations {
                intent_digest: SCHEMA,
                ..episode_expect()
            }),
            Err(TokenError::IntentMismatch)
        ));
    }

    #[test]
    fn the_intent_is_looked_up_by_eid() {
        let signer = rfc_signer();
        let check = |digest_of: &dyn Fn(u128) -> Option<String>| {
            verify_episode_token_with(
                EPISODE_VECTOR,
                &signer.verifier(),
                20_001,
                7,
                digest_of,
                &episodes(),
                T0,
            )
        };
        assert_eq!(
            check(&|eid| (eid == EID).then(|| ACTION.to_owned()))
                .unwrap()
                .eid,
            EID
        );
        // Another intent's digest, or an eid the registry does not know.
        assert!(matches!(
            check(&|_| Some(SCHEMA.to_owned())),
            Err(TokenError::IntentMismatch)
        ));
        assert!(matches!(check(&|_| None), Err(TokenError::IntentMismatch)));
        // The lookup runs only after the signature, peer and epoch checks.
        let looked_up = std::cell::Cell::new(false);
        let result = verify_episode_token_with(
            EPISODE_VECTOR,
            &signer.verifier(),
            20_009,
            7,
            |_| {
                looked_up.set(true);
                None
            },
            &episodes(),
            T0,
        );
        assert!(matches!(result, Err(TokenError::PeerMismatch)));
        assert!(!looked_up.get());
    }

    #[test]
    fn is_over_reports_ended_idle_expired_and_unknown_episodes() {
        let exp = T0 + EPISODE_MAX_LIFETIME_SECS;
        let states = EpisodeStates::new(64, EPISODE_IDLE_SECS, CLOCK_SKEW_SECS);
        states.start(EID, exp, T0).unwrap();
        assert!(!states.is_over(EID, T0));
        assert!(!states.is_over(EID, T0 + EPISODE_IDLE_SECS));
        assert!(states.is_over(EID + 1, T0));
        // Idle, and idle is final.
        assert!(states.is_over(EID, T0 + EPISODE_IDLE_SECS + 1));
        assert!(states.is_over(EID, T0));
        // Expired, whatever its activity.
        let states = EpisodeStates::new(64, u64::MAX / 2, CLOCK_SKEW_SECS);
        states.start(EID, exp, T0).unwrap();
        assert!(!states.is_over(EID, exp + CLOCK_SKEW_SECS));
        assert!(states.is_over(EID, exp + CLOCK_SKEW_SECS + 1));
        // Ended.
        let states = EpisodeStates::new(64, EPISODE_IDLE_SECS, CLOCK_SKEW_SECS);
        states.start(EID, exp, T0).unwrap();
        states.end(EID).unwrap();
        assert!(states.is_over(EID, T0));
    }

    #[test]
    fn episode_expiry_and_skew() {
        let signer = rfc_signer();
        let exp = T0 + EPISODE_MAX_LIFETIME_SECS;
        let verify = |states: &EpisodeStates, now| {
            verify_episode_token(
                EPISODE_VECTOR,
                &signer.verifier(),
                &episode_expect(),
                states,
                now,
            )
        };
        // Kept active, so only the token's own window matters.
        let states = EpisodeStates::new(64, u64::MAX / 2, CLOCK_SKEW_SECS);
        states.start(EID, exp, T0).unwrap();
        assert!(verify(&states, exp + CLOCK_SKEW_SECS).is_ok());
        assert!(matches!(
            verify(&states, exp + CLOCK_SKEW_SECS + 1),
            Err(TokenError::Expired)
        ));
        // Issued in the future by more than the skew.
        let states = EpisodeStates::new(64, EPISODE_IDLE_SECS, CLOCK_SKEW_SECS);
        states.start(EID, exp, T0 - 100).unwrap();
        assert!(matches!(
            verify(&states, T0 - CLOCK_SKEW_SECS - 1),
            Err(TokenError::NotYetValid)
        ));
        assert!(verify(&states, T0 - CLOCK_SKEW_SECS).is_ok());
    }

    #[test]
    fn idle_timeout_ends_the_episode() {
        let signer = rfc_signer();
        let states = episodes();
        let verify = |now| {
            verify_episode_token(
                EPISODE_VECTOR,
                &signer.verifier(),
                &episode_expect(),
                &states,
                now,
            )
        };
        assert!(verify(T0 + EPISODE_IDLE_SECS).is_ok());
        // That use reset the timer.
        assert!(verify(T0 + 2 * EPISODE_IDLE_SECS).is_ok());
        assert!(matches!(
            verify(T0 + 3 * EPISODE_IDLE_SECS + 1),
            Err(TokenError::EpisodeIdle)
        ));
        // Idle is final: a backward clock step cannot revive it.
        assert!(matches!(verify(T0), Err(TokenError::EpisodeEnded)));
    }

    #[test]
    fn end_is_keyed_by_eid() {
        let signer = rfc_signer();
        let states = episodes();
        let later = mint_episode_token(
            &signer,
            &EpisodeClaims {
                iat: T0 + 5,
                ..episode_claims()
            },
        )
        .unwrap();
        let verify = |token: &str| {
            verify_episode_token(
                token,
                &signer.verifier(),
                &episode_expect(),
                &states,
                T0 + 5,
            )
        };
        assert!(verify(EPISODE_VECTOR).is_ok());
        assert!(verify(&later).is_ok());
        states.end(EID).unwrap();
        // Every token of the episode is refused, however it was minted or encoded.
        assert!(matches!(
            verify(EPISODE_VECTOR),
            Err(TokenError::EpisodeEnded)
        ));
        assert!(matches!(verify(&later), Err(TokenError::EpisodeEnded)));
        assert!(matches!(verify(&high_s(&later)), Err(TokenError::HighS)));
        assert!(matches!(
            states.end(EID + 1),
            Err(TokenError::UnknownEpisode)
        ));
        let stranger = mint_episode_token(
            &signer,
            &EpisodeClaims {
                eid: EID + 1,
                ..episode_claims()
            },
        )
        .unwrap();
        assert!(matches!(verify(&stranger), Err(TokenError::UnknownEpisode)));
    }

    #[test]
    fn episode_table_limits() {
        let states = EpisodeStates::new(2, EPISODE_IDLE_SECS, CLOCK_SKEW_SECS);
        states.start(1, T0 + 100, T0).unwrap();
        assert!(matches!(
            states.start(1, T0 + 100, T0),
            Err(TokenError::EpisodeExists)
        ));
        states.start(2, T0 + 200, T0).unwrap();
        assert!(matches!(
            states.start(3, T0 + 300, T0),
            Err(TokenError::TooManyEpisodes)
        ));
        // Once episode 1's tokens can no longer be valid, its slot frees.
        states
            .start(3, T0 + 300, T0 + 100 + CLOCK_SKEW_SECS + 1)
            .unwrap();
    }

    // ---- Call Proof ----

    #[test]
    fn proof_bindings_checked() {
        let signer = rfc_signer();
        let check = |expect: CallProofExpectations<'_>| {
            verify_call_proof(PROOF_VECTOR, &signer.verifier(), &expect, &cache(), T0)
        };
        assert!(matches!(
            check(CallProofExpectations {
                server_id: "b",
                ..proof_expect()
            }),
            Err(TokenError::ServerMismatch)
        ));
        assert!(matches!(
            check(CallProofExpectations {
                release_epoch: 6,
                ..proof_expect()
            }),
            Err(TokenError::EpochMismatch)
        ));
        assert!(matches!(
            check(CallProofExpectations {
                tool_schema_digest: ACTION,
                ..proof_expect()
            }),
            Err(TokenError::SchemaDigestMismatch)
        ));
        assert!(matches!(
            check(CallProofExpectations {
                action_digest: SCHEMA,
                ..proof_expect()
            }),
            Err(TokenError::ActionDigestMismatch)
        ));
        let head = header(CALL_PROOF_TYP, KID);
        for (key, value) in [
            ("iss", JcsValue::string("spiffe://corp.example/agent")),
            ("aud", JcsValue::string("spiffe://corp.example/tool-a")),
        ] {
            let token = forge(
                &signer,
                &head,
                &edited_claims(PROOF_VECTOR, key, Some(value)),
            );
            assert!(matches!(
                verify_proof(&token, &signer),
                Err(TokenError::IssuerOrAudience)
            ));
        }
        // aud must be a single string, not an array that merely contains the broker.
        let array = JcsValue::Array(vec![JcsValue::string(CALL_PROOF_AUD)]);
        let token = forge(
            &signer,
            &head,
            &edited_claims(PROOF_VECTOR, "aud", Some(array)),
        );
        assert!(matches!(
            verify_proof(&token, &signer),
            Err(TokenError::InvalidClaims)
        ));
    }

    #[test]
    fn payment_claims_exactly_on_payments() {
        let signer = rfc_signer();
        let verifier = signer.verifier();
        // A payment proof for a tool the lockfile does not mark as a payment, and the reverse.
        assert!(matches!(
            verify_call_proof(PROOF_VECTOR, &verifier, &read_expect(), &cache(), T0),
            Err(TokenError::PaymentClaimsMismatch)
        ));
        let read = issue_call_proof(&signer, &read_claims("r", T0)).unwrap();
        assert!(matches!(
            verify_call_proof(&read, &verifier, &proof_expect(), &cache(), T0),
            Err(TokenError::PaymentClaimsMismatch)
        ));
        assert!(verify_call_proof(&read, &verifier, &read_expect(), &cache(), T0).is_ok());
        // Payment members come together or not at all.
        let head = header(CALL_PROOF_TYP, KID);
        for key in PAYMENT_MEMBERS {
            let token = forge(&signer, &head, &edited_claims(PROOF_VECTOR, key, None));
            assert!(
                matches!(
                    verify_proof(&token, &signer),
                    Err(TokenError::InvalidClaims)
                ),
                "{key}"
            );
        }
        let token = forge(
            &signer,
            &head,
            &edited_claims(&read, "rid", JcsValue::int(1)),
        );
        assert!(matches!(
            verify_call_proof(&token, &verifier, &read_expect(), &cache(), T0),
            Err(TokenError::InvalidClaims)
        ));
        // The budget must match the forwarded arguments.
        for expected in [
            ExpectedPayment {
                amount_minor: 5001,
                currency: "USD",
            },
            ExpectedPayment {
                amount_minor: 5000,
                currency: "EUR",
            },
        ] {
            let expect = CallProofExpectations {
                payment: Some(expected),
                ..proof_expect()
            };
            assert!(matches!(
                verify_call_proof(PROOF_VECTOR, &verifier, &expect, &cache(), T0),
                Err(TokenError::BudgetMismatch)
            ));
        }
    }

    #[test]
    fn proof_lifetime_is_capped() {
        let signer = rfc_signer();
        let long = CallProofClaims {
            exp: T0 + CALL_PROOF_TTL_SECS + 1,
            ..proof_claims("j", T0)
        };
        assert!(matches!(
            issue_call_proof(&signer, &long),
            Err(TokenError::LifetimeNotAllowed)
        ));
        let claims = edited_claims(PROOF_VECTOR, "exp", JcsValue::int(1_800_000_061));
        let token = forge(&signer, &header(CALL_PROOF_TYP, KID), &claims);
        assert!(matches!(
            verify_proof(&token, &signer),
            Err(TokenError::LifetimeNotAllowed)
        ));
        let bad_jti = proof_claims("not a jti", T0);
        assert!(matches!(
            issue_call_proof(&signer, &bad_jti),
            Err(TokenError::InvalidClaims)
        ));
    }

    #[test]
    fn broker_boot_second_cutoff() {
        let signer = rfc_signer();
        let verifier = signer.verifier();
        let booted_at_t0 = ReplayCache::new(16, T0, CLOCK_SKEW_SECS);
        assert!(matches!(
            verify_call_proof(PROOF_VECTOR, &verifier, &proof_expect(), &booted_at_t0, T0),
            Err(TokenError::BeforeBoot)
        ));
        let next = issue_call_proof(&signer, &proof_claims("next", T0 + 1)).unwrap();
        assert!(
            verify_call_proof(&next, &verifier, &proof_expect(), &booted_at_t0, T0 + 1).is_ok()
        );
    }

    #[test]
    fn replays_rejected() {
        let signer = rfc_signer();
        let verifier = signer.verifier();
        let cache = cache();
        let verify = |token: &str| verify_call_proof(token, &verifier, &proof_expect(), &cache, T0);
        assert!(verify(PROOF_VECTOR).is_ok());
        assert!(matches!(verify(PROOF_VECTOR), Err(TokenError::Replayed)));
        // A different proof reusing the jti is a replay too.
        let reused =
            issue_call_proof(&signer, &proof_claims("AAAAAAAAAAAAAAAAAAAAAA", T0 + 1)).unwrap();
        assert!(matches!(verify(&reused), Err(TokenError::Replayed)));
    }

    #[test]
    fn invalid_proofs_do_not_fill_the_cache() {
        let signer = rfc_signer();
        let cache = ReplayCache::new(1, T0 - 10, CLOCK_SKEW_SECS);
        let wrong = CallProofExpectations {
            server_id: "b",
            ..proof_expect()
        };
        for _ in 0..3 {
            assert!(
                verify_call_proof(PROOF_VECTOR, &signer.verifier(), &wrong, &cache, T0).is_err()
            );
        }
        assert!(
            verify_call_proof(
                PROOF_VECTOR,
                &signer.verifier(),
                &proof_expect(),
                &cache,
                T0
            )
            .is_ok()
        );
    }

    #[test]
    fn full_cache_fails_closed() {
        let signer = rfc_signer();
        let verifier = signer.verifier();
        let cache = ReplayCache::new(2, T0 - 10, CLOCK_SKEW_SECS);
        let proof = |jti: &str, iat| issue_call_proof(&signer, &proof_claims(jti, iat)).unwrap();
        let verify =
            |token: &str, now| verify_call_proof(token, &verifier, &proof_expect(), &cache, now);
        assert!(verify(&proof("a", T0), T0).is_ok());
        assert!(verify(&proof("b", T0), T0).is_ok());
        let error = verify(&proof("c", T0), T0).unwrap_err();
        assert!(matches!(error, TokenError::ReplayCacheFull));
        assert_eq!(error.to_agent_code(), PEP_UNAVAILABLE);
        // Once a and b can never pass the time window again, they are evicted.
        let later = T0 + CALL_PROOF_TTL_SECS + CLOCK_SKEW_SECS + 1;
        assert!(verify(&proof("c", later), later).is_ok());
    }

    #[test]
    fn clock_high_water_mark_survives_a_backward_step() {
        let signer = rfc_signer();
        let verifier = signer.verifier();
        let cache = cache();
        let verify =
            |token: &str, now| verify_call_proof(token, &verifier, &proof_expect(), &cache, now);
        assert!(verify(PROOF_VECTOR, T0).is_ok());
        // Time passes beyond the proof's window, which evicts its jti...
        let later = T0 + CALL_PROOF_TTL_SECS + CLOCK_SKEW_SECS + 1;
        assert!(
            verify(
                &issue_call_proof(&signer, &proof_claims("b", later)).unwrap(),
                later
            )
            .is_ok()
        );
        // ...and a clock stepped back to T0 still cannot re-admit it.
        assert!(matches!(verify(PROOF_VECTOR, T0), Err(TokenError::Expired)));
        // The same holds for Episode Tokens.
        let states = EpisodeStates::new(64, u64::MAX / 2, CLOCK_SKEW_SECS);
        let exp = T0 + EPISODE_MAX_LIFETIME_SECS;
        states.start(EID, exp, T0).unwrap();
        let verify = |now| {
            verify_episode_token(
                EPISODE_VECTOR,
                &signer.verifier(),
                &episode_expect(),
                &states,
                now,
            )
        };
        assert!(matches!(
            verify(exp + CLOCK_SKEW_SECS + 1),
            Err(TokenError::Expired)
        ));
        assert!(matches!(verify(T0), Err(TokenError::Expired)));
    }

    #[test]
    fn concurrent_replays_admit_exactly_once() {
        // G3's concurrency class, in-process (RV4 #14): eight threads present the same unspent
        // proof at once.
        let signer = rfc_signer();
        let verifier = signer.verifier();
        let cache = cache();
        let results: Vec<_> = thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        verify_call_proof(PROOF_VECTOR, &verifier, &proof_expect(), &cache, T0)
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect()
        });
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert!(
            results
                .iter()
                .filter(|result| result.is_err())
                .all(|result| matches!(result, Err(TokenError::Replayed)))
        );
    }

    #[test]
    fn payment_claims_only_for_held_reservations() {
        let reservation = |state| Reservation {
            id: 3,
            call_id: "7".to_owned(),
            amount_minor: 5000,
            entity: "INV-1001".to_owned(),
            action_digest: ACTION.to_owned(),
            witness_seq: 1,
            state,
        };
        let mut budget = Budget::empty();
        budget.reserved = 7000;
        budget.committed = 1000;
        let claims = PaymentClaims::for_held(
            &reservation(ResState::Held),
            &budget,
            "USD",
            vec![PROV.to_owned()],
        )
        .unwrap();
        assert_eq!(claims.rid(), 3);
        assert_eq!(claims.prov(), [PROV.to_owned()]);
        assert_eq!(
            claims.budget(),
            &BudgetClaim {
                currency: "USD".to_owned(),
                amount_minor: 5000,
                reserved_minor: 7000,
                committed_minor: 1000,
            }
        );
        for state in [
            ResState::AwaitingStepUp,
            ResState::NeedsReconcile,
            ResState::Released,
            ResState::Committed,
        ] {
            assert!(matches!(
                PaymentClaims::for_held(&reservation(state), &budget, "USD", vec![PROV.to_owned()]),
                Err(TokenError::NotHeld)
            ));
        }
        let held = reservation(ResState::Held);
        for prov in [
            vec![],
            vec![PROV.to_owned(); 3],
            vec!["sha-256:short".to_owned()],
        ] {
            assert!(matches!(
                PaymentClaims::for_held(&held, &budget, "USD", prov),
                Err(TokenError::InvalidClaims)
            ));
        }
        assert!(matches!(
            PaymentClaims::for_held(&held, &budget, "usd", vec![PROV.to_owned()]),
            Err(TokenError::InvalidClaims)
        ));
    }

    #[test]
    fn agent_codes() {
        assert_eq!(TokenError::Replayed.to_agent_code(), PEP_DENIED);
        assert_eq!(TokenError::EpisodeEnded.to_agent_code(), PEP_DENIED);
        assert_eq!(TokenError::HighS.to_agent_code(), PEP_DENIED);
        assert_eq!(TokenError::Poisoned.to_agent_code(), PEP_UNAVAILABLE);
    }
}
