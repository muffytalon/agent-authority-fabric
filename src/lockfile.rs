//! The lockfile v1 (L1): a JCS-canonical payload inside a DSSE envelope.
//!
//! The payload carries each server's full `server/discover` result and `tools/list`
//! definitions, which the PEP serves as pinned (M1) and the drift poller compares upstream
//! against ([`crate::poll`]), and per tool the policy the engine enforces, under the engine's
//! own names, with a strict argument schema ([`crate::schema`]).
//!
//! **The envelope** ([`verify_envelope`]) is DSSE v1 with `payloadType`
//! [`PAYLOAD_TYPE`]: `{"payload": base64, "payloadType": …, "signatures": [{"keyid"?: …,
//! "sig": base64}]}`, nothing else. Either base64 alphabet is accepted, padded or not, as DSSE
//! allows, but never both in one field and never with non-zero trailing bits. Each signature is
//! ECDSA P-256 over SHA-256 of the PAE, in strict DER only, so one signature has one encoding;
//! `keyid` is a hint and is not trusted. The payload must already be JCS-canonical, so
//! `lockfile_digest = digest(payload)` hashes exactly the signed bytes. The config's signers
//! hold each key in one role, and the lockfile needs that role's threshold of distinct keys:
//! [`RELEASE_ROLE`] always, and [`SECURITY_ROLE`] too when it pins a payment, a sink, or a tool
//! whose output can witness an amount ([`needs_security`], SPEC §4).
//!
//! ```json
//! {"lockfile_version": 1, "release_epoch": 7, "instructions": "…",
//!  "stores": {"notes://agent": {"case_insensitive": false}},
//!  "servers": {"a": {"endpoint": "…", "identity": "…", "protocol_version": "2026-07-28",
//!    "discover": {…}, "tools": {"get_note": {"definition": {"name": "get_note", …},
//!      "policy": {"effect": "read", "args": [{"pointer": "/key", "role": "store_key"}], …}}}}}}
//! ```
//!
//! Load refuses, beyond what the engine checks ([`crate::engine::validate_pins`]):
//! - tool names that are not 1 to 128 characters of `[A-Za-z0-9_.-]`, or that two servers
//!   share;
//! - a definition that carries `x-mcp-header` anywhere (RV2);
//! - the effect classes `destructive` and `code_exec`, and `role_contracts` or dynamic sinks;
//! - a payment tool with no `currency` argument;
//! - a store reader (`reads_stores`) whose `output_label` is below the high-water label of a
//!   store some pinned tool writes (RV4 #8);
//! - a `strict_schema` whose leaves are not exactly the `args` pointers, or whose types do not
//!   fit their roles: an `amount` is an integer with `minimum` ≥ 0 and `maximum` ≤ 2^53 − 1, a
//!   `currency` a string of exactly three characters (any `enum` of three uppercase letters),
//!   and an `entity`, `store_uri`, `store_key` or `sink_destination` a string, each required;
//! - a `step_up_over_minor` on a tool that is not a payment.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use base64::Engine as _;
use base64::alphabet::{self, Alphabet};
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};

use crate::config::{Fields, LoadError, LockfileSection, Problem, as_array, as_str, is_plain_name};
use crate::engine::{
    AmountBinding, ArgRole, ArgSpec, Confidentiality, EffectClass, EntityKind, Integrity,
    KeyPolicy, Label, ToolPins, ToolPolicy, validate_pins,
};
use crate::forward::{PROTOCOL_VERSION, is_header_safe_tool_name};
use crate::jcs::{self, JcsValue, MAX_SAFE_INTEGER, ParseOptions};
use crate::schema::{ArgSchema, SchemaType};
use crate::tokens::Es256Signer;

/// The payload format this module reads.
pub const LOCKFILE_VERSION: u64 = 1;
/// The DSSE `payloadType` of a signed lockfile (step 10).
pub const PAYLOAD_TYPE: &str = "application/vnd.pep-sidecar.lockfile.v1+json";
/// Longest `server_id`: the broker routes `/mcp/{server_id}`.
pub const MAX_SERVER_ID: usize = 64;
/// Largest signed lockfile read: a payload at the definition profile's 8 MiB, in base64, with
/// its signatures.
pub const MAX_ENVELOPE_BYTES: usize = 12 * 1024 * 1024;
/// Most signatures one envelope may carry.
pub const MAX_SIGNATURES: usize = 16;
/// Most signer keys a config may trust, which bounds the verifications one load can cost.
pub const MAX_SIGNERS: usize = 16;
/// The role whose threshold every lockfile needs.
pub const RELEASE_ROLE: &str = "release";
/// The role whose threshold a lockfile also needs when [`needs_security`] holds (SPEC §4).
pub const SECURITY_ROLE: &str = "security";
/// The largest DER encoding of a P-256 ECDSA signature.
const MAX_DER_SIGNATURE_BYTES: usize = 72;
/// Values an envelope may hold: its members and up to [`MAX_SIGNATURES`] signatures.
const MAX_ENVELOPE_NODES: usize = 128;

/// The label of anything an agent may have written to a store: the most confidential, and
/// agent-written (RV4 #8). No store policy caps it in Week 2.
pub const STORE_HIGH_WATER: Label =
    Label::new(Confidentiality::Secret, Integrity::UntrustedAgentWrite);

/// One pinned server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedServer {
    /// Where the broker reaches it. The broker routes by its own config (RV4 #12); this is the
    /// reviewed value its route must match.
    pub endpoint: String,
    /// The server's workload identity.
    pub identity: String,
    /// The MCP revision it speaks.
    pub protocol_version: String,
    /// Its full `server/discover` result, for drift.
    pub discover: JcsValue,
    /// Its full tool definitions in name order: what `tools/list` serves while it serves.
    pub definitions: Vec<JcsValue>,
}

/// A loaded lockfile payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lockfile {
    /// `lockfile_digest`: the digest of the payload.
    pub digest: String,
    /// The release epoch.
    pub release_epoch: u64,
    /// Pinned `instructions` the PEP's `server/discover` serves, if any (M1).
    pub instructions: Option<String>,
    /// The servers, by `server_id`.
    pub servers: BTreeMap<String, PinnedServer>,
    /// The engine's view.
    pub pins: ToolPins,
}

impl Lockfile {
    /// The definitions `tools/list` serves (M1): every tool of every server for which
    /// `serving` holds, by server and then by name.
    pub fn tools_list(&self, serving: impl Fn(&str) -> bool) -> Vec<JcsValue> {
        self.servers
            .iter()
            .filter(|(server_id, _)| serving(server_id))
            .flat_map(|(_, server)| server.definitions.iter().cloned())
            .collect()
    }
}

/// DSSE's pre-authentication encoding: `"DSSEv1" SP LEN(type) SP type SP LEN(body) SP body`,
/// with each length in ASCII decimal. Signatures cover this, never the envelope's text.
#[must_use]
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "DSSEv1 {} {payload_type} {} ",
        payload_type.len(),
        payload.len()
    )
    .into_bytes();
    out.extend_from_slice(payload);
    out
}

/// One alphabet, padded or not, rejecting non-zero trailing bits (the crate's default).
const fn engine(alphabet: &Alphabet) -> GeneralPurpose {
    GeneralPurpose::new(
        alphabet,
        GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
    )
}

const STANDARD: GeneralPurpose = engine(&alphabet::STANDARD);
const URL_SAFE: GeneralPurpose = engine(&alphabet::URL_SAFE);

/// Decodes an envelope field in either base64 alphabet, as DSSE allows. A field that mixes the
/// two is refused rather than read under one of them.
fn decode_base64(text: &str) -> Option<Vec<u8>> {
    let standard = text.bytes().any(|byte| matches!(byte, b'+' | b'/'));
    let url_safe = text.bytes().any(|byte| matches!(byte, b'-' | b'_'));
    match (standard, url_safe) {
        (true, true) => None,
        (false, true) => URL_SAFE.decode(text).ok(),
        _ => STANDARD.decode(text).ok(),
    }
}

/// Whether the lockfile pins anything SPEC §4 puts behind the security role: a payment, an
/// external sink or any tool that sends to a destination, or a tool whose output can witness a
/// payment amount (Trusted output, `trusted_fields`, or the lookup of an `amount_binding`).
#[must_use]
pub fn needs_security(pins: &ToolPins) -> bool {
    let lookups: BTreeSet<&str> = pins
        .tools
        .values()
        .filter_map(|tool| tool.amount_binding.as_ref())
        .map(|binding| binding.lookup_tool.as_str())
        .collect();
    pins.tools.values().any(|tool| {
        matches!(
            tool.effect,
            EffectClass::Payment | EffectClass::MutatingExternal
        ) || !tool.destinations.is_empty()
            || tool
                .args
                .iter()
                .any(|spec| spec.role == ArgRole::SinkDestination)
            || tool.output_label.integ == Integrity::Trusted
            || !tool.trusted_fields.is_empty()
            || lookups.contains(tool.name.as_str())
    })
}

fn bad(why: &'static str) -> LoadError {
    LoadError::at("lockfile", Problem::Signature(why))
}

/// Reads the signed lockfile at `section.path` with `read`, and verifies it with
/// [`verify_envelope`].
///
/// # Errors
///
/// Returns a [`LoadError`] if the file cannot be read, or as [`verify_envelope`] does.
pub fn load_signed(
    section: &LockfileSection,
    read: &dyn Fn(&Path) -> Option<Vec<u8>>,
) -> Result<Lockfile, LoadError> {
    let bytes = read(&section.path)
        .ok_or_else(|| LoadError::at("lockfile.path", Problem::Invalid("unreadable")))?;
    verify_envelope(&bytes, section)
}

/// Verifies a signed lockfile against `section`'s signers, thresholds and rollback floor, and
/// parses its payload with [`parse_payload`]. Nothing parses the payload until the release
/// role's threshold is met. Payload errors are reported under `lockfile.payload`.
///
/// # Errors
///
/// Returns a [`LoadError`] for an envelope that is not exactly DSSE v1 with the lockfile's
/// `payloadType`, a payload that is not JCS-canonical, a malformed signature, a role whose
/// threshold of distinct keys is not met, a `release_epoch` below `min_accepted_epoch`, or any
/// payload error.
pub fn verify_envelope(bytes: &[u8], section: &LockfileSection) -> Result<Lockfile, LoadError> {
    if bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(bad("larger than 12 MiB"));
    }
    let options = ParseOptions::result(MAX_ENVELOPE_BYTES, MAX_ENVELOPE_NODES);
    let envelope = jcs::parse_with(bytes, &options)
        .map_err(|error| LoadError::at("lockfile", Problem::Json(error)))?
        .value;
    let mut fields = Fields::of(&envelope, "lockfile")?;
    if fields.string("payloadType")? != PAYLOAD_TYPE {
        return Err(bad("payloadType is not the lockfile v1 type"));
    }
    let payload =
        decode_base64(fields.string("payload")?).ok_or_else(|| bad("payload is not base64"))?;
    let signatures_path = fields.path_of("signatures");
    let signatures = as_array(fields.value("signatures")?, &signatures_path)?;
    fields.done()?;
    if signatures.is_empty() || signatures.len() > MAX_SIGNATURES {
        return Err(bad("an envelope carries 1 to 16 signatures"));
    }
    let signed = pae(PAYLOAD_TYPE, &payload);
    // Each trusted key that signed, by role. A key counts once however many signatures it made.
    let mut signed_by: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for (index, entry) in signatures.iter().enumerate() {
        let mut signature = Fields::of(entry, &format!("{signatures_path}[{index}]"))?;
        // A hint only: every trusted key is tried.
        let keyid_path = signature.path_of("keyid");
        if let Some(keyid) = signature.optional("keyid") {
            as_str(keyid, &keyid_path)?;
        }
        let der = decode_base64(signature.string("sig")?)
            .filter(|der| der.len() <= MAX_DER_SIGNATURE_BYTES)
            .ok_or_else(|| bad("a sig is not base64 of a DER signature"))?;
        signature.done()?;
        for signer in &section.signers {
            match signer.key.verify_der(&signed, &der) {
                Ok(()) => {
                    signed_by
                        .entry(signer.role.as_str())
                        .or_default()
                        .insert(signer.key.kid());
                }
                Err(crate::tokens::TokenError::SignatureEncoding) => {
                    return Err(bad("a sig is not strict DER"));
                }
                Err(_) => {}
            }
        }
    }
    let met = |role: &str| {
        let needed = section.thresholds.get(role).copied().unwrap_or(0);
        let have = signed_by.get(role).map_or(0, BTreeSet::len);
        needed >= 1 && u32::try_from(have).is_ok_and(|have| have >= needed)
    };
    // The release signers vouch for the bytes before anything parses them; only the security
    // rule needs the parsed pins.
    if !met(RELEASE_ROLE) {
        return Err(bad("the release role's threshold is not met"));
    }
    if payload.len() > jcs::MAX_DEFINITION_BYTES {
        return Err(bad("payload larger than 8 MiB"));
    }
    let value = jcs::parse_with(&payload, &ParseOptions::definition())
        .map_err(|error| LoadError::at("lockfile.payload", Problem::Json(error)))?
        .value;
    if value.to_canonical_bytes() != payload {
        return Err(bad("payload is not JCS-canonical"));
    }
    let lockfile = parse_payload(&value, "lockfile.payload")?;
    if needs_security(&lockfile.pins) && !met(SECURITY_ROLE) {
        return Err(bad(
            "it pins a payment, a sink or an amount witness, and the security role's threshold is not met",
        ));
    }
    if lockfile.release_epoch < section.min_accepted_epoch {
        return Err(LoadError::at(
            "lockfile.payload.release_epoch",
            Problem::Invalid("below lockfile.min_accepted_epoch"),
        ));
    }
    Ok(lockfile)
}

/// The envelope fields of an existing signed lockfile, unverified: what `pepctl lock sign`
/// adds a signature to.
fn envelope_parts(bytes: &[u8]) -> Result<(Vec<u8>, Vec<JcsValue>), LoadError> {
    if bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(bad("larger than 12 MiB"));
    }
    let options = ParseOptions::result(MAX_ENVELOPE_BYTES, MAX_ENVELOPE_NODES);
    let envelope = jcs::parse_with(bytes, &options)
        .map_err(|error| LoadError::at("lockfile", Problem::Json(error)))?
        .value;
    let mut fields = Fields::of(&envelope, "lockfile")?;
    if fields.string("payloadType")? != PAYLOAD_TYPE {
        return Err(bad("payloadType is not the lockfile v1 type"));
    }
    let payload =
        decode_base64(fields.string("payload")?).ok_or_else(|| bad("payload is not base64"))?;
    let signatures_path = fields.path_of("signatures");
    let signatures = as_array(fields.value("signatures")?, &signatures_path)?.to_vec();
    fields.done()?;
    Ok((payload, signatures))
}

/// Signs a lockfile with `signer`. `input` is either a payload, which must be JCS-canonical and
/// parse as one ([`parse_payload`]), or an envelope made by this function, to which the
/// signature is added. The output is canonical JSON with the payload and signatures in
/// standard padded base64 and the signer's RFC 7638 thumbprint as `keyid`.
///
/// # Errors
///
/// Returns a [`LoadError`] for a payload that is not canonical or does not parse, an envelope
/// that is malformed or already signed by this key, or more than [`MAX_SIGNATURES`] signatures.
pub fn sign(input: &[u8], signer: &Es256Signer) -> Result<Vec<u8>, LoadError> {
    let is_envelope = jcs::parse_with(
        input,
        &ParseOptions::result(MAX_ENVELOPE_BYTES, MAX_ENVELOPE_NODES),
    )
    .ok()
    .is_some_and(|parsed| parsed.value.get("payloadType").is_some());
    let (payload, mut signatures) = if is_envelope {
        envelope_parts(input)?
    } else {
        (input.to_vec(), Vec::new())
    };
    let value = jcs::parse_with(&payload, &ParseOptions::definition())
        .map_err(|error| LoadError::at("lockfile.payload", Problem::Json(error)))?
        .value;
    if value.to_canonical_bytes() != payload {
        return Err(bad("payload is not JCS-canonical"));
    }
    parse_payload(&value, "lockfile.payload")?;
    let pre_auth = pae(PAYLOAD_TYPE, &payload);
    let verifier = signer.verifier();
    let already = signatures.iter().any(|entry| {
        entry
            .get("sig")
            .and_then(JcsValue::as_str)
            .and_then(decode_base64)
            .is_some_and(|der| verifier.verify_der(&pre_auth, &der).is_ok())
    });
    if already {
        return Err(bad("this key has already signed it"));
    }
    if signatures.len() >= MAX_SIGNATURES {
        return Err(bad("an envelope carries 1 to 16 signatures"));
    }
    let der = signer
        .sign_der(&pre_auth)
        .map_err(|_| bad("signing failed"))?;
    let entry = |keyid: &str, sig: &str| -> Result<JcsValue, LoadError> {
        Ok(JcsValue::Object(
            jcs::JcsObject::from_entries(vec![
                (jcs::JcsString::new("keyid"), JcsValue::string(keyid)),
                (jcs::JcsString::new("sig"), JcsValue::string(sig)),
            ])
            .map_err(|error| LoadError::at("lockfile", Problem::Json(error)))?,
        ))
    };
    signatures.push(entry(signer.kid(), &STANDARD.encode(der))?);
    let envelope = jcs::JcsObject::from_entries(vec![
        (
            jcs::JcsString::new("payload"),
            JcsValue::string(STANDARD.encode(&payload)),
        ),
        (
            jcs::JcsString::new("payloadType"),
            JcsValue::string(PAYLOAD_TYPE),
        ),
        (
            jcs::JcsString::new("signatures"),
            JcsValue::Array(signatures),
        ),
    ])
    .map_err(|error| LoadError::at("lockfile", Problem::Json(error)))?;
    Ok(JcsValue::Object(envelope).to_canonical_bytes())
}

/// Parses and checks the payload `value`, found at `path` in the config.
///
/// # Errors
///
/// Returns a [`LoadError`] naming the first field that is missing, unexpected, of the wrong
/// type or not allowed.
pub fn parse_payload(value: &JcsValue, path: &str) -> Result<Lockfile, LoadError> {
    let mut fields = Fields::of(value, path)?;
    if fields.u64("lockfile_version")? != LOCKFILE_VERSION {
        return Err(LoadError::at(
            &fields.path_of("lockfile_version"),
            Problem::Invalid("unsupported lockfile version"),
        ));
    }
    let release_epoch = fields.u64("release_epoch")?;
    let instructions_path = fields.path_of("instructions");
    let instructions = fields
        .optional("instructions")
        .map(|value| as_str(value, &instructions_path).map(str::to_owned))
        .transpose()?;
    let mut stores = BTreeMap::new();
    let mut store_fields = fields.object("stores")?;
    for (uri, policy, policy_path) in store_fields.members() {
        let mut policy = Fields::of(policy, &policy_path)?;
        stores.insert(
            uri.to_owned(),
            KeyPolicy {
                case_insensitive: policy.bool("case_insensitive")?,
            },
        );
        policy.done()?;
    }
    store_fields.done()?;
    let mut servers = BTreeMap::new();
    let mut tools = BTreeMap::new();
    let mut readers = Vec::new();
    let mut server_fields = fields.object("servers")?;
    for (server_id, server, server_path) in server_fields.members() {
        if !is_plain_name(server_id, MAX_SERVER_ID) {
            return Err(LoadError::at(
                &server_path,
                Problem::Invalid("a server_id is 1 to 64 characters of [A-Za-z0-9_.-]"),
            ));
        }
        let pinned = pinned_server(server_id, server, &server_path, &mut tools, &mut readers)?;
        servers.insert(server_id.to_owned(), pinned);
    }
    server_fields.done()?;
    fields.done()?;
    let pins = ToolPins {
        release_epoch,
        lockfile_digest: jcs::digest_value(value),
        stores,
        tools,
    };
    validate_pins(&pins).map_err(|error| LoadError::at(path, Problem::Engine(error)))?;
    for (tool, stores_read, reader_path) in &readers {
        check_reader(&pins, tool, stores_read, reader_path)?;
    }
    check_secret_stays_home(&pins, path)?;
    Ok(Lockfile {
        digest: pins.lockfile_digest.clone(),
        release_epoch,
        instructions,
        servers,
        pins,
    })
}

type Reader = (String, Vec<String>, String);

fn pinned_server(
    server_id: &str,
    value: &JcsValue,
    path: &str,
    tools: &mut BTreeMap<String, ToolPolicy>,
    readers: &mut Vec<Reader>,
) -> Result<PinnedServer, LoadError> {
    let mut fields = Fields::of(value, path)?;
    let endpoint = non_empty(&mut fields, "endpoint")?;
    let identity = non_empty(&mut fields, "identity")?;
    let protocol_version = fields.string("protocol_version")?;
    if protocol_version != PROTOCOL_VERSION {
        return Err(LoadError::at(
            &fields.path_of("protocol_version"),
            Problem::Invalid("the PEP speaks only 2026-07-28"),
        ));
    }
    let discover_path = fields.path_of("discover");
    let discover = fields.value("discover")?;
    if discover.as_object().is_none() {
        return Err(LoadError::at(&discover_path, Problem::Type("an object")));
    }
    let discover = discover.clone();
    let mut definitions = Vec::new();
    let mut tool_fields = fields.object("tools")?;
    for (name, tool, tool_path) in tool_fields.members() {
        let mut entry = Fields::of(tool, &tool_path)?;
        let definition_path = entry.path_of("definition");
        let definition = entry.value("definition")?;
        check_definition(name, definition, &definition_path)?;
        if tools.contains_key(name) {
            return Err(LoadError::at(
                &tool_path,
                Problem::Invalid("a tool name may be pinned on one server only"),
            ));
        }
        let policy_path = entry.path_of("policy");
        let (policy, stores_read) = policy(
            name,
            server_id,
            jcs::digest_value(definition),
            entry.value("policy")?,
            &policy_path,
        )?;
        entry.done()?;
        if !stores_read.is_empty() {
            readers.push((name.to_owned(), stores_read, policy_path));
        }
        tools.insert(name.to_owned(), policy);
        definitions.push(definition.clone());
    }
    tool_fields.done()?;
    fields.done()?;
    Ok(PinnedServer {
        endpoint,
        identity,
        protocol_version: protocol_version.to_owned(),
        discover,
        definitions,
    })
}

/// A definition is an object named `name`, with a header-safe name and no `x-mcp-header`.
fn check_definition(name: &str, definition: &JcsValue, path: &str) -> Result<(), LoadError> {
    let object = definition
        .as_object()
        .ok_or_else(|| LoadError::at(path, Problem::Type("an object")))?;
    if object.get("name").and_then(JcsValue::as_str) != Some(name) {
        return Err(LoadError::at(
            path,
            Problem::Invalid("its name must equal the tool's key"),
        ));
    }
    if !is_header_safe_tool_name(name) {
        return Err(LoadError::at(
            path,
            Problem::Invalid("a tool name is 1 to 128 characters of [A-Za-z0-9_.-]"),
        ));
    }
    let mut stack = vec![definition];
    while let Some(value) = stack.pop() {
        match value {
            JcsValue::Object(object) => {
                for (key, child) in object.entries() {
                    if key.as_str() == "x-mcp-header" {
                        return Err(LoadError::at(
                            path,
                            Problem::Invalid("x-mcp-header is not supported in Week 2"),
                        ));
                    }
                    stack.push(child);
                }
            }
            JcsValue::Array(items) => stack.extend(items.iter()),
            JcsValue::Null | JcsValue::Bool(_) | JcsValue::Number(_) | JcsValue::String(_) => {}
        }
    }
    Ok(())
}

fn policy(
    name: &str,
    server_id: &str,
    schema_digest: String,
    value: &JcsValue,
    path: &str,
) -> Result<(ToolPolicy, Vec<String>), LoadError> {
    let mut fields = Fields::of(value, path)?;
    let effect_path = fields.path_of("effect");
    let effect = match fields.string("effect")? {
        "read" => EffectClass::ReadOnly,
        "mutating_internal" => EffectClass::MutatingInternal,
        "external_sink" => EffectClass::MutatingExternal,
        "mutating_financial" => EffectClass::Payment,
        "destructive" | "code_exec" => {
            return Err(LoadError::at(
                &effect_path,
                Problem::Invalid("not allowed in Week 2"),
            ));
        }
        _ => {
            return Err(LoadError::at(
                &effect_path,
                Problem::Invalid("unknown effect class"),
            ));
        }
    };
    let args_path = fields.path_of("args");
    let mut args = Vec::new();
    for (index, spec) in as_array(fields.value("args")?, &args_path)?
        .iter()
        .enumerate()
    {
        args.push(arg_spec(spec, &format!("{args_path}[{index}]"))?);
    }
    if effect == EffectClass::Payment && !args.iter().any(|spec| spec.role == ArgRole::Currency) {
        return Err(LoadError::at(
            &args_path,
            Problem::Invalid("a payment tool must declare a currency argument"),
        ));
    }
    let store_uri_path = fields.path_of("store_uri");
    let store_uri = fields
        .optional("store_uri")
        .map(|value| as_str(value, &store_uri_path).map(str::to_owned))
        .transpose()?;
    let sink_path = fields.path_of("sink_clearance");
    let sink_clearance = confidentiality(fields.string("sink_clearance")?, &sink_path)?;
    let mut destinations = BTreeMap::new();
    let destinations_path = fields.path_of("destinations");
    if let Some(value) = fields.optional("destinations") {
        let mut entries = Fields::of(value, &destinations_path)?;
        for (destination, clearance, clearance_path) in entries.members() {
            let clearance = confidentiality(as_str(clearance, &clearance_path)?, &clearance_path)?;
            destinations.insert(destination.to_owned(), clearance);
        }
        entries.done()?;
    }
    let mut label = fields.object("output_label")?;
    let conf_path = label.path_of("conf");
    let integ_path = label.path_of("integ");
    let output_label = Label::new(
        confidentiality(label.string("conf")?, &conf_path)?,
        integrity(label.string("integ")?, &integ_path)?,
    );
    label.done()?;
    let trusted_fields = string_set(&mut fields, "trusted_fields")?;
    let amount_binding = if fields.optional("amount_binding").is_some() {
        let mut binding = fields.object("amount_binding")?;
        let parsed = AmountBinding {
            lookup_tool: binding.string("lookup_tool")?.to_owned(),
            entity_arg_pointer: binding.string("entity_arg_pointer")?.to_owned(),
            lookup_entity_pointer: binding.string("lookup_entity_pointer")?.to_owned(),
            result_amount_pointer: binding.string("result_amount_pointer")?.to_owned(),
            result_currency_pointer: binding.string("result_currency_pointer")?.to_owned(),
        };
        binding.done()?;
        Some(parsed)
    } else {
        None
    };
    let max_result_bytes = fields.positive_usize("max_result_bytes")?;
    let max_result_nodes = fields.positive_usize("max_result_nodes")?;
    let reads_stores: Vec<String> = string_set(&mut fields, "reads_stores")?
        .into_iter()
        .collect();
    let schema_path = fields.path_of("strict_schema");
    let schema = ArgSchema::parse(fields.value("strict_schema")?)
        .map_err(|error| LoadError::at(&schema_path, Problem::Schema(error)))?;
    check_schema(&schema, &args, &schema_path)?;
    let step_up_path = fields.path_of("step_up_over_minor");
    let step_up_over_minor = fields
        .optional("step_up_over_minor")
        .map(|_| fields.u64("step_up_over_minor"))
        .transpose()?;
    if step_up_over_minor.is_some() && effect != EffectClass::Payment {
        return Err(LoadError::at(
            &step_up_path,
            Problem::Invalid("only a payment tool has a step-up threshold"),
        ));
    }
    fields.done()?;
    check_clearance(
        effect,
        &args,
        sink_clearance,
        &destinations,
        store_uri.is_some() || !reads_stores.is_empty(),
        &sink_path,
    )?;
    let policy = ToolPolicy {
        name: name.to_owned(),
        server_id: server_id.to_owned(),
        schema_digest,
        effect,
        args,
        store_uri,
        sink_clearance,
        destinations,
        output_label,
        trusted_fields,
        amount_binding,
        max_result_bytes,
        max_result_nodes,
        schema: Some(schema),
        step_up_over_minor,
    };
    Ok((policy, reads_stores))
}

/// The strict schema and the `args` list must declare the same argument pointers, with types
/// that fit their roles, and every argument but free `data` must be required (L1). So the
/// schema refuses exactly what the engine's role checks would, and declares nothing they do not
/// know about.
fn check_schema(schema: &ArgSchema, args: &[ArgSpec], path: &str) -> Result<(), LoadError> {
    let invalid = |why| Err(LoadError::at(path, Problem::Invalid(why)));
    let mut roles = BTreeMap::new();
    for spec in args {
        if roles.insert(spec.pointer.as_str(), spec.role).is_some() {
            return invalid("an argument pointer may be declared once");
        }
    }
    let leaves = schema.leaves();
    if leaves.len() != roles.len() {
        return invalid("its leaves must be exactly the args pointers");
    }
    for leaf in &leaves {
        let Some(role) = roles.get(leaf.pointer.as_str()) else {
            return invalid("its leaves must be exactly the args pointers");
        };
        let node = leaf.node;
        let fits = match role {
            ArgRole::Amount => {
                node.kind == SchemaType::Integer
                    && node.minimum.is_some_and(|minimum| minimum >= 0)
                    && node
                        .maximum
                        .is_some_and(|maximum| maximum <= MAX_SAFE_INTEGER)
            }
            ArgRole::Currency => {
                node.kind == SchemaType::String
                    && node.min_length == Some(3)
                    && node.max_length == Some(3)
                    && node.allowed.as_ref().is_none_or(|codes| {
                        codes.iter().all(|code| {
                            code.as_str().is_some_and(|code| {
                                code.len() == 3
                                    && code.bytes().all(|byte| byte.is_ascii_uppercase())
                            })
                        })
                    })
            }
            ArgRole::Entity(_)
            | ArgRole::SinkDestination
            | ArgRole::StoreUri
            | ArgRole::StoreKey => node.kind == SchemaType::String,
            ArgRole::Data | ArgRole::StoreWrite => true,
        };
        if !fits {
            return invalid(
                "a leaf's type does not fit its role: an amount is an integer from minimum >= 0 to maximum <= 2^53 - 1, a currency a string of length 3, and an entity, store or destination a string",
            );
        }
        if *role != ArgRole::Data && !leaf.always_present {
            return invalid("every argument but free data must be required");
        }
    }
    Ok(())
}

fn non_empty(fields: &mut Fields<'_>, key: &str) -> Result<String, LoadError> {
    let path = fields.path_of(key);
    let text = fields.string(key)?;
    if text.is_empty() {
        return Err(LoadError::at(&path, Problem::Invalid("empty")));
    }
    Ok(text.to_owned())
}

/// An optional array of distinct strings; absent is empty.
fn string_set(fields: &mut Fields<'_>, key: &str) -> Result<BTreeSet<String>, LoadError> {
    let path = fields.path_of(key);
    let mut set = BTreeSet::new();
    if let Some(value) = fields.optional(key) {
        for (index, item) in as_array(value, &path)?.iter().enumerate() {
            let item_path = format!("{path}[{index}]");
            if !set.insert(as_str(item, &item_path)?.to_owned()) {
                return Err(LoadError::at(&item_path, Problem::Invalid("repeated")));
            }
        }
    }
    Ok(set)
}

fn arg_spec(value: &JcsValue, path: &str) -> Result<ArgSpec, LoadError> {
    let mut fields = Fields::of(value, path)?;
    let pointer = fields.string("pointer")?.to_owned();
    let role_path = fields.path_of("role");
    let role = match fields.string("role")? {
        "entity" => {
            let kind_path = fields.path_of("kind");
            ArgRole::Entity(match fields.string("kind")? {
                "invoice" => EntityKind::Invoice,
                "recipient" => EntityKind::Recipient,
                _ => {
                    return Err(LoadError::at(
                        &kind_path,
                        Problem::Invalid("must be \"invoice\" or \"recipient\""),
                    ));
                }
            })
        }
        "amount" => ArgRole::Amount,
        "currency" => ArgRole::Currency,
        "data" => ArgRole::Data,
        "sink_destination" => ArgRole::SinkDestination,
        "store_uri" => ArgRole::StoreUri,
        "store_key" => ArgRole::StoreKey,
        "store_write" => ArgRole::StoreWrite,
        _ => return Err(LoadError::at(&role_path, Problem::Invalid("unknown role"))),
    };
    fields.done()?;
    Ok(ArgSpec { pointer, role })
}

fn confidentiality(text: &str, path: &str) -> Result<Confidentiality, LoadError> {
    Confidentiality::from_name(text).ok_or_else(|| {
        LoadError::at(
            path,
            Problem::Invalid("must be public, internal, confidential or secret"),
        )
    })
}

fn integrity(text: &str, path: &str) -> Result<Integrity, LoadError> {
    Integrity::from_name(text).ok_or_else(|| {
        LoadError::at(
            path,
            Problem::Invalid("must be trusted, untrusted_external or untrusted_agent_write"),
        )
    })
}

/// What `secret` clearance may go on (RV5 D4). It turns `G_label`'s confidentiality check off for
/// what the tool sends, so a tool that sends anywhere new would be an unchecked way out: a sink
/// or a payment (whose memo becomes a sink) never gets it, nor does a destination, and a read
/// tool with free `data` arguments gets it only if it reads a pinned store, whose server already
/// holds what that store's readers can see.
fn check_clearance(
    effect: EffectClass,
    args: &[ArgSpec],
    clearance: Confidentiality,
    destinations: &BTreeMap<String, Confidentiality>,
    reads_a_store: bool,
    path: &str,
) -> Result<(), LoadError> {
    if destinations
        .values()
        .any(|cleared| *cleared == Confidentiality::Secret)
    {
        return Err(LoadError::at(
            path,
            Problem::Invalid("a destination cannot be cleared for secret"),
        ));
    }
    if clearance != Confidentiality::Secret {
        return Ok(());
    }
    if matches!(effect, EffectClass::MutatingExternal | EffectClass::Payment) {
        return Err(LoadError::at(
            path,
            Problem::Invalid("a sink or a payment cannot be cleared for secret"),
        ));
    }
    let free = args.iter().any(|spec| spec.role == ArgRole::Data);
    if effect == EffectClass::ReadOnly && free && !reads_a_store {
        return Err(LoadError::at(
            path,
            Problem::Invalid(
                "a read tool with data arguments must read a pinned store to be cleared for secret",
            ),
        ));
    }
    Ok(())
}

/// `check_clearance` lets a read tool with `data` arguments keep `secret` clearance because its
/// server already holds what its store's readers can see. That reasoning covers that server's
/// secrets only: a secret read from another server could otherwise leave through such a tool's
/// arguments, with `G_label` satisfied. So every tool that outputs `secret` must be on the same
/// server as every such tool.
fn check_secret_stays_home(pins: &ToolPins, path: &str) -> Result<(), LoadError> {
    let cleared = pins.tools.values().find(|tool| {
        tool.sink_clearance == Confidentiality::Secret
            && tool.args.iter().any(|spec| spec.role == ArgRole::Data)
    });
    let Some(cleared) = cleared else {
        return Ok(());
    };
    let elsewhere = pins.tools.values().any(|tool| {
        tool.output_label.conf == Confidentiality::Secret && tool.server_id != cleared.server_id
    });
    if elsewhere {
        return Err(LoadError::at(
            path,
            Problem::Invalid(
                "a tool cleared for secret with data arguments shares a server with every tool that outputs secret",
            ),
        ));
    }
    Ok(())
}

/// RV4 #8: a read tool that returns stored data without naming its location declares the
/// stores it reads. If any pinned tool writes one of them, the reader's `output_label` must be
/// at least [`STORE_HIGH_WATER`], or short secrets, which are never content-indexed (F-08),
/// would come back through it unlabelled.
fn check_reader(
    pins: &ToolPins,
    reader: &str,
    stores_read: &[String],
    path: &str,
) -> Result<(), LoadError> {
    let policy = pins
        .tools
        .get(reader)
        .ok_or_else(|| LoadError::at(path, Problem::Missing))?;
    if policy.effect != EffectClass::ReadOnly {
        return Err(LoadError::at(
            path,
            Problem::Invalid("only a read tool declares reads_stores"),
        ));
    }
    for store in stores_read {
        if !pins.stores.contains_key(store) {
            return Err(LoadError::at(
                path,
                Problem::Invalid("reads_stores names a store that is not pinned"),
            ));
        }
        // Every tool whose call taints a store location (the engine's `planned_writes`): a
        // `mutating_internal` tool, or any tool with a `store_write` argument (RV5 V15).
        let written = pins.tools.values().any(|tool| {
            (tool.effect == EffectClass::MutatingInternal
                || tool
                    .args
                    .iter()
                    .any(|spec| spec.role == ArgRole::StoreWrite))
                && (tool.store_uri.as_deref() == Some(store.as_str())
                    || tool.args.iter().any(|spec| spec.role == ArgRole::StoreUri))
        });
        if written && policy.output_label.join(STORE_HIGH_WATER) != policy.output_label {
            return Err(LoadError::at(
                path,
                Problem::Invalid(
                    "a reader of a store agents write must carry output_label secret, untrusted_agent_write (RV4 #8)",
                ),
            ));
        }
    }
    Ok(())
}

/// Signer keys and lockfiles for unit tests elsewhere in the crate.
#[cfg(test)]
#[allow(clippy::expect_used)]
pub(crate) mod fixtures {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    use crate::jcs::{self, ParseOptions};
    use crate::tokens::Es256Signer;

    /// The test release key.
    pub(crate) fn release() -> Es256Signer {
        Es256Signer::from_secret_bytes(&[0x11; 32]).expect("key")
    }

    /// The test security key.
    pub(crate) fn security() -> Es256Signer {
        Es256Signer::from_secret_bytes(&[0x22; 32]).expect("key")
    }

    /// The `signers` and `thresholds` members of a `lockfile` section that trusts both keys.
    pub(crate) fn signers_json() -> String {
        let key =
            |signer: Es256Signer| URL_SAFE_NO_PAD.encode(signer.verifier().to_sec1_uncompressed());
        format!(
            r#""signers":[{{"role":"release","key":"{}"}},{{"role":"security","key":"{}"}}],"thresholds":{{"release":1,"security":1}}"#,
            key(release()),
            key(security())
        )
    }

    /// An envelope around `payload`'s exact bytes, signed by `signers`, with no check of the
    /// payload: for tests of what the loader refuses.
    pub(crate) fn envelope(payload: &[u8], signers: &[&Es256Signer]) -> Vec<u8> {
        let signed = super::pae(super::PAYLOAD_TYPE, payload);
        let signatures: Vec<String> = signers
            .iter()
            .map(|signer| {
                format!(
                    r#"{{"keyid":"{}","sig":"{}"}}"#,
                    signer.kid(),
                    super::STANDARD.encode(signer.sign_der(&signed).expect("sign"))
                )
            })
            .collect();
        format!(
            r#"{{"payload":"{}","payloadType":"{}","signatures":[{}]}}"#,
            super::STANDARD.encode(payload),
            super::PAYLOAD_TYPE,
            signatures.join(",")
        )
        .into_bytes()
    }

    /// `payload` (any JSON text), canonicalized and signed by both keys.
    pub(crate) fn signed_lockfile(payload: &str) -> Vec<u8> {
        let canonical = jcs::parse_with(payload.as_bytes(), &ParseOptions::definition())
            .expect("payload")
            .value
            .to_canonical_bytes();
        let once = super::sign(&canonical, &release()).expect("release signature");
        super::sign(&once, &security()).expect("security signature")
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
    use std::path::PathBuf;

    use super::fixtures::{envelope, release, security, signed_lockfile};
    use super::*;
    use crate::config::Signer;

    const READ: &str = r#""get_note":{"definition":{"name":"get_note"},"policy":{"effect":"read",
        "args":[{"pointer":"/key","role":"data"}],"sink_clearance":"confidential",
        "output_label":{"conf":"internal","integ":"untrusted_external"},"max_result_bytes":1024,"max_result_nodes":64,
        "strict_schema":{"type":"object","additionalProperties":false,"properties":{"key":{"type":"string"}}}}}"#;
    const PAY: &str = r#""pay":{"definition":{"name":"pay"},"policy":{"effect":"mutating_financial",
        "args":[{"pointer":"/to","role":"entity","kind":"recipient"},{"pointer":"/amount","role":"amount"},{"pointer":"/currency","role":"currency"}],
        "sink_clearance":"internal","output_label":{"conf":"internal","integ":"untrusted_external"},"max_result_bytes":1024,"max_result_nodes":64,
        @STEP_UP@"strict_schema":{"type":"object","additionalProperties":false,"required":["to","amount","currency"],"properties":{
          "to":{"type":"string"},"amount":{"type":"integer","minimum":0,"maximum":100000},
          "currency":{"type":"string","minLength":3,"maxLength":3,"enum":["USD"]}}}}}"#;

    /// A payload on one server, `a`, with `tools` (joined members of its `tools` object).
    fn payload(epoch: u64, tools: &[&str]) -> String {
        format!(
            r#"{{"lockfile_version":1,"release_epoch":{epoch},"stores":{{}},"servers":{{"a":{{"endpoint":"unix:/a",
            "identity":"spiffe://a","protocol_version":"2026-07-28","discover":{{}},"tools":{{{}}}}}}}}}"#,
            tools.join(",").replace("@STEP_UP@", "")
        )
    }

    fn canonical(text: &str) -> Vec<u8> {
        jcs::parse_with(text.as_bytes(), &ParseOptions::definition())
            .unwrap()
            .value
            .to_canonical_bytes()
    }

    fn section(signers: &[(&str, &Es256Signer)], thresholds: &[(&str, u32)]) -> LockfileSection {
        LockfileSection {
            path: PathBuf::from("/lockfile"),
            signers: signers
                .iter()
                .map(|(role, key)| Signer {
                    role: (*role).to_owned(),
                    key: key.verifier(),
                })
                .collect(),
            thresholds: thresholds
                .iter()
                .map(|(role, n)| ((*role).to_owned(), *n))
                .collect(),
            min_accepted_epoch: 1,
        }
    }

    fn both() -> LockfileSection {
        section(
            &[("release", &release()), ("security", &security())],
            &[("release", 1), ("security", 1)],
        )
    }

    fn refused(bytes: &[u8], section: &LockfileSection) -> Problem {
        verify_envelope(bytes, section).unwrap_err().problem
    }

    #[test]
    fn pae_matches_the_dsse_specification() {
        assert_eq!(
            pae("http://example.com/HelloWorld", b"hello world"),
            b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"
        );
    }

    #[test]
    fn a_lockfile_signed_by_both_roles_loads() {
        let text = payload(7, &[READ, PAY]);
        let loaded = verify_envelope(&signed_lockfile(&text), &both()).unwrap();
        assert_eq!(loaded.release_epoch, 7);
        // The digest is the signed bytes' digest.
        assert_eq!(loaded.digest, jcs::digest(&canonical(&text)).unwrap());
        let pay = &loaded.pins.tools["pay"];
        assert!(pay.schema.is_some());
        assert_eq!(pay.step_up_over_minor, None);
    }

    #[test]
    fn the_security_role_is_needed_only_for_what_spec_section_4_names() {
        let release_only = canonical(&payload(7, &[READ, PAY]));
        let signed = sign(&release_only, &release()).unwrap();
        assert_eq!(
            refused(&signed, &both()),
            Problem::Signature(
                "it pins a payment, a sink or an amount witness, and the security role's threshold is not met"
            )
        );
        // A lockfile of plain reads needs the release role alone.
        let reads = canonical(&payload(7, &[READ]));
        assert!(verify_envelope(&sign(&reads, &release()).unwrap(), &both()).is_ok());
        // The security role never stands in for the release role.
        assert_eq!(
            refused(&sign(&reads, &security()).unwrap(), &both()),
            Problem::Signature("the release role's threshold is not met")
        );
    }

    #[test]
    fn needs_security_covers_sinks_and_witnesses() {
        let lockfile = |tools: &[&str]| {
            parse_payload(
                &jcs::parse_with(payload(7, tools).as_bytes(), &ParseOptions::definition())
                    .unwrap()
                    .value,
                "p",
            )
            .unwrap()
        };
        assert!(!needs_security(&lockfile(&[READ]).pins));
        assert!(needs_security(&lockfile(&[PAY]).pins));
        for (old, new) in [
            (r#""role":"data"}],"#, r#""role":"sink_destination"}],"#),
            (r#""integ":"untrusted_external""#, r#""integ":"trusted""#),
            (
                r#""sink_clearance":"confidential","#,
                r#""sink_clearance":"public","destinations":{"https://x":"internal"},"#,
            ),
            (r#""effect":"read""#, r#""effect":"external_sink""#),
        ] {
            let tool = READ.replace(old, new).replace(
                r#""properties":{"key":"#,
                r#""required":["key"],"properties":{"key":"#,
            );
            assert!(needs_security(&lockfile(&[&tool]).pins), "{new}");
        }
    }

    #[test]
    fn thresholds_count_distinct_keys() {
        let second = Es256Signer::from_secret_bytes(&[0x33; 32]).unwrap();
        let two_of_two = section(
            &[("release", &release()), ("release", &second)],
            &[("release", 2)],
        );
        let reads = canonical(&payload(7, &[READ]));
        // One key signing twice is one key.
        let once = sign(&reads, &release()).unwrap();
        assert_eq!(
            sign(&once, &release()).unwrap_err().problem,
            Problem::Signature("this key has already signed it")
        );
        let twice = envelope(&reads, &[&release(), &release()]);
        assert_eq!(
            refused(&twice, &two_of_two),
            Problem::Signature("the release role's threshold is not met")
        );
        assert!(verify_envelope(&sign(&once, &second).unwrap(), &two_of_two).is_ok());
        // A key the config does not trust adds nothing.
        let stranger = Es256Signer::from_secret_bytes(&[0x44; 32]).unwrap();
        assert_eq!(
            refused(&envelope(&reads, &[&stranger]), &both()),
            Problem::Signature("the release role's threshold is not met")
        );
        // Nobody's bytes are parsed before the release role vouches for them: a payload that is
        // not even JSON fails on its signatures, not in the parser.
        assert_eq!(
            refused(&envelope(b"{\"lockfile_version\":", &[&stranger]), &both()),
            Problem::Signature("the release role's threshold is not met")
        );
    }

    #[test]
    fn a_changed_payload_or_type_fails() {
        let text = payload(7, &[READ]);
        let good = String::from_utf8(signed_lockfile(&text)).unwrap();
        // Swap in another payload under the same signatures.
        let other = STANDARD.encode(canonical(&payload(8, &[READ])));
        let original = STANDARD.encode(canonical(&text));
        let swapped = good.replace(&original, &other);
        assert_ne!(swapped, good);
        assert_eq!(
            refused(swapped.as_bytes(), &both()),
            Problem::Signature("the release role's threshold is not met")
        );
        let retyped = good.replace(PAYLOAD_TYPE, "application/vnd.in-toto+json");
        assert_eq!(
            refused(retyped.as_bytes(), &both()),
            Problem::Signature("payloadType is not the lockfile v1 type")
        );
        let extra = good.replacen('{', r#"{"note":"x","#, 1);
        assert_eq!(refused(extra.as_bytes(), &both()), Problem::Unexpected);
    }

    #[test]
    fn the_payload_must_be_canonical() {
        let spaced = payload(7, &[READ]).into_bytes();
        let signed = envelope(&spaced, &[&release()]);
        assert_eq!(
            refused(&signed, &both()),
            Problem::Signature("payload is not JCS-canonical")
        );
        assert_eq!(
            sign(&spaced, &release()).unwrap_err().problem,
            Problem::Signature("payload is not JCS-canonical")
        );
    }

    #[test]
    fn signatures_are_strict_der_in_either_alphabet() {
        let reads = canonical(&payload(7, &[READ]));
        let good = String::from_utf8(sign(&reads, &release()).unwrap()).unwrap();
        let value = jcs::parse(good.as_bytes()).unwrap();
        let sig = value
            .pointer("/signatures/0/sig")
            .unwrap()
            .as_str()
            .unwrap();
        let der = STANDARD.decode(sig).unwrap();
        // URL-safe and unpadded is the same signature.
        let url = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&der);
        assert!(verify_envelope(good.replace(sig, &url).as_bytes(), &both()).is_ok());
        // Raw r‖s is not DER.
        let raw = p256::ecdsa::Signature::from_der(&der).unwrap().to_bytes();
        let raw = STANDARD.encode(raw.as_slice());
        assert_eq!(
            refused(good.replace(sig, &raw).as_bytes(), &both()),
            Problem::Signature("a sig is not strict DER")
        );
        // A non-minimal length is BER, not DER.
        let mut ber = vec![0x30, 0x81, der[1]];
        ber.extend_from_slice(&der[2..]);
        assert_eq!(
            refused(
                good.replace(sig, &STANDARD.encode(&ber)).as_bytes(),
                &both()
            ),
            Problem::Signature("a sig is not strict DER")
        );
        // Mixing the alphabets, or a non-zero trailing bit, is not base64 here.
        let mixed = format!(
            "{}-_",
            sig.trim_end_matches('=').get(..sig.len() - 4).unwrap()
        );
        assert!(matches!(
            refused(good.replace(sig, &mixed).as_bytes(), &both()),
            Problem::Signature(_)
        ));
        let payload_text = value.get("payload").unwrap().as_str().unwrap().to_owned();
        let mut chars: Vec<char> = payload_text.trim_end_matches('=').chars().collect();
        if let Some(last) = chars.last_mut() {
            // Flip the lowest bit of the last character: unused bits become non-zero.
            let index = alphabet::STANDARD.as_str().find(*last).unwrap();
            *last = alphabet::STANDARD.as_str().chars().nth(index ^ 1).unwrap();
        }
        let trailing: String = chars.into_iter().collect();
        if STANDARD.decode(&trailing).is_err() {
            assert_eq!(
                refused(good.replace(&payload_text, &trailing).as_bytes(), &both()),
                Problem::Signature("payload is not base64")
            );
        }
    }

    #[test]
    fn signature_count_and_rollback_floor_are_enforced() {
        let reads = canonical(&payload(7, &[READ]));
        let keys: Vec<Es256Signer> = (1..=17_u8)
            .map(|n| Es256Signer::from_secret_bytes(&[n; 32]).unwrap())
            .collect();
        let many = envelope(&reads, &keys.iter().collect::<Vec<_>>());
        assert_eq!(
            refused(&many, &both()),
            Problem::Signature("an envelope carries 1 to 16 signatures")
        );
        let none = envelope(&reads, &[]);
        assert_eq!(
            refused(&none, &both()),
            Problem::Signature("an envelope carries 1 to 16 signatures")
        );
        let mut floor = both();
        floor.min_accepted_epoch = 8;
        let error = verify_envelope(&sign(&reads, &release()).unwrap(), &floor).unwrap_err();
        assert_eq!(error.path, "lockfile.payload.release_epoch");
    }

    fn schema_error(tool: &str) -> LoadError {
        let text = payload(7, &[tool]);
        parse_payload(
            &jcs::parse_with(text.as_bytes(), &ParseOptions::definition())
                .unwrap()
                .value,
            "p",
        )
        .unwrap_err()
    }

    #[test]
    fn the_strict_schema_must_match_the_args() {
        let mismatch = |old: &str, new: &str| {
            let error = schema_error(&PAY.replace(old, new));
            assert_eq!(
                error.path, "p.servers.a.tools.pay.policy.strict_schema",
                "{new}"
            );
            error.problem
        };
        // A leaf with no role, or a role with no leaf.
        assert!(matches!(
            mismatch(
                r#""to":{"type":"string"},"#,
                r#""to":{"type":"string"},"memo":{"type":"string"},"#
            ),
            Problem::Invalid("its leaves must be exactly the args pointers")
        ));
        assert!(matches!(
            mismatch(
                r#""required":["to","amount","currency"],"properties":{
          "to":{"type":"string"},"#,
                r#""required":["amount","currency"],"properties":{"#
            ),
            Problem::Invalid("its leaves must be exactly the args pointers")
        ));
        // Types that do not fit the role.
        for (old, new) in [
            (r#""minimum":0,"maximum":100000"#, r#""minimum":0"#),
            (
                r#""minimum":0,"maximum":100000"#,
                r#""minimum":-1,"maximum":100000"#,
            ),
            (
                r#""type":"integer","minimum":0,"maximum":100000"#,
                r#""type":"number""#,
            ),
            (
                r#""minLength":3,"maxLength":3,"enum":["USD"]"#,
                r#""maxLength":3"#,
            ),
            (r#""enum":["USD"]"#, r#""enum":["usd"]"#),
            (r#""to":{"type":"string"}"#, r#""to":{"type":"integer"}"#),
        ] {
            let problem = mismatch(old, new);
            assert!(
                matches!(&problem, Problem::Invalid(why) if why.starts_with("a leaf's type")),
                "{new}: {problem:?}"
            );
        }
        // Every role argument is required.
        assert_eq!(
            mismatch(
                r#""required":["to","amount","currency"]"#,
                r#""required":["to","amount"]"#
            ),
            Problem::Invalid("every argument but free data must be required")
        );
        // A schema outside the subset.
        assert_eq!(
            mismatch(
                r#""to":{"type":"string"}"#,
                r#""to":{"type":"string","pattern":"^r"}"#
            ),
            Problem::Schema(crate::schema::SchemaError::UnknownKeyword)
        );
        // It is required.
        let missing = schema_error(&READ.replace(r#""strict_schema""#, r#""argument_schema""#));
        assert_eq!(missing.problem, Problem::Missing);
    }

    #[test]
    fn only_a_payment_has_its_own_step_up() {
        let text = payload(
            7,
            &[&PAY.replace("@STEP_UP@", r#""step_up_over_minor":2500,"#)],
        );
        let loaded = parse_payload(
            &jcs::parse_with(text.as_bytes(), &ParseOptions::definition())
                .unwrap()
                .value,
            "p",
        )
        .unwrap();
        assert_eq!(loaded.pins.tools["pay"].step_up_over_minor, Some(2500));
        let read = READ.replace(
            r#""max_result_bytes""#,
            r#""step_up_over_minor":1,"max_result_bytes""#,
        );
        assert_eq!(
            schema_error(&read).problem,
            Problem::Invalid("only a payment tool has a step-up threshold")
        );
    }
}
