//! The lockfile v1 payload (L1).
//!
//! In step 7 the payload is the config's `pins` section; step 10 wraps the same format in a
//! DSSE envelope and polls upstream for drift against it. The payload carries each server's
//! full `server/discover` result and `tools/list` definitions, which the PEP serves as pinned
//! (M1), and per tool the policy the engine enforces, under the engine's own names.
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
//!   store some pinned tool writes (RV4 #8).

use std::collections::{BTreeMap, BTreeSet};

use crate::config::{Fields, LoadError, Problem, as_array, as_str, is_plain_name};
use crate::engine::{
    AmountBinding, ArgRole, ArgSpec, Confidentiality, EffectClass, EntityKind, Integrity,
    KeyPolicy, Label, ToolPins, ToolPolicy, validate_pins,
};
use crate::forward::{PROTOCOL_VERSION, is_header_safe_tool_name};
use crate::jcs::{self, JcsValue};

/// The payload format this module reads.
pub const LOCKFILE_VERSION: u64 = 1;
/// The DSSE `payloadType` of a signed lockfile (step 10).
pub const PAYLOAD_TYPE: &str = "application/vnd.pep-sidecar.lockfile.v1+json";
/// Longest `server_id`: the broker routes `/mcp/{server_id}`.
pub const MAX_SERVER_ID: usize = 64;

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
    let reads_stores = string_set(&mut fields, "reads_stores")?
        .into_iter()
        .collect();
    fields.done()?;
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
    };
    Ok((policy, reads_stores))
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
        let written = pins.tools.values().any(|tool| {
            tool.effect == EffectClass::MutatingInternal
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
