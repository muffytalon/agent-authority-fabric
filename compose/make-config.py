"""Writes the Compose configs under config/ (WEEK2_PLAN §4) from one source.

Usage: python3 compose/make-config.py   (from the repository root)

- config/lockfile/pins.json: the unsigned lockfile v1 payload (L1), shared by the PEP, the
  broker and the tool servers.
- config/pep/config.json: the PEP's config, with that payload as `pins`, and intents bound to
  its digest.
- config/broker/config.json: the broker's own config (RV4 #12).
- config/tool-a/config.json, config/tool-b/config.json: the stub tool servers.

Paths are the containers' (§4's mounts), and the uids are §4's: agent 20001, PEP 20002,
broker 20003, operator 20004, tool-a 20005, tool-b 20008. The digest is JCS over ASCII
data with integers only, which sorted, compact JSON reproduces.
"""
import base64, hashlib, json, os

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def digest(value):
    raw = hashlib.sha256(canonical(value).encode()).digest()
    return "sha-256:" + base64.urlsafe_b64encode(raw).decode().rstrip("=")

DISCOVER = {"cacheScope": "public", "capabilities": {"tools": {}}, "resultType": "complete",
            "supportedVersions": ["2026-07-28"], "ttlMs": 0}
ROW = {"max_result_bytes": 1048576, "max_result_nodes": 8192}

def tool(name, description, schema, policy):
    return {name: {"definition": {"name": name, "description": description, "inputSchema": schema},
                   "policy": dict(policy, **ROW)}}

def obj(properties, required):
    return {"type": "object", "properties": properties, "required": required, "additionalProperties": False}

STRING = {"type": "string", "maxLength": 256}
server_a = {}
server_a.update(tool("get_invoice", "Look up an invoice.", obj({"invoice_id": STRING}, ["invoice_id"]), {
    "effect": "read", "args": [{"pointer": "/invoice_id", "role": "store_key"}], "store_uri": "billing://invoices",
    "sink_clearance": "secret", "output_label": {"conf": "internal", "integ": "trusted"},
    "trusted_fields": ["/structuredContent/amount_due_minor", "/structuredContent/currency"]}))
server_a.update(tool("pay_invoice", "Pay an invoice.", obj({"invoice_id": STRING, "amount": {"type": "integer", "minimum": 0},
    "currency": {"type": "string", "minLength": 3, "maxLength": 3}}, ["invoice_id", "amount", "currency"]), {
    "effect": "mutating_financial", "args": [{"pointer": "/invoice_id", "role": "entity", "kind": "invoice"},
        {"pointer": "/amount", "role": "amount"}, {"pointer": "/currency", "role": "currency"}],
    "sink_clearance": "internal", "output_label": {"conf": "internal", "integ": "untrusted_external"},
    "amount_binding": {"lookup_tool": "get_invoice", "entity_arg_pointer": "/invoice_id", "lookup_entity_pointer": "/invoice_id",
        "result_amount_pointer": "/structuredContent/amount_due_minor", "result_currency_pointer": "/structuredContent/currency"}}))
server_b = {}
server_b.update(tool("save_note", "Save a note.", obj({"key": STRING, "text": {"type": "string", "maxLength": 4096}}, ["key", "text"]), {
    "effect": "mutating_internal", "args": [{"pointer": "/key", "role": "store_key"}, {"pointer": "/text", "role": "store_write"}],
    "store_uri": "notes://agent", "sink_clearance": "secret", "output_label": {"conf": "internal", "integ": "untrusted_external"}}))
server_b.update(tool("get_note", "Read a note.", obj({"key": STRING}, ["key"]), {
    "effect": "read", "args": [{"pointer": "/key", "role": "store_key"}], "store_uri": "notes://agent",
    "sink_clearance": "secret", "output_label": {"conf": "internal", "integ": "untrusted_external"}}))
server_b.update(tool("search_notes", "Search the notes.", obj({"query": STRING}, ["query"]), {
    "effect": "read", "args": [{"pointer": "/query", "role": "data"}], "sink_clearance": "secret",
    "output_label": {"conf": "secret", "integ": "untrusted_agent_write"}, "reads_stores": ["notes://agent"]}))
server_b.update(tool("fetch", "Fetch a URL.", obj({"url": STRING}, ["url"]), {
    "effect": "read", "args": [{"pointer": "/url", "role": "sink_destination"}], "sink_clearance": "public",
    "destinations": {"https://partner.example": "confidential"},
    "output_label": {"conf": "internal", "integ": "untrusted_external"}}))

pins = {"lockfile_version": 1, "release_epoch": 1,
        "stores": {"billing://invoices": {"case_insensitive": True}, "notes://agent": {"case_insensitive": False}},
        "servers": {
            "a": {"endpoint": "tcp:tool-a:8080", "identity": "spiffe://corp.example/tools/a",
                  "protocol_version": "2026-07-28", "discover": DISCOVER, "tools": server_a},
            "b": {"endpoint": "tcp:tool-b:8080", "identity": "spiffe://corp.example/tools/b",
                  "protocol_version": "2026-07-28", "discover": DISCOVER, "tools": server_b}}}

def intent(kind, ids, uses, max_calls):
    return {"release_epoch": 1, "lockfile_digest": digest(pins),
            "limits": {"currency": "USD", "per_call_max_minor": 100000, "cumulative_max_minor": 500000,
                       "max_calls": max_calls, "step_up_over_minor": 50000, "max_declines": 3},
            "entities": {"kind": kind, "ids": ids, "per_entity_max_uses": uses}, "seq": "unconstrained"}

pep = {
    "agent": {"uid": 20001, "gid": 20001, "socket": "/run/pep/agent.sock"},
    "operator": {"uid": 20004, "gid": 20004, "socket": "/run/pep-ctl/ctl.sock"},
    "broker": {"uid": 20003, "gid": 20003, "socket": "/run/broker/broker.sock"},
    "pep": {"spiffe_id": "spiffe://corp.example/pep", "pubkey_dir": "/run/pep-pub"},
    "lockfile": {"path": "/etc/lockfile/lockfile.dsse.json", "min_accepted_epoch": 1, "signers": [], "thresholds": {}},
    "journal": {"path": "/var/lib/pep/journal.jsonl", "lock": "/var/lib/pep/journal.lock"},
    "log": {"path": "/var/log/pep/decisions.jsonl", "max_bytes": 67108864},
    "limits": {"connections": 32, "control_connections": 4, "header_bytes": 16384, "body_bytes": 1048576,
               "read_timeout_ms": 5000, "episode_idle_ms": 1800000, "episodes": 4, "call_burst": 20,
               "call_rate_per_s": 10, "clock_skew_ms": 2000, "replay_cache_entries": 32768},
    # compose/check.py makes seven payments across the pay intent. Two are on INV-5005, which
    # an operator decline and then a step-up timeout each release; `calls` still counts them.
    "intents": {"pay": intent("invoice", ["INV-1001", "INV-2002", "INV-3003", "INV-4004", "INV-5005"], 1, 8),
                "notes": intent("recipient", ["rcpt_A"], 2, 5)},
    "pins": pins}
broker = {
    "socket": "/run/broker/broker.sock", "pep": {"uid": 20002, "gid": 20002},
    "pep_key": "/run/pep-pub/call-proof.pub", "pins": "/etc/lockfile/pins.json",
    "routes": {"a": {"endpoint": "tcp:tool-a:8080", "credential": "/run/credential-a"},
               "b": {"endpoint": "tcp:tool-b:8080", "credential": "/run/credential-b"}},
    "replay_cache_entries": 32768, "clock_skew_ms": 2000, "connections": 64,
    "upstream_timeout_ms": 10000, "log": "/var/lib/broker/broker.jsonl"}
invoices = {"INV-1001": {"amount_due_minor": 30000, "currency": "USD", "status": "executed"},
            "INV-2002": {"amount_due_minor": 60000, "currency": "USD", "status": "executed"},
            "INV-3003": {"amount_due_minor": 30000, "currency": "USD", "status": "declined"},
            "INV-4004": {"amount_due_minor": 30000, "currency": "USD", "status": "pending"},
            "INV-5005": {"amount_due_minor": 60000, "currency": "USD", "status": "executed"}}
def tool_config(server):
    return {"server_id": server, "listen": "tcp:0.0.0.0:8080", "verifier": "/run/credential.sha256",
            "pins": "/etc/lockfile/pins.json", "store": "/var/lib/tool/dedupe.jsonl",
            "log": "/var/lib/tool/tool.jsonl", "invoices": invoices}

def write(path, value):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="\n") as f:
        f.write(json.dumps(value, indent=2, sort_keys=True) + "\n")
    print("wrote", path)

write("config/lockfile/pins.json", pins)
write("config/pep/config.json", pep)
write("config/broker/config.json", broker)
write("config/tool-a/config.json", tool_config("a"))
write("config/tool-b/config.json", tool_config("b"))
