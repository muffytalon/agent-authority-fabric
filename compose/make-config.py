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
import base64, copy, hashlib, json, os

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

# --- config/kit: what compose/gate1.yaml mounts instead (step 9) ---
#
# The attacks need more than the step 8 flows: a free `memo`, a store an agent can write, a public
# sink, and short deadlines. They also use fixtures up, because an invoice pays once across the
# PEP and the ratchet never falls within an intent: so every attack takes invoices of its own,
# and every attack that reads a secret takes an intent of its own.
kit_a, kit_b = copy.deepcopy(server_a), copy.deepcopy(server_b)
pay_tool = kit_a["pay_invoice"]
pay_tool["definition"]["inputSchema"]["properties"]["memo"] = STRING
pay_tool["policy"]["args"].append({"pointer": "/memo", "role": "data"})
kit_a.update(tool("update_invoice", "Annotate an invoice.", obj({"invoice_id": STRING, "text": STRING}, ["invoice_id", "text"]), {
    "effect": "mutating_internal", "args": [{"pointer": "/invoice_id", "role": "store_key"}, {"pointer": "/text", "role": "store_write"}],
    "store_uri": "billing://invoices", "sink_clearance": "secret", "output_label": {"conf": "internal", "integ": "untrusted_external"}}))
kit_b.update(tool("post_public", "Post to a public page.", obj({"text": STRING}, ["text"]), {
    "effect": "external_sink", "args": [{"pointer": "/text", "role": "data"}], "sink_clearance": "public",
    "output_label": {"conf": "public", "integ": "untrusted_external"}}))
kit_pins = dict(pins, servers={
    "a": dict(pins["servers"]["a"], tools=kit_a), "b": dict(pins["servers"]["b"], tools=kit_b)})

KIT_PLAIN = [f"INV-K{n:03}" for n in range(1, 301)]
KIT_DECLINED = [f"INV-D{n:03}" for n in range(1, 11)]
KIT_PENDING = [f"INV-U{n:03}" for n in range(1, 11)]
KIT_SLOW = [f"INV-S{n:03}" for n in range(1, 11)]
KIT_ODD = ["INV-R-WRONG-ID", "INV-R-TWO", "INV-R-FORGED"]
KIT_BIG = ["INV-B001"]
KIT_SMALL = ["INV-M001", "INV-M002"]
kit_ids = KIT_PLAIN + KIT_DECLINED + KIT_PENDING + KIT_SLOW + KIT_ODD + KIT_BIG + KIT_SMALL
def row(status="executed", amount=1000):
    return {"amount_due_minor": amount, "currency": "USD", "status": status}
kit_invoices = {invoice: row() for invoice in KIT_PLAIN + KIT_SLOW + KIT_SMALL}
kit_invoices.update({invoice: row("declined") for invoice in KIT_DECLINED})
kit_invoices.update({invoice: row("pending") for invoice in KIT_PENDING})
kit_invoices.update({"INV-R-WRONG-ID": row(), "INV-R-TWO": row(), "INV-R-FORGED": row("declined"), "INV-B001": row(amount=150000)})
kit_misbehave = {f"pay_invoice:{invoice}": "delay_ms:1500" for invoice in KIT_SLOW}
kit_misbehave.update({"pay_invoice:INV-R-WRONG-ID": "wrong_id", "pay_invoice:INV-R-TWO": "two_responses",
                      "pay_invoice:INV-R-FORGED": "forged_outcome"})

def kit_intent(kind, ids, max_calls=500, per_call=100000, cumulative=50000000, declines=40, per_entity=1):
    return {"release_epoch": 1, "lockfile_digest": digest(kit_pins),
            "limits": {"currency": "USD", "per_call_max_minor": per_call, "cumulative_max_minor": cumulative,
                       "max_calls": max_calls, "step_up_over_minor": 50000, "max_declines": declines},
            "entities": {"kind": kind, "ids": ids, "per_entity_max_uses": per_entity}, "seq": "unconstrained"}

KIT_SECRET_INTENTS = 8
kit_intents = {"pay": kit_intent("invoice", kit_ids), "pay2": kit_intent("invoice", kit_ids),
               "small": kit_intent("invoice", KIT_SMALL, per_call=1000, cumulative=1500),
               "notes": kit_intent("recipient", ["rcpt_A"], per_entity=2)}
kit_intents.update({f"secret-{n}": kit_intent("invoice", KIT_PLAIN) for n in range(1, KIT_SECRET_INTENTS + 1)})
kit_pep = dict(pep, pins=kit_pins, intents=kit_intents, limits=dict(
    pep["limits"], connections=48, episodes=12, episode_idle_ms=12000, episode_lifetime_ms=25000,
    upstream_timeout_ms=3000, step_up_timeout_ms=2000))
kit_pep["lockfile"] = dict(pep["lockfile"])
kit_broker = dict(broker, upstream_timeout_ms=3000)
def kit_tool(server):
    extra = {"invoices": kit_invoices, "record": "/var/lib/tool/requests.jsonl"}
    if server == "a":
        extra["misbehave"] = kit_misbehave
    else:
        extra["drift"] = {"flag": "/var/lib/tool/drift", "change": "description"}
    return dict(tool_config(server), **extra)

write("config/kit/lockfile/pins.json", kit_pins)
write("config/kit/pep/config.json", kit_pep)
write("config/kit/broker/config.json", kit_broker)
write("config/kit/tool-a/config.json", kit_tool("a"))
write("config/kit/tool-b/config.json", kit_tool("b"))

# --- config/load: G4's load (compose/load.yaml, O1) ---
#
# 10,500 calls at under 5 a second an episode take at least 42 episodes, and every payment needs an
# invoice of its own. The pins are the release ones. The extra intents are for the head-of-line
# run and the 1 MiB requests, which are measured apart.
LOAD_EPISODES, LOAD_SPARE, LOAD_PAYMENTS = 44, 4, 50
def load_id(episode, n):
    return f"INV-L{episode:02}-{n:03}"
load_intents = {f"load-{episode:02}": intent("invoice", [load_id(episode, n) for n in range(LOAD_PAYMENTS)], 1, LOAD_PAYMENTS)
                for episode in range(LOAD_EPISODES + LOAD_SPARE)}
for limits_holder in load_intents.values():
    limits_holder["limits"]["cumulative_max_minor"] = 1000000
load_invoices = {load_id(episode, n): {"amount_due_minor": 1000, "currency": "USD", "status": "executed"}
                 for episode in range(LOAD_EPISODES + LOAD_SPARE) for n in range(LOAD_PAYMENTS)}
load_pep = dict(pep, intents=load_intents, limits=dict(
    pep["limits"], connections=192, episodes=LOAD_EPISODES + LOAD_SPARE, call_burst=20, call_rate_per_s=5))
def load_tool(server):
    return dict(tool_config(server), invoices=load_invoices)

write("config/load/pep/config.json", load_pep)
write("config/load/tool-a/config.json", load_tool("a"))
write("config/load/tool-b/config.json", load_tool("b"))
