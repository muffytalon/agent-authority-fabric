"""The D2 spike's client scenarios against the real PEP (WEEK2_PLAN step 7, RV4 #11).

Usage: real_pep.py BIN_DIR [WORK]
  BIN_DIR holds pep-sidecar, stub-broker, stub-tool and stub-operator (cargo build).
  WORK is the spike's work directory, with pyenv/ and node_modules/ from run.sh
  (default ~/.cache/pep-d2-spike).

Each scenario gets a fresh episode: the scripted operator starts it, the harness writes the
Episode Token to the client's stdin (E1), and ends the episode afterwards. Every transcript is
saved in results/real-*.txt next to this script, and a summary is printed.
"""
import hashlib, json, os, shutil, socket, subprocess, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = sys.argv[1]
WORK = os.path.realpath(sys.argv[2] if len(sys.argv) > 2 else os.path.expanduser("~/.cache/pep-d2-spike"))
RESULTS = os.path.join(HERE, "results")

base = tempfile.mkdtemp(prefix="pep-real-")
os.chmod(base, 0o700)
def mkdir(name, mode):
    path = os.path.join(base, name)
    os.mkdir(path)
    os.chmod(path, mode)
    return path
for name in ["pep", "ctl", "broker", "tool-a"]:
    mkdir(name, 0o750)
for name in ["pub", "state", "logs", "secrets"]:
    mkdir(name, 0o700)
p = lambda name: os.path.join(base, name)
uid, gid = os.geteuid(), os.getegid()

DISCOVER = {"cacheScope": "public", "capabilities": {"tools": {}}, "resultType": "complete",
            "supportedVersions": ["2026-07-28"], "ttlMs": 0}
DEFINITION = {"name": "get_invoice", "description": "Look up an invoice.",
              "inputSchema": {"type": "object", "properties": {"invoice_id": {"type": "string"}}, "required": ["invoice_id"]}}
pins = {"lockfile_version": 1, "release_epoch": 7, "stores": {"billing://invoices": {"case_insensitive": True}},
        "servers": {"a": {"endpoint": "unix:a", "identity": "spiffe://tools/a", "protocol_version": "2026-07-28",
            "discover": DISCOVER, "tools": {"get_invoice": {"definition": DEFINITION, "policy": {
                "effect": "read", "args": [{"pointer": "/invoice_id", "role": "store_key"}], "store_uri": "billing://invoices",
                "sink_clearance": "secret", "output_label": {"conf": "internal", "integ": "trusted"},
                "trusted_fields": ["/structuredContent/amount_due_minor", "/structuredContent/currency"],
                "max_result_bytes": 65536, "max_result_nodes": 1024}}}}}}

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
import base64
digest = "sha-256:" + base64.urlsafe_b64encode(hashlib.sha256(canonical(pins)).digest()).decode().rstrip("=")

with open(p("pins.json"), "w") as f:
    json.dump(pins, f)
open(p("secrets/cred-a"), "w").write("credential-a")
open(p("secrets/verifier-a"), "w").write(hashlib.sha256(b"credential-a").hexdigest())
invoices = {inv: {"amount_due_minor": 1000, "currency": "USD", "status": "executed"} for inv in ["INV-1", "INV-2", "INV-3"]}
json.dump({"server_id": "a", "listen": "unix:" + p("tool-a/tool.sock"), "verifier": p("secrets/verifier-a"),
           "pins": p("pins.json"), "store": p("state/dedupe-a.jsonl"), "log": p("logs/tool-a.jsonl"),
           "invoices": invoices}, open(p("tool-a.json"), "w"))
json.dump({"socket": p("broker/broker.sock"), "pep": {"uid": uid, "gid": gid}, "pep_key": p("pub/call-proof.pub"),
           "pins": p("pins.json"), "routes": {"a": {"endpoint": "unix:" + p("tool-a/tool.sock"), "credential": p("secrets/cred-a")}},
           "replay_cache_entries": 1000, "clock_skew_ms": 2000, "connections": 16, "upstream_timeout_ms": 5000,
           "log": p("logs/broker.jsonl")}, open(p("broker.json"), "w"))
json.dump({
    "agent": {"uid": uid, "gid": gid, "socket": p("pep/agent.sock")},
    "operator": {"uid": uid, "gid": gid, "socket": p("ctl/ctl.sock")},
    "broker": {"uid": uid, "gid": gid, "socket": p("broker/broker.sock")},
    "pep": {"spiffe_id": "spiffe://corp.example/pep", "pubkey_dir": p("pub")},
    "lockfile": {"path": "/etc/pep/lockfile.dsse.json", "min_accepted_epoch": 7, "signers": [], "thresholds": {}},
    "journal": {"path": p("state/journal.jsonl"), "lock": p("state/journal.lock")},
    "log": {"path": p("logs/decisions.jsonl"), "max_bytes": 1048576},
    "limits": {"connections": 16, "control_connections": 4, "header_bytes": 16384, "body_bytes": 1048576,
               "read_timeout_ms": 5000, "episode_idle_ms": 600000, "episodes": 4, "call_burst": 50, "call_rate_per_s": 50,
               "clock_skew_ms": 2000, "replay_cache_entries": 1000},
    "intents": {"spike": {"release_epoch": 7, "lockfile_digest": digest,
        "limits": {"currency": "USD", "per_call_max_minor": 1000, "cumulative_max_minor": 1000, "max_calls": 1, "step_up_over_minor": 1000},
        "entities": {"kind": "recipient", "ids": ["rcpt_A"], "per_entity_max_uses": 1}, "seq": "unconstrained"}},
    "pins": pins}, open(p("pep.json"), "w"))

children = []
def spawn(binary, config):
    child = subprocess.Popen([os.path.join(BIN, binary), config], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    children.append(child)
    return child
def wait_socket(path):
    deadline = time.time() + 20
    while time.time() < deadline:
        try:
            s = socket.socket(socket.AF_UNIX); s.connect(path); s.close(); return
        except OSError:
            time.sleep(0.05)
    raise SystemExit(f"{path} never came up")

try:
    spawn("stub-tool", p("tool-a.json")); wait_socket(p("tool-a/tool.sock"))
    spawn("stub-broker", p("broker.json")); wait_socket(p("broker/broker.sock"))
    time.sleep(1.05 - (time.time() % 1))   # the broker refuses proofs from its boot second (R1)
    pep = spawn("pep-sidecar", p("pep.json"))
    while "serving" not in (line := pep.stderr.readline()):
        if not line:
            raise SystemExit("the PEP exited")

    def operator(request):
        out = subprocess.run([os.path.join(BIN, "stub-operator"), p("ctl/ctl.sock"), json.dumps(request)],
                             capture_output=True, text=True, timeout=30)
        return json.loads(out.stdout)

    shutil.copy(os.path.join(HERE, "py_client.py"), WORK)
    shutil.copy(os.path.join(HERE, "ts_client.mjs"), WORK)
    clients = {
        "py": [os.path.join(WORK, "pyenv/bin/python"), "py_client.py", p("pep/agent.sock")],
        "ts": ["node", "ts_client.mjs", p("pep/agent.sock")],
    }
    # (sdk, scenario, lines the transcript must contain)
    scenarios = [
        ("py", "token", ["tools/list: ['get_invoice']", "tools/call: invoice INV-1 isError: False", "listen ended gracefully", "client closed cleanly"]),
        ("py", "enforce-header", ["unlisted call: invoice INV-1 isError: False", "call from a recreated client: invoice INV-2 isError: False", "client closed cleanly"]),
        ("py", "enforce-meta-only", ["unlisted call raised", "client closed cleanly"]),
        ("ts", "token", ["tools/list: [ 'get_invoice' ]", "tools/call: invoice INV-1 isError: false", "listen closed:", "client closed cleanly"]),
        ("ts", "enforce-header", ["unlisted call: invoice INV-1 isError: false", "call from a recreated client: invoice INV-2 isError: false", "client closed cleanly"]),
        ("ts", "enforce-meta-only", ["unlisted call: invoice INV-1 isError: false", "call from a recreated client: invoice INV-2 isError: false", "client closed cleanly"]),
    ]
    env = dict(os.environ, PEP_TOKEN_FROM_STDIN="1", PEP_REAL="1")
    failed = False
    for sdk, scenario, expected in scenarios:
        deadline = time.time() + 10
        while "result" not in (started := operator({"call": "start_episode", "intent": "spike"})):
            if time.time() > deadline:
                raise SystemExit(f"could not start an episode: {started}")
            time.sleep(0.05)
        token, eid = started["result"]["episode_token"], started["result"]["eid"]
        run = subprocess.run(clients[sdk] + [scenario], input=token + "\n", capture_output=True, text=True,
                             cwd=WORK, env=env, timeout=120)
        transcript = run.stdout + run.stderr
        with open(os.path.join(RESULTS, f"real-{sdk}-{scenario}.txt"), "w") as f:
            f.write(transcript.replace(token, "<episode token>"))
        missing = [line for line in expected if line not in transcript]
        print(("ok   " if not missing else "FAIL ") + f"{sdk} {scenario}" + (f": missing {missing}" if missing else ""))
        failed |= bool(missing)
        operator({"call": "end_episode", "eid": eid})
    print("REAL PEP RUNS " + ("FAILED" if failed else "PASSED"))
    sys.exit(1 if failed else 0)
finally:
    for child in children:
        child.kill()
    shutil.rmtree(base, ignore_errors=True)
