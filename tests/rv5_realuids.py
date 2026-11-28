#!/usr/bin/env python3
"""RV5: the SPEC §1 uid and directory layout, as real processes under real uids (no Docker
daemon here). Runs the real binaries, the data flow agent -> PEP -> broker -> tool, and the
C-UID, C-LOCK, C-CTL, C-CRED and C-PROC attacks that do not need containers."""
import base64, hashlib, json, os, pwd, shutil, signal, socket, stat, subprocess, sys, time

BIN = sys.argv[1]
ROOT = "/run/rv5"
AGENT, PEP, BROKER, OPERATOR, TOOL_A, TOOL_B, OTHER = 20001, 20002, 20003, 20004, 20005, 20008, 20009

PINS = {
 "lockfile_version": 1, "release_epoch": 7,
 "stores": {"billing://invoices": {"case_insensitive": True}, "notes://agent": {"case_insensitive": False}},
 "servers": {
  "a": {"endpoint": f"unix:{ROOT}/tool-a/tool.sock", "identity": "spiffe://tools/a", "protocol_version": "2026-07-28",
   "discover": {"cacheScope": "public", "capabilities": {"tools": {}}, "resultType": "complete", "supportedVersions": ["2026-07-28"], "ttlMs": 0},
   "tools": {
    "get_invoice": {"definition": {"name": "get_invoice", "description": "Look up an invoice.", "inputSchema": {"type": "object"}},
     "policy": {"effect": "read", "args": [{"pointer": "/invoice_id", "role": "store_key"}], "store_uri": "billing://invoices", "sink_clearance": "secret",
      "output_label": {"conf": "internal", "integ": "trusted"}, "trusted_fields": ["/structuredContent/amount_due_minor", "/structuredContent/currency"],
      "max_result_bytes": 65536, "max_result_nodes": 1024}},
    "pay_invoice": {"definition": {"name": "pay_invoice", "description": "Pay an invoice.", "inputSchema": {"type": "object"}},
     "policy": {"effect": "mutating_financial", "args": [{"pointer": "/invoice_id", "role": "entity", "kind": "invoice"}, {"pointer": "/amount", "role": "amount"}, {"pointer": "/currency", "role": "currency"}],
      "sink_clearance": "internal", "output_label": {"conf": "internal", "integ": "untrusted_external"},
      "amount_binding": {"lookup_tool": "get_invoice", "entity_arg_pointer": "/invoice_id", "lookup_entity_pointer": "/invoice_id",
       "result_amount_pointer": "/structuredContent/amount_due_minor", "result_currency_pointer": "/structuredContent/currency"},
      "max_result_bytes": 65536, "max_result_nodes": 1024}}}},
  "b": {"endpoint": f"unix:{ROOT}/tool-b/tool.sock", "identity": "spiffe://tools/b", "protocol_version": "2026-07-28",
   "discover": {"cacheScope": "public", "capabilities": {"tools": {}}, "resultType": "complete", "supportedVersions": ["2026-07-28"], "ttlMs": 0},
   "tools": {
    "save_note": {"definition": {"name": "save_note", "inputSchema": {"type": "object"}},
     "policy": {"effect": "mutating_internal", "args": [{"pointer": "/key", "role": "store_key"}, {"pointer": "/text", "role": "store_write"}], "store_uri": "notes://agent",
      "sink_clearance": "secret", "output_label": {"conf": "internal", "integ": "untrusted_external"}, "max_result_bytes": 65536, "max_result_nodes": 1024}},
    "get_note": {"definition": {"name": "get_note", "inputSchema": {"type": "object"}},
     "policy": {"effect": "read", "args": [{"pointer": "/key", "role": "store_key"}], "store_uri": "notes://agent",
      "sink_clearance": "secret", "output_label": {"conf": "internal", "integ": "untrusted_external"}, "max_result_bytes": 65536, "max_result_nodes": 1024}}}}}}

def digest(value):
    canon = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return "sha-256:" + base64.urlsafe_b64encode(hashlib.sha256(canon).digest()).rstrip(b"=").decode()

def mk(path, uid, gid, mode):
    os.makedirs(path, exist_ok=True)
    os.chown(path, uid, gid)
    os.chmod(path, mode)

def put(path, text, uid=0, gid=0, mode=0o644):
    with open(path, "w") as handle:
        handle.write(text)
    os.chown(path, uid, gid)
    os.chmod(path, mode)

shutil.rmtree(ROOT, ignore_errors=True)
os.makedirs(ROOT, mode=0o755)
os.chmod(ROOT, 0o755)
mk(f"{ROOT}/bin", 0, 0, 0o755)
for name in ["pep-sidecar", "stub-broker", "stub-tool", "stub-operator"]:
    shutil.copy2(f"{BIN}/{name}", f"{ROOT}/bin/{name}")
    os.chmod(f"{ROOT}/bin/{name}", 0o755)
mk(f"{ROOT}/cfg", 0, 0, 0o755)
mk(f"{ROOT}/pep", PEP, AGENT, 0o2750)
mk(f"{ROOT}/pep-ctl", PEP, OPERATOR, 0o2750)
mk(f"{ROOT}/broker", BROKER, PEP, 0o2750)
mk(f"{ROOT}/pep-pub", PEP, BROKER, 0o2750)
mk(f"{ROOT}/tool-a", TOOL_A, BROKER, 0o2750)
mk(f"{ROOT}/tool-b", TOOL_B, BROKER, 0o2750)
mk(f"{ROOT}/pep-state", PEP, PEP, 0o700)
mk(f"{ROOT}/pep-log", PEP, PEP, 0o2750)
mk(f"{ROOT}/broker-state", BROKER, BROKER, 0o700)
mk(f"{ROOT}/tool-a-state", TOOL_A, TOOL_A, 0o700)
mk(f"{ROOT}/tool-b-state", TOOL_B, TOOL_B, 0o700)
mk(f"{ROOT}/broker-secrets", BROKER, BROKER, 0o700)

put(f"{ROOT}/cfg/pins.json", json.dumps(PINS))
cred = {"a": base64.b64encode(os.urandom(32)).decode(), "b": base64.b64encode(os.urandom(32)).decode()}
for server, uid, state in [("a", TOOL_A, "tool-a-state"), ("b", TOOL_B, "tool-b-state")]:
    put(f"{ROOT}/broker-secrets/cred-{server}", cred[server], BROKER, BROKER, 0o400)
    put(f"{ROOT}/{state}/verifier", hashlib.sha256(cred[server].encode()).hexdigest(), uid, uid, 0o400)
INVOICES = {"INV-1001": {"amount_due_minor": 30000, "currency": "USD", "status": "executed"},
            "INV-2002": {"amount_due_minor": 60000, "currency": "USD", "status": "executed"}}
for server, state in [("a", "tool-a-state"), ("b", "tool-b-state")]:
    put(f"{ROOT}/cfg/tool-{server}.json", json.dumps({"server_id": server, "listen": f"unix:{ROOT}/tool-{server}/tool.sock",
        "verifier": f"{ROOT}/{state}/verifier", "pins": f"{ROOT}/cfg/pins.json", "store": f"{ROOT}/{state}/dedupe.jsonl",
        "log": f"{ROOT}/{state}/exec.jsonl", "invoices": INVOICES}))
put(f"{ROOT}/cfg/broker.json", json.dumps({"socket": f"{ROOT}/broker/broker.sock", "pep": {"uid": PEP, "gid": PEP},
    "pep_key": f"{ROOT}/pep-pub/call-proof.pub", "pins": f"{ROOT}/cfg/pins.json",
    "routes": {"a": {"endpoint": f"unix:{ROOT}/tool-a/tool.sock", "credential": f"{ROOT}/broker-secrets/cred-a"},
               "b": {"endpoint": f"unix:{ROOT}/tool-b/tool.sock", "credential": f"{ROOT}/broker-secrets/cred-b"}},
    "replay_cache_entries": 32768, "clock_skew_ms": 2000, "connections": 64, "upstream_timeout_ms": 5000, "log": f"{ROOT}/broker-state/broker.jsonl"}))
lock_digest = digest(PINS)
intent = {"release_epoch": 7, "lockfile_digest": lock_digest,
          "limits": {"currency": "USD", "per_call_max_minor": 100000, "cumulative_max_minor": 500000, "max_calls": 5, "step_up_over_minor": 50000, "max_declines": 3},
          "entities": {"kind": "invoice", "ids": ["INV-1001", "INV-2002"], "per_entity_max_uses": 1}, "seq": "unconstrained"}
put(f"{ROOT}/cfg/pep.json", json.dumps({
    "agent": {"uid": AGENT, "gid": AGENT, "socket": f"{ROOT}/pep/mcp.sock"},
    "operator": {"uid": OPERATOR, "gid": OPERATOR, "socket": f"{ROOT}/pep-ctl/ctl.sock"},
    "broker": {"uid": BROKER, "gid": BROKER, "socket": f"{ROOT}/broker/broker.sock"},
    "pep": {"spiffe_id": "spiffe://corp.example/pep", "pubkey_dir": f"{ROOT}/pep-pub"},
    "lockfile": {"path": "/etc/pep/lockfile.dsse.json", "min_accepted_epoch": 7, "signers": [], "thresholds": {}},
    "journal": {"path": f"{ROOT}/pep-state/journal.jsonl", "lock": f"{ROOT}/pep-state/journal.lock"},
    "log": {"path": f"{ROOT}/pep-log/decisions.jsonl", "max_bytes": 1048576},
    "limits": {"connections": 64, "control_connections": 4, "header_bytes": 16384, "body_bytes": 1048576, "read_timeout_ms": 5000,
               "upstream_timeout_ms": 5000, "step_up_timeout_ms": 10000, "episode_idle_ms": 600000, "episodes": 8, "call_burst": 50,
               "call_rate_per_s": 50, "clock_skew_ms": 2000, "replay_cache_entries": 32768},
    "intents": {"pay": intent}, "pins": PINS}))

def demote(uid, gid, groups=()):
    def run():
        os.setgroups(list(groups))
        os.setgid(gid)
        os.setuid(uid)
    return run

children = []
def spawn(name, uid, gid, args):
    log = open(f"/tmp/rv5-{name}.log", "w")
    child = subprocess.Popen(args, preexec_fn=demote(uid, gid), stdout=log, stderr=subprocess.STDOUT)
    children.append((name, child))
    return child

def wait_sock(path):
    for _ in range(400):
        if os.path.exists(path):
            return
        time.sleep(0.02)
    raise SystemExit(f"no socket {path}")

results = []
def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail else ""), flush=True)

def as_user(uid, gid, code, groups=()):
    """Runs python code as uid:gid; returns (exit status, stdout)."""
    run = subprocess.run([sys.executable, "-I", "-c", code], preexec_fn=demote(uid, gid, groups),
                         capture_output=True, text=True, timeout=30)
    return run.returncode, run.stdout.strip() + run.stderr.strip()

CLIENT = r'''
import json, socket, sys
def request(path, body, headers=""):
    s = socket.socket(socket.AF_UNIX); s.settimeout(8); s.connect(path)
    raw = ("POST /mcp HTTP/1.1\r\nHost: pep.local\r\nAccept: application/json, text/event-stream\r\nContent-Type: application/json\r\nMCP-Protocol-Version: 2026-07-28\r\n"+headers+"Content-Length: %d\r\n\r\n%s" % (len(body), body)).encode()
    s.sendall(raw); out = b""
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk: break
            out += chunk
    except OSError as e:
        return "ERR:"+str(e)
    return out.decode(errors="replace")
def call(path, tool, args, token, id=1):
    meta = {"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"dev.pep-sidecar/episode":token}
    body = json.dumps({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":tool,"arguments":args,"_meta":meta}})
    return request(path, body, "Mcp-Method: tools/call\r\nMcp-Name: %s\r\n" % tool)
'''

try:
    spawn("tool-a", TOOL_A, TOOL_A, [f"{ROOT}/bin/stub-tool", f"{ROOT}/cfg/tool-a.json"]); wait_sock(f"{ROOT}/tool-a/tool.sock")
    spawn("tool-b", TOOL_B, TOOL_B, [f"{ROOT}/bin/stub-tool", f"{ROOT}/cfg/tool-b.json"]); wait_sock(f"{ROOT}/tool-b/tool.sock")
    spawn("broker", BROKER, BROKER, [f"{ROOT}/bin/stub-broker", f"{ROOT}/cfg/broker.json"]); wait_sock(f"{ROOT}/broker/broker.sock")
    time.sleep(1.1)
    pep = spawn("pep", PEP, PEP, [f"{ROOT}/bin/pep-sidecar", f"{ROOT}/cfg/pep.json"]); wait_sock(f"{ROOT}/pep/mcp.sock")
    time.sleep(0.3)
    for path, want_uid, want_gid, want_mode in [(f"{ROOT}/pep/mcp.sock", PEP, AGENT, 0o660), (f"{ROOT}/pep-ctl/ctl.sock", PEP, OPERATOR, 0o660),
            (f"{ROOT}/broker/broker.sock", BROKER, PEP, 0o660), (f"{ROOT}/pep/mcp.sock.lock", PEP, AGENT, 0o600)]:
        st = os.stat(path)
        check(f"layout {path}", (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) == (want_uid, want_gid, want_mode),
              f"{st.st_uid}:{st.st_gid} {oct(stat.S_IMODE(st.st_mode))}")
    # The operator starts an episode.
    op = subprocess.run([f"{ROOT}/bin/stub-operator", f"{ROOT}/pep-ctl/ctl.sock", '{"call":"start_episode","intent":"pay"}'],
                        preexec_fn=demote(OPERATOR, OPERATOR), capture_output=True, text=True, timeout=30)
    token = json.loads(op.stdout)["result"]["episode_token"]
    check("operator (20004) starts an episode", bool(token))
    # The data flow: agent -> PEP -> broker -> tool, under real uids.
    code = CLIENT + f'''
print(call("{ROOT}/pep/mcp.sock", "get_invoice", {{"invoice_id":"INV-1001"}}, "{token}", 1))
print(call("{ROOT}/pep/mcp.sock", "pay_invoice", {{"invoice_id":"INV-1001","amount":30000,"currency":"USD"}}, "{token}", 2))
'''
    status, out = as_user(AGENT, AGENT, code)
    check("agent (20001) reads and pays through PEP, broker and tool", '"status":"executed"' in out, out[-120:])
    execs = [json.loads(l) for l in open(f"{ROOT}/tool-a-state/exec.jsonl")]
    pay = [e for e in execs if e["tool"] == "pay_invoice"]
    check("the tool saw the F-07 key, once", len(pay) == 1 and pay[0]["idempotency_key"].startswith("pep-"))
    # C-UID: a stolen live token, from the wrong peers. Each passes the socket's mode, by group.
    code = CLIENT + f'''
r = call("{ROOT}/pep/mcp.sock", "get_invoice", {{"invoice_id":"INV-1001"}}, "{token}")
print(repr(r))
'''
    for label, uid, gid, groups in [("wrong uid 20009:20001", OTHER, AGENT, ()), ("root 0:20001", 0, AGENT, ()),
                                    ("overflow 65534:20001", 65534, AGENT, ()), ("uid right, gid wrong 20001:20009", AGENT, OTHER, (AGENT,))]:
        status, out = as_user(uid, gid, code, groups)
        served = "HTTP/1.1" in out
        check(f"C-UID {label}: refused unread", not served, out[:60])
    # C-LOCK, C-CTL, C-CRED, as the agent.
    code = f'''
import os, socket
def attempt(name, fn):
    try:
        fn(); print(name, "ALLOWED")
    except OSError as e:
        print(name, "denied", e.errno)
attempt("open-lock", lambda: open("{ROOT}/pep/mcp.sock.lock"))
attempt("plant", lambda: open("{ROOT}/pep/x", "w"))
attempt("unlink-socket", lambda: os.unlink("{ROOT}/pep/mcp.sock"))
attempt("rename-socket", lambda: os.rename("{ROOT}/pep/mcp.sock", "{ROOT}/pep/y"))
attempt("connect-ctl", lambda: socket.socket(socket.AF_UNIX).connect("{ROOT}/pep-ctl/ctl.sock"))
attempt("connect-broker", lambda: socket.socket(socket.AF_UNIX).connect("{ROOT}/broker/broker.sock"))
attempt("connect-tool", lambda: socket.socket(socket.AF_UNIX).connect("{ROOT}/tool-a/tool.sock"))
attempt("read-journal", lambda: open("{ROOT}/pep-state/journal.jsonl"))
attempt("read-log", lambda: open("{ROOT}/pep-log/decisions.jsonl"))
attempt("read-cred", lambda: open("{ROOT}/broker-secrets/cred-a"))
attempt("read-verifier", lambda: open("{ROOT}/tool-a-state/verifier"))
attempt("read-pep-pub", lambda: open("{ROOT}/pep-pub/call-proof.pub"))
'''
    status, out = as_user(AGENT, AGENT, code)
    for line in out.splitlines():
        name, verdict = line.split(" ", 1)
        check(f"agent cannot {name}", verdict.startswith("denied"), verdict)
    # C-PROC: same PID namespace here, the harder case than Compose's.
    pid = pep.pid
    code = f'''
for path in ["/proc/{pid}/mem", "/proc/{pid}/environ", "/proc/{pid}/fd/0"]:
    try:
        open(path, "rb").read(16); print(path, "ALLOWED")
    except OSError as e:
        print(path, "denied", e.errno)
import ctypes, ctypes.util
libc = ctypes.CDLL(None, use_errno=True)
r = libc.ptrace(16, {pid}, 0, 0)
print("ptrace-attach", "ALLOWED" if r == 0 else "denied " + str(ctypes.get_errno()))
'''
    status, out = as_user(AGENT, AGENT, code)
    for line in out.splitlines():
        name, verdict = line.split(" ", 1)
        check(f"agent cannot {name}", verdict.startswith("denied"), verdict)
    cmdline = open(f"/proc/{pid}/cmdline", "rb").read()
    check("C-PROC PEP argv holds no key", b"BEGIN" not in cmdline and len(cmdline) < 200, cmdline.decode(errors="replace").replace("\0", " "))
    # A second PEP is blocked by the lock.
    second = subprocess.run([f"{ROOT}/bin/pep-sidecar", f"{ROOT}/cfg/pep.json"], preexec_fn=demote(PEP, PEP), capture_output=True, text=True, timeout=20)
    check("a second PEP refuses to start", second.returncode != 0 and "lock" in second.stderr, second.stderr.strip()[:90])
    # The broker admits only the PEP's uid and gid.
    code = '''
import socket
s = socket.socket(socket.AF_UNIX); s.settimeout(3)
s.connect("%s/broker/broker.sock")
s.sendall(b"POST /mcp/a HTTP/1.1\\r\\nHost: x\\r\\nContent-Length: 2\\r\\n\\r\\n{}")
try:
    print(repr(s.recv(100)))
except OSError as e:
    print("ERR", e)
''' % ROOT
    status, out = as_user(OTHER, PEP, code)
    check("broker refuses uid 20009 with the PEP's group", "HTTP/1.1" not in out, out[:60])
    # What is world-visible on the Call Proof key file.
    st = os.stat(f"{ROOT}/pep-pub/call-proof.pub")
    check("Call Proof key readable only through the 2750 directory", stat.S_IMODE(st.st_mode) == 0o644, oct(stat.S_IMODE(st.st_mode)))
finally:
    for name, child in children:
        child.terminate()
    for name, child in children:
        try:
            child.wait(timeout=3)
        except Exception:
            child.kill()
failed = [r for r in results if not r[1]]
print(f"\n{len(results)-len(failed)} of {len(results)} real-uid checks hold")
sys.exit(1 if failed else 0)
