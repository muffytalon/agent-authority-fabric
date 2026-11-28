"""The 79 checks of WEEK2_PLAN §3, each with its proof.

Usage, from the root of the WSL-side clone:
    PEP_SECRETS_DIR=~/.config/pep-gate1/secrets python3 compose/checks.py --check-log FILE [--keep] [--only TEXT]
    python3 compose/checks.py --cargo
    python3 compose/checks.py --list

Attacks count toward G1. Checks do not, but they must pass, and §3 says they run in CI, and in
Compose where they can. So every check is one entry here, with one kind of proof:

- **live:** run here on the live stack, the release images and `compose/gate1.yaml`, through
  `stub-injector wire`, which sends exactly the given bytes and returns exactly what came back.
  Each goes through the kit's oracle, so a request wrongly accepted shows as an execution.
- **log:** `compose/check.py` proves it, and FILE, its saved output, must hold the named lines.
- **rust:** it needs an injected errno, a test hook or a bad broker, so it is a named Rust test.
  `--cargo` runs them and requires each one to have run and passed, not merely to exist.

CI runs the first form in the `compose` job and `--cargo` in the verification loop. Each exits 0
only if every entry of its kind passed and the manifest still has §3's count for each category.
Tokens never reach the output.
"""
import base64, json, os, re, subprocess, sys, threading, time

import check
import kit
from check import dc, expect, in_background, journal_results, pointer, run
from kit import BIN, call_request, denied, operator, recorded, run_test, status, unavailable, wire

check.PROJECT = "pep-checks"

# §3's table: how many checks each category holds.
PLANNED = {"C-UID": 1, "C-PID": 6, "C-LOCK": 5, "C-NET": 1, "C-PROC": 1, "C-POSTURE": 8, "C-HTTP": 18, "C-MCP": 18,
           "C-FWD": 1, "C-RES": 3, "C-JSON": 7, "C-EPI": 1, "C-CRED": 1, "C-CTL": 6, "C-OUT": 2}
PLANNED_TOTAL = 79
PROTOCOL = "2026-07-28"
READ_TIMEOUT_S = 5        # limits.read_timeout_ms in config/kit
PARSE_ERROR, INVALID_PARAMS, HEADER_MISMATCH, UNSUPPORTED_VERSION = -32700, -32602, -32020, -32022
RUST_RESULT = re.compile(r"^test (\S+) \.\.\. (ok|FAILED|ignored)", re.M)

LIVE, LOGGED, RUST = [], [], []


def live(category, title, expected="deny", reason=None):
    def register(function):
        LIVE.append(dict(category=category, title=title, expected=expected, reason=reason, function=function))
        return function
    return register


def logged(category, title, *patterns):
    LOGGED.append(dict(category=category, title=title, patterns=patterns))


def rust(category, title, *tests):
    RUST.append(dict(category=category, title=title, tests=tests))


# --- the wire ---

def meta(**extra):
    return dict({"io.modelcontextprotocol/clientCapabilities": {}, "io.modelcontextprotocol/protocolVersion": PROTOCOL}, **extra)


def message(method, params=None, the_meta=None, request_id=1):
    return json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method,
                       "params": dict(params or {}, _meta=meta() if the_meta is None else the_meta)}, separators=(",", ":"))


def head_fields(method, name=None, token=None):
    fields = {"Host": "pep.local", "Accept": "application/json, text/event-stream", "Content-Type": "application/json",
              "MCP-Protocol-Version": PROTOCOL, "Mcp-Method": method}
    if name:
        fields["Mcp-Name"] = name
    if token:
        fields["Pep-Episode"] = token
    return fields


def http(body, fields, *extra, drop=(), length=None, line="POST /mcp HTTP/1.1", end="\r\n"):
    """An HTTP request: `fields`, less `drop`, then the raw `extra` lines."""
    rows = [line] + [f"{name}: {value}" for name, value in fields.items() if name not in drop] + list(extra)
    rows.append(f"Content-Length: {len(body.encode()) if length is None else length}")
    return end.join(rows + ["", ""]) + body


def note_call(token, **options):
    """The well-formed tools/call that every malformed one below starts from."""
    params = {"name": "get_note", "arguments": {"key": "wire"}}
    body = message("tools/call", params, meta(**{kit.EPISODE_KEY: token}))
    return http(body, head_fields("tools/call", "get_note", token), **options), body


def note_fields(token):
    return head_fields("tools/call", "get_note", token)


def refused(reply, wanted, code=None):
    """None if `reply` has that status and JSON-RPC code, else what it was."""
    if reply.status != wanted or (code is not None and reply.code != code):
        return f"wanted {wanted} {code or ''}, got {reply!r}"


# --- the control: the wire works, so a refusal below is a refusal ---

@live("control", "a well-formed tools/call succeeds over the same wire", expected="allow:1")
def control_wire(window):
    agent = window.agent("notes")
    request, _ = note_call(agent.token)
    window.begin()
    reply = wire(agent, request)
    if reply.status != 200 or "result" not in (reply.json or {}):
        return f"the control got {reply!r}"


@live("control", "the same bytes split in two succeed", expected="allow:1")
def control_split(window):
    agent = window.agent("notes")
    request, _ = note_call(agent.token)
    window.begin()
    reply = wire(agent, request[:40], request[40:], gap_ms=50)
    if reply.status != 200 or "result" not in (reply.json or {}):
        return f"the control got {reply!r}"


# --- C-NET, C-PROC ---

@live("C-NET", "only lo is present")
def net_lo(window):
    out = dc(*kit.PROFILES, "run", "--rm", "-T", "--no-deps", "--user", kit.AGENT_USER, "--entrypoint",
             f"{BIN}/net-probe", "probe", "cat", "/proc/net/dev", check=False, timeout=60).stdout
    interfaces = sorted(row.split(":")[0].strip() for row in out.splitlines() if ":" in row)
    if interfaces != ["lo"]:
        return f"interfaces: {interfaces}, from {out[:120]!r}"


@live("C-PROC", "the agent's argv and env hold no Episode Token", expected="allow:1")
def proc_token(window):
    agent = window.agent("pay")
    invoice = next(kit.SLOW)
    agent.lookup(invoice)
    window.begin()
    thread, box = in_background(agent.pay, invoice)
    kit.upstream_call("pay_invoice", invoice)
    seen = []
    for pid in agent.probe("pids").split():
        cmdline = agent.probe("cat", f"/proc/{pid}/cmdline")
        if "stub-agent" in cmdline:
            seen.append((cmdline, agent.probe("cat", f"/proc/{pid}/environ")))
    thread.join()
    if not seen:
        return "no stub-agent was running to look at, so this saw nothing"
    if any(agent.token in text or "eyJ" in text for row in seen for text in row):
        return "a token is in a stub-agent's argv or environment"
    if status(box.get("reply")) != "executed":
        return f"the call under observation was {box.get('reply')}"


# --- C-HTTP ---

def refuses_call(agent, build, wanted=400):
    """What `build(token, fields, body)` gets, which must be refused and run nothing."""
    _, body = note_call(agent.token)
    return refused(wire(agent, build(agent.token, note_fields(agent.token), body)), wanted)


@live("C-HTTP", "CL+TE")
def http_cl_te(window):
    return refuses_call(window.agent("notes"), lambda t, f, b: http(b, f, "Transfer-Encoding: chunked"))


@live("C-HTTP", "TE only")
def http_te(window):
    def build(token, fields, body):
        rows = ["POST /mcp HTTP/1.1"] + [f"{name}: {value}" for name, value in fields.items()]
        return "\r\n".join(rows + ["Transfer-Encoding: chunked", "", f"{len(body):x}", body, "0", "", ""])
    return refuses_call(window.agent("notes"), build)


@live("C-HTTP", "duplicate CL")
def http_two_lengths(window):
    return refuses_call(window.agent("notes"), lambda t, f, b: http(b, f, f"Content-Length: {len(b)}"))


@live("C-HTTP", "CL mismatch")
def http_mismatch(window):
    agent = window.agent("notes")
    _, body = note_call(agent.token)
    short = wire(agent, http(body, note_fields(agent.token), length=len(body) - 1))
    if short.status != 400:
        return f"a short CL got {short!r}"
    long = wire(agent, http(body, note_fields(agent.token), length=len(body) + 1), half_close=True)
    if long.status not in (None, 400) or "result" in (long.json or {}):
        return f"a long CL got {long!r}"


@live("C-HTTP", "obs-fold")
def http_fold(window):
    return refuses_call(window.agent("notes"), lambda t, f, b: http(b, f, "X-Fold: a", " b"))


@live("C-HTTP", "bare LF")
def http_bare_lf(window):
    return refuses_call(window.agent("notes"), lambda t, f, b: http(b, f, end="\n"))


@live("C-HTTP", "header over the cap")
def http_big_head(window):
    return refuses_call(window.agent("notes"), lambda t, f, b: http(b, f, "X-Long: " + "x" * 17000))


@live("C-HTTP", "body over the cap")
def http_big_body(window):
    return refuses_call(window.agent("notes"), lambda t, f, b: http(b, f, length=1048577))


@live("C-HTTP", "slowloris headers, including one byte per interval")
def http_slowloris(window):
    agent = window.agent("notes")
    request, _ = note_call(agent.token)
    head = request.partition("\r\n\r\n")[0]
    for name, parts, gap in [("one byte per interval", list(head), 100),
                             ("one line per interval", [line + "\r\n" for line in head.split("\r\n")], 1000)]:
        reply = wire(agent, *parts, gap_ms=gap)
        if "result" in (reply.json or {}) or reply.ms > (READ_TIMEOUT_S + 2) * 1000:
            return f"{name}: {reply!r} after {reply.ms} ms"


@live("C-HTTP", "slow body")
def http_slow_body(window):
    agent = window.agent("notes")
    request, _ = note_call(agent.token)
    head, _, body = request.partition("\r\n\r\n")
    reply = wire(agent, head + "\r\n\r\n", *list(body), gap_ms=100)
    if "result" in (reply.json or {}) or reply.ms > (2 * READ_TIMEOUT_S + 2) * 1000:
        return f"{reply!r} after {reply.ms} ms"


@live("C-HTTP", "a pipelined second request", expected="allow:1")
def http_pipelined(window):
    agent = window.agent("notes")
    request, _ = note_call(agent.token)
    window.begin()
    reply = wire(agent, request + request)
    if reply.text.count("HTTP/1.1 ") != 1:
        return f"{reply.text.count('HTTP/1.1 ')} responses to a pipelined pair"


@live("C-HTTP", "Content-Encoding")
def http_encoding(window):
    return refuses_call(window.agent("notes"), lambda t, f, b: http(b, f, "Content-Encoding: gzip"))


@live("C-HTTP", "HTTP/1.0")
def http_one_oh(window):
    return refuses_call(window.agent("notes"), lambda t, f, b: http(b, f, line="POST /mcp HTTP/1.0"))


@live("C-HTTP", "an HTTP/2 preface")
def http_preface(window):
    agent = window.agent()
    return refused(wire(agent, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), 400)


@live("C-HTTP", "GET gets 405")
def http_get(window):
    agent = window.agent()
    return refused(wire(agent, "GET /mcp HTTP/1.1\r\nHost: pep.local\r\n\r\n"), 405)


@live("C-HTTP", "DELETE gets 405")
def http_delete(window):
    agent = window.agent()
    return refused(wire(agent, "DELETE /mcp HTTP/1.1\r\nHost: pep.local\r\n\r\n"), 405)


@live("C-HTTP", "a notification POST gets 400, except notifications/cancelled, 202 and ignored")
def http_notification(window):
    agent = window.agent()
    def notification(method):
        body = json.dumps({"jsonrpc": "2.0", "method": method, "params": {"requestId": 1}}, separators=(",", ":"))
        return wire(agent, http(body, head_fields(method)))
    return refused(notification("notifications/progress"), 400) or refused(notification("notifications/cancelled"), 202)


@live("C-HTTP", "a duplicated standard header, whitespace before a colon, or another target gets 400")
def http_duplicates(window):
    agent = window.agent("notes")
    _, body = note_call(agent.token)
    fields = note_fields(agent.token)
    cases = {f"a second {name}": http(body, fields, f"{name}: {fields[name]}")
             for name in ("MCP-Protocol-Version", "Mcp-Method", "Mcp-Name", "Pep-Episode", "Content-Type", "Host")}
    cases["whitespace before a colon"] = http(body, fields, "X-Space : a")
    for target in ("/mcp?x=1", "/mcp/", "http://pep.local/mcp", "/other"):
        cases[f"target {target}"] = http(body, fields, line=f"POST {target} HTTP/1.1")
    for name, request in cases.items():
        problem = refused(wire(agent, request), 400)
        if problem:
            return f"{name}: {problem}"


# --- C-MCP ---

@live("C-MCP", "the version header differs from _meta")
def mcp_version(window):
    agent = window.agent("notes")
    _, body = note_call(agent.token)
    fields = dict(note_fields(agent.token), **{"MCP-Protocol-Version": "2025-11-25"})
    return refused(wire(agent, http(body, fields)), 400, HEADER_MISMATCH)


@live("C-MCP", "Mcp-Method differs from the body")
def mcp_method(window):
    agent = window.agent("notes")
    _, body = note_call(agent.token)
    fields = dict(note_fields(agent.token), **{"Mcp-Method": "tools/list"})
    return refused(wire(agent, http(body, fields)), 400, HEADER_MISMATCH)


@live("C-MCP", "Mcp-Name differs from the body")
def mcp_name(window):
    agent = window.agent("notes")
    _, body = note_call(agent.token)
    fields = dict(note_fields(agent.token), **{"Mcp-Name": "search_notes"})
    return refused(wire(agent, http(body, fields)), 400, HEADER_MISMATCH)


def encoded(text):
    return f"=?base64?{base64.b64encode(text.encode()).decode()}?="


@live("C-MCP", "a base64-sentinel Mcp-Name mismatch")
def mcp_sentinel(window):
    agent = window.agent("notes")
    _, body = note_call(agent.token)
    wrong = dict(note_fields(agent.token), **{"Mcp-Name": encoded("search_notes")})
    invalid = dict(note_fields(agent.token), **{"Mcp-Name": "=?base64?not base64!?="})
    return (refused(wire(agent, http(body, wrong)), 400, HEADER_MISMATCH)
            or refused(wire(agent, http(body, invalid)), 400, HEADER_MISMATCH))


@live("C-MCP", "a batch array body")
def mcp_batch(window):
    agent = window.agent("notes")
    _, body = note_call(agent.token)
    return refused(wire(agent, http(f"[{body}]", note_fields(agent.token))), 400)


@live("C-MCP", "any Mcp-Param-* header")
def mcp_param(window):
    agent = window.agent("notes")
    _, body = note_call(agent.token)
    return refused(wire(agent, http(body, note_fields(agent.token), "Mcp-Param-Key: wire")), 400, HEADER_MISMATCH)


@live("C-MCP", "a missing MCP-Protocol-Version")
def mcp_no_version(window):
    agent = window.agent("notes")
    _, body = note_call(agent.token)
    return refused(wire(agent, http(body, note_fields(agent.token), drop=("MCP-Protocol-Version",))), 400, HEADER_MISMATCH)


@live("C-MCP", "a JSON-RPC response as the body")
def mcp_response(window):
    agent = window.agent()
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {}}, separators=(",", ":"))
    return refused(wire(agent, http(body, head_fields("tools/list"))), 400)


@live("C-MCP", "any Origin gets 403")
def mcp_origin(window):
    agent = window.agent("notes")
    _, body = note_call(agent.token)
    for origin in ("http://localhost", "http://evil.example", "null"):
        problem = refused(wire(agent, http(body, note_fields(agent.token), f"Origin: {origin}")), 403)
        if problem:
            return f"{origin}: {problem}"


@live("C-MCP", "an unsupported version gets -32022, with the data MCP requires")
def mcp_unsupported(window):
    agent = window.agent()
    the_meta = dict(meta(), **{"io.modelcontextprotocol/protocolVersion": "2025-11-25"})
    fields = dict(head_fields("tools/list"), **{"MCP-Protocol-Version": "2025-11-25"})
    reply = wire(agent, http(message("tools/list", {}, the_meta), fields))
    problem = refused(reply, 400, UNSUPPORTED_VERSION)
    if problem:
        return problem
    data = pointer(reply.json, "/error/data")
    if data != {"requested": "2025-11-25", "supported": [PROTOCOL]}:
        return f"its data was {data}"


@live("C-MCP", "Accept without text/event-stream")
def mcp_accept(window):
    agent = window.agent("notes")
    _, body = note_call(agent.token)
    fields = dict(note_fields(agent.token), Accept="application/json")
    return refused(wire(agent, http(body, fields)), 400)


@live("C-MCP", "a missing _meta protocolVersion")
def mcp_no_meta_version(window):
    agent = window.agent()
    the_meta = {"io.modelcontextprotocol/clientCapabilities": {}}
    return refused(wire(agent, http(message("tools/list", {}, the_meta), head_fields("tools/list"))), 400, INVALID_PARAMS)


@live("C-MCP", "a missing _meta clientCapabilities")
def mcp_no_capabilities(window):
    agent = window.agent()
    the_meta = {"io.modelcontextprotocol/protocolVersion": PROTOCOL}
    return refused(wire(agent, http(message("tools/list", {}, the_meta), head_fields("tools/list"))), 400, INVALID_PARAMS)


@live("C-MCP", "server/discover is answered without upstream instructions")
def mcp_discover(window):
    agent = window.agent()
    reply = wire(agent, http(message("server/discover"), head_fields("server/discover")))
    result = pointer(reply.json, "/result") or {}
    if result.get("supportedVersions") != [PROTOCOL] or result.get("capabilities") != {"tools": {}}:
        return f"discover answered {reply!r}"
    if "instructions" in result:
        return f"it carried instructions: {result['instructions'][:60]!r}"


@live("C-MCP", "subscriptions/listen is acknowledged first, then completed and closed, with no notifications/cancelled")
def mcp_listen(window):
    agent = window.agent()
    reply = wire(agent, http(message("subscriptions/listen", {"notifications": {}}), head_fields("subscriptions/listen")))
    if reply.status != 200 or "text/event-stream" not in reply.head:
        return f"listen answered {reply.text[:120]!r}"
    events = [json.loads(line[len("data: "):]) for line in reply.raw_body.split("\n") if line.startswith("data: ")]
    if len(events) != 2 or events[0].get("method") != "notifications/subscriptions/acknowledged":
        return f"the events were {events}"
    if events[0]["params"].get("notifications") != {} or not events[0]["params"].get("_meta"):
        return f"the acknowledgement was {events[0]}"
    if pointer(events[1], "/result/resultType") != "complete":
        return f"the last event was {events[1]}"
    if "notifications/cancelled" in reply.text:
        return "it sent notifications/cancelled"


@live("C-MCP", "Mcp-Name base64 with NFC is compared correctly", reason="ToolNotPinned")
def mcp_nfc(window):
    agent = window.agent("notes")
    decomposed = "café"           # NFD in the header, and NFC in the body
    composed = "café"
    params = {"name": composed, "arguments": {}}
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": dict(params, _meta=meta(**{kit.EPISODE_KEY: agent.token}))}, separators=(",", ":"))
    fields = head_fields("tools/call", encoded(decomposed), agent.token)
    window.begin()
    reply = wire(agent, http(body, fields))
    # Past the header check, the name is simply not pinned: a 200 and a denial, not -32020.
    if reply.status != 200 or not denied(reply.json):
        return f"it got {reply!r}"


@live("C-MCP", "every PEP result carries resultType, and discover and list carry ttlMs and cacheScope", expected="allow:1")
def mcp_result_fields(window):
    agent = window.agent("notes")
    discover = wire(agent, http(message("server/discover"), head_fields("server/discover")))
    listed = wire(agent, http(message("tools/list", {}, meta(**{kit.EPISODE_KEY: agent.token})),
                              head_fields("tools/list", token=agent.token)))
    for name, reply, scope in (("discover", discover, "public"), ("tools/list", listed, "private")):
        result = pointer(reply.json, "/result") or {}
        if result.get("resultType") != "complete" or result.get("ttlMs") != 0 or result.get("cacheScope") != scope:
            return f"{name}: {result}"
    request, _ = note_call(agent.token)
    window.begin()
    called = wire(agent, request)
    if pointer(called.json, "/result/resultType") != "complete":
        return f"tools/call: {called!r}"


@live("C-MCP", "tools/list with the token as a Pep-Episode header alone is served, and a header that differs from _meta is not")
def mcp_header_token(window):
    agent = window.agent("notes")
    alone = wire(agent, http(message("tools/list"), head_fields("tools/list", token=agent.token)))
    if alone.status != 200 or not pointer(alone.json, "/result/tools"):
        return f"the header alone got {alone!r}"
    body = message("tools/list", {}, meta(**{kit.EPISODE_KEY: agent.token}))
    return refused(wire(agent, http(body, head_fields("tools/list", token=agent.token + "x"))), 400, HEADER_MISMATCH)


# --- C-FWD ---

@live("C-FWD", "the upstream body is the PEP's own canonical bytes", expected="allow:1")
def fwd_canonical(window):
    agent = window.agent("pay")
    invoice = next(kit.PLAIN)
    # The agent's spelling: spaces, its own key order, and an escape.
    body = ('{ "params" : { "arguments" : { "invoice_id" : "' + invoice.replace("I", "\\u0049", 1) + '" } , "name" : "get_invoice" , "_meta" : '
            + json.dumps(meta(**{kit.EPISODE_KEY: agent.token})) + ' } , "method" : "tools/call" , "id" : 1 , "jsonrpc" : "2.0" }')
    window.begin()
    reply = wire(agent, http(body, head_fields("tools/call", "get_invoice", agent.token)))
    if reply.status != 200 or "result" not in (reply.json or {}):
        return f"the call got {reply!r}"
    forwarded = recorded()[-1]["body"]
    parsed = json.loads(forwarded)
    if forwarded != json.dumps(parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=False):
        return f"the upstream body is not canonical: {forwarded[:120]}"
    if parsed["params"]["arguments"] != {"invoice_id": invoice} or parsed["id"] == 1:
        return f"the upstream call is not the PEP's own: {forwarded[:160]}"


# --- C-RES ---

@live("C-RES", "an unknown or absent resultType is never recorded or returned", expected="allow:2")
def res_type(window):
    agent = window.agent("pay")
    window.begin()
    for invoice in ("INV-R-TYPE", "INV-R-NOTYPE"):
        reply = agent.lookup(invoice)
        if not unavailable(reply):
            return f"{invoice} got {reply}"
    # Nothing was recorded, so neither can fund a payment.
    reply = agent.pay("INV-R-TYPE")
    if not denied(reply):
        return f"a payment on it got {reply}"


@live("C-RES", "input_required is not recorded, and a payment's reservation follows the broker's outcome", expected="allow:2")
def res_input(window):
    agent = window.agent("pay")
    window.begin()
    agent.lookup("INV-R-INPUT")
    reply = agent.pay("INV-R-INPUT")
    if not unavailable(reply):
        return f"the payment got {reply}"
    def after():
        results = journal_results()
        if results[-1:] != ["unknown"]:
            return f"the journal ends {results[-3:]}"
    return after


rust("C-RES", "an SSE reply from the broker is invalid", "upstream::tests::anything_else_is_no_reply")


# --- C-JSON ---

def json_refused(window, *bodies):
    """Each body must get 400, with `TOKEN` in it the episode's token."""
    agent = window.agent("notes")
    fields = head_fields("tools/call", "get_note", agent.token)
    for body in bodies:
        problem = refused(wire(agent, http(body.replace("TOKEN", agent.token), fields)), 400)
        if problem:
            return f"{body[-60:]!r}: {problem}"


def call_body(arguments='{"key":"wire"}', name='"name":"get_note"'):
    return ('{"id":1,"jsonrpc":"2.0","method":"tools/call","params":{"_meta":' + json.dumps(meta(**{kit.EPISODE_KEY: "TOKEN"}))
            + ',"arguments":' + arguments + ',' + name + '}}')


@live("C-JSON", "duplicate keys, name twice, forward nothing")
def json_duplicates(window):
    return json_refused(window, call_body(name='"name":"get_note","name":"save_note"'))


@live("C-JSON", "NaN or Infinity")
def json_nan(window):
    return json_refused(window, *(call_body('{"key":' + word + "}") for word in ("NaN", "Infinity", "-Infinity")))


@live("C-JSON", "lone surrogates")
def json_surrogate(window):
    return json_refused(window, call_body('{"key":"\\ud800"}'), call_body('{"key":"\\udc00x"}'))


@live("C-JSON", "a depth bomb")
def json_depth(window):
    return json_refused(window, call_body('{"key":' + "[" * 20000 + "]" * 20000 + "}"))


@live("C-JSON", "a huge number")
def json_huge(window):
    return json_refused(window, call_body('{"key":9007199254740992}'), call_body('{"key":' + "9" * 400 + "}"))


@live("C-JSON", "a BOM")
def json_bom(window):
    return json_refused(window, "﻿" + call_body())


rust("C-JSON", "pins with a fractional minimum and over 8,192 values load under the definition profile, and the request profile refuses both",
     "jcs::tests::definition_profile_accepts_what_definitions_hold")


# --- C-CRED ---

@live("C-CRED", "each tool server rejects calls without its own credential, from a probe on its network")
def cred_absent(window):
    for service, net, name, arguments in (("tool-a", "tools_a", "get_invoice", {"invoice_id": next(kit.PLAIN)}),
                                          ("tool-b", "tools_b", "get_note", {"key": "k"})):
        address = kit.tool_address(service, net)
        body = json.dumps({"jsonrpc": "2.0", "id": "stray", "method": "tools/call", "params": {"name": name, "arguments": arguments}})
        request = (f"POST /mcp HTTP/1.1\r\nHost: {service}\r\nContent-Type: application/json\r\nAccept: application/json\r\n"
                   f"Content-Length: {len(body)}\r\n\r\n{body}")
        out = run(["docker", "run", "--rm", "-i", "--network", kit.network(net), "--read-only", "--cap-drop", "ALL",
                   "--user", kit.AGENT_USER, "--entrypoint", f"{BIN}/net-probe", kit.PROBE_IMAGE, "tcp", address, "8080"],
                  input=request, check=False, timeout=60)
        if not out.stdout.startswith(("HTTP/1.1 401", "HTTP/1.1 403")):
            return f"{service} answered {out.stdout[:60]!r}"


# --- C-CTL ---

def awaiting(deadline_s=4):
    """The payment the operator sees waiting, once there is one."""
    until = time.time() + deadline_s
    while time.time() < until:
        first = pointer(operator({"call": "pending"}), "/result/approvals/0")
        if first:
            return first
        time.sleep(0.05)


def approval_of(pending, amount):
    return {"call": "approve", "eid": pending["eid"], "rid": pending["rid"],
            "action_digest": pending["action_digest"], "amount_minor": amount}


AMOUNT = 60000              # over the kit's step_up_over_minor
RELEASED_WITHIN_S = 6       # under the kit's step_up_timeout_ms of 8 s, which would release it anyway


@live("C-CTL", "an approval with any of eid, rid, action_digest or amount mismatched is refused", expected="allow:1")
def ctl_mismatch(window):
    other = window.agent("pay2")
    agent = window.agent("pay")
    invoice = next(STEP_UP)
    agent.lookup(invoice)
    window.begin()
    thread, box = in_background(agent.pay, invoice, AMOUNT)
    pending = awaiting()
    if not pending:
        thread.join()
        return f"nothing awaited approval: {box.get('reply')}"
    good = approval_of(pending, AMOUNT)
    # The exact errors, or this could pass on a step-up that had simply timed out.
    for field, wrong, error in (("eid", other.eid, "not_awaiting"), ("rid", good["rid"] + 1, "not_awaiting"),
                                ("action_digest", "sha-256:" + "0" * 43, "mismatch"), ("amount_minor", AMOUNT - 1, "mismatch")):
        reply = operator(dict(good, **{field: wrong}))
        if reply.get("error") != error:
            return f"an approval with the wrong {field} got {reply}"
    taken = operator(good)
    thread.join()
    if "result" not in taken or status(box.get("reply")) != "executed":
        return f"the right approval got {taken}, and the call {box.get('reply')}"


@live("C-CTL", "a declined step-up leaves the reservation Released, and the agent gets PEP_DENIED")
def ctl_decline(window):
    agent = window.agent("pay")
    invoice = next(STEP_UP)
    agent.lookup(invoice)
    window.begin()
    thread, box = in_background(agent.pay, invoice, AMOUNT)
    pending = awaiting()
    if not pending:
        thread.join()
        return "nothing awaited approval"
    operator(dict(approval_of(pending, AMOUNT), call="decline"))
    thread.join()
    if not denied(box.get("reply")):
        return f"the agent got {box.get('reply')}"
    def after():
        if journal_results()[-1:] != ["released"]:
            return f"the journal ends {journal_results()[-3:]}"
    return after


@live("C-CTL", "an approval that arrives after the agent disconnected is refused")
def ctl_late(window):
    agent = window.agent("pay")
    invoice = next(STEP_UP)
    agent.lookup(invoice)
    window.begin()
    args = {"invoice_id": invoice, "amount": AMOUNT, "currency": "USD"}
    thread, _ = in_background(agent.send, [{"request": call_request("pay_invoice", args, agent.token), "drop_after_ms": 800}])
    pending = awaiting()
    if not pending:
        thread.join()
        return "nothing awaited approval"
    thread.join()
    time.sleep(0.2)
    reply = operator(approval_of(pending, AMOUNT))
    if "result" in reply:
        return f"the late approval was taken: {reply}"


@live("C-CTL", "after end_episode, later calls are denied and in-flight legs finish", expected="allow:1")
def ctl_end(window):
    agent = window.agent("pay")
    invoice = next(kit.SLOW)
    agent.lookup(invoice)
    token = agent.token
    window.begin()
    thread, box = in_background(agent.pay, invoice)
    kit.upstream_call("pay_invoice", invoice)
    eid = agent.eid
    ended = operator({"call": "end_episode", "eid": eid})
    agent.eid = None
    if "result" not in ended:
        return f"end_episode got {ended}"
    later = wire(agent, note_call(token)[0])
    thread.join()
    if not denied(later.json):
        return f"a later call got {later!r}"
    def after():
        if journal_results()[-1:] != ["executed"]:
            return f"the leg in flight ended {journal_results()[-3:]}"
    return after


@live("C-CTL", "start_episode is refused while the intent has a live episode")
def ctl_one_live(window):
    agent = window.agent("pay2")
    reply = operator({"call": "start_episode", "intent": "pay2"})
    if pointer(reply, "/result/episode_token"):
        return "a second live episode of one intent started"
    agent.end()
    time.sleep(0.2)
    fresh = window.agent("pay2")
    if not fresh.token:
        return "the intent did not free once its episode ended"


@live("C-CTL", "end_episode lands promptly while the agent saturates its socket", expected="any")
def ctl_saturated(window):
    agent = window.agent("notes")
    flood = [{"request": call_request("get_note", {"key": "flood"}, agent.token)}] * 150
    threads = [threading.Thread(target=agent.send, args=(flood,), daemon=True) for _ in range(4)]
    for thread in threads:
        thread.start()
    time.sleep(0.5)
    began = time.time()
    ended = operator({"call": "end_episode", "eid": agent.eid})
    took = time.time() - began
    agent.eid = None
    for thread in threads:
        thread.join()
    if "result" not in ended or took > 2:
        return f"end_episode took {took:.2f} s: {ended}"


# --- C-OUT ---

@live("C-OUT", "denials from every guard have identical wire bytes", expected="any")
def out_identical(window):
    replies = {}
    invoice = next(kit.PLAIN)
    pay = window.agent("pay")
    def call_of(agent, name, arguments):
        params = {"name": name, "arguments": arguments}
        return http(message("tools/call", params, meta(**{kit.EPISODE_KEY: agent.token})),
                    head_fields("tools/call", name, agent.token))
    plain = {"invoice_id": invoice, "amount": 1000, "currency": "USD"}
    replies["G_pin"] = wire(pay, call_of(pay, "delete_everything", {}))
    replies["G_canon"] = wire(pay, call_of(pay, "get_invoice", {"invoice_id": invoice, "extra": {"a": 1}}))
    replies["G_prov"] = wire(pay, call_of(pay, "pay_invoice", plain))
    small = window.agent("small")
    # A read may name any invoice: the allowlist is on what is paid.
    small.lookup(invoice)
    replies["G_entity"] = wire(small, call_of(small, "pay_invoice", plain))
    pay.lookup(invoice)
    replies["G_amount"] = wire(pay, call_of(pay, "pay_invoice", dict(plain, amount=999)))
    ordered = window.agent("ordered")
    replies["G_seq"] = wire(ordered, call_of(ordered, "get_note", {"key": "k"}))
    first, second = "INV-M001", "INV-M002"
    small.lookup(first)
    small.lookup(second)
    small.pay(first)
    replies["G_budget"] = wire(small, call_of(small, "pay_invoice", {"invoice_id": second, "amount": 1000, "currency": "USD"}))
    secret = window.agent(next(kit.SECRET_INTENTS))
    secret.call("search_notes", {"query": "x"})
    replies["G_label"] = wire(secret, call_of(secret, "post_public", {"text": "x"}))
    texts = {reply.text for reply in replies.values()}
    if len(texts) != 1 or not denied(replies["G_pin"].json):
        return f"{len(texts)} different denials: { {name: reply.text[-70:] for name, reply in replies.items()} }"
    reasons = window.reasons()
    missing = [word for word in ("ToolNotPinned", "UndeclaredArgument", "ProvenanceMissing", "EntityNotAllowed", "AmountNotBound",
                                 "SequenceViolation", "CumulativeMaxExceeded", "ConfidentialityViolation") if word not in reasons]
    if missing:
        return f"these guards never spoke, so the comparison proves less than it says: {missing}"


@live("C-OUT", "a disconnect before the point of forwarding, and a half-close, each release the reservation", expected="any")
def out_before_forwarding(window):
    agent = window.agent("pay")
    for how in ("disconnect", "half-close"):
        invoice = next(STEP_UP)
        agent.lookup(invoice)
        args = {"invoice_id": invoice, "amount": AMOUNT, "currency": "USD"}
        request = call_request("pay_invoice", args, agent.token)
        before = len(journal_results())
        began = time.time()
        if how == "disconnect":
            agent.send([{"request": request, "drop_after_ms": 300}])
        else:
            wire(agent, request, half_close=True)
        # The step-up timeout releases it too, after 2 s, so only an earlier release proves this.
        while len(journal_results()) == before and time.time() - began < RELEASED_WITHIN_S:
            time.sleep(0.05)
        results = journal_results()[before:]
        if results != ["released"]:
            return f"within {RELEASED_WITHIN_S} s of a {how} the journal gained {results}"


# The rest of that check, which no agent can reach, so it does not count as a check of its own.
rust("supporting C-OUT", "release_unforwarded refuses a Forwarded reservation", "engine::tests::a_forwarded_payment_cannot_be_released")


# --- proved by compose/check.py ---

logged("C-POSTURE", "every container has CapEff 0", r"^ok   .*: CapEff 0, CapBnd 0$")
logged("C-POSTURE", "NoNewPrivs 1", r"^ok   .*: NoNewPrivs 1$")
logged("C-POSTURE", "Seccomp 2, with the AF_UNIX-only profile on the agent, the PEP, the operator and the probe",
       r"^ok   .*: Seccomp 2$", r"^ok   .*: runs the AF_UNIX-only profile$")
logged("C-POSTURE", "io_uring_setup fails under that profile", r"^ok   AF_UNIX-only profile: io_uring_setup is refused")
logged("C-POSTURE", "no socketcall rule, and x86_64 has no subArchitectures", r"^ok   profile: no socketcall rule$",
       r"^ok   profile: x86_64 has no subArchitectures")
logged("C-POSTURE", "pep-log keeps its records across docker restart and docker kill", r"^ok   pep-log: keeps its records across docker restart",
       r"^ok   pep-log: keeps its records across docker kill")
logged("C-POSTURE", "no container mounts docker.sock", r"^ok   .*: no docker.sock$")
logged("C-POSTURE", "the agent's pids_limit, memory limit and private /tmp are in effect", r"^ok   agent: pids_limit 256 in effect$",
       r"^ok   agent: mem_limit 1g in effect$", r"^ok   agent: a private, size-capped /tmp")


# --- proved by a Rust test, because each needs what a live stack cannot give ---

rust("C-UID", "socketpair self-connect", "peercred::tests::socketpair_self_connect")
rust("C-PID", "a getsockopt error rejects", "peercred::tests::pidfd::pidfd_errno_rejects")
rust("C-PID", "fdinfo Pid: -1 rejects", "peercred::tests::pidfd::fdinfo_pid_parser")
rust("C-PID", "the peer exits between accept and check", "peercred::tests::pidfd::reaped_peer_rejected")
rust("C-PID", "Pid: 0 is handled per Q1", "peercred::tests::pidfd::pidfd_liveness_rule")
rust("C-PID", "ENOPROTOOPT rejects", "peercred::tests::pidfd::pidfd_errno_rejects")
rust("C-PID", "no pidfd leaks", "peercred::tests::pidfd::pidfd_cloexec_and_closed")
rust("C-LOCK", "a second instance is blocked", "peercred::tests::second_instance_blocked")
rust("C-LOCK", "a stale socket is replaced only under the lock", "peercred::tests::stale_socket_replaced_only_under_the_lock")
rust("C-LOCK", "the lock is released on a crash", "peercred::tests::lock_released_on_crash")
rust("C-LOCK", "a read-only lock directory fails", "peercred::tests::read_only_directory_fails")
rust("C-LOCK", "a symlink planted at the socket path is refused", "peercred::tests::symlink_at_socket_path_refused")
rust("C-EPI", "peer_uid mismatch", "registry::tests::tokens_are_bound_to_their_peer_their_key_and_a_live_episode")


def manifest_problems():
    """How the manifest differs from §3's table."""
    counts = {}
    for entry in LIVE + LOGGED + RUST:
        if entry["category"] in PLANNED:
            counts[entry["category"]] = counts.get(entry["category"], 0) + 1
    return {name: (counts.get(name, 0), wanted) for name, wanted in PLANNED.items() if counts.get(name, 0) != wanted}


def require_manifest():
    problems = manifest_problems()
    if problems:
        raise SystemExit(f"the manifest differs from §3's table (have, want): {problems}")


def cargo_checks():
    """Each named test must have run here and passed."""
    out = subprocess.run(["cargo", "test", "--locked", "--lib"], cwd=check.ROOT, capture_output=True, text=True, check=False)
    results = {}
    for name, result in RUST_RESULT.findall(out.stdout):
        results[name] = result
    for entry in RUST:
        states = [results.get(name, "did not run") for name in entry["tests"]]
        expect(f"{entry['category']} {entry['title']}", all(state == "ok" for state in states), dict(zip(entry["tests"], states)))
    if out.returncode != 0:
        print(out.stdout[-1500:], out.stderr[-500:])
    print(f"CHECKS: {len(RUST)} proved by Rust tests, {len(check.failures)} failed", flush=True)
    return 1 if check.failures or out.returncode != 0 else 0


def logged_checks(path):
    with open(path) as f:
        text = f.read()
    for entry in LOGGED:
        missing = [pattern for pattern in entry["patterns"] if not re.search(pattern, text, re.M)]
        expect(f"{entry['category']} {entry['title']}", not missing, missing)
    failed = re.findall(r"^FAIL .*$", text, re.M)
    expect("check.py: its log holds no failure", not failed, failed[:3])


def live_checks(only):
    kit.remove_parked()
    dc(*kit.PROFILES, "down", "-v", "--remove-orphans")
    dc(*kit.PROFILES, "build")
    dc("up", "-d", "--wait", "--wait-timeout", "120")
    time.sleep(1.1)   # the broker refuses proofs from its boot second (R1)
    for entry in LIVE:
        name = f"{entry['category']} {entry['title']}"
        if not only or only in name:
            run_test(name, entry["expected"], entry["reason"], False, entry["function"])


def main():
    arguments = sys.argv[1:]
    require_manifest()
    if "--list" in arguments:
        for kind, entries in (("live", LIVE), ("log", LOGGED), ("rust", RUST)):
            for entry in entries:
                print(f"{kind:5} {entry['category']:10} {entry['title']}")
        print(f"{len(LIVE)} live with their controls, {len(LOGGED)} from check.py, {len(RUST)} Rust")
        return 0
    if "--cargo" in arguments:
        return cargo_checks()
    keep = "--keep" in arguments
    only = arguments[arguments.index("--only") + 1] if "--only" in arguments else None
    if not os.environ.get("PEP_SECRETS_DIR"):
        raise SystemExit("set PEP_SECRETS_DIR (WEEK2_PLAN §4)")
    if "--check-log" in arguments:
        logged_checks(arguments[arguments.index("--check-log") + 1])
    elif not only:
        raise SystemExit("--check-log FILE is required: C-POSTURE's 8 checks come from compose/check.py's output")
    try:
        live_checks(only)
    finally:
        if not keep:
            kit.remove_parked()
            dc(*kit.PROFILES, "down", "-v", "--remove-orphans", check=False)
    print(f"CHECKS: {kit.tally['held']} live tests held, with their controls, and {kit.tally['failed']} failed. The manifest has "
          f"{PLANNED_TOTAL}: {len(LIVE) - 2} live, {len(LOGGED)} from check.py, {PLANNED_TOTAL - (len(LIVE) - 2) - len(LOGGED)} in Rust; "
          f"{'all held' if not check.failures else f'{len(check.failures)} FAILED'}", flush=True)
    return 1 if check.failures else 0


STEP_UP = iter(f"INV-V{n:03}" for n in range(1, 11))

if __name__ == "__main__":
    sys.exit(main())
