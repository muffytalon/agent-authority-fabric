"""G2: the rug-pull mutations of WEEK2_PLAN §3, on the live stack (step 10, L1).

Usage, from the root of the WSL-side clone:
    PEP_SECRETS_DIR=~/.config/pep-gate1/secrets python3 compose/mutations.py [--keep] [--only TEXT]

It runs as its own project, `pep-mut`, with compose/gate1.yaml over compose.yaml: the kit's
fixtures (config/kit), whose tool servers serve the rug pull their flag file names
(src/stubs/drift.rs). Each case starts from a PEP on an empty journal with both servers serving,
then tells one server to drift, and the PEP's drift poller, not a restart, must find it:

- the server's state changes within T = 10 s of the change, by the PEP's own log timestamps;
- the agent's calls to it are then refused, and the decision log names `ToolQuarantined`;
- `tools/list` hides every tool of that server, and only that server's;
- the server executes nothing after the refusal;
- the journal holds one quarantine, for that server, and a restart on the same lockfile keeps
  it (RV4 #5). A lockfile with a new digest lifts it: tests/e2e.rs shows that, since it needs a
  second signed lockfile.

#26's failed polls suspend instead: refused alike, nothing journaled, and serving again within T
of the failure ending. #27 reverts the change after detection, which lifts nothing, and before any
poll could see it, which is not drift. #28 drifts the server whose lookup witnessed a payment to
the other server, after detection and while the payment waits for step-up. The step-up timing
case (RV3 A4) drifts the payment's own server during its wait. The negatives respell what a
server serves without changing its meaning, and must still serve after two polls.

Writes `reports/Gate1 mutation report.md`. Exits 0 only if every case held. `--only TEXT`, which
may repeat, runs the cases whose name holds TEXT. Tokens never reach the output.
"""
import datetime, json, os, re, sys, time

import check
import kit
from check import dc, expect, fetch, in_background, lines, pointer, run
from kit import Agent, denied, operator

check.PROJECT = "pep-mut"
check.COMPOSE_FILES = ["compose.yaml", "compose/gate1.yaml"]

# `docker compose ps` takes about a second, and a case asks for containers dozens of times. Only
# the PEP's is ever replaced, so the rest are looked up once.
_containers = {}
_lookup = check.container


def _cached(service):
    if not _containers.get(service):
        _containers[service] = _lookup(service)
    return _containers[service]


def forget_pep():
    _containers.pop("pep", None)


check.container = _cached

T_S = 10                  # L1: the longest interval (6 s), the poll deadline (3 s) and 1 s
POLL_MAX_S = 6            # drift_poll_ms 5,000 + 20%
STEP_UP_S = 8             # limits.step_up_timeout_ms in config/kit
FLAG = "/var/lib/tool/drift"
REPORT = "reports/Gate1 mutation report.md"
STEP_UP_AMOUNT = 60000    # over the kit's step_up_over_minor

with open(os.path.join(check.ROOT, "config/kit/lockfile/pins.json")) as pins_file:
    PINS = json.load(pins_file)
TOOLS = {server: sorted(entry["tools"]) for server, entry in PINS["servers"].items()}
with open(os.path.join(check.ROOT, "config/kit/pep/config.json")) as config_file:
    _ids = json.load(config_file)["intents"]["pay"]["entities"]["ids"]
STEP_UP = iter(i for i in _ids if i.startswith("INV-V"))

# What the agent calls to see whether a server serves.
PROBE = {"a": ("get_invoice", lambda invoice: {"invoice_id": invoice}),
         "b": ("get_note", lambda invoice: {"key": "probe"})}


# --- the stack ---

def set_flag(server, change):
    run(["docker", "exec", check.container(f"tool-{server}"), "sh", "-c", f"printf %s {change} > {FLAG}"])


def clear_flag(server):
    run(["docker", "exec", check.container(f"tool-{server}"), "rm", "-f", FLAG])


def fresh_pep():
    """A PEP on an empty journal, so no quarantine carries over and both servers serve. It is
    killed, not stopped: as PID 1 it ignores SIGTERM, and a stop would wait out its timeout."""
    for server in PROBE:
        clear_flag(server)
    run(["docker", "kill", check.container("pep")], check=False)
    dc("rm", "-f", "pep")
    forget_pep()
    run(["docker", "volume", "rm", f"{check.PROJECT}_pep-state"])
    dc("up", "-d", "--wait", "--wait-timeout", "120", "--no-deps", "pep")
    forget_pep()


def tool_lines(server):
    return lines("oracle", f"/logs/tool-{server}/tool.jsonl")


def quarantines():
    return [record.get("server_id") for record in lines("pep", "/var/lib/pep/journal.jsonl")
            if record.get("type") == "quarantine"]


def decisions():
    return fetch("oracle", kit.DECISIONS)


def parse_time(stamp):
    """A docker log timestamp (RFC 3339, nanoseconds, Z) as Unix seconds."""
    head, _, rest = stamp.rstrip("Z").partition(".")
    fraction = (rest + "000000")[:6]
    moment = datetime.datetime.fromisoformat(f"{head}.{fraction}+00:00")
    return moment.timestamp()


def state_changes(server, since):
    """The PEP's log lines about `server` since Unix time `since`: (time, what) each."""
    out = run(["docker", "logs", "-t", "--since", f"{since:.3f}", check.container("pep")], check=False)
    found = []
    for line in (out.stdout + out.stderr).splitlines():
        stamp, _, text = line.partition(" ")
        marker = f"pep-sidecar: server {server}: "
        if marker in text:
            found.append((parse_time(stamp), text.split(marker, 1)[1]))
    return found


def first_change(server, since, within_s):
    deadline = time.time() + within_s
    while time.time() < deadline:
        changes = state_changes(server, since)
        if changes:
            return changes[0]
        time.sleep(0.2)
    return None


def polls(server, since):
    """The PEP's polls of `server` the broker logged since Unix time `since`: one discover each,
    however many `tools/list` pages follow it."""
    return [line for line in lines("oracle", kit.BROKER_LOG)
            if line.get("method") == "server/discover" and line.get("server_id") == server
            and line.get("ts_ms", 0) >= since * 1000]


def after_a_poll(server, timeout_s=POLL_MAX_S + 4):
    """Waits for the next poll of `server` to end, so the one after is at least 4 s away."""
    start = time.time()
    while time.time() - start < timeout_s:
        if polls(server, start):
            time.sleep(0.5)   # every page of it
            return True
        time.sleep(0.1)
    return False


def listed(agent):
    return sorted(tool.get("name") for tool in pointer(agent.list_tools(), "/result/tools") or [])


def probe(agent, server, invoice):
    tool, arguments = PROBE[server]
    return agent.call(tool, arguments(invoice))


def other(server):
    return "b" if server == "a" else "a"


def logged_reasons(text):
    return sorted(set(re.findall(r'"reason":"([^"]{1,60})"', text)))


def fresh_probe(server, invoice):
    """A call to `server` from a new episode of another intent: after a long wait the case's own
    episode may have gone idle (12 s in config/kit), and its refusals would then say nothing
    about the server. The reply, and the reasons logged since it was sent."""
    agent = Agent("pay2")
    try:
        decided_at = len(decisions().encode())
        reply = probe(agent, server, invoice)
        return reply, decisions().encode()[decided_at:].decode(errors="replace")
    finally:
        agent.close()


# --- what every quarantine must show ---

def quarantined(server, agent, invoice, since, refused_reason="ToolQuarantined"):
    """The checks every quarantine passes: (problems, seconds to detection)."""
    problems = []
    change = first_change(server, since, T_S + 3)
    if not change:
        return [f"the PEP logged no state change for {server}"], None
    at, what = change
    seconds = at - since
    if seconds > T_S:
        problems.append(f"found after {seconds:.1f} s, past T")
    if what != "Differs, Quarantined":
        problems.append(f"the PEP logged {what!r}")
    decided_at = len(decisions().encode())
    reply = probe(agent, server, next(kit.PLAIN))
    if not denied(reply):
        problems.append(f"a call after detection got {reply}")
    executed = len(tool_lines(server))
    if refused_reason not in decisions().encode()[decided_at:].decode(errors="replace"):
        problems.append(f"no {refused_reason} in the decision log")
    shown = listed(agent)
    if shown != TOOLS[other(server)]:
        problems.append(f"tools/list shows {shown}")
    for _ in range(3):
        probe(agent, server, invoice)
    time.sleep(1)
    if len(tool_lines(server)) != executed:
        problems.append("the server executed a call after detection")
    if quarantines() != [server]:
        problems.append(f"the journal's quarantines are {quarantines()}")
    return problems, seconds


def survives_restart(server):
    """A restart on the same lockfile keeps the quarantine (RV4 #5)."""
    since = time.time()
    kit.restart_pep()
    forget_pep()
    agent = Agent("pay")
    try:
        problems = []
        if not denied(probe(agent, server, next(kit.PLAIN))):
            problems.append("served again after a restart")
        if listed(agent) != TOOLS[other(server)]:
            problems.append("listed again after a restart")
        logged = [what for _, what in state_changes(server, since)]
        if "quarantined (journal)" not in logged:
            problems.append(f"the restart logged {logged}")
        if quarantines() != [server]:
            problems.append(f"the journal's quarantines are {quarantines()} after the restart")
        return problems
    finally:
        agent.close()


# --- the cases ---

CASES = []
rows = []


def case(label, number, server, change=None):
    def register(function):
        CASES.append(dict(name=f"#{number} {label}" if number else label, server=server,
                          change=change, function=function))
        return function
    return register


def rug_pull(server, change, extra=None):
    """The common case: the server drifts, the poller quarantines it within T."""
    def attempt(agent, invoice):
        if "result" not in probe(agent, server, invoice):
            return ["the server did not serve before the change"], None
        since = time.time()
        set_flag(server, change)
        problems, seconds = quarantined(server, agent, invoice, since)
        if extra:
            problems += extra(agent)
        clear_flag(server)
        if not problems:
            problems += survives_restart(server)
        return problems, seconds
    return attempt


def unpinned_tool_refused(agent):
    """#9: the added tool is never served: unpinned, it is refused by G_pin."""
    decided_at = len(decisions().encode())
    reply = agent.call("export_all", {})
    if not denied(reply) or "ToolNotPinned" not in decisions().encode()[decided_at:].decode(errors="replace"):
        return [f"the added tool got {reply}"]
    return []


MUTATIONS = [
    (1, "description reworded", "a", "description"),
    (2, "hidden instruction appended to the description", "b", "hidden_instruction"),
    (3, "instruction inside an <IMPORTANT> tag", "a", "important_tag"),
    (4, "instruction in a parameter description", "b", "parameter_description"),
    (5, "new inputSchema property", "a", "new_property"),
    (6, "property type changed", "b", "property_type"),
    (7, "required changed", "a", "required"),
    (8, "outputSchema added", "b", "output_schema"),
    (9, "tool added", "a", "tool_added"),
    (10, "tool removed", "b", "tool_removed"),
    (11, "tool renamed", "a", "tool_renamed"),
    (12, "a name another server pins (pay_invoice) added", "b", "name_collision"),
    (13, "readOnlyHint true to false", "a", "read_only_hint"),
    (14, "destructiveHint false to true", "a", "destructive_hint"),
    (15, "idempotentHint and openWorldHint flipped", "a", "idempotent_hint"),
    (16, "Cyrillic homoglyph in the name", "b", "homoglyph"),
    (17, "zero-width joiner in the description", "a", "zero_width_joiner"),
    (18, "bidi override in the description", "b", "bidi_override"),
    (19, "x-mcp-header annotation added", "a", "x_mcp_header"),
    (20, "definition changed between two polls, no notification", "b", "list_changed"),
    (21, "title and icon on a security-role tool (get_invoice)", "a", "title_icon"),
    (22, "default value injected into the schema", "b", "default_value"),
    (23, "an integer past 2^53 changed by one", "a", "big_integer"),
    (24, "a definition changed on a later page only", "b", "last_page"),
    (25, "cross-server shadowing of pay_invoice", "b", "shadowing"),
]
for number, label, server, change in MUTATIONS:
    extra = unpinned_tool_refused if change == "tool_added" else None
    case(label, number, server, change)(rug_pull(server, change, extra))
case("discover result changed", None, "a", "discover")(rug_pull("a", "discover"))


def suspended_by(server, change):
    def attempt(agent, invoice):
        if "result" not in probe(agent, server, invoice):
            return ["the server did not serve before the change"], None
        since = time.time()
        set_flag(server, change)
        found = first_change(server, since, T_S + 3)
        problems, seconds = [], None
        if not found:
            return ["the PEP logged no state change"], None
        at, what = found
        seconds = at - since
        if seconds > T_S:
            problems.append(f"suspended after {seconds:.1f} s, past T")
        if what != "Failed, Suspended":
            problems.append(f"the PEP logged {what!r}")
        decided_at = len(decisions().encode())
        if not denied(probe(agent, server, invoice)):
            problems.append("a call to the suspended server was served")
        if "ToolQuarantined" not in decisions().encode()[decided_at:].decode(errors="replace"):
            problems.append("no ToolQuarantined in the decision log")
        if listed(agent) != TOOLS[other(server)]:
            problems.append("tools/list still shows the suspended server")
        if quarantines():
            problems.append(f"a failed poll was journaled as a quarantine: {quarantines()}")
        # The next matching poll lifts it.
        ended = time.time()
        clear_flag(server)
        back = None
        while time.time() - ended < T_S + 2:
            changes = [what for _, what in state_changes(server, ended)]
            if "Matches, Serving" in changes:
                back = time.time() - ended
                break
            time.sleep(0.2)
        if back is None or back > T_S + 1:
            problems.append("not serving again within T of the failure ending")
        else:
            reply, reasons = fresh_probe(server, invoice)
            if "result" not in reply:
                problems.append(f"serving, but a call was refused: {logged_reasons(reasons)}")
        return problems, seconds
    return attempt


case("tools/list answers errors after the change", 26, "a", "list_fails")(suspended_by("a", "list_fails"))
case("tools/list times out after the change", 26, "b", "list_times_out")(suspended_by("b", "list_times_out"))


@case("revert after detection", 27, "a", "description")
def revert_after(agent, invoice):
    since = time.time()
    set_flag("a", "description")
    problems, seconds = quarantined("a", agent, invoice, since)
    clear_flag("a")
    time.sleep(T_S + 1)
    reply, reasons = fresh_probe("a", invoice)
    if not denied(reply) or "ToolQuarantined" not in reasons:
        problems.append(f"a revert after detection lifted the quarantine: {logged_reasons(reasons)}")
    if quarantines() != ["a"]:
        problems.append(f"the journal's quarantines are {quarantines()}")
    return problems, seconds


@case("revert before any poll saw it", 27, "b", "description")
def revert_before(agent, invoice):
    if not after_a_poll("b"):
        return ["no poll of b was seen"], None
    set_flag("b", "description")
    time.sleep(0.5)
    clear_flag("b")
    since = time.time()
    time.sleep(T_S + 1)
    problems = []
    reply, reasons = fresh_probe("b", invoice)
    if "result" not in reply:
        problems.append(f"a change no poll saw was treated as drift: {logged_reasons(reasons)}")
    if state_changes("b", since) or quarantines():
        problems.append(f"the PEP changed b's state: {state_changes('b', since)}, {quarantines()}")
    return problems, None


def settle(agent, invoice, amount):
    return agent.call("settle_invoice", {"invoice_id": invoice, "amount": amount, "currency": "USD"})


@case("a payment to b witnessed by a's lookup, after a drifts", 28, "a", "description")
def witness_after(agent, invoice):
    control = next(kit.PLAIN)
    agent.lookup(control)
    if pointer(settle(agent, control, 1000), "/result/structuredContent/status") != "executed":
        return ["the fixture cannot settle an invoice at all"], None
    agent.lookup(invoice)
    since = time.time()
    set_flag("a", "description")
    problems, seconds = quarantined("a", agent, next(kit.PLAIN), since)
    settled_before = sum(1 for line in tool_lines("b") if line.get("tool") == "settle_invoice")
    decided_at = len(decisions().encode())
    reply = settle(agent, invoice, 1000)
    if not denied(reply):
        problems.append(f"the payment got {reply}")
    if "WitnessQuarantined" not in decisions().encode()[decided_at:].decode(errors="replace"):
        problems.append("no WitnessQuarantined in the decision log")
    if sum(1 for line in tool_lines("b") if line.get("tool") == "settle_invoice") != settled_before:
        problems.append("b settled it")
    clear_flag("a")
    return problems, seconds


def drift_during_step_up(pay, paid_server, drifting, reason):
    """A payment waits for step-up; `drifting` drifts and is found; then the operator approves.
    The re-check before forwarding must refuse it (P1, RV3 A4, RV4 #2)."""
    def attempt(agent, _invoice):
        invoice = next(STEP_UP)
        agent.lookup(invoice)
        if not after_a_poll(drifting):
            return [f"no poll of {drifting} was seen"], None
        paid_before = len(tool_lines(paid_server))
        thread, box = in_background(pay, agent, invoice)
        pending = None
        until = time.time() + 3
        while time.time() < until and not pending:
            pending = pointer(operator({"call": "pending"}), "/result/approvals/0")
        if not pending:
            thread.join()
            return [f"nothing awaited approval: {box.get('reply')}"], None
        since = time.time()
        set_flag(drifting, "description")
        found = first_change(drifting, since, STEP_UP_S - 1)
        problems, seconds = [], None
        if not found:
            problems.append("not found before the step-up would time out")
        else:
            seconds = found[0] - since
        decided_at = len(decisions().encode())
        approval = operator({"call": "approve", "eid": pending["eid"], "rid": pending["rid"],
                             "action_digest": pending["action_digest"], "amount_minor": STEP_UP_AMOUNT})
        thread.join()
        if "result" in approval:
            problems.append(f"the approval was taken: {approval}")
        if not denied(box.get("reply")):
            problems.append(f"the payment got {box.get('reply')}")
        if reason not in decisions().encode()[decided_at:].decode(errors="replace"):
            problems.append(f"no {reason} in the decision log")
        if len(tool_lines(paid_server)) != paid_before:
            problems.append(f"{paid_server} executed it")
        clear_flag(drifting)
        return problems, seconds
    return attempt


case("a payment to b witnessed by a's lookup, while it waits for step-up", 28, "a", "description")(
    drift_during_step_up(lambda agent, invoice: settle(agent, invoice, STEP_UP_AMOUNT), "b", "a", "WitnessQuarantined"))
case("step-up timing: the paid server drifts during the wait (RV3 A4)", None, "a", "description")(
    drift_during_step_up(lambda agent, invoice: agent.pay(invoice, STEP_UP_AMOUNT), "a", "a", "ToolQuarantined"))


def negative(server):
    def attempt(agent, invoice):
        since = time.time()
        set_flag(server, "respelled")
        deadline = time.time() + 2 * POLL_MAX_S + 4
        while len(polls(server, since)) < 2 and time.time() < deadline:
            time.sleep(0.5)
        time.sleep(1)
        problems = []
        if len(polls(server, since)) < 2:
            problems.append("two polls never came")
        reply, reasons = fresh_probe(server, invoice)
        if "result" not in reply:
            problems.append(f"respelled definitions were treated as drift: {logged_reasons(reasons)}")
        if state_changes(server, since) or quarantines():
            problems.append(f"the PEP changed the state: {state_changes(server, since)}")
        clear_flag(server)
        return problems, None
    return attempt


case("negative: keys reordered, whitespace, \\u escapes, 0.50 for 0.5, one tool a page", None, "a", "respelled")(negative("a"))
case("negative: the same respelling on b, whose list is paged differently", None, "b", "respelled")(negative("b"))


# --- running them ---

def run_case(entry):
    fresh_pep()
    agent = Agent("pay")
    problems, seconds = [], None
    try:
        problems, seconds = entry["function"](agent, next(kit.PLAIN))
    except SystemExit as error:
        problems = [f"stopped: {error}"]
    finally:
        agent.close()
    held = expect(entry["name"] + (f" ({seconds:.1f} s)" if seconds is not None else ""), not problems,
                  "; ".join(problems))
    rows.append(dict(name=entry["name"], server=entry["server"], change=entry["change"],
                     seconds=seconds, held=held, detail="; ".join(problems)))
    return held


def write_report(started):
    timed = [row["seconds"] for row in rows if row["seconds"] is not None]
    held = sum(row["held"] for row in rows)
    numbered = {row["name"].split()[0] for row in rows if row["name"].startswith("#") and row["held"]}
    lines_out = [
        "# Gate 1 mutation report (G2)", "",
        f"Generated by `compose/mutations.py` on {started:%Y-%m-%d}. T = {T_S} s (L1).", "",
        f"**{held} of {len(rows)} cases held; {len(numbered)} of the 28 numbered mutations of §3 were found within T.**"
        + (f" Detection took {min(timed):.1f} to {max(timed):.1f} s after the change, by the PEP's own log." if timed else ""),
        "",
        "Each case starts from a PEP on an empty journal with both servers serving, and the drift poller, not a restart, "
        "finds the change. A quarantine holds only if the server's state changed within T, its calls were refused with "
        "`ToolQuarantined` (`WitnessQuarantined` for #28's witness), `tools/list` hid every tool of that server and no "
        "other, the server executed nothing after the refusal, the journal held one quarantine for it, and a restart on "
        "the same lockfile kept it. #26 suspends instead, and must serve again within T of the failure ending.", "",
        "| Case | Server | Change | Detected after (s) | Held | Detail |", "|---|---|---|---:|---|---|"]
    for row in rows:
        seconds = f"{row['seconds']:.1f}" if row["seconds"] is not None else "—"
        lines_out.append(f"| {row['name']} | {row['server']} | `{row['change']}` | {seconds} | "
                         f"{'yes' if row['held'] else 'NO'} | {row['detail'].replace('|', '/') or '—'} |")
    with open(os.path.join(check.ROOT, REPORT), "w", newline="\n") as f:
        f.write("\n".join(lines_out) + "\n")
    print("wrote", REPORT, flush=True)


def main():
    arguments = sys.argv[1:]
    keep = "--keep" in arguments
    only = [arguments[index + 1] for index, argument in enumerate(arguments) if argument == "--only"]
    if not os.environ.get("PEP_SECRETS_DIR"):
        raise SystemExit("set PEP_SECRETS_DIR (WEEK2_PLAN §4)")
    started = datetime.datetime.now()
    dc(*kit.PROFILES, "build")
    kit.remove_parked()
    dc(*kit.PROFILES, "down", "-v", "--remove-orphans")
    try:
        dc("up", "-d", "--wait", "--wait-timeout", "120")
        time.sleep(1.1)   # the broker refuses proofs from its boot second (R1)
        for entry in CASES:
            if only and not any(text in entry["name"] for text in only):
                continue
            run_case(entry)
    finally:
        if not keep:
            kit.remove_parked()
            dc(*kit.PROFILES, "down", "-v", "--remove-orphans", check=False)
    if not only:
        write_report(started)
    failures = len(check.failures)
    print(f"MUTATIONS: {sum(row['held'] for row in rows)} of {len(rows)} cases held; "
          f"{'all held' if not failures else f'{failures} FAILED'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
