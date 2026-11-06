"""The Gate 1 kit (WEEK2_PLAN step 9, §3). What step 9's attacks stand on, and the first of them.

Usage, from the root of the WSL-side clone:
    PEP_SECRETS_DIR=~/.config/pep-gate1/secrets python3 compose/kit.py [--keep]

It runs as its own Compose project, `pep-kit`, from empty volumes, with compose/gate1.yaml over
compose.yaml, so the broker captures proofs and the test-only `probe` and `injector` exist.

Every test declares what it expects before it runs (§2a): `deny`, nothing may reach a tool, or
`allow:N`, exactly N executions. Tests run one at a time. Each takes the oracle's mark, makes its
attempt, then waits for every leg it started to end, and the oracle judges the window. A test
holds only if its attempt failed as it should and the oracle found nothing.

The controls run first. A sandbox that blocks nothing because the probe is broken, or an oracle
that reads the wrong files, would otherwise look exactly like a clean result. Exits 0 only if
every control and every test held. Tokens never reach the output.
"""
import json, os, sys, time

import check
from check import call, dc, expect, fetch, lines, operator, pointer, run, start_episode

check.PROJECT = "pep-kit"
check.COMPOSE_FILES = ["compose.yaml", "compose/gate1.yaml"]

PROFILES = ("--profile", "run", "--profile", "gate1")
ORACLE = "/usr/local/bin/stub-oracle"
NOISE = "/logs/pep/decisions.jsonl.protocol"
LEGS_END_WITHIN_S = 10    # limits.upstream_timeout_ms: §2a's window
SIGSYS = "signal:31"
AF_UNIX, AF_INET = 1, 2
SOCK_STREAM = 1
SWEEP_ROWS = 4 * 64 * 3   # routes × families × types in net-probe.c
PLANNED_ATTACKS = 60      # §3


def oracle(*args):
    return dc("exec", "-T", "oracle", ORACLE, *args, check=False, timeout=60)


def mark():
    out = oracle("mark")
    if out.returncode != 0:
        raise SystemExit(f"the oracle cannot mark: {out.stderr.strip()}")
    return out.stdout.strip()


def judged(offsets, expected):
    """The oracle's verdict, once every leg the test started has ended (§2a's window)."""
    deadline = time.time() + LEGS_END_WITHIN_S
    while True:
        out = oracle("judge", offsets, expected)
        if out.returncode == 2:
            raise SystemExit(f"the oracle cannot read the logs: {out.stderr.strip()}")
        verdict = json.loads(out.stdout)
        if verdict["open_legs"] == 0 or time.time() >= deadline:
            return verdict
        time.sleep(0.2)


def hold(name, expected, attempt):
    """Runs one test. `attempt` returns None if it failed as it should, or what went wrong."""
    offsets = mark()
    problem = attempt()
    verdict = judged(offsets, expected)
    findings = list(verdict["findings"])
    if verdict["open_legs"]:
        findings.append(f"{verdict['open_legs']} legs never ended")
    detail = "; ".join(([f"attempt: {problem}"] if problem else []) + [f"oracle: {item}" for item in findings])
    return expect(f"{name} [{expected}]", not detail, detail)


# --- the controls: can each instrument tell? ---

def sweep(*docker_args, service=True):
    """net-probe's rows as {(route, family, type): result}."""
    if service:
        out = dc(*PROFILES, "run", "--rm", "-T", "--no-deps", "--user", "20001:20001",
                 "--entrypoint", "/usr/local/bin/net-probe", "probe", check=False, timeout=120)
    else:
        out = run(["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
                   "--security-opt", "no-new-privileges:true", *docker_args, "--user", "20001:20001",
                   "--entrypoint", "/usr/local/bin/net-probe", "pep-gate1/probe:dev"], check=False, timeout=120)
    rows = {}
    for line in out.stdout.splitlines():
        route, family, kind, result = line.split()
        rows[route, int(family), int(kind)] = result
    return rows


def control_oracle(token):
    """A real read must show up, or the oracle is reading the wrong files and every deny is empty."""
    def attempt():
        reply = call("get_invoice", {"invoice_id": "INV-1001"}, token)
        if pointer(reply, "/result/structuredContent/amount_due_minor") != 30000:
            return f"the read failed: {reply}"
    return hold("control: the oracle sees a real read and joins it", "allow:1", attempt)


def control_sweep():
    """Under Docker's default profile the sweep must create sockets, or it proves nothing."""
    rows = sweep(service=False)
    expect("control: net-probe made every attempt", len(rows) == SWEEP_ROWS, len(rows))
    made = rows.get(("native", AF_INET, SOCK_STREAM))
    expect("control: Docker's default profile lets AF_INET through natively", made == "ok", made)
    # Whether a kernel has the compat ABIs is its own business: the profile must refuse them
    # either way. Recorded, because here they are real routes (RV4 #6).
    for route in ["int80", "socketcall", "x32"]:
        result = rows.get((route, AF_INET, SOCK_STREAM))
        print(f"note control: {route} AF_INET under Docker's default profile: {result}", flush=True)
    expect("control: the sweep's judge flags Docker's default profile", judge_sweep(rows) is not None)


def control_probe(token):
    """The stolen token must be good: from the agent's own uid and gid, the same call runs."""
    def attempt():
        params = {"name": "get_invoice", "arguments": {"invoice_id": "INV-1001"}}
        out = dc(*PROFILES, "run", "--rm", "-T", "--no-deps", "--user", "20001:20001", "probe",
                 "tools/call", "get_invoice", json.dumps(params), input=token + "\n", check=False, timeout=120)
        if out.returncode != 0:
            return f"the rightful peer was refused: {out.stdout.strip() or out.stderr.strip()}"
    return hold("control: the same call from the agent's uid and gid is served", "allow:1", attempt)


# --- the attacks ---

def stolen_token_attempt(user, token, refusal):
    """A live Episode Token presented from the wrong peer (C-UID, RV3 A10)."""
    def attempt():
        before = len(fetch("oracle", NOISE))
        params = {"name": "get_invoice", "arguments": {"invoice_id": "INV-1001"}}
        out = dc(*PROFILES, "run", "--rm", "-T", "--no-deps", "--user", user, "probe",
                 "tools/call", "get_invoice", json.dumps(params), input=token + "\n", check=False, timeout=120)
        if out.stdout.strip():
            return f"the PEP answered: {out.stdout.strip()}"
        # Reaching accept() is the point of the group: a probe stopped by the socket's mode would
        # prove nothing about require_peer.
        if refusal not in fetch("oracle", NOISE)[before:]:
            return f"no refusal at the door ({refusal}): the probe never reached accept()"
    return attempt


def judge_sweep(rows):
    """What is wrong with a sweep's rows, or None for AF_UNIX-only on every route."""
    if len(rows) != SWEEP_ROWS:
        return f"{len(rows)} rows of {SWEEP_ROWS}: the probe was cut short"
    made = [key for key, result in rows.items() if result == "ok" and not (key[0] == "native" and key[1] == AF_UNIX)]
    if made:
        return f"sockets made: {made[:8]}"
    if rows["native", AF_UNIX, SOCK_STREAM] != "ok":
        return "AF_UNIX failed natively, so the sweep ran broken"
    survived = [key for key, result in rows.items() if key[0] != "native" and result != SIGSYS]
    if survived:
        return f"a compat route was not killed: {[(key, rows[key]) for key in survived[:8]]}"
    other = {result for key, result in rows.items() if key[0] == "native" and key[1] != AF_UNIX}
    if other != {"97"}:
        return f"native families other than AF_UNIX gave {sorted(other)}, not only EAFNOSUPPORT"


def attack_sockets():
    """C-NET's eighth: no socket of any family but AF_UNIX, by any route to the kernel."""
    return judge_sweep(sweep())


def replay_captured():
    """G3's first class: every captured Call Proof, verbatim, through the broker socket."""
    broker_before = len(lines("oracle", "/logs/broker/broker.jsonl"))
    out = dc(*PROFILES, "run", "--rm", "-T", "--no-deps", "injector", check=False, timeout=120)
    summary = json.loads(out.stdout.strip().splitlines()[-1]) if out.stdout.strip() else {}
    if not summary.get("attempts"):
        return f"nothing was replayed: {out.stderr.strip()}"
    if summary.get("accepted"):
        return f"{summary['accepted']} of {summary['attempts']} replays were accepted"
    fresh = lines("oracle", "/logs/broker/broker.jsonl")[broker_before:]
    reasons = {line.get("reason") for line in fresh}
    if len(fresh) != summary["attempts"] or reasons != {"call proof replayed"}:
        return f"not refused as a replay: {reasons}"
    print(f"note G3: {summary['attempts']} captured proofs replayed, none accepted", flush=True)


def main():
    keep = "--keep" in sys.argv[1:]
    if not os.environ.get("PEP_SECRETS_DIR"):
        raise SystemExit("set PEP_SECRETS_DIR (WEEK2_PLAN §4)")
    dc(*PROFILES, "build")
    dc(*PROFILES, "down", "-v", "--remove-orphans")
    attacks = 0
    try:
        dc("up", "-d", "--wait", "--wait-timeout", "120")
        time.sleep(1.1)   # the broker refuses proofs from its boot second (R1)
        token, eid, started = start_episode("pay")
        if not expect("kit: an episode to steal from", bool(token), started):
            return 1
        control_sweep()
        if not control_oracle(token) or not control_probe(token):
            print("KIT STOPPED: a control failed, so no verdict below would mean anything")
            return 1

        # C-UID: each probe passes the socket's mode by its group, holding a live token.
        for name, user, refusal in [
                ("wrong uid", "20009:20001", "peer uid 20009 is not the expected uid 20001"),
                ("root", "0:20001", "peer uid 0 is not the expected uid 20001"),
                ("overflow uid", "65534:20001", "peer uid 65534 is not the expected uid 20001"),
                ("uid right, gid wrong", "20001:20009", "peer gid 20009 is not the expected gid 20001")]:
            hold(f"C-UID {name} ({user}) with a stolen live token", "deny",
                 stolen_token_attempt(user, token, refusal))
            attacks += 1

        hold("C-NET no socket but AF_UNIX: native, int 0x80, socketcall, x32", "deny", attack_sockets)
        attacks += 1

        # What the replay needs: a read's proof and a payment's, both spent.
        paid = call("pay_invoice", {"invoice_id": "INV-1001", "amount": 30000, "currency": "USD"}, token)
        expect("kit: a payment to capture", pointer(paid, "/result/structuredContent/status") == "executed", paid)
        hold("G3 verbatim replay of every captured Call Proof", "deny", replay_captured)
        expect("operator: end_episode", "result" in operator({"call": "end_episode", "eid": eid}))
    finally:
        if not keep:
            dc(*PROFILES, "down", "-v", "--remove-orphans", check=False)
    failures = check.failures
    print(f"KIT: {attacks} of {PLANNED_ATTACKS} G1 attacks written; "
          f"{'all held' if not failures else f'{len(failures)} FAILED'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
