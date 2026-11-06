"""G4's latency harness (WEEK2_PLAN O1): open-loop load on the release images, in Compose.

Usage, from the root of the WSL-side clone:
    PEP_SECRETS_DIR=~/.config/pep-gate1/secrets python3 compose/latency.py [--keep]

It runs as its own project, `pep-load`, with compose/load.yaml over compose.yaml, and writes
`reports/Gate1 latency report.md`. One run can mislead on a shared machine, so it makes
PEP_LOAD_RUNS runs (5), each from empty volumes, and the report shows every one. Each run:

- 10,500 calls after 500 warm-up calls, over 44 episodes, each with one live intent, at 4 calls a
  second an episode. A repeating mix of a read, its payment, a store write, a read and a list, so
  the journal's fsyncs are on the measured path. No step-up: a human's wait is not latency.
- G4 gates on the agent-side latency less the tool server's own time, because that latency
  starts when the plan said the call should go, so queueing counts. O1's residence figures, the
  PEP's and the broker's, are reported beside it.
- A head-of-line case and 1 MiB requests are measured apart.
- Three threads beside the load, touching no PEP code, watch the machine: how late a 1 ms sleep
  wakes, how long a `sync_data` of a rewritten file takes (the journal's path), and how long an
  append takes (a log line's path), so a stall can be laid against what the machine was doing.

Exits 0 only if every run's p99 is within G4's 25 ms and nothing failed. Tokens never reach the
output.
"""
import datetime, json, os, platform, sys, time

import check
import kit
from check import dc, expect, lines, run
from kit import BIN, SOCKET, call_request, raw_request

check.PROJECT = "pep-load"
check.COMPOSE_FILES = ["compose.yaml", "compose/load.yaml"]
PROFILES = ("--profile", "run", "--profile", "load")

EPISODES = 44
WARM_UP = 500
MEASURED = 10000
GAP_MS = int(os.environ.get("PEP_LOAD_GAP_MS", 250))   # 4 calls a second an episode, under the limit of 5
RUNS = int(os.environ.get("PEP_LOAD_RUNS", 5))
CONCURRENCY_CAP = 256
G4_MS = 25
REPORT = "reports/Gate1 latency report.md"
DISK = "/var/lib/load"       # on the VM's disk, as the journal is
STALL_GAP_MS = 1000          # slow calls further apart than this are two stalls
# Kept in every report, so that a clean batch cannot stand for the whole record.
EARLIER_RUNS = """Before this batch, 20 runs were made on 2026-11-06 with the journal as it is now. Fourteen met G4, including 8 of 8 in the batch just before this one. These six did not, with p99s of 21,855.71, 552.06, 138.48, 68.58, 55.76 and 42.88 ms, and the first two also had failed calls: 400 and 66.

- **What those stalls looked like.** One stretch of a run, not a general tail. In the 552 ms run calls were slow from 50.3 s to 55.5 s, every failure fell inside that stretch, and the worst call waited 1.58 s. Medians did not move.
- **The failures were the stall's, and failed closed.** Of the 66, 45 were payments denied `ProvenanceMissing`, because a payment arrived before its delayed lookup was recorded. The other 21 were reads answered `PEP_UNAVAILABLE`. The 400 were not broken down the same way: 393 denied and 7 unavailable.
- **Where the time went.** Mostly outside the PEP's and the broker's residence and outside `tool_us`, between the tool finishing that measure and the PEP having the reply. The stub tool writes its log line in that gap, on the same disk as the journal.
- **The cause is not proven.** The worst scheduling delay in the 552 ms run was 69 ms, so the CPU alone does not explain it. The disk probes came later, and no large stall has happened with them running. Of the smaller stalls in the table above, some line up with a slow `sync_data` and others with nothing, so they are not explained either. The stall table will show which probe moves if a large stall comes back."""
BIG_TEXT_BYTES = 900 * 1024
LARGEST_TEXT_BYTES = 1024 * 1024 - 4096   # the cap holds the PEP's own `_meta` too (RV5 V2)


def invoice(episode, n):
    return f"INV-L{episode:02}-{n:03}"


def plan_main(tokens):
    """Every call, in time order, with what the report needs to find its lines in the logs."""
    per_episode = (WARM_UP + MEASURED) // EPISODES + 1
    calls = []
    for episode, token in enumerate(tokens):
        for step in range(per_episode):
            cycle, position = divmod(step, 5)
            at_ms = step * GAP_MS + episode * GAP_MS // EPISODES
            bill, note = invoice(episode, cycle), f"load-{episode:02}-{cycle:03}"
            if position == 0:
                tool, key, kind, request = "get_invoice", bill, "read", call_request("get_invoice", {"invoice_id": bill}, token)
            elif position == 1:
                arguments = {"invoice_id": bill, "amount": 1000, "currency": "USD"}
                tool, key, kind, request = "pay_invoice", bill, "payment", call_request("pay_invoice", arguments, token)
            elif position == 2:
                tool, key, kind, request = "save_note", note, "write", call_request("save_note", {"key": note, "text": "load"}, token)
            elif position == 3:
                tool, key, kind, request = "get_note", note, "read", call_request("get_note", {"key": note}, token)
            else:
                tool, key, kind, request = None, None, "list", raw_request("tools/list", {}, token)
            calls.append(dict(at_ms=at_ms, request=request, tool=tool, key=key, kind=kind))
    calls.sort(key=lambda call: call["at_ms"])
    return calls


def disk_volume():
    return f"{check.PROJECT}_load-disk"


def drive(generator, calls, *disk):
    """Runs `calls` through stub-load, and returns each one's row and what its probes saw."""
    stdin = "".join(json.dumps({"at_ms": call["at_ms"], "request": call["request"]}) + "\n" for call in calls)
    out = run(["docker", "exec", "-i", generator.name, f"{BIN}/stub-load", SOCKET, str(CONCURRENCY_CAP), *disk],
              input=stdin, check=False, timeout=600)
    rows = [json.loads(line) for line in out.stdout.splitlines()]
    if len(rows) != len(calls) + 1:
        raise SystemExit(f"{len(rows)} results for {len(calls)} calls: {out.stderr.strip()[:300]}")
    return rows[:-1], rows[-1]


def percentile(values, fraction):
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(fraction * len(ordered)))]


def summary(values_us):
    """p50, p99, p99.9 and max, in milliseconds."""
    if not values_us:
        return ["—"] * 4
    return [f"{value / 1000:.2f}" for value in (percentile(values_us, 0.5), percentile(values_us, 0.99),
                                                percentile(values_us, 0.999), max(values_us))]


def row(name, values_us):
    return f"| {name} | {len(values_us)} | " + " | ".join(summary(values_us)) + " |"


def logs():
    executions = {}
    for service in ["tool-a", "tool-b"]:
        for line in lines("oracle", f"/logs/{service}/tool.jsonl"):
            executions[line["tool"], line["key"]] = line
    residence = {line["upstream_id"]: line["pep_us"] for line in lines("oracle", "/logs/pep/decisions.jsonl") if "pep_us" in line}
    broker = {line["upstream_id"]: line["broker_us"] for line in lines("oracle", "/logs/broker/broker.jsonl")
              if line.get("verdict") == "forwarded" and line.get("broker_us") is not None}
    return executions, residence, broker


def main_run(generator, tokens):
    calls = plan_main(tokens)
    print(f"note: {len(calls)} calls over {len(tokens)} episodes, about {calls[-1]['at_ms'] // 1000} s", flush=True)
    results, probes = drive(generator, calls, DISK)
    measured = list(zip(calls, results))[WARM_UP:]
    executions, residence, broker = logs()
    gate, gate_at, pep, hop, total = [], [], [], [], []
    per_kind, pep_kind, broker_kind = {}, {}, {}
    failed = {}
    for call, result in measured:
        if result["reply"] != "accepted":
            failed[result["reply"]] = failed.get(result["reply"], 0) + 1
            continue
        execution = executions.get((call["tool"], call["key"]))
        tool_us = execution["tool_us"] if execution else 0
        gate.append(result["latency_us"] - tool_us)
        gate_at.append((call["at_ms"], result["latency_us"] - tool_us))
        per_kind.setdefault(call["kind"], []).append(result["latency_us"] - tool_us)
        if execution:
            upstream_id = execution["upstream_id"]
            pep_us, broker_us = residence.get(upstream_id), broker.get(upstream_id)
            if pep_us is not None:
                pep.append(pep_us)
                pep_kind.setdefault(call["kind"], []).append(pep_us)
            if broker_us is not None:
                hop.append(broker_us)
                broker_kind.setdefault(call["kind"], []).append(broker_us)
            if pep_us is not None and broker_us is not None:
                total.append(pep_us + broker_us)
    return dict(gate=gate, pep=pep, broker=hop, residence=total, kinds=per_kind, pep_kinds=pep_kind,
                broker_kinds=broker_kind, failed=failed, gate_at=gate_at, probes=probes,
                count=len(measured), raw=[result["latency_us"] for _, result in measured])


def head_of_line(generator, tokens):
    """One episode reads results near 1 MiB while others make small calls (A1)."""
    big_token, small_tokens = tokens[0], tokens[1:]
    text = "x" * BIG_TEXT_BYTES
    calls = [dict(at_ms=0, request=call_request("save_note", {"key": "big", "text": text}, big_token))]
    calls += [dict(at_ms=500 + 500 * n, request=call_request("get_note", {"key": "big"}, big_token)) for n in range(20)]
    small = []
    for position, token in enumerate(small_tokens):
        for n in range(40):
            small.append(dict(at_ms=500 + 250 * n + position * 80, small=True,
                              request=call_request("get_note", {"key": f"small-{position}-{n}"}, token)))
    every = sorted(calls + small, key=lambda call: call["at_ms"])
    rows, _ = drive(generator, every)
    return [result["latency_us"] for call, result in zip(every, rows) if call.get("small") and result["reply"] == "accepted"]


def largest_requests(generator, token):
    """Requests near the 1 MiB cap: hashing cost grows with bytes × depth (O1)."""
    text = "y" * LARGEST_TEXT_BYTES
    calls = [dict(at_ms=1000 * n, request=call_request("save_note", {"key": f"large-{n}", "text": text}, token)) for n in range(20)]
    rows, _ = drive(generator, calls)
    return [result["latency_us"] for result in rows if result["reply"] == "accepted"]


def probe_values(result, name):
    return [us for _, us in result["probes"][name]]


def stalls(result):
    """Each moment the gate passed G4's limit, with the worst each probe saw around it."""
    slow = sorted(at for at, value in result["gate_at"] if value > G4_MS * 1000)
    windows = []
    for at in slow:
        if windows and at - windows[-1][1] <= STALL_GAP_MS:
            windows[-1][1] = at
        else:
            windows.append([at, at])
    found = []
    for start, end in windows:
        def worst(name):
            return max((us for at, us in result["probes"][name] if start - STALL_GAP_MS <= at <= end + STALL_GAP_MS), default=0)
        values = [value for at, value in result["gate_at"] if start <= at <= end and value > G4_MS * 1000]
        found.append(dict(start=start, end=end, calls=len(values), worst=max(values), late=worst("late"),
                          sync=worst("sync"), append=worst("append")))
    return found


def ms(us):
    return f"{us / 1000:.2f}"


def write_report(runs):
    ordered = sorted(runs, key=lambda each: each["p99_ms"])
    middle = ordered[len(ordered) // 2]
    result, small, large = middle["result"], middle["small"], middle["large"]
    met = sum(1 for each in runs if each["passed"])
    with open("/proc/cpuinfo") as f:
        model = next(line.split(":", 1)[1].strip() for line in f if line.startswith("model name"))
    docker = run(["docker", "version", "--format", "{{.Server.Version}}"]).stdout.strip()
    header = "| Figure | Calls | p50 | p99 | p99.9 | max |\n|---|---:|---:|---:|---:|---:|"
    kinds = "\n".join(row(kind, values) for kind, values in sorted(result["kinds"].items()))
    residence_rows = "\n".join(
        row(f"{hop}, {kind}", values)
        for hop, table in (("PEP", result["pep_kinds"]), ("Broker", result["broker_kinds"]))
        for kind, values in sorted(table.items()))
    every_run = "\n".join(
        f"| {number} | {len(each['result']['gate'])} of {each['result']['count']} | {ms(percentile(each['result']['gate'], 0.5))} "
        f"| {each['p99_ms']:.2f} | {ms(percentile(each['result']['gate'], 0.999))} | {ms(max(each['result']['gate']))} "
        f"| {'met' if each['passed'] else 'NOT met'} | {ms(max(probe_values(each['result'], 'late')))} "
        f"| {ms(max(probe_values(each['result'], 'sync')))} | {ms(max(probe_values(each['result'], 'append')))} |"
        for number, each in enumerate(runs, 1))
    stall_rows = "\n".join(
        f"| {number} | {stall['start'] / 1000:.1f} to {stall['end'] / 1000:.1f} | {stall['calls']} | {ms(stall['worst'])} "
        f"| {ms(stall['late'])} | {ms(stall['sync'])} | {ms(stall['append'])} |"
        for number, each in enumerate(runs, 1) for stall in stalls(each["result"]))
    failed = {number: each["result"]["failed"] for number, each in enumerate(runs, 1) if each["result"]["failed"]}
    text = f"""# Gate 1 latency report (G4)

Generated by `compose/latency.py` on {datetime.date.today()}. Times are in milliseconds.

**G4: met in {met} of {len(runs)} runs, against a limit of {G4_MS} ms at p99.** The median run's p99 is {middle['p99_ms']:.2f} ms; the best is {ordered[0]['p99_ms']:.2f} ms and the worst {ordered[-1]['p99_ms']:.2f} ms.{f" Calls failed in these runs: {failed}." if failed else " Every measured call succeeded."}

## Every run in this batch
The gate for each run, from empty volumes, in the order they ran. The last three columns are the worst each probe saw, from threads that run no PEP code: a 1 ms sleep's lateness, a `sync_data` of a rewritten file on the same disk as the journal, and an append with no sync.

| Run | Succeeded | p50 | p99 | p99.9 | max | G4 | Worst sleep | Worst `sync_data` | Worst append |
|---:|---|---:|---:|---:|---:|---|---:|---:|---:|
{every_run}

## Stalls
Every stretch of a run with a call over {G4_MS} ms, as seconds into the run, with the worst each probe saw within {STALL_GAP_MS / 1000:.0f} s of it.

| Run | Seconds | Calls over | Worst call | Worst sleep | Worst `sync_data` | Worst append |
|---:|---|---:|---:|---:|---:|---:|
{stall_rows or "| — | none | | | | | |"}

## Earlier runs
{EARLIER_RUNS}

## The gate, in the median run
O1's gate is the agent-side latency less the tool server's own time. It runs from the time the plan said each call should go, so a call kept waiting by an earlier one counts its wait.

{header}
{row("**Agent-side less tool time (G4)**", result["gate"])}
{kinds}

## Beside it
Residence is O1's formula: first byte in to first byte upstream, plus last byte back to last byte out. The residence figures cover calls that went upstream, so `tools/list`, which the PEP answers itself, is only in the gate above. The Unix socket between the PEP and the broker is in the agent-side figure and in neither residence.

{header}
{row("PEP plus broker residence", result["residence"])}
{row("PEP alone", result["pep"])}
{row("Broker alone", result["broker"])}
{row("Agent-side end to end, tool time included", result["raw"])}
{residence_rows}

## The machine
The median run's probes, across the whole main run.

{header.replace("Calls", "Samples")}
{row("How late a 1 ms sleep woke", probe_values(result, "late"))}
{row("`sync_data` of a rewritten file, the journal's path", probe_values(result, "sync"))}
{row("Append with no sync, a log line's path", probe_values(result, "append"))}

## Measured apart

{header}
{row("Small calls beside an episode reading 900 KiB results", small)}
{row("Requests of about 1 MiB", large)}

## The run
- **Build:** release profile, in Compose, on the images `compose.yaml` builds. Only the fixtures and the limits differ (`compose/load.yaml`).
- **Machine:** {model}, {os.cpu_count()} logical CPUs, Linux {platform.release()}, Docker {docker}. The PEP's container is limited to 2 CPUs.
- **Load:** open loop, {EPISODES} episodes, one live per intent, each sending a call every {GAP_MS} ms, with their phases spread evenly: about {EPISODES * 1000 // GAP_MS} calls a second in all, at most {CONCURRENCY_CAP} in flight. {WARM_UP} warm-up calls are left out.
- **Mix:** a repeating cycle of a read, the payment it funds, a store write, a read and `tools/list`: 40% reads, 20% payments, 20% writes, 20% lists.
- **On the measured path:** the journal's fsyncs, for each payment's `forwarded` record and each write's taint record (R1), and the ES256 sign at the PEP and verify at the broker.
- **Left out:** step-up calls, which wait for a human.
"""
    with open(os.path.join(check.ROOT, REPORT), "w", newline="\n") as f:
        f.write(text)
    print(f"wrote {REPORT}", flush=True)


def clean():
    kit.remove_parked()
    dc(*PROFILES, "down", "-v", "--remove-orphans", check=False)
    run(["docker", "volume", "rm", "-f", disk_volume()], check=False)


def one_run():
    """One run from empty volumes, or None if it could not start."""
    clean()
    generator = None
    try:
        dc("up", "-d", "--wait", "--wait-timeout", "120")
        time.sleep(1.1)   # the broker refuses proofs from its boot second (R1)
        generator = kit.Agent(mounts=("-v", f"{disk_volume()}:{DISK}"))
        tokens = []
        for episode in range(EPISODES + 4):
            reply = kit.operator({"call": "start_episode", "intent": f"load-{episode:02}"})
            tokens.append(check.pointer(reply, "/result/episode_token"))
        if not expect("load: every episode started", all(tokens)):
            return None
        result = main_run(generator, tokens[:EPISODES])
        small = head_of_line(generator, tokens[EPISODES:EPISODES + 3])
        large = largest_requests(generator, tokens[EPISODES + 3])
        p99_ms = percentile(result["gate"], 0.99) / 1000 if result["gate"] else float("inf")
        passed = p99_ms <= G4_MS and not result["failed"]
        expect(f"G4: p99 {p99_ms:.2f} ms, limit {G4_MS} ms, {len(result['failed'])} kinds of failure",
               passed, result["failed"])
        return dict(result=result, small=small, large=large, p99_ms=p99_ms, passed=passed)
    finally:
        if generator:
            run(["docker", "rm", "-f", generator.name], check=False)


def main():
    keep = "--keep" in sys.argv[1:]
    if not os.environ.get("PEP_SECRETS_DIR"):
        raise SystemExit("set PEP_SECRETS_DIR (WEEK2_PLAN §4)")
    dc(*PROFILES, "build")
    runs = []
    try:
        for number in range(RUNS):
            print(f"note: run {number + 1} of {RUNS}", flush=True)
            each = one_run()
            if each is None:
                return 1
            runs.append(each)
    finally:
        if not keep:
            clean()
    write_report(runs)
    return 1 if check.failures else 0


if __name__ == "__main__":
    sys.exit(main())
