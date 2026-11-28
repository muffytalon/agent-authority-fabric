"""Gate 1 (WEEK2_PLAN step 11, §0): every criterion, on the release profile in Compose, and one report.

Usage, from the root of the WSL-side clone:
    PEP_SECRETS_DIR=~/.config/pep-gate1/secrets python3 compose/gate1.py [--runs N] [--skip SUITE ...]

The suites run one after another, so nothing overlaps the latency runs, each as its own Compose
project on the release images, from empty volumes, and each writes its log beside the report:

- G1 and G3: compose/kit.py, the 63 attacks of §3 judged by the oracle, and the replay classes;
- G2: compose/mutations.py, the 28 rug pulls, each found by the drift poller within T;
- G4: compose/latency.py, PEP_LOAD_RUNS runs (--runs, 10 by default) of O1's open-loop load;
- G5: `cargo deny check`, and in `cargo tree --target all`, exactly one crypto-bigint, at least
  0.7.6, and no getrandom, the tree listed fail-closed (step 3);
- G6: every decision in §1's register CLOSED;

and the checks that must pass but do not count (§3): compose/check.py, compose/checks.py both
ways, compose/conformance.py, and compose/sabotage.py, which shows that C-ENG's and C-OUT's
attacks can fail. The sabotage leg resumes an unfinished run of the same tree, and
`python3 compose/sabotage.py --status` shows its progress meanwhile. `--skip` names a suite (check, kit, checks, checks-cargo, mutations,
conformance, sabotage, latency) whose earlier log and exit status in reports/gate1-logs are read
instead, so one suite can be run again without the rest.

Writes `reports/Gate1 results.md`. Exits 0 only if every criterion is met and every check
passed. Whether G4 is met when some runs miss is the owner's call (O1): the report gives every
run, and the gate counts G4 met only if every run met it.
"""
import datetime, hashlib, os, re, subprocess, sys, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORT = "reports/Gate1 results.md"
DECISIONS = {"D1", "D2", "N1", "Q1", "S1", "M1", "M2", "P1", "R1", "E1", "H1", "T1", "L1", "O1", "B1",
             "U1", "J1", "A1"}
SUITES = ("check", "kit", "checks", "mutations", "conformance", "sabotage", "latency")


def tree():
    """The source tree as git sees it: the commit, plus a digest of any uncommitted change."""
    head = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, cwd=ROOT).stdout.strip()
    changes = subprocess.run(["git", "status", "--porcelain", "--untracked-files=all"], capture_output=True,
                             text=True, cwd=ROOT).stdout
    if not changes:
        return head or "unknown"
    diff = subprocess.run(["git", "diff", "HEAD"], capture_output=True, cwd=ROOT).stdout
    digest = hashlib.sha256(diff + changes.encode()).hexdigest()[:8]
    return f"{head}+changes {digest}"


def run(args, log, env=None, timeout=10800):
    """Runs `args` with its output in `log`, its exit status in `log`.exit and the tree it ran on
    in `log`.tree: (exit status, output, seconds)."""
    started = time.time()
    with open(f"{log}.tree", "w") as f:
        f.write(f"{tree()}, {datetime.date.today()}\n")
    with open(log, "w") as out:
        result = subprocess.run(args, stdout=out, stderr=subprocess.STDOUT, cwd=ROOT, timeout=timeout,
                                env=dict(os.environ, **(env or {})))
    with open(f"{log}.exit", "w") as f:
        f.write(f"{result.returncode}\n")
    with open(log) as f:
        text = f.read()
    return result.returncode, text, time.time() - started


def ran_on(log):
    """The tree a suite's log was made on, as `run` recorded it."""
    try:
        with open(f"{log}.tree") as f:
            return f.read().strip()
    except OSError:
        return "not recorded"


def previous(log):
    """A skipped suite's earlier run: (its exit status, its output, 0). A log with no recorded
    status counts as failed."""
    with open(log) as f:
        text = f.read()
    try:
        with open(f"{log}.exit") as f:
            status = int(f.read().strip())
    except (OSError, ValueError):
        status = 1
    return status, text, 0


ANSI = re.compile(r"\x1b\[[0-9;]*m")


def last(pattern, text, default="not found"):
    """The last match of `pattern` in `text`, without terminal colours or markdown emphasis."""
    found = re.findall(pattern, ANSI.sub("", text), re.M)
    return found[-1].replace("**", "") if found else default


def headline(report):
    """A report's bold first finding, or a note that it is missing."""
    try:
        with open(os.path.join(ROOT, report), encoding="utf-8") as f:
            return last(r"^\*\*(.+?)\*\*", f.read(), f"`{report}` not found")
    except OSError:
        return f"`{report}` not found"


def supply_chain(directory):
    """G5: cargo deny, and the crypto-bigint and getrandom facts from the whole tree."""
    status, deny, _ = run(["cargo", "deny", "check"], f"{directory}/g5-deny.log")
    tree_log = f"{directory}/g5-tree.log"
    tree_status, tree, _ = run(["cargo", "tree", "--locked", "--target", "all", "--all-features", "--prefix", "none",
                                "-e", "normal,build,dev"], tree_log)
    versions = sorted({line.split()[1] for line in tree.splitlines() if line.startswith("crypto-bigint v")})
    getrandom = [line for line in tree.splitlines() if line.startswith("getrandom v")]

    def at_least(version, floor=(0, 7, 6)):
        parts = tuple(int(part) for part in re.findall(r"\d+", version)[:3])
        return parts >= floor
    met = (status == 0 and tree_status == 0 and len(versions) == 1 and at_least(versions[0])
           and not getrandom)
    detail = (f"`cargo deny check` {'clean' if status == 0 else 'FAILED'}"
              f" ({last(r'(advisories \S+, bans \S+, licenses \S+, sources \S+)', deny, 'see g5-deny.log')}); "
              f"crypto-bigint {', '.join(versions) or 'absent'}; "
              f"getrandom {'absent' if not getrandom else 'PRESENT: ' + '; '.join(getrandom)}; "
              f"{len(tree.splitlines())} tree lines" + ("" if tree_status == 0 else ", and `cargo tree` FAILED"))
    return met, detail


def decisions():
    """G6: each of §1's 18 decisions, as its register row says."""
    with open(os.path.join(ROOT, "WEEK2_PLAN.md"), encoding="utf-8") as f:
        text = f.read()
    register = text.split("## 1. Decision register", 1)[1].split("\n### ", 1)[0]
    closed, open_ = [], []
    for line in register.splitlines():
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if cells and cells[0] in DECISIONS:
            (closed if "CLOSED" in cells[-1] else open_).append(cells[0])
    met = sorted(closed) == sorted(DECISIONS) and not open_
    return met, f"{len(closed)} of {len(DECISIONS)} CLOSED in §1's register" + (f"; open: {', '.join(open_)}" if open_ else "")


def main():
    arguments = sys.argv[1:]
    runs = arguments[arguments.index("--runs") + 1] if "--runs" in arguments else "10"
    skip = {arguments[index + 1] for index, argument in enumerate(arguments) if argument == "--skip"}
    if not os.environ.get("PEP_SECRETS_DIR"):
        raise SystemExit("set PEP_SECRETS_DIR (WEEK2_PLAN §4)")
    started = datetime.datetime.now()
    directory = os.path.join(ROOT, "reports", "gate1-logs")
    os.makedirs(directory, exist_ok=True)
    results = {}

    def suite(name, args, env=None):
        log = f"{directory}/{name}.log"
        results[name] = previous(log) if name in skip else run(args, log, env)
        print(f"{name}: exit {results[name][0]} in {results[name][2]:.0f} s", flush=True)

    suite("check", [sys.executable, "compose/check.py"])
    suite("kit", [sys.executable, "compose/kit.py"])
    suite("checks", [sys.executable, "compose/checks.py", "--check-log", f"{directory}/check.log"])
    suite("checks-cargo", [sys.executable, "compose/checks.py", "--cargo"])
    suite("mutations", [sys.executable, "compose/mutations.py"])
    suite("conformance", [sys.executable, "compose/conformance.py"])
    # An unfinished sabotage of this same tree, as a shutdown leaves one, continues (its --status).
    suite("sabotage", [sys.executable, "compose/sabotage.py", "--resume"])
    suite("latency", [sys.executable, "compose/latency.py"], env={"PEP_LOAD_RUNS": runs})
    g5_met, g5 = supply_chain(directory)
    g6_met, g6 = decisions()

    kit_status, kit_text, _ = results["kit"]
    kit_line = last(r"^KIT: .*$", kit_text)
    attacks_run = int(last(r"KIT: (\d+) of \d+ G1 attacks ran", kit_text, "0"))
    accepted = last(r"G3 attempts, (\d+) accepted", kit_text, "?")
    attempts = int(last(r"(\d+) G3 attempts", kit_text, "0"))
    mut_status, mut_text, _ = results["mutations"]
    lat_status, lat_text, _ = results["latency"]
    latency_report = ""
    try:
        with open(os.path.join(ROOT, "reports/Gate1 latency report.md")) as f:
            latency_report = f.read()
    except OSError:
        pass
    g4_line = last(r"^\*\*G4: .*?\*\*.*$", latency_report)
    rows = [
        ("G1", "Containment attacks, 0 bypasses, ≥ 50 in Compose",
         kit_status == 0 and attacks_run >= 50, f"{kit_line}. `reports/gate1-logs/kit.log`"),
        ("G2", "Rug-pull mutations quarantined within T, 0 false positives",
         mut_status == 0, f"{last(r'^MUTATIONS: .*$', mut_text)}. `reports/Gate1 mutation report.md`"),
        ("G3", "Replays and token misuse rejected, ≥ 1,000",
         kit_status == 0 and accepted == "0" and attempts >= 1000, f"{accepted} of {attempts} accepted. `reports/gate1-logs/kit.log`"),
        ("G4", "p99 added latency ≤ 25 ms (O1)",
         lat_status == 0, f"{g4_line} `reports/Gate1 latency report.md`"),
        ("G5", "Supply chain", g5_met, g5),
        ("G6", "Every decision CLOSED", g6_met, g6),
    ]
    checks = [
        ("compose/check.py (C-POSTURE's proof, the flows)", results["check"][0] == 0,
         last(r"^STEP 8 CHECKS PASSED$", results["check"][1], "FAILED")),
        ("compose/checks.py, live", results["checks"][0] == 0, last(r"^CHECKS: .*$", results["checks"][1])),
        ("compose/checks.py --cargo", results["checks-cargo"][0] == 0, last(r"^CHECKS: .*$", results["checks-cargo"][1])),
        ("compose/conformance.py", results["conformance"][0] == 0, last(r"^conformance: of .*$", results["conformance"][1])),
        ("compose/sabotage.py (C-ENG and C-OUT can fail)", results["sabotage"][0] == 0,
         f"{headline('reports/Gate1 sabotage report.md')} `reports/Gate1 sabotage report.md`"),
    ]
    gate = all(met for _, _, met, _ in rows) and all(ok for _, ok, _ in checks)
    out = ["# Gate 1 results", "",
           f"Generated by `compose/gate1.py` on {started:%Y-%m-%d}, on the release images in Compose on this machine. "
           "Each suite's log is in `reports/gate1-logs/`.", "",
           f"**Gate 1: {'met' if gate else 'NOT met'}.** " +
           ("" if gate else "Not met: " + ", ".join([name for name, _, met, _ in rows if not met] +
                                                    [name for name, ok, _ in checks if not ok]) + "."), "",
           "| # | Criterion | Met | Evidence |", "|---|---|---|---|"]
    out += [f"| {name} | {criterion} | {'yes' if met else 'NO'} | {detail.replace('|', '/')} |"
            for name, criterion, met, detail in rows]
    out += ["", "**Checks that must pass but do not count (§3):**", "", "| Check | Passed | Summary |", "|---|---|---|"]
    out += [f"| {name} | {'yes' if ok else 'NO'} | {summary.replace('|', '/')} |" for name, ok, summary in checks]
    out += ["", "G4 counts as met here only if every run met it. O1 leaves the call on a record with misses to the owner, "
            "and the latency report gives every run, its stalls, and what the machine was doing."]
    now = tree()
    names = ("check", "kit", "checks", "checks-cargo", "mutations", "conformance", "sabotage", "latency")
    out += ["", "**Which tree each suite ran on.** `--skip` reuses a finished suite's log, so a report can join runs "
            f"from more than one tree. This report was written on `{now}`.", "",
            "| Suite | Ran on | Reused here |", "|---|---|---|"]
    out += [f"| {name} | {ran_on(f'{directory}/{name}.log').replace('|', '/')} | {'yes' if name in skip else 'no'} |"
            for name in names]
    with open(os.path.join(ROOT, REPORT), "w", newline="\n") as f:
        f.write("\n".join(out) + "\n")
    print(f"wrote {REPORT}: Gate 1 {'met' if gate else 'NOT met'}", flush=True)
    return 0 if gate else 1


if __name__ == "__main__":
    sys.exit(main())
