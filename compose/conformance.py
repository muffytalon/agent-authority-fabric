"""The official MCP conformance suite against the PEP (WEEK2_PLAN step 9, RV3 D5, Appendix B).

Usage, from the root of the WSL-side clone:
    PEP_SECRETS_DIR=~/.config/pep-gate1/secrets python3 compose/conformance.py [--keep]

It runs the release images as its own project, `pep-conf`, with a real episode behind a test-only
bridge (compose/conformance/bridge.py), because the suite speaks HTTP to a URL and knows nothing
of Episode Tokens. The suite comes pinned, from compose/conformance/package-lock.json.

It runs the server scenarios 2026-07-28 requires. Most of them need fixtures that a policy gateway
has no reason to serve: tools called `test_simple_text`, prompts, resources, and a server that
asks the client for input. compose/conformance/expected-failures.txt lists those check by check,
with the reason for each group, because listing a scenario would hide the checks in it that do
pass. A listed check that starts passing fails the run, as does an unlisted one that fails, so the
list cannot go stale. Exits 0 only if neither happens. Tokens never reach the output.
"""
import collections, json, os, re, subprocess, sys, tempfile, time

import check
import kit
from check import dc, expect, run

check.PROJECT = "pep-conf"
check.COMPOSE_FILES = ["compose.yaml"]
PROFILES = ("--profile", "run")
HERE = os.path.join(check.ROOT, "compose", "conformance")
PYTHON_IMAGE = "python:3.13-slim-bookworm@sha256:a5a7017efc5969e00ae2b91c8eb0631049a569652aa4ffc4501769049ae45c72"
PORT = 18765
URL = f"http://127.0.0.1:{PORT}/mcp"
NOT_PASSING = ("FAILURE", "WARNING")


def expected_failures():
    """Each (scenario, check id) that the suite should not pass."""
    with open(f"{HERE}/expected-failures.txt") as f:
        return {tuple(line.split()) for line in f if line.strip() and not line.startswith("#")}


def actual_failures(results):
    """Each (scenario, check id) that did not pass, and how many checks had each status."""
    found, statuses = set(), collections.Counter()
    for entry in os.listdir(results):
        scenario = re.fullmatch(r"server-(.+)-\d{4}-\d{2}-\d{2}T.*", entry)
        with open(f"{results}/{entry}/checks.json") as f:
            checks = json.load(f)
        statuses.update(item["status"] for item in checks)
        found |= {(scenario[1], item["id"]) for item in checks if item["status"] in NOT_PASSING}
    return found, statuses


def start_bridge(token):
    # Pulled apart, because its first line of output is how the bridge says it is serving.
    run(["docker", "pull", "-q", PYTHON_IMAGE], timeout=300)
    process = subprocess.Popen(
        ["docker", "run", "--rm", "-i", "--name", f"{check.PROJECT}-agent-bridge", "--read-only", "--cap-drop", "ALL",
         "--security-opt", "no-new-privileges:true", "--user", "20001:20001", "-p", f"127.0.0.1:{PORT}:8080",
         "-v", f"{kit.network('pep-sock')}:/run/pep", "-v", f"{HERE}/bridge.py:/bridge.py:ro",
         PYTHON_IMAGE, "python3", "-I", "/bridge.py"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    process.stdin.write(token + "\n")
    process.stdin.flush()
    line = process.stdout.readline()
    if "serving" not in line:
        raise SystemExit(f"the bridge did not start: {line.strip()}")
    return process


def main():
    keep = "--keep" in sys.argv[1:]
    if not os.environ.get("PEP_SECRETS_DIR"):
        raise SystemExit("set PEP_SECRETS_DIR (WEEK2_PLAN §4)")
    dc(*PROFILES, "build")
    kit.remove_parked()
    dc(*PROFILES, "down", "-v", "--remove-orphans")
    bridge = None
    with tempfile.TemporaryDirectory(prefix="pep-conformance-") as work:
        run(["cp", f"{HERE}/package.json", f"{HERE}/package-lock.json", work])
        out = subprocess.run(["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"], cwd=work,
                             capture_output=True, text=True, timeout=300, check=False)
        if out.returncode != 0:
            raise SystemExit(f"npm ci failed: {out.stderr[-400:]}")
        try:
            # The probe image holds the operator; a pep-only build would leave it out.
            run(["docker", "build", "-q", "--target", "probe", "-t", kit.PROBE_IMAGE, "."], timeout=600)
            dc("up", "-d", "--wait", "--wait-timeout", "120")
            time.sleep(1.1)   # the broker refuses proofs from its boot second (R1)
            reply = kit.operator({"call": "start_episode", "intent": "notes"})
            token = check.pointer(reply, "/result/episode_token")
            if not expect("conformance: an episode for the suite", bool(token), reply):
                return 1
            bridge = start_bridge(token)
            expected = expected_failures()
            results = os.environ.get("PEP_CONFORMANCE_OUT", f"{work}/results")
            with open(f"{work}/baseline.yml", "w") as f:
                f.write("server:\n" + "".join(f"  - {name}\n" for name in sorted({scenario for scenario, _ in expected})))
            suite = subprocess.run(
                ["npx", "--no-install", "conformance", "server", "--url", URL, "--requirements", "2026-07-28",
                 "--expected-failures", f"{work}/baseline.yml", "--output-dir", results],
                cwd=work, capture_output=True, text=True, timeout=600, check=False)
            print(check.redact(suite.stdout)[-1500:], flush=True)
            print(check.redact(suite.stderr)[-1500:], flush=True)
            actual, statuses = actual_failures(results)
            expect("conformance: every scenario failed or passed as listed", suite.returncode == 0, f"exit {suite.returncode}")
            expect("conformance: nothing new fails", not actual - expected, sorted(actual - expected))
            expect("conformance: nothing listed passes", not expected - actual, sorted(expected - actual))
            print(f"conformance: of {sum(statuses.values())} checks, {dict(sorted(statuses.items()))}", flush=True)
        finally:
            if bridge:
                bridge.kill()
            kit.remove_parked()
            if not keep:
                dc(*PROFILES, "down", "-v", "--remove-orphans", check=False)
    return 1 if check.failures else 0


if __name__ == "__main__":
    sys.exit(main())
