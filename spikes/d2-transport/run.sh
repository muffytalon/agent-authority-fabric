#!/usr/bin/env bash
# Reproduces the D2 transport spike (WEEK2_PLAN.md: D2, and Appendix A "SDK runs").
#
# Copies the spike into a work directory outside the repo (default ~/.cache/pep-d2-spike,
# or $SPIKE_WORK), creates a virtualenv there from requirements.txt, runs `npm ci`, then
# runs every recorded scenario against the stand-in and checks each outcome against the
# recorded one. The repo is in OneDrive, so nothing is installed or run inside it.
#
# Per run, $WORK/results/ gets <run>.log (the stand-in's JSONL log) and <run>.client.txt
# (the client's output). Exit status: 0 if every scenario reproduces, 1 if any differs.
set -euo pipefail

HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
REPO=$(cd -- "$HERE/../.." && pwd -P)
WORK=$(realpath -m -- "${SPIKE_WORK:-$HOME/.cache/pep-d2-spike}")
CLIENT_TIMEOUT=${CLIENT_TIMEOUT:-60}

case "$WORK/" in
  "$REPO"/*) echo "run.sh: the work directory must be outside the repo ($REPO)" >&2; exit 2 ;;
esac
for tool in python3 node npm timeout realpath; do
  command -v "$tool" >/dev/null || { echo "run.sh: $tool not found" >&2; exit 2; }
done

mkdir -p -- "$WORK/results"
cd -- "$WORK"
cp -f -- "$HERE"/{pep_standin.py,py_client.py,ts_client.mjs,summarize.py,package.json,package-lock.json,requirements.txt} .
rm -f -- pep.sock results/*.log results/*.client.txt results/*.server.err

echo "== Python: fresh virtualenv in $WORK/pyenv from requirements.txt"
python3 -m venv --clear pyenv
pyenv/bin/pip install --quiet --disable-pip-version-check -r requirements.txt
echo "== Node: npm ci (ts_client.mjs must sit next to node_modules)"
npm ci --no-audit --no-fund --loglevel=error

echo "== Versions"
echo "date:     $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "kernel:   $(uname -r)"
echo "node:     $(node --version) (bundled undici $(node -p process.versions.undici)), npm $(npm --version)"
echo "python:   $(pyenv/bin/python -c 'import platform; print(platform.python_version())')"
pyenv/bin/python -I -c 'from importlib.metadata import version as v; print("packages:", ", ".join(f"{p} {v(p)}" for p in ("mcp", "httpx2", "httpcore2", "anyio")))'
node -e 'console.log("packages:", ["@modelcontextprotocol/client", "@modelcontextprotocol/core", "undici"].map((p) => p + " " + require("./node_modules/" + p + "/package.json").version).join(", "))'

FAILED=()

# run NAME VARIANT STATUS EXPECTATION... -- CLIENT-COMMAND...
#   VARIANT, STATUS: the stand-in's subscription variant and its status for notification POSTs.
#   Each EXPECTATION is checked against the client output plus the summarized server log:
#   "text" must appear, "!text" must not appear, "1*text" must appear on exactly one line.
run() {
  local name=$1 variant=$2 status=$3
  shift 3
  local -a expect=()
  while [[ $1 != -- ]]; do expect+=("$1"); shift; done
  shift
  local log=results/$name.log out=results/$name.client.txt err=results/$name.server.err

  rm -f -- pep.sock
  python3 -I pep_standin.py pep.sock "$log" "$variant" "$status" >/dev/null 2>"$err" &
  local srv=$! i
  for i in $(seq 50); do [[ -S pep.sock ]] && break; sleep 0.1; done
  if [[ ! -S pep.sock ]]; then
    echo "run.sh: the stand-in did not start for $name" >&2; cat -- "$err" >&2; kill "$srv" 2>/dev/null; exit 1
  fi

  echo
  echo "===== $name   stand-in: $variant, notifications -> $status   client: $*"
  local rc=0
  timeout "$CLIENT_TIMEOUT" "$@" >"$out" 2>&1 || rc=$?
  sleep 1                                   # let the stand-in log anything still in flight
  kill "$srv"
  wait "$srv" 2>/dev/null || true
  [[ -s $err ]] || rm -f -- "$err"

  cat -- "$out"
  echo "  (client exit status $rc)"
  echo "  --- server saw:"
  local summary
  summary=$(python3 -I summarize.py "$log")
  printf '%s\n' "$summary"

  local all e n ok=1
  all=$(cat -- "$out"; printf '%s\n' "$summary")
  for e in "${expect[@]}"; do
    case $e in
      '!'*)  if grep -qF -- "${e#!}" <<<"$all"; then echo "  UNEXPECTED: ${e#!}"; ok=0; fi ;;
      '1*'*) n=$(grep -cF -- "${e#'1*'}" <<<"$all" || true)
             if [[ $n != 1 ]]; then echo "  EXPECTED ONCE, SAW $n: ${e#'1*'}"; ok=0; fi ;;
      *)     if ! grep -qF -- "$e" <<<"$all"; then echo "  MISSING: $e"; ok=0; fi ;;
    esac
  done
  if ((ok)); then echo "  => reproduces the recorded outcome"; else echo "  => DIFFERS from the recorded outcome"; FAILED+=("$name"); fi
}

PY=(pyenv/bin/python -I py_client.py pep.sock)
TS=(node ts_client.mjs pep.sock)

# Appendix A, part 1: the MCP Python SDK.
run py-plain plain 202 \
  "server/discover id=1" "tools/call id=3" "subscriptions/listen id=listen-1" \
  "listen acknowledged, honored: {}" "listen ended gracefully; events: []" "client closed cleanly" \
  "1*subscriptions/listen" "!M1 check" \
  -- "${PY[@]}"
run py-cancelled cancelled 202 \
  "SubscriptionLost: subscription 'listen-1' ended without the server's graceful close; re-listen and refetch" "!M1 check" \
  -- "${PY[@]}"

# Appendix A, part 2: the MCP TypeScript SDK.
run ts-default-plain-202 plain 202 \
  "initialize id=0" "connect failed: CLIENT_HTTP_NOT_IMPLEMENTED" "Method not found" "!server/discover" \
  -- "${TS[@]}" default
run ts-main-plain-202 plain 202 \
  "server/discover id=server-discover-probe-1" "subscriptions/listen id=listen:0" \
  "listen acknowledged, honoredFilter: {}" "listen closed: graceful" \
  "slow call (1 s timeout): REQUEST_TIMEOUT" "call after the timeout: invoice INV-2" "client closed cleanly" \
  "1*subscriptions/listen" "!notifications/cancelled" "!client.onerror" "!M1 check" \
  -- "${TS[@]}" main
run ts-global-fetch-plain-202 plain 202 \
  "global fetch failed:" "fetch failed" "!server/discover" \
  -- "${TS[@]}" global-fetch
run ts-listchanged-plain-202 plain 202 \
  "server/discover id=server-discover-probe-1" "autoOpenedSubscription: none" "!subscriptions/listen" \
  -- "${TS[@]}" listchanged
run ts-main-cancelled-202 cancelled 202 \
  "listen closed: remote" "Received a response for an unknown message ID" "call after the timeout: invoice INV-2" "!M1 check" \
  -- "${TS[@]}" main
run ts-clientclose-hold-202 hold 202 \
  'notifications/cancelled notification params={"requestId": "listen:0"}' \
  "sub.close() resolved" "closed: local" "call after close: invoice INV-3" "client closed cleanly" "!client.onerror" \
  -- "${TS[@]}" clientclose
run ts-clientclose-hold-400 hold 400 \
  'notifications/cancelled notification params={"requestId": "listen:0"}' \
  "client.onerror: CLIENT_HTTP_NOT_IMPLEMENTED Error POSTing to endpoint" \
  "sub.close() resolved" "closed: local" "call after close: invoice INV-3" "client closed cleanly" \
  -- "${TS[@]}" clientclose

echo
if ((${#FAILED[@]})); then
  echo "DIFFERS from the recorded outcome: ${FAILED[*]}"
  exit 1
fi
echo "All 9 runs reproduce the recorded outcomes. Logs and client output: $WORK/results/"
