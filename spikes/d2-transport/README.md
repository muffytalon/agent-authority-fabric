# D2 transport spike

Evidence for decision D2 in `WEEK2_PLAN.md` (agent-facing transport), closed on 2026-11-03 with option (a): MCP 2026-07-28 Streamable HTTP over the Unix socket. This is throwaway test code. Nothing here is built, linted or shipped with `pep-sidecar`.

## What it proves
- **Both MCP SDK v2 lines reach an HTTP server on a Unix socket, with custom headers:**
  - TypeScript: `@modelcontextprotocol/client` with undici's `fetch` and `Agent({ connect: { socketPath } })`;
  - Python: `mcp` with an `httpx2.AsyncHTTPTransport(uds=…)` client, passed as `http_client`.
- **Each runs the 2026-07-28 sequence** (`server/discover`, `tools/list`, `tools/call`, `subscriptions/listen`), with no `initialize`, and sends every header and `_meta` field M1 checks. Request ids may be strings.
- **Each lets the caller attach the Episode Token** (added after RV3's finding E1):
  - a client-wide `Pep-Episode` header reaches every request, the SDK's own `server/discover` probe and `subscriptions/listen` included;
  - `_meta["dev.pep-sidecar/episode"]` can be set on `tools/list` and `tools/call`, and survives next to the SDK's own `_meta` keys;
  - neither SDK takes caller `_meta` on `subscriptions/listen`, so the header is the only carrier there.
- **The SDKs' own `tools/list` needs the token in a header** (added after RV4 #11, from the token-enforcing runs):
  - the Python SDK lists a tool it has not listed in this session right after calling it, and both SDKs re-list after a -32020, each with no caller `_meta`;
  - with the token only in `_meta`, Python reports `PEP_DENIED` for a call that has already executed, and its -32020 retry fails; TypeScript reports the denied re-list through `onerror` and resends anyway;
  - with the token also sent client-wide as `Pep-Episode`, which M1 now accepts alone on `tools/list`, every call succeeds in both SDKs.
- **How each SDK takes M1's `subscriptions/listen` reply:** acknowledgement then completion closes gracefully; a `notifications/cancelled` before the completion reads as an unexpected close.
- **How the TypeScript SDK reacts** to a 202 or a 400 for its own `notifications/cancelled`, and to a client-side timeout.
- **The conditions D2 puts on agents:**
  - TypeScript needs `versionNegotiation: { mode: { pin: '2026-07-28' } }`, and `fetch` and `Agent` from the same `undici` package;
  - Python needs `trust_env=False`, because httpx2 ignores `uds` whenever a proxy applies.

## What it does not prove
- **`pep_standin.py` is a stand-in, not the PEP.**
  - It answers as M1's router specifies, and logs M1's header and `_meta` checks without enforcing them, except in its `enforce` variant, which applies M1's token rule to a fixed test token.
  - It verifies no signatures, and has no engine, lockfile or peer checks.
  - It is built on Python's `http.server`, so it says nothing about the hand-rolled parser in `src/http.rs`.
- **Nothing ran in Compose.** Client and stand-in ran under the same uid, with the socket in a work directory, not `/run/pep`.
- **Only these SDK versions were run.** A later release may change a default, such as the TypeScript SDK's `versionNegotiation`.
- **Step 7's tests rebuild these checks against the real PEP** (M1's router rows and client notification rows).

## Versions
| Item | Version |
|---|---|
| Date | 2026-11-03 |
| Kernel | 6.18.54.1-microsoft-standard-WSL2 |
| Node | 24.22.2 (bundles undici 7.30.1) |
| npm | 11.19.1 |
| Python | 3.14.4 |
| `mcp` | 2.3.0 |
| `httpx2` | 2.16.0 (with `httpcore2` 2.16.0, `anyio` 4.16.0) |
| `@modelcontextprotocol/client` | 2.4.0 (with `@modelcontextprotocol/core` 2.4.0) |
| `undici` | 8.12.3 |

`package.json` pins the two npm packages exactly, and `package-lock.json` pins the rest. `requirements.txt` is the full `pip freeze`.

## How to run
```bash
bash spikes/d2-transport/run.sh
```
- **What it does:**
  - copies the spike into a work directory, `~/.cache/pep-d2-spike` by default (`SPIKE_WORK=…` overrides it);
  - creates a virtualenv there from `requirements.txt`, and runs `npm ci`;
  - runs the eleven scenarios below, and checks each against its recorded outcome;
  - replaces `$HOME` with `~` in client output, so tracebacks carry no username;
  - writes `results/<run>.log` (the stand-in's JSONL log) and `results/<run>.client.txt` (the client's output) in the work directory.
- **It needs** `python3` with `venv`, `node`, `npm`, and network access to PyPI and the npm registry.
- **The work directory must be outside the repo.** The repo is in OneDrive, which would sync `node_modules`; `run.sh` refuses a work directory inside it.
- **Exit status:** 0 if every run reproduces its recorded outcome, 1 otherwise. `CLIENT_TIMEOUT` (default 60 s) bounds each client.
- **One run by hand,** from the work directory:
  ```bash
  python3 -I pep_standin.py pep.sock results/x.log plain 202 &
  node ts_client.mjs pep.sock main
  kill %1; python3 -I summarize.py results/x.log
  ```
  - The socket path is relative: an absolute path in a deep directory can exceed the 108-byte `sun_path` limit.
  - `ts_client.mjs` must sit next to `node_modules`, because Node resolves its imports relative to the script.

| Run | Stand-in | Client |
|---|---|---|
| `py-plain` | `plain 202` | `py_client.py` |
| `py-cancelled` | `cancelled 202` | `py_client.py` |
| `py-token-plain-202` | `plain 202` | `py_client.py … token` |
| `ts-default-plain-202` | `plain 202` | `ts_client.mjs … default` |
| `ts-main-plain-202` | `plain 202` | `ts_client.mjs … main` |
| `ts-global-fetch-plain-202` | `plain 202` | `ts_client.mjs … global-fetch` |
| `ts-token-plain-202` | `plain 202` | `ts_client.mjs … token` |
| `ts-listchanged-plain-202` | `plain 202` | `ts_client.mjs … listchanged` |
| `ts-main-cancelled-202` | `cancelled 202` | `ts_client.mjs … main` |
| `ts-clientclose-hold-202` | `hold 202` | `ts_client.mjs … clientclose` |
| `ts-clientclose-hold-400` | `hold 400` | `ts_client.mjs … clientclose` |

## Files
| File | What it is |
|---|---|
| `pep_standin.py` | Standard-library stand-in for the PEP's agent endpoint. `pep_standin.py SOCKET LOGFILE [plain\|cancelled\|hold] [202\|400]`: the `subscriptions/listen` variant, and the status for notification POSTs. Its tool `slow` answers after 3 s. It also flags a `Pep-Episode` header that differs from `_meta` |
| `py_client.py` | MCP Python SDK v2 client over `httpx2.AsyncHTTPTransport(uds=…)`. `py_client.py SOCKET [token]` |
| `ts_client.mjs` | MCP TypeScript SDK v2 client over undici. `node ts_client.mjs SOCKET SCENARIO`, with scenarios `default`, `main`, `global-fetch`, `token`, `listchanged` and `clientclose` |
| `summarize.py` | Prints a stand-in log as a readable sequence, marking which carrier (`header`, `meta`) brought an Episode Token |
| `run.sh` | Reproduces every run (above) |
| `package.json`, `package-lock.json`, `requirements.txt` | The pinned SDKs |
| `results/` | The output of `run.sh` on 2026-11-03 (Provenance) |

The stand-in's docstring still says U1 answers notifications with 400; the plan changed that after the first runs (M1: `notifications/cancelled` gets 202).

## Results
Copied from `WEEK2_PLAN.md`, Appendix A.

**SDK runs (2026-11-03), part 1: the MCP Python SDK 2.3.0 over a Unix socket.**
- **Setup:**
  - a scratch virtualenv with `mcp` 2.3.0, `httpx2` 2.16.0, `httpcore2` 2.16.0 and `anyio` 4.16.0;
  - the client was `httpx2.AsyncClient(transport=httpx2.AsyncHTTPTransport(uds=…), trust_env=False, timeout=httpx2.Timeout(30.0, read=300.0))`, passed to `streamable_http_client(…, http_client=…)` and then `Client(…)`;
  - the server was a standard-library stand-in for the PEP's endpoint, answering as M1's router specifies. It logged every request and checked M1's header and `_meta` rules without rejecting anything.
- **Sequence:** `server/discover`, `tools/list`, `tools/call`, then `subscriptions/listen`. There was no GET, no DELETE, and no initialize handshake. The listen request's JSON-RPC id was the string `"listen-1"`, so the PEP must accept string ids.
- **Headers** on every request:
  - `Accept: application/json, text/event-stream`, `MCP-Protocol-Version: 2026-07-28` and `Mcp-Method`;
  - `Mcp-Name` on `tools/call`;
  - no `Origin`.
- **`_meta`** on every request, `server/discover` included: `protocolVersion` `2026-07-28`, `clientCapabilities: {}` and `clientInfo`. None of M1's checks fired.
- **`subscriptions/listen`:**

  | Variant | Outcome |
  |---|---|
  | Acknowledgement (empty filter), then the completion result | Accepted: `honored` was `{}`, iteration ended gracefully, and no re-listen came in the next 2 s. The SDK's own docs say "There is no replay and no automatic re-listen" |
  | Acknowledgement, then `notifications/cancelled`, then the completion result | `SubscriptionLost`: "ended without the server's graceful close; re-listen and refetch" |

- **Other results:** the SDK also accepted a discover result with no `serverInfo` field.
- **The Episode Token** (`py-token-plain-202`): with `httpx2.AsyncClient(headers={"Pep-Episode": …})` and `meta=` on `list_tools` and `call_tool`, the stand-in saw the header on all four requests and `_meta` on `tools/list` and `tools/call`. `Client.listen()` takes no `meta`.

**SDK runs, part 2: the MCP TypeScript SDK 2.4.0 over a Unix socket.**
- **Setup:**
  - Node 24.22.2, `@modelcontextprotocol/client` 2.4.0 (with `@modelcontextprotocol/core` 2.4.0) and `undici` 8.12.3;
  - the client was `StreamableHTTPClientTransport(url, { fetch })`, where `fetch` is undici's `fetch` with `dispatcher: new Agent({ connect: { socketPath } })`;
  - the server was the same stand-in, with two extra modes. One answers notification POSTs with 400. The other holds a subscription open for 5 s;
  - a tool, `slow`, answers after 3 s.

| Scenario | Outcome |
|---|---|
| Default options (no `versionNegotiation`) | The client sent a 2025 `initialize` with no `MCP-Protocol-Version` header, no `Mcp-Method` and no `_meta`. It got 404 and -32601, and `connect()` failed with `CLIENT_HTTP_NOT_IMPLEMENTED` |
| Pinned to `2026-07-28` | `server/discover` (id `"server-discover-probe-1"`), then `tools/list`, `tools/call` and `subscriptions/listen` (id `"listen:0"`), all over the socket. Every request carried `Accept: application/json, text/event-stream`, `MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name` on `tools/call`, and `_meta` with `protocolVersion`, `clientCapabilities: {}` and `clientInfo`. None of M1's checks fired |
| `subscriptions/listen`, acknowledgement then completion | `honoredFilter` was `{}`, and `closed` resolved `'graceful'`. No re-listen came in the next 2 s |
| `subscriptions/listen`, with `notifications/cancelled` before the completion | `closed` resolved `'remote'` (an unexpected disconnect). In some runs `onerror` also reported "Received a response for an unknown message ID" for the completion result: whether it does depends on timing |
| The Episode Token (`token`) | With `requestInit: { headers: { 'Pep-Episode': … } }` and `_meta` in the `listTools` and `callTool` params, the stand-in saw the header on all four requests, the `server/discover` probe included, and `_meta` on `tools/list` and `tools/call`. `listen()` takes no `_meta` |
| A `tools/call` with a 1 s timeout against `slow` | `REQUEST_TIMEOUT`. The client aborted its HTTP request and sent no `notifications/cancelled`. The next call worked |
| `listChanged` configured | No subscription was auto-opened, because the PEP advertises no list-changed capability |
| The client closes an open subscription itself | It POSTs `notifications/cancelled` `{"requestId": "listen:0"}` with `MCP-Protocol-Version` but no `Mcp-Method`. Answered with 202: clean. Answered with 400: `onerror` fires ("Error POSTing to endpoint"), but `close()` resolves, `closed` is `'local'`, and later calls work |
| Node's built-in `fetch` with the undici 8.12.3 `Agent` | Failed. The cause chain is `TypeError: fetch failed <- UND_ERR_INVALID_ARG: invalid onRequestStart method`. Node 24.22.2 bundles undici 7.30.1 |

**Token-enforcing runs (2026-11-04, RV4 #11).** The stand-in's `enforce` variant applies M1's amended token rule: `tools/call` needs the token in `_meta`; `tools/list` takes it in `_meta` or as a `Pep-Episode` header alone; a header that differs from `_meta` gets 400/-32020; a missing token gets `PEP_DENIED` (-31403). Its `stale` tool answers -32020 once. Each client makes three calls, each from a fresh client that has listed nothing: `get_invoice`, `get_invoice` again (a client recreated mid-episode), and `stale`.

| Run | Outcome |
|---|---|
| `py-enforce-meta-only` (token in `_meta` only) | Both `get_invoice` calls executed, then the SDK's own `tools/list` (from `validate_tool_result`) carried no token and was denied, so `call_tool` raised `MCPError: PEP_DENIED` for calls that had executed. The `stale` call's -32020 re-list was denied too, so it raised `Header mismatch` and never executed. This reproduces RV4 #11 |
| `py-enforce-header` (also a client-wide `Pep-Episode`) | The SDK's `tools/list` was admitted on the header alone, and all three calls succeeded, the -32020 re-list and resend included |
| `ts-enforce-meta-only` | `callTool` does not list first, so `get_invoice` succeeded. The -32020 re-list carried no token and was denied; the SDK reported it through `onerror` (`-31403 PEP_DENIED`) and resent anyway, so `stale` executed |
| `ts-enforce-header` | All three succeeded; the -32020 re-list was admitted on the header alone |

The SDK sources agree: Python's `ClientSession.validate_tool_result` calls `list_tools()` when the tool is not cached, and `Client._relist_tool` calls `list_tools(cursor=…, cache_mode="refresh")`, both without `meta`; TypeScript's `callTool` calls `listTools(void 0, …)` on -32020 whenever the connection is modern and not in a browser.

## Provenance
- **The recorded runs** (Appendix A) were made on 2026-11-03, between 07:05 and 07:14 UTC, in a session scratchpad under `/tmp`.
- **That scratchpad was deleted** when WSL restarted at 11:27 UTC, before it was copied here. The original JSONL logs, the virtualenv and `node_modules` went with it.
- **The four scripts were rebuilt** from the session's record of the commands that wrote and patched them, by replaying those exact commands. Nothing was retyped.
- **The pins were regenerated** on 2026-11-03 at 11:50 UTC, with the same top-level versions.
  - The original installs were unpinned, so most transitive versions were not recorded. The original `pip list` did record `httpcore2` 2.16.0, `anyio` 4.16.0 and `pydantic` 2.14.2, so those were pinned to match.
  - The npm tree has 14 packages, as the original install did.
- **A first `run.sh` run,** on 2026-11-03 at 11:53 UTC with these pins, reproduced every recorded outcome.
- **After RV3** (the same day), the spike gained the two `token` runs, the cause chain on `global-fetch`, the `Pep-Episode`/`_meta` check in the stand-in, and the `$HOME` scrub.
  - The "unknown message ID" error in `ts-main-cancelled-202` proved intermittent: it was missing from one run and present in the next. `run.sh` no longer requires it. The stable outcome, `closed: remote`, is still checked.
- **`results/` is the output of `run.sh`** on 2026-11-03 at 12:49 UTC. All 11 runs reproduced their outcomes.
- **One line is new since the recorded runs.** The Python `cancelled` client also logs "Error parsing SSE message" (an `anyio.BrokenResourceError`) before it raises `SubscriptionLost`. The recorded run kept only the last 15 lines of its output, so whether that line appeared then is unknown.
