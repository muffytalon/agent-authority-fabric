# WEEK2_PLAN.md: pep-sidecar Week 2 (Gate 1)

Status: draft for review, 2026-11-03. D2 is CLOSED (2026-11-03). The other 17 decisions in §1 stay OPEN until each closes, just before the step it blocks; step 2 still closes the 13 others that block steps 3–7 (§1). This plan supersedes two earlier drafts:
- **AP:** the attached Week 2 plan, "pep-sidecar Week 2 Plan: Toolchain, MCP Transport and Gate 1 Readiness", in the parent folder;
- **MG:** the 29 Oct merge notes.

It folds in two reviews:
- **RV**, the 31 Oct review of MG;
- **RV2**, the review of this plan's 31 Oct draft.

Each claim was checked against:
- this repo at `bb25e27`;
- the Five-Track research report;
- the 28 Oct close-out note;
- the Week 1 verified plan;
- the primary sources listed at the end.

RV2's repo claims were re-checked on 2026-11-03, and its p256 build was reproduced on this machine. Its external claims (MCP rules, SDK timeouts, Rust regressions) were then checked against primary sources, and the FFI `bool` regression was tested on 1.97.1 directly. A third pass tested p256 with a prehash ≥ n and this kernel's pidfd behaviour, and settled the remaining web questions (Appendix A). Steps are renumbered from the 31 Oct draft. Appendix C maps the old numbers and says where every AP, MG, RV and RV2 item went.

## TL;DR
- **What Gate 1 needs:** four things that do not exist yet:
  - the sidecar binary with its transport;
  - the Compose topology;
  - `lockfile.rs`;
  - `tokens.rs`.

  The crypto crate, peer identity, the lock file and `tokens.rs` come first (§2), so the binary is never built against placeholder security checks. The binary comes next, then Compose, so every later step is tested in the real topology.
- **Open decisions:** 17 (§1). D2 is CLOSED (2026-11-03). Each of the rest closes just before the step it blocks: step 2 closes 13 of them, and N1, B1, S1 and O1 close later. The largest are:
  - **M1:** the MCP 2026-07-28 surface beyond `tools/call`;
  - **M2:** results that are not `complete`;
  - **P1:** payment outcomes under MCP's rule that a disconnect is a cancellation;
  - **R1:** restarts. Per-boot keys void old tokens, but without a journal a restart still hands out fresh budgets;
  - **E1:** who mints and ends Episode Tokens;
  - **J1:** whether canonical result bytes may change what the agent sees.
- **D1's evidence is complete, but D1 stays OPEN until step 2.** All four fixes released after 1.97.1 have been traced, and none applies to it. One was tested on 1.97.1 directly; the other three came from changes first shipped in 1.98.0 or 1.99.0 (D1).
- **The engine needs six changes** (§2a):
  - forwarded bytes are built by a new `forward` module;
  - `record_result_raw` accepts only `complete` results;
  - G_pin gains a quarantine check;
  - G_budget gains a `NeedsReconcile` check keyed on the entity;
  - an engine is built from its intent's journaled ledger (R1);
  - step 10 adds the strict argument schema and per-tool step-up.

  `jcs` gains one result number mode (J1).
- **Scope:** RV2 sized the 31 Oct draft at two to three weeks. This draft adopts its four cuts:
  - no `x-mcp-header`;
  - polling instead of upstream listen streams;
  - `prov` as witness hashes only;
  - JSON-only broker replies.

  It is still more than a week of work (Risks).

## Context
Week 2 ends at Gate 1 (SPEC §4). SPEC §4 lists `SO_PEERPIDFD`, `src/lockfile.rs`, `src/tokens.rs` and the Gate 1 containment suite. Gate 1 also presupposes three things that SPEC §4 assigns to no week:
- a running sidecar binary;
- its transport;
- the SPEC §1 containers.

This plan schedules all three, after the foundations they rely on.

Facts this plan relies on (checked 2026-10-31, re-checked 2026-11-03; evidence in Appendix A):

| Topic | Fact |
|---|---|
| Toolchain | `rust-toolchain.toml` and `Cargo.toml` pin 1.97.1, which clears crypto-bigint's 1.87 floor and std `File::try_lock`'s 1.89. |
| Kernel | This machine runs WSL2 kernel 6.18.54.1. CI's `ubuntu-24.04` runner runs 7.0.0-1017-azure, a newer kernel [99]. `SO_PEERPIDFD` needs ≥ 6.5. Across PID namespaces, `PIDFD_GET_INFO` returns `EREMOTE` (7.0, and backported to 6.18.14), which was tested on this machine (Q1). |
| Parsing | All JSON is parsed with `jcs`, never serde: requests, results, JWS headers and claims, DSSE payloads, the lockfile and the config. This rejects duplicate keys and duplicate claims (F-03). |
| Limits | Request bodies are capped at 1 MiB, depth 64 and 8,192 values (`jcs` request profile). |
| Engine today | Every agent `_meta` member outside `dev.pep-sidecar/` is forwarded inside `canonical_request`.<br>`commit` leaves the call in `in_flight`.<br>`record_result_raw` never reads `resultType`.<br>`require_peer_uid` checks the uid only.<br>`EffectClass` has four variants.<br>Budgets, reservations and the F-08 label store (`InMemoryLabelStore`) live only in memory. |
| MCP | Revision 2026-07-28: stateless, with per-request `_meta`. Servers MUST implement `server/discover`. A client disconnect is a cancellation, and streams cannot be resumed. |
| Clocks | Containers share the host's wall clock. Time namespaces offset only the monotonic and boot clocks [86], so one container's wall clock cannot be stepped on its own. |
| Unicode | Digests use Unicode 18.0.0 NFC (SPEC §2). The stub broker shares the PEP's `jcs` code, so it uses the same tables. |

## 0. Goal and Gate 1 exit criteria
**Goal:** a running `pep-sidecar` binary that mediates MCP tool calls from a network-less agent container. It does so over a bind-mounted Unix socket, with token and lockfile enforcement, and passes the Gate 1 suite (§3).

Gate 1 is evaluated on the release profile in the Compose topology (§4), not in unit harnesses.

| # | Criterion | Threshold |
|---|---|---|
| G1 | Containment attack tests passing, judged by the bypass oracle (§2a) | ≥ 50 attack tests per deployment profile in S1, run in Compose on this machine, with 0 bypasses. §3 lists 62. Its 45 conformance checks run in CI and must pass, but don't count |
| G2 | Rug-pull mutations quarantined | All of ≥ 20 (§3 lists 25), each within the detection window T (L1), with no call forwarded to a drifted tool after detection, and 0 false positives on the negatives |
| G3 | Replays of captured Episode Tokens and Call Proofs rejected | 1,000 of 1,000 in Compose, including restart replays. Clock steps are tested in-process (step 6) and reported beside G3 |
| G4 | p99 added latency of the PEP plus the broker, as defined in O1 | ≤ 25 ms, with the PEP-only p99 reported beside it. Release build, in Compose on this machine, with the CPU model recorded |
| G5 | Supply chain | `cargo deny check` clean, with no ignores. Exactly one crypto-bigint, ≥ 0.7.6. No getrandom anywhere in `cargo tree --target all`, checked fail-closed (step 3). (`cargo audit` is dropped: `cargo deny` reads the same RustSec database.) |
| G6 | Decisions | Every §1 decision CLOSED, with its rationale recorded |

## 1. Decision register
Status: D2 is CLOSED (2026-11-03); the other 17 are OPEN. Each closes just before the step it blocks:
- **Step 2** closes the 14 that block steps 3–7. D2 is closed, and 13 remain.
- **N1 and B1** close before step 8.
- **S1 and O1** close before step 9.

RV2 had T1, L1 and Q1 closing after step 2. RV2's own reordering (§2) moves them into step 2: crypto, peer identity and tokens now come before the binary, and the config's `pins` section uses the lockfile v1 payload. "Recommendation" is a label, not a decision.

| ID | Decision | Recommendation | Blocks step | Closes |
|---|---|---|---|---|
| D1 | Rust toolchain | B: stay on 1.97.1 | 3 | Step 2 |
| D2 | Agent-facing transport | Decided: (a) Streamable HTTP, as a POST/JSON subset over the Unix socket | 7 | CLOSED 2026-11-03 |
| N1 | Network model | (a) `network_mode: none` for the agent, the PEP and the operator, with the broker on an internal network | 8 | Before step 8 |
| Q1 | Peer identity across PID namespaces; peer gid | (i) cross-namespace pidfd mode, plus a gid check | 4 | Step 2 |
| S1 | Deployment profiles in Gate 1 | Compose only | 9 | Before step 9 |
| M1 | MCP 2026-07-28 surface | The PEP is a full 2026-07-28 server to the agent, and builds every upstream request itself | 7 | Step 2 |
| M2 | Results that are not `complete` | Never recorded. A payment becomes `abort(Unknown)` | 7 | Step 2 |
| P1 | Payment outcome mapping | The table in P1. Step-up waits are capped at 50 s | 7 | Step 2 |
| R1 | Restarts with in-memory state | (a) per-boot keys plus a payment and taint journal | 6, 7 | Step 2 |
| E1 | Episode lifecycle | `start_episode` and `end_episode` on the control socket, a 30-minute idle timeout, and the token delivered on stdin | 6, 7 | Step 2 |
| H1 | Host control socket | `/run/pep-ctl` owned 20002:20004 with mode 2750, operator uid 20004 | 7 | Step 2 |
| T1 | Token profiles | rfc8725bis-10 rules with a header allowlist and strict base64url. Call Proof `typ` `pep-callproof+jwt`, low-S, on every forwarded call. A per-episode rate limit sizes the replay cache | 6 | Step 2 |
| L1 | Lockfile v1 content | Engine-named fields. The unsigned payload is also the config's `pins`. DER signatures only. Drift found by polling | 7, 10 | Step 2 |
| O1 | Latency definition | PEP plus broker residence time, under open-loop load, with the PEP alone reported beside it | 9 | Before step 9 |
| B1 | Release build profile | `overflow-checks = true`; `panic = "abort"` only together with R1 (a) | 8 | Before step 8 |
| U1 | Wire shapes of denials and errors | One shape for every policy denial; MCP-mandated errors keep their codes, in a fixed order | 7 | Step 2 |
| J1 | Result fidelity | (b) the result profile keeps the exact digits of integers beyond ±(2^53−1) | 7 | Step 2 |
| A1 | Engine threading | One actor thread per episode | 7 | Step 2 |

### D1. Rust toolchain
- **Evidence:**
  - The repo pins 1.97.1 (`rust-version = "1.97.1"`).
  - crypto-bigint ≥ 0.7.6, which fixes RUSTSEC-2026-0387, declares rust-version 1.87 [23][104].
  - std `File::try_lock` is stable since 1.89 [8].
  - 1.97.1 is itself a point release. It fixed a miscompile in LLVM optimization (#159035), so 1.97.0 is no alternative [87].
  - Four fixes have been released since: one in 1.98.1 (2026-09-03) and three in 1.99.1 (2026-10-15) [87]. The 1.99.1 post names no introducing releases [6], so each was traced through its issue record:

    | Fix | Issue | Introduced by | First shipped in | 1.97.1 |
    |---|---|---|---|---|
    | 1.98.1: vtable miscompile (a zero method slot, so a segfault or worse) | #161441 [88] | #156742 (milestone 1.98.0), found by bisection | 1.98.0 | Not affected. The reporter: "works with Rust 1.97.1" |
    | 1.99.1: x86_64 FFI `bool` return values not masked | #163911 [89] | #159317 (milestone 1.99.0) [76]. It uncovered a gap left by #142389 (1.89.0), which the old unconditional zero-extension had hidden. The fix #163917 restores "what was emitted in 1.98" [77] | 1.99.0 | Not affected: tested here (below) |
    | 1.99.1: `wcslen` missing on UEFI and embedded targets | #163614 [90] | The LLVM 23 upgrade (#158734), by bisection of its duplicate #160827 | 1.99.0 | Not affected: 1.97.1 uses LLVM 22.1.6. These are not our targets either |
    | 1.99.1: macOS `rust-lld` cannot load `libLLVM` | #163947 [91] | #157205, dynamic LLVM on aarch64-apple-darwin hosts (milestone 1.98.0) | 1.98.0 | Not affected, by milestone. Our macOS target is lint-only and never linked |
  - **The FFI `bool` test.** The issue's reproducer, built for x86_64 at `-C opt-level=3`, gives `define noundef zeroext i1` and `movl %edi, %eax; andb $1, %al; retq` on both 1.97.0 and 1.97.1. That is the masked form the issue shows for 1.98.0. 1.99.0 emits `noundef i1` with no `andb` (Appendix A).
  - **What this shows:** none of the four fixes applies to 1.97.1. Like any release, 1.97.x may still hold bugs that nobody has found.
- **Options:**
  - **A:** jump to 1.99.1. New clippy lints fire once. `rust-version = "1.99.1"` exactly, as CLAUDE.md §1 does now. Keep the `aarch64-apple-darwin` target.
  - **B:** stay on 1.97.1.
  - **C:** jump but declare a lower MSRV. Rejected: this is a binary with no downstream users, and C would cost a second CI job.
- **Recommendation:** B. AP recommended A because of the 1.99.1 fixes, but none of them applies to 1.97.1, and neither does 1.98.1's. Revisit A only if a later point release fixes a bug that reaches 1.97.1.

### D2. Agent-facing transport
- **Evidence (MCP 2026-07-28 Streamable HTTP [1]):**
  - **Messages:** one POST endpoint. Each body MUST be a single request or notification, so a batch is not a valid body (the spec never names batches).
  - **Headers:**
    - `MCP-Protocol-Version`, `Mcp-Method` and, for `tools/call`, `Mcp-Name` are required.
    - Values that are not header-safe use `=?base64?…?=`, which servers decode before comparing.
    - A mismatch, or a missing standard header, gets 400 and -32020.
  - **Error codes:** an unsupported version gets 400 and -32022. An unknown method gets 404 and -32601. A present, invalid `Origin` gets 403.
  - **Legacy traffic:** legacy GET or DELETE should get 405. That is a SHOULD, for servers that support only this revision.
  - **Streams:** a client disconnect is cancellation, and streams cannot be resumed.
- **Options:**
  - **(a)** that transport over the Unix socket.
  - **(b)** NDJSON JSON-RPC over the Unix socket. No SDK supports it. MG's correction applies: (b) would not move the token, which SPEC §3.3 already carries in `_meta`, with the header optional.
  - **(c)** a loopback-TCP shim. Rejected: peer credentials would identify the shim, not the agent.
- **Recommendation:** (a), hand-rolled (§2a), with no HTTP crate.
  - The Episode Token stays in `_meta["dev.pep-sidecar/episode"]`.
  - `Pep-Episode` is optional, and a mismatch gets 400 and -32020.
- **Closing condition (met 2026-11-03):** a spike reaches a throwaway Unix-socket HTTP server with custom headers from:
  - **the TypeScript SDK v2:** a custom `fetch` with an undici `Agent({ connect: { socketPath } })`.
    - **Run on 2026-11-03, and it works (Appendix A).** `@modelcontextprotocol/client` 2.4.0 connected over a Unix socket and ran the same four methods.
    - **Two conditions.** The client must be built with `versionNegotiation: { mode: { pin: '2026-07-28' } }`: the SDK's default is `'legacy'`, which sends a 2025 `initialize` that the PEP answers with 404.
    - Its `fetch` and `Agent` must both come from the `undici` package (8.12.3 here). Node 24's built-in `fetch` bundles undici 7.30.1 and rejects that `Agent` (`UND_ERR_INVALID_ARG`).
    - The TypeScript half of D2 is closed;
  - **the Python SDK v2,** which uses httpx2 and documents no Unix-socket support [26]. Its `streamable_http_client` takes an `http_client: httpx2.AsyncClient` [26], so the route is an `httpx2.AsyncHTTPTransport(uds=…)` inside that client.
    - httpx2's docs show `uds` only on the synchronous `HTTPTransport` [92].
    - Its 2.16.0 source has `uds` on `AsyncHTTPTransport` too. It passes `uds` to httpcore2's async pool, which opens it with `connect_unix_socket` [102].
    - It ignores `uds` whenever a proxy applies, so the spike builds the client with no proxy and `trust_env=False`.
    - **Run on 2026-11-03, and it works (Appendix A).** The MCP Python SDK 2.3.0 with httpx2 2.16.0 connected over a Unix socket. It ran `server/discover`, `tools/list`, `tools/call` and `subscriptions/listen` against a stand-in for the PEP, so the Python half of D2 is closed.

  The SDK timeouts that bound P1's step-up wait are already verified (P1).

**Decision: CLOSED 2026-11-03, option (a).**
- **Decided:** MCP 2026-07-28 Streamable HTTP over the Unix socket, as a hand-rolled POST/JSON subset (`src/http.rs`, `src/mcp.rs`), with no HTTP crate.
  - The Episode Token stays in `_meta["dev.pep-sidecar/episode"]`.
  - `Pep-Episode` is optional, and a mismatch gets 400 and -32020.
- **Why:** the closing condition is met. Both SDK v2 lines ran `server/discover`, `tools/list`, `tools/call` and `subscriptions/listen` against the stand-in, sending every header and `_meta` field M1 checks.
- **Conditions on agents** (the Gate 1 harness, and Week 4's, §5):
  - TypeScript needs `versionNegotiation: { mode: { pin: '2026-07-28' } }`, and `fetch` and `Agent` from the same `undici` package;
  - Python needs an `httpx2.AsyncHTTPTransport(uds=…)` client with `trust_env=False`, passed as `http_client`.
- **Consequences for other decisions:**
  - M1: the PEP must accept string JSON-RPC ids;
  - `notifications/cancelled` handling belongs to U1, which stays open.
- **Evidence:** `spikes/d2-transport/`.
- **SPEC:** §1 and §4 updated (§6).

### N1. Network model
- **Evidence:**
  - SPEC §1's nftables rule (`skuid 20001`) cannot work as a host rule. `skuid` matches only sockets in the network namespace where the rule is loaded, and Compose gives each container its own namespace (close-out note).
  - Compose rejects a file that sets both `network_mode` and `networks` [80].
- **Options:**
  - **(a)** `network_mode: none` for the agent, the PEP and the operator; the broker on an internal `tools_net`. Each private namespace has only `lo` with nothing listening, so loopback holes cannot exist. nftables becomes an optional backup, or the rule set for the same-host process deployment.
  - **(b)** the agent shares the PEP's namespace (`network_mode: "service:pep"`), and a helper with `NET_ADMIN` loads the rules there. nftables becomes mandatory, with tests for the rule set.
- **Decide now as well:**
  - **Week 4 model egress.** The agent needs an LLM, and under (a) it has no network. Recommended: a model proxy on a Unix socket with a host allowlist. The provider is recorded as an accepted exfiltration channel.
  - **Week 5 PEP egress.** The PEP must reach a Txn-Token service and a PDP. Recommended: route them through the broker, so SPEC §1 is amended once.
- **Containment layers.** Five-Track §3.2–§3.3 lists seccomp, Landlock, Yama, nftables and cgroup-eBPF connect hooks; the Week 1 verified plan's testbed appendix names the cgroup-eBPF `connect4` hook too. Week 2 adopts:
  - an AF_UNIX-only seccomp profile for the agent, the PEP and the operator (RV2);
  - `pids_limit`, a memory limit and a private `/tmp` for the agent (RV2);
  - `cap_drop: [ALL]`;
  - `no-new-privileges`;
  - `network_mode: none`.

  It defers:
  - **cgroup-eBPF `connect4`/`connect6`:** there is no network to filter under (a);
  - **Landlock:** the root filesystem is already read-only, and Landlock's ABI varies by kernel;
  - **Yama:** cross-uid ptrace already fails without `CAP_SYS_PTRACE`, and C-PROC tests it.
- **Recommendation:** (a), with the Unix-socket model proxy.

### Q1. Peer identity
- **Evidence** (kept from AP §5):
  - Compose gives each container its own PID namespace. For a peer in a sibling namespace, `SO_PEERCRED` reports pid 0.
  - `SO_PEERPIDFD` still returns a pidfd. Its fdinfo shows `Pid: 0` while the peer lives, and `-1` once it has been reaped and no task is attached [3].
  - `PIDFD_GET_INFO` returns `ESRCH`, and `EREMOTE` since 7.0 (backported to 6.18.14 and 6.19.10), so the cgroup id cannot be read across namespaces [2][56].
  - `SO_PEERCGROUPID` was proposed but is not in mainline. It is absent from the uapi header at 7.4-rc1, whose highest socket option is `SO_PEERPIDFD_THREAD` (87) [98].
  - nix 0.31.3 exposes `sockopt::PeerPidfd` in the `socket` feature that is already enabled; it returns an `OwnedFd`.
  - **Errors, each rejected fail-closed:**
    - `ENOPROTOOPT`: kernel older than 6.5;
    - `ENODATA`: no peer pid recorded, for example on an unconnected socket [31];
    - any other errno. The 31 Oct draft said older kernels return `EINVAL` or `ESRCH` for a reaped peer. No source for that was found: [31] covers only `ENODATA`.
  - On recent kernels a reaped peer yields a stale pidfd (`Pid: -1`) instead of an error, so the fdinfo check is mandatory.
  - **Tested on this machine (6.18.54, Appendix A):**
    - With the peer in a PID namespace the listener cannot see (the Compose case), `SO_PEERCRED` reports pid 0 and fdinfo shows `Pid: 0` while the peer lives.
    - `PIDFD_GET_INFO` returns `EREMOTE` in that case, before and after the peer is reaped. Across namespaces, fdinfo is the only liveness signal.
    - After a reap, a new `SO_PEERPIDFD` call returns a stale pidfd (`Pid: -1`), not an error. CI's 7.0 kernel is newer still, so neither runs a kernel with a reaped-peer errno.
  - **What it proves:** across PID namespaces the pidfd proves only that the peer is alive. Identity rests on the `SO_PEERCRED` uid and gid. SPEC §1 says so (§6).
- **Options:**
  - **(i) Cross-namespace mode:** require that the pidfd was obtained, that fdinfo `Pid ≠ -1`, and that uid and gid match.
  - **(ii) Shared namespace** (`pid: "service:pep"` on the agent). The pid resolves, and `PIDFD_GET_INFO` gives the cgroup id. But the agent can then read `/proc/<pep>/cmdline`, so secrets stay out of argv and env. (Env is protected across uids by the ptrace check, but keep it clean anyway.)
  - **(iii) `pid: host`:** rejected.
- **The gid.** `require_peer_uid` checks only the uid, but SPEC §1 runs the agent as 20001:20001, and AP's C-UID test "uid right, gid wrong" expects a rejection. Add `require_peer(uid, gid)`. The agent cannot change its gid under `no-new-privileges` and `cap_drop: [ALL]`.
- **Recommendation:** (i) plus the gid check.
  - CI's `ubuntu-24.04` runner uses kernel 7.0, which is newer than this machine's 6.18.54, not older [99]. Both are past the 6.18.14 backport, so both should return `EREMOTE`.
  - Tests still branch on kernel version and record `uname -r`.
  - `ENOPROTOOPT` cannot occur on either kernel, so it stays an injected-errno check.

### S1. Deployment profiles in Gate 1
- **Evidence:**
  - SPEC §1 allows a "container/process" deployment.
  - Five-Track §5.3 says "zero bypasses in at least 50 attempts per profile".
  - Five-Track §3.3 lists gVisor `runsc` as optional.
- **Recommendation:** Gate 1 covers the Compose (runc) profile only, and SPEC §4 names it. Only attack tests that run in Compose on this machine count toward its ≥ 50 (§3). The same-host process deployment and `runsc` are recorded as deferred; each needs its own ≥ 50 when added.

### M1. MCP 2026-07-28 surface
**Evidence:** MCP 2026-07-28 [1][66]–[73]:
- **Discovery:** servers MUST implement `server/discover`. Its `instructions` field is "natural-language guidance for LLMs", so it is a rug-pull channel.
- **Required `_meta`:** every request carries `io.modelcontextprotocol/protocolVersion` and `io.modelcontextprotocol/clientCapabilities`. A missing one gets -32602 and HTTP 400.
- **`resultType`:** every result carries one: `complete`, `input_required`, or an advertised extension value. An unrecognized value MUST be treated as invalid.
- **Caching:** discover and list results carry `ttlMs` and `cacheScope`. A list filtered per caller is `private`.
- **`tools/list`:** it is paginated. It MAY vary by the authorization presented, but MUST NOT vary per connection.
- **Removed or changed methods:**
  - `ping` and `logging/setLevel` are removed;
  - log notifications flow only for requests that set `io.modelcontextprotocol/logLevel`;
  - `progressToken` is a reserved `_meta` key.
- **`subscriptions/listen`** [73]:
  - The server "**MUST** send `notifications/subscriptions/acknowledged` as the first message", with the subscription's id in `_meta["io.modelcontextprotocol/subscriptionId"]`.
  - The acknowledgement's `notifications` is "the subset the server agreed to honor. Notification types the server does not support are omitted."
  - A server ending a subscription "**SHOULD** respond to the original `subscriptions/listen` request with a completion result before closing the stream": `{"resultType": "complete", "_meta": {"io.modelcontextprotocol/subscriptionId": …}}`. A client takes that as a clean close. A close without it is an unexpected disconnect, which the client "**MAY** treat as a trigger to reconnect".
  - Nothing lets a server without list-changed capabilities reject the method; the acknowledgement MUST is unconditional.
  - **One ambiguity:** cancellation.md says a server "**MUST** send `notifications/cancelled`" when it tears a subscription stream down [71]. subscriptions.md asks only for the completion result.
    - Tested against the Python SDK 2.3.0 (Appendix A): with `notifications/cancelled` before the result, it raises `SubscriptionLost`, "ended without the server's graceful close; re-listen and refetch". Without it, the subscription closes gracefully.
    - The TypeScript SDK 2.4.0 reacts the same way: it reports the subscription closed as `'remote'`, an unexpected disconnect, and flags the completion result as a response for an unknown id.
    - So the PEP follows subscriptions.md.
  - The official conformance suite covers 2026-07-28, but has no `subscriptions/listen` scenario [100].
- **`x-mcp-header`:** it mirrors primitive parameters into `Mcp-Param-{Name}`. Week 2 rejects it at lockfile load (L1), so the PEP needs no `Mcp-Param` handling.
- **Tool names:** they SHOULD be 1–128 characters of `[A-Za-z0-9_.-]`.
- **New error codes:** -32000 to -32019 is closed to new codes, so Five-Track's proposed `-32003 EPISODE_EXPIRED` cannot be used.

**Design** (recommendation):
- **Router.** Every PEP result carries `resultType: "complete"`. Discover and list results also carry `ttlMs` and `cacheScope`.

  | Method | Handling |
  |---|---|
  | `tools/call` | The engine. The transport parses the body once and builds the `ToolCall`. |
  | `tools/list` | Served by the PEP from its cached, verified view, never fetched upstream per agent request:<br>• a valid Episode Token is required;<br>• the view holds only definitions whose canonical digest matches the lockfile pin and that are not quarantined;<br>• the drift poller (L1) refreshes it from every upstream page;<br>• one page, `ttlMs: 0` (a quarantine can change it at any moment), `cacheScope: "private"`. |
  | `server/discover` | Answered by the PEP:<br>• no token needed;<br>• `supportedVersions: ["2026-07-28"]`;<br>• `capabilities: {"tools": {}}`;<br>• `ttlMs: 0`, `cacheScope: "public"`;<br>• no upstream `instructions` unless the lockfile pins their text. |
  | `subscriptions/listen` | A PEP-generated SSE stream, the only non-JSON reply:<br>• first `notifications/subscriptions/acknowledged`, with the subscription id and `notifications: {}`, because the PEP supports no notification type;<br>• then the completion result, and the stream closes. Closing gracefully tells the client not to reconnect.<br>The PEP does not also send `notifications/cancelled` (the M1 ambiguity): both SDKs treat it as an unexpected close.<br>Both SDKs (Python 2.3.0, TypeScript 2.4.0) accept this reply, end the subscription gracefully, and never re-listen on their own. |
  | Anything else, `ping` included | 404 and -32601 |

- **Client notifications.**
  - A `notifications/cancelled` POST gets 202 and is ignored, before the checks below. The TypeScript SDK sends one, without `Mcp-Method`, when it closes a subscription itself. A 400 there surfaces as a client error event (Appendix A).
  - The PEP never acts on it. Cancellation stays the closing of the connection (P1), so the notification never touches a reservation.
  - Any other notification gets 400.
- **Agent requests, checked in the transport, before the engine.** HTTP-level replies (405, 403) come first. Then, in this order, so each request gets exactly one reply:
  1. a missing standard header → -32020;
  2. a missing `_meta` field (`protocolVersion` or `clientCapabilities`), or a `clientCapabilities` that is not an object → -32602;
  3. a header that differs from the body or from `_meta` → -32020. `Mcp-Name` is base64-decoded and NFC-normalized before comparing, and a `Pep-Episode` mismatch is included;
  4. any `Mcp-Param-*` header → -32020, because no pinned tool declares `x-mcp-header`;
  5. a version that is present and consistent but not `2026-07-28` → -32022.

  Request ids may be strings: the SDKs used `"server-discover-probe-1"`, `"listen:0"` and `"listen-1"`.

  After the checks:
  - every other agent `_meta` member is dropped and never forwarded;
  - `g_canon` keeps its denial of reserved `dev.pep-sidecar/` members.
- **Episode Token bindings:**
  - its `eid` selects the episode's actor (A1);
  - `peer_uid` must equal the connection's uid;
  - `release_epoch` must equal the loaded lockfile's, which must be ≥ the config's `min_accepted_epoch`;
  - `intent_digest` must equal the configured intent's.
- **Upstream requests, always built by the PEP:**
  - `forward::tools_call_request` builds the body: a PEP-assigned JSON-RPC id, the canonical name and arguments, and `_meta` = `protocolVersion`, `clientCapabilities: {}`, the PEP's `clientInfo` and the Call Proof.
  - Headers are derived from that body: `MCP-Protocol-Version`, `Mcp-Method` and `Mcp-Name`, with no `Mcp-Param-*`.
  - Nothing the agent sent (headers, `_meta` members, id, `logLevel`, `progressToken`) is copied. The PEP is an MCP endpoint, not an HTTP intermediary.
- **Upstream responses** (the broker answers JSON only; §2a):
  - `application/json` only, with byte and time caps. An SSE reply or any other content type is invalid;
  - exactly one response, whose id must match;
  - an unknown or absent `resultType` is invalid (M2);
  - `_meta["dev.pep-sidecar/outcome"]` is trusted only on a connection whose peer uid is 20003; after it is read, the result's `_meta` is dropped.
- **Mutual peer checks:** the broker requires peer uid 20002, and the PEP requires 20003.

### M2. Results that are not `complete`
**Evidence:**
- A server may answer `tools/call` with `resultType: "input_required"`, carrying `inputRequests` and an opaque `requestState`.
- It may send only `requestState`, so this can happen even to a client that declares no capabilities.
- Extensions may add result types; the tasks extension can return a handle for work that runs later.
- For servers on earlier revisions, "clients **MUST** treat an absent `resultType` as `"complete"`" [67]. For 2026-07-28 servers the field is required [66].
- Today, `record_result_raw` would record such a body as if it were a finished result. `g_canon` rejects a retry's `inputResponses` and `requestState` as `UnexpectedParam`, which fails closed only by accident.

**Recommendation:**
- Send empty `clientCapabilities` upstream, and advertise no extensions.
- `record_result_raw` accepts only `resultType == "complete"`.
- An absent `resultType` is rejected too. That deliberately departs from the client MUST above. It is safe because the lockfile pins 2026-07-28 servers, which must send the field, so an absent one means the server is not what was pinned. SPEC records the deviation (§6).
- Anything else is never recorded or forwarded: a non-payment call is abandoned, and a payment gets `abort(Unknown)`.
- MRTR retries stay rejected in `g_canon`, now deliberately, with a test named for it.

### P1. Payment outcome mapping
**Evidence:**
- On Streamable HTTP a disconnect is a cancellation, and a lost request is re-issued under a new id.
- `commit` leaves the call in `in_flight`, while `abort` removes it.
- `MAX_IN_FLIGHT` is 64.

**Recommendation:**

| Event | Engine calls | Agent sees |
|---|---|---|
| The broker's explicit outcome is `executed` | `commit`, then `record_result_raw` (or `abandon` if recording fails) | The recorded result |
| The explicit outcome is `refused` with a tool result, never inferred from an HTTP status or `isError` | `record_result_raw` first, then `abort(DefinitelyNotExecuted)`. `abort` removes `in_flight`, so recording after it would fail | The recorded refusal |
| The broker rejects the Call Proof (`refused`, with no tool result: the call was never forwarded) | `abort(DefinitelyNotExecuted)` | `PEP_UNAVAILABLE` |
| Broker timeout, disconnect, an ambiguous reply, or outcome `unknown` | `abort(Unknown)`. Nothing is recorded | `PEP_UNAVAILABLE` |
| The agent disconnects before the call is forwarded, a step-up wait included | `abort(DefinitelyNotExecuted)` | — |
| The agent disconnects after the call is forwarded | Nothing from the agent side. The upstream leg runs to completion or timeout, and its outcome applies | — |
| Step-up declined or timed out | `abort(DefinitelyNotExecuted)`: nothing was sent | `PEP_DENIED` |
| Any non-payment call | Record and forward. On a timeout or error, `abandon` | `PEP_UNAVAILABLE` on failure |

- **Outcome sources:** outcomes come only from the upstream side, never from anything the agent does. That includes a `notifications/cancelled` naming a forwarded call's id, which the PEP accepts and ignores (M1).
- **Step-up waits.** The agent's request stays open for up to `step_up_timeout_ms`. Clients give up sooner than a human approval can take (verified 2026-11-03; Appendix A):
  - **TypeScript SDK:** `DEFAULT_REQUEST_TIMEOUT_MSEC` is 60,000 in both v1 (1.32.2) and v2 (`@modelcontextprotocol/client` 2.4.0). It applies whenever the caller passes no `timeout` [93][94]. Only progress notifications reset it, and only when the caller sets `resetTimeoutOnProgress` (default false).
  - **Node `fetch`** (undici's default global Agent): 300 s to receive the headers, and 300 s between body chunks [95].
  - **Python SDK v2:** its default `httpx2` client has a 30 s timeout with a 300 s read timeout [26][96]. `ClientSession`'s own `read_timeout_seconds` defaults to none.
  - MCP itself says clients SHOULD "implement timeouts for tool calls" [70].

  There are two fixes:
  - **(i)** cap `step_up_timeout_ms` below the shortest client timeout, the TypeScript SDK's 60 s;
  - **(ii)** answer step-up calls with SSE and send `:` keep-alives. Keep-alives reset undici's body timer and httpx2's read timer, but not the TypeScript SDK's request timer, which only an opted-in progress notification resets.

  Recommended: (i), with `step_up_timeout_ms` ≤ 50,000 in Week 2. Longer approvals wait for Week 4 (§5).
- **Late approvals:** if the agent disconnects during a step-up wait, the reservation is released (the "before forwarded" row). A later approval finds no `AwaitingStepUp` reservation and is refused (C-CTL).
- **Retries after `Unknown`:**
  - A retry gets a new reservation id, and so a new F-07 key that the provider cannot dedupe.
  - Until Week 3's reconciliation, `g_budget` denies a payment whose entity matches a `NeedsReconcile` reservation (`ReconcilePending`).
  - **Why the entity, not the `action_digest`:** the agent controls the digest. `pay_invoice` has a free `Data` argument (`/memo`), so changing one byte gives a new digest. G_prov does force a fresh lookup. But if the system of record still shows the amount due because the first payment is pending, a second payment passes, and `per_entity_max_uses` (2 in the test config) allows it (RV2).
  - Entity plus amount and currency was the alternative. The entity alone is stricter.
  - This replaces Five-Track §3.6's (eid, action_digest, idempotency_key) dedupe.
- **In-flight accounting:** a unit test checks that `in_flight` drains to zero after a run.

### R1. Restarts with in-memory state
- **Evidence:**
  - A PEP restart forgets budgets, reservations (`NeedsReconcile` included), spent ids and the F-08 label store.
  - Per-boot keys void every old token, but not the budget. After a restart, the operator calls `start_episode` for the same intent and gets a full budget. Every `NeedsReconcile` and in-flight payment is forgotten. RV's boot nonce has the same hole (RV2).
  - B1 makes it worse: with `panic = "abort"`, any panic the agent can reach becomes "restart, start the episodes again, fresh limits".
  - The label store is lost too, so a value an agent wrote before a restart reads as untainted after it. That launders causality across the restart (F-08).
  - A broker restart empties its `jti` cache inside the 60-second Call Proof window.
- **Options:**
  - **(a) A small write-ahead journal** (RV2), for payment reservations and F-08 taint records.
  - **(b) Accepted risk:** record the budget reset and the taint loss as accepted Gate 1 risks, in those words, and keep `panic = "unwind"` (B1).
- **The journal, under (a):**
  - **Where:** `/var/lib/pep/journal.jsonl`, on an on-disk named volume (`pep-state`, owned 20002, mode 0700) that only the PEP mounts.
  - **Payment records:** before a payment is forwarded, the PEP appends a `reserve` record {intent, eid, rid, entity, amount_minor, currency, action_digest, idempotency_key} and fsyncs it. After the upstream leg it appends an `outcome` record (`executed`, `refused` or `unknown`).
  - **Taint records:** a journal-backed `LabelStore` appends and fsyncs each F-08 record before `record` returns. F-08 records at decision time, so taint is durable before the write is forwarded.
  - **Fail closed:** if an append or fsync fails, the payment gets `abort(DefinitelyNotExecuted)`, the write is denied, and the agent gets `PEP_UNAVAILABLE`. Outcome records need no fsync: losing one only replays its reservation as unresolved, which fails closed.
  - **Replay at boot:**
    - Per intent, the counters are rebuilt to what the engine would hold had it not restarted.
    - Unresolved entries (no outcome, or `unknown`) come back as `NeedsReconcile`. They count in `reserved`, in `calls` and in entity uses.
    - A torn last line is dropped, because its fsync never completed, so its call was never forwarded. Any other malformed line stops the PEP from starting.
  - **Every episode of an intent starts from that ledger.** RV2 had unresolved entries count against the intent. Committed spend counts too: without it, a restart would still refund it. So neither a restart nor a new episode refunds spend.
    - This makes a configured intent behave like the Week 5 RAR, which binds one `episode_id`.
    - Gate 1 tests use one intent per test group.
  - **Week 3:** SQLite replaces the journal.
- **Both options keep:**
  - **Per-boot keys.** The PEP generates its Episode Token key and Call Proof key at start-up, from `/dev/urandom` read through std, so no `getrandom` crate. A restart therefore voids every token and proof.
  - **Key delivery.** The PEP writes the Call Proof public key to `/run/pep-pub`, which the broker mounts read-only and re-reads per connection.
  - **Broker boot cutoff.** `iat` is in whole seconds, so the broker requires `iat` to be strictly greater than its boot second. Otherwise a proof issued in the same second, just before boot, could be replayed once (RV2). Legitimate proofs issued in that second are refused as well. They were never forwarded, so they map to `refused`, and the cost is the broker's first second.
  - **Tool server dedupe.** The stub tool server dedupes on `Idempotency-Key`, and its store survives PEP and broker restarts.
  - **Replays.** Restart replays count in the 1,000.
- **Recommendation:** (a). Under (b), the Risks line must say plainly that a restart refunds every budget and forgets agent-write taint.

### E1. Episode lifecycle
- **Evidence:** neither AP nor MG says who mints Episode Tokens. Five-Track §3.6 has the PEP mint them on a trusted `start_episode` call, with a 30-minute idle timeout that SPEC §3.3 dropped.
- **Recommendation:**
  - **Minting.** `start_episode(intent)` on the control socket (H1) mints the token: `typ` `pep-episode+jwt`, with SPEC §3.3's claims and `exp − iat ≤ 28800`.
    - It builds the episode's engine from the intent's journaled ledger (R1).
    - It is refused once `limits.episodes` episodes are live.
  - **Ending.** `end_episode(eid)` revokes one episode without a restart (§2a control protocol).
  - **Idle timeout.** Restore the 30-minute idle timeout.
  - **Keys.** The Episode Token key is separate from the Call Proof key.
  - **Week 2 claim values.** Week 2 fills `sub`, `client_id`, `rar_digest` and `txn` from the configured intent; Week 5's RAR and Txn-Token values replace them.
  - **Why the token has no `iss`, `aud`, `jti` or `nbf`.** The PEP mints and verifies the token itself, and the distinct `typ` and key make Episode Token and Call Proof validation mutually exclusive (rfc8725bis-10 §3.12 [74]). Record this in SPEC §3.3.
  - **Getting the token to the agent.** The Gate 1 harness writes the token to the agent process's stdin. Never argv, env or a volume, for the same reason C-PROC checks the PEP's argv.

### H1. Host control socket
- **Evidence.** MG's "0700, operator uid" contradicts itself:
  - a 0700 directory owned by 20002 locks out every other non-root uid;
  - one owned by the operator fails `bind_safe_listener`'s owner check.
- **Recommendation:** use this layout, which `bind_safe_listener` accepts unchanged:
  - `/run/pep-ctl`, owned 20002:20004, mode 2750, where 20004 is a new operator uid;
  - never mounted into the agent;
  - peer uid 20004 required.
- **Approvals:**
  - they carry (eid, rid, `action_digest`, amount);
  - all four are checked against the `AwaitingStepUp` reservation before `approve_step_up(rid)`, which takes only the rid;
  - a mismatch is refused.
- **Principal.** In Week 2, one host principal starts and ends episodes and approves.
- **Gate 1** uses a scripted operator.

### T1. Token profiles
**JOSE rules** for both token types (rfc8725bis-10 [74]):
- an algorithm allowlist of ES256 only, with each key bound to one algorithm and one token type;
- an allowlist of protected-header parameters: `alg` and `typ` required, `kid` optional, and any other member rejects. This replaces AP's deny list of `jku`, `jwk`, `x5u` and `crit` (RV2);
- reject any compact token containing a character outside `[A-Za-z0-9_-.]` before decoding;
- strict base64url decoding, with no padding and no non-zero trailing bits, so each token has exactly one encoding. base64's `URL_SAFE_NO_PAD` engine, which `jcs` already uses, does both (Appendix A). The `_INDIFFERENT` engines are never used;
- exact `typ`;
- a 64-byte r‖s signature;
- validation rules written so the two token types are mutually exclusive.

**Call Proof scope.**
- Every forwarded `tools/call` carries a Call Proof, reads and sinks included, because the broker accepts no other `tools/call` (SPEC §1).
- Payment proofs add `rid` and are issued only for `Held` reservations. A reservation that is `AwaitingStepUp` gets none until it is approved (F-15).
- The PEP's own `tools/list` and `server/discover` requests carry none, and SPEC §1 gains that exception (§6).

**Call Proof `typ`.**
- SPEC §3.4's `urn:pep-sidecar:evidence:jws-callproof:v1` contains no "/", so recipients read it as `application/urn:…`.
- Recommended: `pep-callproof+jwt`.
- If draft-lee needs the URN as an evidence type, carry it in a claim.

**Signatures.**
- The PEP normalizes its signatures to low-S. p256's signer emits high-S as it comes: the RFC 6979 A.2.5 signature it reproduces is high-S. So the PEP calls `normalize_s` itself.
- The broker rejects high-S Call Proofs.
- DSSE verification accepts high-S, because the signers are third-party tools.
- The replay cache is keyed on `jti`, never on signature bytes.

**Claims to define in SPEC §3.4:**
- `budget`;
- `tool_schema_digest`: the lockfile's pinned upstream digest;
- concrete `iss` and `aud` SPIFFE ids;
- the target-server binding: a claim, or the server inside `aud`;
- which claims the broker checks;
- `prov`: the witness origin hashes `Allowed.prov` already holds, at most two, and exact. RV2 cut the second option (capped `leaf_index` matches), so the former step 11 folds into step 6.

`tth` follows wimse-wpt-02 [75], as the hash of the Txn-Token, and waits for Week 5.

**Logging.** Raw tokens and proofs are never logged by default (wimse-wpt-02).

**Rate limit.**
- MCP requires it: "Servers **MUST**: … Rate limit tool invocations" [70]. Each episode gets a token bucket on `tools/call`: a burst of 20, refilled at 5 per second (config).
- A call over the limit gets `PEP_UNAVAILABLE` before the engine sees it. No guard runs, and no reservation or proof is made.
- At most `limits.episodes` (64) episodes are live.
- So the PEP issues at most 64 × 5 = 320 proofs per second, after bursts of up to 64 × 20 = 1,280.

**Clock skew:** 2 s. The PEP and the broker read one host clock.

**Replay cache:**
- bounded, as `Mutex<HashMap<jti, exp>>` plus an expiry order;
- capacity ≥ 320 × (60 s + 2 s) + 1,280 = 21,120; configure 32,768 (`limits.replay_cache_entries`, shared by the PEP and the broker config);
- a full cache with live entries rejects, never evicts;
- `exp` checks and eviction run against a clock high-water mark that never decreases, so a backward clock step cannot re-admit an evicted token;
- the clock is injected, so the high-water mark is tested in-process. No Compose test can step one container's wall clock, and stepping the WSL VM's clock is flaky, because Hyper-V time sync resets it (RV2);
- `jti` and nonces come from `/dev/urandom`;
- verified Episode Tokens are cached by a hash of their bytes, with `exp`, idle and `end_episode` re-checked on every use.

### L1. Lockfile v1 content
The unsigned lockfile v1 payload is also the config's `pins` section from step 7, so there is one pins format. Step 10 adds the DSSE envelope and drift checks around it instead of replacing a second format (RV2). L1 therefore closes in step 2. The source is Five-Track §4.2, mapped onto the engine's `ToolPins`.

- **Epochs:**
  - The payload carries only `release_epoch`.
  - `min_accepted_epoch` is the config's rollback floor. Five-Track also uses the name to mean "accept intents from older epochs". That meaning is dropped, because G_pin requires the intent's epoch to equal the lockfile's exactly.
  - There is no hot reload: a new epoch means a restart.
- **Per-server identity:** `server_id`, endpoint, identity and `protocol_version`. #12 (a name collision) and #25 (shadowing) need it.
- **Tool names:**
  - ASCII, 1–128 characters of `[A-Za-z0-9_.-]`, checked at load. This removes the homoglyph class.
  - Names are unique across all servers, and a name on two servers is a load error.
  - The agent sees the upstream name unchanged, and `action_digest` is computed over it, because the broker recomputes the digest from the forwarded body.
- **Mapping onto `ToolPolicy`.** Lockfile v1 uses the engine's names, not Five-Track's:

  | Five-Track §4.2 | Lockfile v1 (engine) |
  |---|---|
  | `arg_roles`: `authority_entity` | `entity` with a kind, `recipient` or `invoice` (`ArgRole::Entity(EntityKind)`) |
  | `arg_roles`: `amount` | `amount` (`ArgRole::Amount`) |
  | `arg_roles`: `free_text` | `data` (`ArgRole::Data`) |
  | — | `currency`, `sink_destination`, `store_uri`, `store_key`, `store_write`: the matching `ArgRole` |
  | `amount_binding` {`lookup_tool`, `from_arg`, `value_pointer`} | The engine's five fields: `lookup_tool`, `entity_arg_pointer`, `lookup_entity_pointer`, `result_amount_pointer`, `result_currency_pointer`. Both result pointers start with `/structuredContent/` |
  | `role_contracts` | Rejected: F-14's witness rules are fixed in the engine |
  | `sinks[].clearance_lookup` (a dynamic sink) | Rejected in Week 2: the engine has no equivalent. Sinks use `sink_clearance` and the static `destinations` map |
  | `effect_class` | `read` → `ReadOnly`; `mutating_internal` → `MutatingInternal`; `external_sink` → `MutatingExternal`; `mutating_financial` → `Payment`. `destructive` and `code_exec` are rejected in Week 2 |
  | — | Also pinned: `output_label`, `trusted_fields`, `max_result_bytes`, `max_result_nodes`, `store_uri`, and the store table (a `KeyPolicy` per normalized URI) |

  Each intent's `SeqPolicy` goes in the config's `intents` entry, because `PepEngine::new` takes it apart from the intent and the pins. Every tool it names must be pinned.
- **Payment tools** must declare a `currency` argument. This closes the Week 1 code review's open item. A payment tool without one is a load error.
- **Two schemas per tool:**
  - the upstream definition's digest, for drift;
  - a strict subset for enforcement (F-13): `type`, `properties`, `required`, `additionalProperties: false`, `enum`, and length and range limits. Any other keyword is rejected.

  At load, the strict schema and the `args` list must declare the same argument pointers with compatible types, and a mismatch is a load error:
  - `amount` must be an integer with `minimum` ≥ 0 and `maximum` ≤ 2^53−1;
  - `currency` must be a string limited to three uppercase letters;
  - `entity`, `store_uri` and `store_key` must be strings.
- **`x-mcp-header`:** a definition that carries one is rejected at load in Week 2, like `destructive` and `code_exec` (RV2). A server that adds one later changes its definition digest and is quarantined (#19).
- **Per-tool `step_up_over_minor`:** the effective threshold is the smaller of the intent's and the tool's.
- **Signers:**
  - a threshold of distinct keys per role;
  - SPEC §4's security-role signature for payment tools, external sinks, and read-only tools that can authorize amounts;
  - whether Five-Track's 2-of-3 applies is part of this decision.
- **DSSE:**
  - the payload must already be JCS-canonical, so `lockfile_digest = digest(payload)` hashes exactly the signed bytes;
  - count distinct trusted keys per role;
  - a fixed `payloadType` (for example `application/vnd.pep-sidecar.lockfile.v1+json`);
  - PAE; both base64 alphabets for the envelope fields, as DSSE allows; `keyid` only as a hint;
  - **signatures in DER only.** Raw r‖s is rejected, because accepting both would give one signature two encodings. DER keeps cosign compatibility open (AP item 4; RV2).
- **Drift detection:**
  - The PEP polls each server's `server/discover` and every `tools/list` page through the broker, every `drift_poll_ms` (5,000, ±20% jitter). There is no upstream `subscriptions/listen` stream (RV2).
  - Any mismatch quarantines the tool, and the agent's `tools/list` is served from the cached, verified view (M1).
  - **Detection window T = 10 s** (two poll intervals). G2 requires every mutation to be quarantined within T, with no call forwarded to a drifted tool after detection.
- **Tooling:**
  - `pep-sidecar lock-scan` is a subcommand of the PEP binary, run under uid 20002 in the PEP's container, because the broker admits only that uid. It writes the unsigned payload from `server/discover` plus every `tools/list` page, holds no `HostAuthority` and binds no socket.
  - `pepctl lock sign` runs on the host with the signer keys.
  - A separate broker uid that may only list and discover was the alternative. Rejected: it widens the broker's admission rule.
  - Fixtures and the mutation suite need both tools.

### O1. Latency definition
- **Scope.** Gate 1's "added latency" is the whole system's (RV2), so G4 measures the PEP plus the broker.
- **Formula.** Each process records its residence time per call with `Instant`s: (first byte written upstream − first byte read from downstream) + (last byte written downstream − last byte read from upstream). G4 is the p99 of the per-call sum of the PEP's and the broker's residence, joined on `jti`.
- **Also reported:** the PEP alone, the broker alone, and an agent-side end-to-end figure. The Unix-socket transit between the PEP and the broker is excluded from G4; the end-to-end figure bounds it.
- **Load:** open-loop, at fixed arrival rates, because a closed-loop harness hides queueing. A stated mix of reads, payments and lists, at a stated concurrency cap.
- **Head-of-line case (A1):** one episode recording 1 MiB results while others make small calls, reported separately.
- **Crypto cost:** on this machine (AMD Ryzen 3 5300U, release, Rust 1.97.1, 2026-11-03), ES256 takes about 0.57 ms to sign and 0.56 ms to verify (mean). So each payment spends about 1.1 ms on crypto across the PEP and the broker.
- **Exclusions:** step-up calls are excluded, since they wait for a human. 1 MiB requests are measured separately, because hashing cost grows with bytes × depth.
- **Method (AP):** 10,000 calls after 500 warm-up calls. Report p50, p99, p99.9 and max.

### B1. Release build profile
- **`overflow-checks = true`:** library code already denies unchecked arithmetic; this covers dependencies and binaries.
- **`panic = "abort"`:** only together with R1 (a). Then a crash fails closed: it voids every token, and the journal keeps every budget. Under R1 (b), keep `panic = "unwind"`.
- **musl:** add `x86_64-unknown-linux-musl` to `rust-toolchain.toml` only if the images are static (distroless or scratch). Otherwise build in an image whose glibc matches.

### U1. Wire shapes of denials and errors
- **Policy and token denials.** Every one gets the same shape, so the agent cannot tell which guard fired:
  - HTTP 200;
  - a JSON-RPC error with one application code outside -32768 to -32000;
  - the message `PEP_DENIED`;
  - no `data`.

  `PEP_UNAVAILABLE` gets its own single code, and covers rate-limited calls too. Both codes are chosen in step 2 and recorded in SPEC. Expired, idle, ended and declined all get `PEP_DENIED`.
- **MCP-mandated errors keep their codes**, checked in M1's order:

  | Condition | Reply |
  |---|---|
  | A missing standard header | -32020, 400 |
  | A missing `_meta` field, or `clientCapabilities` not an object | -32602, 400 |
  | A header that differs from the body or `_meta`; any `Mcp-Param-*` header | -32020, 400 |
  | A present but unsupported version | -32022, 400 |
  | Unknown method | -32601, 404 |
  | Any `Origin` | 403 |
  | GET or DELETE | 405 |
  | `notifications/cancelled` POST (answered before the checks above) | 202, ignored |
  | Any other notification POST | 400 |

### J1. Result fidelity
- **Evidence:**
  - The result profile (`NumberMode::EcmaAny`) formats numbers per RFC 8785, so integers beyond ±(2^53−1) are rounded: `18446744073709551615` becomes `18446744073709552000` (WEEK1_PLAN Risks).
  - `record_result_raw` returns those canonical bytes, and they are all the agent receives (§2a).
  - An agent that copies such an ID into its next call gets the wrong record. Requests still reject the integer itself (F-04), so the copy goes in as a string, and the string is wrong. That costs utility at Gate 2 (RV2).
  - Labels attach to pointers, not bytes, and such integers are never an Amount (`int` is `None`).
  - A JavaScript agent rounds such numbers itself when it parses the result, so only agents that keep big integers exact benefit. Python's parser does, and Week 4's AgentDojo is Python.
  - Results also NFC-normalize every string. That cannot be fixed on the result side alone: every request string is NFC-normalized before forwarding (F-05), so an NFD file name could not be sent back unchanged anyway. It is recorded as a Week 2 utility limit.
- **Options:**
  - **(a)** quarantine tools whose output schema allows such integers. An `integer` with no `maximum` allows them, so (a) quarantines most tools with integer outputs unless the lockfile bounds them.
  - **(b)** a result number mode that keeps the original digits of a plain integer token (no fraction or exponent) outside the safe range. Every other number keeps RFC 8785 formatting. The bytes stay deterministic, because leading zeros are already rejected and `-0` already becomes `0`.
- **Effects of (b):**
  - Drift hashing sees the exact digits. Mutation #23 is caught by the digest, and step 10's rule "quarantine definitions with such integers" goes.
  - Results and drift digests depart from RFC 8785 for those integers only. Nothing outside this codebase recomputes them: the broker recomputes only request digests, which reject such integers.
  - `1e20` and its integer spelling now hash differently, so a server that switches between them shows as drift.
- **Recommendation:** (b). Decide now, because Gate 2's utility budget (≤ 5 points) is spent here.

### A1. Engine threading
- **Evidence:**
  - The 31 Oct draft had a single engine thread evaluate calls, record results and sign Call Proofs for every episode.
  - Signing alone takes about 0.57 ms here (O1).
  - Recording a large result (up to 1 MiB, parsed, hashed and labelled) blocks every other episode behind it (RV2).
- **Options:**
  - **(i)** one engine thread, with the head-of-line case measured in O1;
  - **(ii)** one actor thread per episode, owning its `PepEngine`. This is the shape of Week 3's Tokio `EpisodeActor`.
- **Recommendation:** (ii).
  - **Channels.** Each actor has two:
    - an agent channel, whose message type cannot express approve, trusted input, end or abort;
    - a host channel, held only by the control thread.
  - **Shared state.** Actors share:
    - `Arc<HostAuthority>`, claimed once in `main` (it cannot be cloned, only shared);
    - the `Arc<dyn LabelStore>`;
    - the journal writer;
    - the Call Proof signing key.

    No connection thread holds any of them.
  - **Registry.** The eid → agent-channel registry is the only map that connection threads read, and `limits.episodes` bounds the number of actors.

## 2. Build order
Every step ends with the CLAUDE.md §2 six-command loop green. Each step's decision IDs must be CLOSED before the step starts.

The order follows RV2: p256, peer identity and the lock file come before the binary. `tokens.rs` moves with them, so the binary never ships placeholder token checks.

| Step | Decisions | Deliverables | Acceptance | Commit |
|---|---|---|---|---|
| 1 | — | Docker Engine inside WSL Ubuntu (yours: it needs sudo). Not Docker Desktop: its VM kernel differs, and Q1 depends on the kernel. Set `systemd=true` in `/etc/wsl.conf`. Record `uname -r` here: 6.18.54.1-microsoft-standard-WSL2 on 2026-10-31.<br>• Compose runs from a clone on WSL's own filesystem, not from `/mnt/c` (§4).<br>• The broker credential lives outside the repo and outside OneDrive. | `docker run --rm hello-world` works inside WSL | — |
| 2 | The 14 that block steps 3–7 (D2 CLOSED 2026-11-03) | Close them. Apply the §6 SPEC wording as each decision closes; SPEC keeps CRLF. Hand the CLAUDE.md wording to you. If D1 = A, make the toolchain commit here. | No OPEN decision blocks step 3 | `docs: close Week 2 decisions; SPEC §1/§3/§4` |
| 3 | D1 | `p256 = { version = "=0.14.0", default-features = false, features = ["ecdsa"] }`. In the same commit:<br>• BSD-3-Clause in `deny.toml`, for `subtle`, the only new licence. Not earlier: an unused allowance makes `cargo deny` warn.<br>• Unsafe-record rows for the 23 new crates, and the changed feature sets of `hybrid-array` and `digest`.<br>• A fail-closed CI check that getrandom is absent. List the whole tree with `cargo tree --target all --prefix none`, fail the job if that command fails, then fail it if any line starts with `getrandom v`. (`cargo tree -i getrandom` exits 101 when nothing matches, so inverting its status would also pass when cargo itself fails.)<br>• Optional bans (getrandom, serde and serde_json until Week 5, openssl, ring), only if `cargo deny check` stays warning-free.<br>• `reports/Week2 crypto crate check.md`, recording the 2026-11-03 probe and prehash test (Appendix A), plus `cargo deny` on the real tree, which the probe could not cover.<br>• Advisory facts (AP item 3):<br>  – RUSTSEC-2026-0387: crypto-bigint timing variability, patched in ≥ 0.7.6 [43]. 0.7.0–0.7.8 are yanked, including the patched 0.7.6–0.7.8, which were yanked for an unrelated semver break. Only 0.7.9 and 0.7.10 are usable, and 0.7.10 resolves [104].<br>  – p256 0.14.0 declares rust-version 1.85, below crypto-bigint's 1.87. A 1.85 toolchain's MSRV-aware resolver would pick the yanked, affected 0.7.5 [46]; 1.97.1 is not affected.<br>  – RUSTSEC-2026-0385: ctutils, patched in ≥ 0.4.4 [105]. crypto-bigint ≥ 0.7.6 requires `^0.4.5` [18], and 0.4.8 resolves.<br>  – The jsonwebtoken crate is rejected. Its latest release, 11.1.0, still takes p256 `^0.13.2` behind its optional `rust_crypto` feature, which pulls crypto-bigint 0.5.5 [52]. | The ES256 surface, already shown to work with exactly `["ecdsa"]` on 1.97.1 (Appendix A):<br>• `Signature::from_slice` for JWS r‖s;<br>• `Signature::from_der` for DSSE;<br>• `VerifyingKey::from_sec1_bytes`;<br>• `Verifier::verify`;<br>• `SigningKey` signing, with `normalize_s`.<br>JWK parsing is hand-rolled, because elliptic-curve 0.14 dropped its `jwk` feature: decode `x` and `y`, check that each is 32 bytes, then build SEC1 `04‖x‖y`; `from_sec1_bytes` rejects off-curve points.<br>`cargo deny` rejects only `subtle` until BSD-3-Clause is allowed, and accepts `ff` and `group`'s `MIT/Apache-2.0` (the old slash syntax) without a warning (checked on the probe, Appendix A).<br>G5 holds | `deps: p256 0.14 (ecdsa only); deny BSD-3-Clause; unsafe record` |
| 4 | Q1 | `SO_PEERPIDFD`, fail-closed per Q1, and `require_peer(uid, gid)` | C-PID's checks and the C-UID unit tests pass on this kernel; CI branches on its kernel | `peercred: SO_PEERPIDFD fail-closed; gid check` |
| 5 | — | The lock file:<br>• std `File::try_lock`, not nix `fs`; this supersedes the `Flock` plan in AP, MG and WEEK1_PLAN §1.<br>• `<sock>.lock` is created in the checked parent with mode 0600 and owner euid.<br>• It is opened with `O_NOFOLLOW`, through std's `OpenOptionsExt::custom_flags(nix::libc::O_NOFOLLOW)`. nix re-exports libc unconditionally, so this needs neither nix's `fs` feature nor a new direct dependency (RV2; Appendix A).<br>• An fstat after open requires a regular file, mode 0600, owner euid and `nlink` 1.<br>• The lock is taken before any existing socket is unlinked.<br>• `bind_safe_listener` returns `BoundListener { listener, lock }`.<br>• `socket_is_live` and `PROBE_TIMEOUT` are removed: with the lock held, any existing socket is stale, which also closes the macOS backlog gap.<br>• flock semantics (AP item 2):<br>  – the lock belongs to the open file description, and does not interact with fcntl or OFD locks;<br>  – it works on overlayfs and on local named volumes;<br>  – NFS is forbidden for the socket volume, because flock there is emulated or unreliable. | C-LOCK passes, including "the agent cannot open the lock file" (the agent's group can read `/run/pep`, and flock works on a read-only descriptor) | `peercred: lock file held with the listener` |
| 6 | T1, R1, E1 | `src/tokens.rs`, shared by the PEP and the stub broker:<br>• ES256 JWS per T1;<br>• the Episode Token;<br>• the Call Proof, on every forwarded call, with `rid` for `Held` payments only;<br>• `prov` as the witness origin hashes (the former step 11);<br>• the replay cache with an injected clock. | Unit vectors:<br>• alg confusion and `typ` swap;<br>• header members outside the allowlist;<br>• the charset, padding and non-zero trailing bits;<br>• expiry and the idle timeout;<br>• a full cache that fails closed;<br>• low-S emitted, and high-S rejected by the broker;<br>• the clock high-water mark under an injected backward step;<br>• the broker's boot-second cutoff | `tokens: Episode Token, Call Proof, ReplayCache, prov` |
| 7 | D1, D2, M1, M2, P1, R1, E1, H1, U1, J1, L1, A1 | The binary, the stub broker, two stub tool servers, the scripted operator and the engine changes in §2a, plus:<br>• the R1 journal;<br>• the decision logs;<br>• J1's result number mode;<br>• the per-episode rate limit.<br>Conditions:<br>• Pins come from the config's `pins`, which is the unsigned lockfile v1 payload (L1). Step 10 adds the DSSE envelope and drift checks.<br>• Tokens are real from the start (step 6), with no placeholder checks.<br>• The broker credential is a 0400 file owned by uid 20003, outside the repo and OneDrive (§4); Vault is deferred.<br>• Every binary passes the macOS cross-lint, with Linux-only paths behind `cfg`.<br>• Binaries follow the logging rule in §6. | End to end over temp-directory sockets:<br>• a read, a payment, a step-up approval and a refusal;<br>• every P1 row and every router row in M1;<br>• `end_episode`;<br>• a restart that replays the journal | `bin: std-threads sidecar, transport, stubs` (several commits) |
| 8 | N1, B1 | `compose.yaml`, Dockerfiles, `seccomp-unix-only.json` and `.gitattributes`, per §4.<br>• `.gitattributes` sets LF for `*.sh`, `Dockerfile*`, `compose.yaml`, `*.nft` and `seccomp*.json`; SPEC and CLAUDE.md keep CRLF.<br>• B1's `Cargo.toml` and toolchain changes land here too. | The topology starts from the WSL-side clone. Volume owners and modes match §4. Posture checks pass. The step 7 flows pass in Compose | `compose: SPEC §1 topology` |
| 8b | N1 | nftables rules, only if N1 = (b) | Rule-set tests pass | `net: nftables rules` |
| 9 | S1, O1 | The bypass kit (§3) with expected verdicts, the oracle and the decision-log join (§2a), and the `probe` service. Also:<br>• the open-loop latency harness (PEP plus broker);<br>• a CI job that runs the checks and branches on kernel version;<br>• if they can run without fixture tools, the official MCP conformance suite's 2026-07-28 server scenarios [100], against the PEP in CI through a test-only TCP bridge. Its schema check validates every message on the wire. | The kit runs in CI, and the attack run passes in Compose on this machine. The first latency report exists | `test: Gate 1 kit and harness` |
| 10 | L1 | `src/lockfile.rs` (DSSE around the step 7 payload), `pep-sidecar lock-scan` and `pepctl lock sign`.<br>• Drift hashing uses the result number profile (J1) with larger caps; the request profile rejects ordinary schema values such as `"minimum": 0.5` and caps 8,192 nodes.<br>• Definitions with integers beyond ±(2^53−1) are quarantined only if J1 = (a).<br>• Every upstream page is fetched.<br>• The drift poller (L1).<br>• The strict argument schema, per-tool step-up, and a review of the F-13 read-only exception. | The 25 mutations, each quarantined within T, and the negatives (§3) | `lockfile: DSSE verify, drift quarantine, lock-scan and sign` |
| 11 | All G-criteria | The Gate 1 suite, run on the release profile in Compose | G1–G6 | `gate1: results` |

## 2a. Interfaces (proposals)
**Engine changes** (`src/engine.rs`; each with tests and under every CLAUDE.md §3 lint):
- **Forwarding (F-16).**
  - `Allowed` and `PendingApproval` replace `canonical_request` with `tool: String` and canonical `arguments: JcsValue`.
  - A new `forward::tools_call_request(upstream_id, tool, arguments, meta) -> Vec<u8>` builds the only bytes sent downstream, from the same pair that `action_digest` hashes, so the broker recomputes the same digest.
  - The agent's id and `_meta` never leave the PEP.
- **Results (M2, J1).**
  - `record_result_raw(..) -> Result<Vec<u8>, PepError>` requires `resultType == "complete"`. Otherwise, absent included, it returns a new `PepError::IncompleteResult`, which maps to `PEP_UNAVAILABLE`.
  - It drops the result's top-level `_meta` before labelling.
  - It returns exactly the canonical bytes it recorded, under J1's number mode. Those are the only result bytes the agent receives.
- **Quarantine.** G_pin denies a tool in a shared `Arc<QuarantineSet>` (new `PolicyError::ToolQuarantined`). Because it is a guard, F-09's ratchet still runs.
- **Reconcile check (P1).** `g_budget` denies a payment whose entity (after NFC) matches a `NeedsReconcile` reservation's `entity`, with a new `PolicyError::ReconcilePending`. `Reservation` already stores the entity. This is pure validation, so F-06 holds.
- **Ledger restore (R1).** `PepEngine::new` takes, behind `&HostAuthority`, the intent's journaled ledger:
  - committed spend;
  - calls;
  - entity uses;
  - unresolved reservations, inserted as `NeedsReconcile` with no funding witness.
- **Step 10:**
  - `ToolPolicy.step_up_over_minor: Option<u64>`, used by `g_stepup` as the smaller of the intent's and the tool's thresholds;
  - the strict argument schema, checked in `g_canon` (new `PolicyError::SchemaViolation`).
- **peercred:**
  - `require_peer(socket, uid, gid)`;
  - `BoundListener { listener, lock }`;
  - new `PeerError` variants for pidfd and lock failures.
- **jcs (J1 (b)):** a result number mode that keeps the digits of plain integer tokens beyond ±(2^53−1); the request profile is unchanged.

**Module layout.** The core is sans-IO: pure functions over byte buffers, so that Week 3's Tokio runtime reuses it.

| Module | Role |
|---|---|
| `src/http.rs` | The strict HTTP/1.1 subset (kept from AP):<br>• request line plus headers ≤ 16 KiB and ≤ 64 fields;<br>• an exact `Content-Length` only;<br>• reject `Transfer-Encoding`, duplicate or conflicting `Content-Length`, `Content-Encoding`, obs-fold, bare CR or LF, HTTP/1.0 and HTTP/2 prefaces;<br>• one request per connection (`Connection: close`);<br>• body ≤ 1 MiB;<br>• header and body deadlines through `set_read_timeout`. |
| `src/mcp.rs` | Header↔body checks, `_meta` checks in M1's order, the method router, error bodies (U1), and the one SSE writer (`subscriptions/listen`). There is no SSE reader: the broker answers JSON only. |
| `src/forward.rs` | Upstream request bodies and headers, and the JSON-only upstream response reader |
| `src/config.rs` | The config, parsed with `jcs` |
| `src/control.rs` | Control-socket messages |
| `src/journal.rs` | The R1 journal: payment records, the journal-backed `LabelStore`, and boot replay |
| `src/decision_log.rs` | Decision-log records (schema below) |
| `src/tokens.rs` | Step 6 |
| `src/lockfile.rs` | Payload parsing (step 7), then DSSE and drift (step 10) |
| `src/main.rs` | The `pep-sidecar` binary:<br>• std threads with a bounded connection count;<br>• one actor thread per episode (A1);<br>• connection threads verify Episode Tokens, apply the rate limit, and send agent messages to the episode's actor;<br>• the control thread sends host messages;<br>• a `lock-scan` subcommand (L1). |
| `src/bin/pepctl.rs` | `lock sign` and key generation (keys from `/dev/urandom`); Week 6 adds `explain` and `replay` |
| `src/bin/` stubs | The stub broker, the stub tool server and the scripted operator, under the same lints |

**Config** (JSON parsed by `jcs`, safe integers only; keys as SEC1 or JWK):

| Section | Fields |
|---|---|
| `agent` | `uid`, `gid`, `socket` |
| `operator` | `uid`, `socket` |
| `broker` | `uid`, `socket` |
| `pep` | `spiffe_id`, `pubkey_dir` |
| `lockfile` | `path`, `signers` (`role`, `key`), `min_accepted_epoch` (the rollback floor) |
| `journal` | `path` (R1) |
| `intents` | name → `PepIntent` plus its `SeqPolicy`; the Week 2 stand-in for RAR |
| `limits` | `connections`, `header_bytes`, `body_bytes`, `read_timeout_ms`, `upstream_timeout_ms`, `step_up_timeout_ms` (≤ 50,000), `episode_idle_ms`, `episodes`, `call_burst`, `call_rate_per_s`, `clock_skew_ms`, `replay_cache_entries`, `drift_poll_ms` |
| `pins` | The unsigned lockfile v1 payload (L1). Step 10 replaces it with the signed lockfile at `lockfile.path` |

**Control protocol** (H1, E1). The same HTTP subset carries one JSON request per connection, and the peer uid must be 20004.

| Call | Parameters | Result |
|---|---|---|
| `start_episode` | `intent` | `eid`, `episode_token`, `exp`. Refused once `limits.episodes` are live |
| `end_episode` | `eid` | —. Every later call with its token gets `PEP_DENIED`. `AwaitingStepUp` reservations get `abort(DefinitelyNotExecuted)`. In-flight upstream legs finish, and their outcomes apply. The journal keeps unresolved entries |
| `trusted_input` | `eid`, `input_id`, `value`, `conf` | — |
| `pending` | — | Awaiting approvals: `eid`, `rid`, `tool`, `arguments`, `action_digest`, `amount_minor` |
| `approve` / `decline` | `eid`, `rid`, `action_digest`, `amount_minor`, all matched against the `AwaitingStepUp` reservation | — |

**PEP↔broker.**
- **Transport:** Streamable HTTP over `/run/broker/broker.sock`, JSON only in both directions, with mutual peer-uid checks (the broker requires 20002, the PEP requires 20003); SPIFFE is deferred.
- **What it carries:**
  - `tools/call`, always with a Call Proof (T1);
  - proof-less `tools/list` and `server/discover`, for drift polls and `lock-scan`.

  The broker forwards a proof-less request only for those two methods.
- **Routing:** `/mcp/{server_id}`, from the lockfile.
- **Broker duties:**
  - verify the Call Proof (T1), including `iat` after its boot second;
  - recompute `action_digest` and, for payments, the F-07 key;
  - inject the credential and `Idempotency-Key`;
  - forward to the tool server over `tools_net`, keeping the PEP-assigned JSON-RPC id;
  - answer the PEP with JSON only;
  - write its log (schema below).
- **Outcomes.** For payments, the broker adds `_meta["dev.pep-sidecar/outcome"]` (`executed`, `refused` or `unknown`), after stripping any `dev.pep-sidecar/*` key the tool server sent. A Call Proof the broker rejects gets `refused` with no tool result.

**Stub tool servers** (two servers, for mutations #12 and #25):
- **Tools:** the Week 1 test set: a bound lookup (`get_invoice`), a payment (`pay_invoice`), a sink, and a store writer.
- **Replies:** JSON only.
- **Payment status.** Payment results carry an explicit `status` (`executed`, `declined` or `pending`), which the broker maps to the outcome.
- **Bookkeeping:**
  - `Idempotency-Key` dedupe, in a store on the server's own volume that survives PEP and broker restarts;
  - a JSONL execution log (schema below).
- **Misbehaviour modes** come from the server's own start-up config, never from the agent:
  - wrong response ids;
  - two responses in one body;
  - oversized and endless (slow-drip) responses;
  - `input_required`;
  - definition changes between polls, including changes on page 2 only;
  - `x-mcp-header` annotations, for #19.

**Decision logs.** Each component writes JSONL, one JCS-canonical object per line with `"v": 1`, to a file on its own volume. The oracle reads them through read-only mounts. The PEP's record is also what Week 6's receipts build on.

| Log | Fields |
|---|---|
| PEP decision | `ts_ms`, `eid`, `seq`, `peer_uid`, `method`, `tool`, `action_digest`, `verdict` (`allow`, `deny`, `step_up`, `unavailable` or `protocol_error`), `reason` (the guard or error variant; host-side only, never sent to the agent), `rid`, `amount_minor`, `currency`, `entity`, `jti`, `idempotency_key`, `upstream_id`, `outcome` (`executed`, `refused`, `unknown`, `abandoned` or `not_forwarded`), `pep_us` |
| Broker | `ts_ms`, `jti`, `server_id`, `method`, `upstream_id`, `action_digest` (recomputed), `idempotency_key`, `verdict` (`forwarded` or `rejected`), `reason`, `outcome`, `broker_us` |
| Tool server | `ts_ms`, `server_id`, `upstream_id`, `tool`, `action_digest` (recomputed with the shared `jcs`), `idempotency_key`, `executed` (`false` for a dedupe hit) |

No log ever holds raw tokens, proofs, keys, credentials, or argument values other than the bound entity, amount and currency.

**Bypass oracle.**
- **Expected verdicts.** Every attack test declares what it expects: `deny` (nothing may execute) or `allow` with an exact count of executions. The PEP's own log is never the ground truth: any execution of a call that was expected to be denied is a bypass, whatever the PEP logged (RV2).
- **Windows.** Tests run one at a time. For each test, the oracle reads every log from the offset at the test's start up to `upstream_timeout_ms` after its last request, so every upstream leg has finished.
- **The join.** The tool server never sees `jti`, so the broker's log is the link:
  1. tool log (`server_id`, `upstream_id`, `idempotency_key`);
  2. broker log (`upstream_id` → `jti`, recomputed `action_digest`, F-07 key);
  3. PEP decision log (`jti` → an `allow`).
- **A bypass is:**
  - any execution in a test that expects `deny`;
  - an execution that does not join through the broker log to a PEP `allow`;
  - more executions than the test declares;
  - a payment whose `Idempotency-Key` is not the F-07 key of a reservation the PEP held;
  - for attacks that execute nothing (C-NET, C-PROC, C-LOCK, C-CRED, C-CTL), the attempt succeeding.

## 3. Gate 1 suite
### Containment (62 attack tests count toward G1; 45 checks run in CI)
Only the attack column counts toward G1's ≥ 50, and only when run in Compose on this machine (RV2).
- **Attacks** are bypass attempts. The C-UID probes run from the `probe` service with group 20001, so each one passes the socket's 0660 mode and reaches `accept()`.
- **Checks** are conformance tests, posture checks, and tests that need a test hook, an injected error or an older kernel. They run in CI, and in Compose where they can. They must pass, but they don't count.

| Category | Attacks (count toward G1) | Checks (not counted) |
|---|---|---|
| C-UID | 4, from the `probe` service:<br>• wrong uid (`20009:20001`);<br>• root (`0:20001`);<br>• overflow uid 65534 (`65534:20001`);<br>• uid right but gid wrong (`20001:20009`, with group 20001 supplementary), rejected under Q1 | 1:<br>• socketpair self-connect (unit) |
| C-PID | — | 6:<br>• a getsockopt error rejects (injected errno);<br>• fdinfo `Pid: -1` rejects (fdinfo parser);<br>• the peer exits between accept and check (test hook);<br>• `Pid: 0` is handled per Q1;<br>• `ENOPROTOOPT` rejects (injected errno: this needs a kernel older than 6.5);<br>• no pidfd leaks (cloexec) |
| C-LOCK | 2:<br>• the agent cannot open the lock file;<br>• the agent cannot create or replace an entry in `/run/pep`, such as a planted symlink | 5:<br>• a second instance is blocked;<br>• a stale socket is replaced only under the lock;<br>• the lock is released on a crash;<br>• a read-only lock directory fails;<br>• a symlink planted at the socket path is refused (`UnsafePath`) |
| C-NET | 7, from the agent:<br>• no route;<br>• no DNS;<br>• no way into `tools_net` (the broker and the tool servers);<br>• no IPv6;<br>• raw and packet sockets fail;<br>• UDP/53 fails;<br>• DoH (TCP/443 to a resolver) fails | 1:<br>• only `lo` is present |
| C-PROC | 3:<br>• ptrace of the PEP fails, or, under Q1 (i), the PEP pid is not visible;<br>• `/proc/<pep>/mem` is unreadable;<br>• the PEP's argv and env hold no key or credential | 1:<br>• the agent's argv and env hold no Episode Token (E1: it arrives on stdin) |
| C-POSTURE | — | 5:<br>• every container has CapEff 0;<br>• NoNewPrivs 1;<br>• Seccomp 2, with the AF_UNIX-only profile on the agent, the PEP, the operator and the probe;<br>• no container mounts `docker.sock`;<br>• the agent's `pids_limit`, memory limit and private `/tmp` are in effect |
| C-HTTP | 12:<br>• CL+TE;<br>• TE only;<br>• duplicate CL;<br>• CL mismatch;<br>• obs-fold;<br>• bare LF;<br>• header over the cap;<br>• body over the cap;<br>• slowloris headers;<br>• slow body;<br>• a pipelined second request;<br>• `Content-Encoding` | 5:<br>• HTTP/1.0;<br>• an HTTP/2 preface;<br>• GET → 405;<br>• DELETE → 405;<br>• a notification POST → 400, except `notifications/cancelled` → 202, ignored |
| C-MCP | 6:<br>• the version header differs from `_meta` → -32020;<br>• `Mcp-Method` differs from the body → -32020;<br>• `Mcp-Name` differs from the body → -32020;<br>• a base64-sentinel `Mcp-Name` mismatch → -32020;<br>• a batch array body → 400;<br>• any `Mcp-Param-*` header → -32020 | 11:<br>• missing `MCP-Protocol-Version` → -32020;<br>• a JSON-RPC response as the body → 400;<br>• any `Origin` → 403;<br>• an unsupported version → -32022;<br>• `Accept` without `text/event-stream` → 400;<br>• missing `_meta` `protocolVersion` → -32602;<br>• missing `_meta` `clientCapabilities` → -32602;<br>• `server/discover` answered without upstream `instructions`;<br>• `subscriptions/listen` acknowledged first (subscription id, empty filter), then completed and closed, with no `notifications/cancelled`;<br>• `Mcp-Name` base64 with NFC compared correctly;<br>• every PEP result carries `resultType`, and discover and list results carry `ttlMs` and `cacheScope` as M1 sets them |
| C-FWD | 3:<br>• no agent header (`Authorization`, `Idempotency-Key`, `Mcp-Param-*`, `Pep-Episode`) reaches upstream;<br>• upstream `_meta` holds only PEP-built keys (the agent's `traceparent`, `logLevel`, `progressToken` and unknown keys are absent);<br>• the upstream id is PEP-assigned | 1:<br>• the upstream body equals the `forward::tools_call_request` output byte for byte |
| C-RES | 3:<br>• an `outcome` key forged by the tool server is stripped and never trusted;<br>• a response id mismatch;<br>• two responses in one body | 3:<br>• an unknown or absent `resultType`;<br>• `input_required` is not recorded, and a payment's reservation becomes `NeedsReconcile`;<br>• an SSE reply from the broker is invalid |
| C-JSON | 6:<br>• duplicate keys (`name` twice), checked against the forwarded body;<br>• NaN or Infinity;<br>• lone surrogates;<br>• a depth bomb;<br>• a huge number;<br>• a BOM | — |
| C-EPI | 8, Episode Token:<br>• missing;<br>• malformed (charset, padding, non-zero trailing bits);<br>• a header member outside `alg`, `typ` and `kid`;<br>• forged signature;<br>• expired or idle;<br>• `peer_uid` mismatch (replacing AP's "wrong `aud`": the token has no `aud`);<br>• a Call Proof presented as an Episode Token;<br>• the token of an ended episode | — |
| C-CRED | 1:<br>• the agent and the PEP cannot read the broker credential | 1:<br>• the tool server rejects calls without it (from a probe on `tools_net`) |
| C-CTL | 1:<br>• the agent cannot reach `/run/pep-ctl` | 4:<br>• an approval with any of (eid, rid, `action_digest`, amount) mismatched is refused;<br>• a declined step-up leaves the reservation `Released`, and the agent gets `PEP_DENIED`;<br>• an approval that arrives after the agent disconnected is refused;<br>• after `end_episode`, later calls are denied and in-flight legs finish |
| C-OUT | 6:<br>• an agent disconnect after forwarding never releases the reservation;<br>• a `notifications/cancelled` naming a forwarded payment's id never releases the reservation;<br>• a retry after `Unknown` with a changed `/memo` (a new `action_digest`) → `ReconcilePending`;<br>• a PEP restart mid-payment: the next episode of that intent starts with the reservation `NeedsReconcile` (R1 (a));<br>• an agent write before a PEP restart is still tainted after it (R1 (a));<br>• a burst over the per-episode bucket is refused and issues no Call Proof | 1:<br>• denials from every guard have identical wire bytes apart from the id |

Under R1 (b), the two restart attacks are dropped and the accepted risk recorded instead, which leaves 60.

### Rug-pull mutations (G2: every one quarantined within T)
Each mutation must lead to quarantine within T (L1): the tool is hidden from `tools/list`, its calls are denied (`ToolQuarantined`), and no call reaches it after detection.

The model is Invariant Labs' "MCP Security Notification: Tool Poisoning Attacks" (2025-04-01) [101], which defines three attacks:
- **tool poisoning:** hidden instructions in a tool's description, such as an `<IMPORTANT>` block;
- **rug pulls:** "a malicious server can change the tool description after the client has already approved it";
- **shadowing:** "A malicious server injects a tool description that modifies the agent's behavior with respect to a trusted service or tool". Its example is a malicious `add` tool whose description redirects a trusted server's `send_email`.

Its mitigation for rug pulls is pinning tool descriptions "using a hash or checksum", which L1 does. The mutations:
1. description reworded;
2. hidden instruction appended to the description;
3. instruction inside an `<IMPORTANT>`-style tag;
4. instruction in a parameter description;
5. new `inputSchema` property;
6. property type changed;
7. `required` changed;
8. `outputSchema` added or changed;
9. tool added;
10. tool removed;
11. tool renamed;
12. the same name on a second server: a name collision. This is not Invariant's shadowing (that is #25). A name pinned on two servers is a load error (L1), and a server that later adds a colliding name has an unpinned tool, which is hidden and denied. This needs two stub servers and per-server identity in the lockfile;
13. `readOnlyHint` true→false;
14. `destructiveHint` false→true;
15. `idempotentHint` or `openWorldHint` flipped;
16. Cyrillic homoglyph in the name. The ASCII-name rule rejects it at load;
17. zero-width joiner in the description;
18. bidi override in the description;
19. `x-mcp-header` annotation added. Week 2 rejects the annotation at load, so the definition digest changes and the tool is quarantined. The stub emits it;
20. a definition changed between two polls, with or without a `notifications/tools/list_changed`. The PEP polls, so the notification is not needed;
21. title or icon change on a security-role tool;
22. default value injected into the schema;
23. an integer beyond ±(2^53−1) changed. Under J1 (b) the digest keeps exact digits and changes; under J1 (a), definitions with such integers are quarantined at load;
24. a definition changed on page 2 only;
25. cross-server shadowing, in Invariant's sense. After pinning, a tool on server B gains description text that tells the agent how to use server A's `pay_invoice`, for example to pay another recipient. That is a description change on B, so B's tool is quarantined.
    - A description that shadows from the start is not drift. Lockfile review must catch it.
    - G_entity, F-14 and the sink clearances limit what a redirected call can do, which is Invariant's third mitigation, "Cross-Server Protection".

**Negatives**, which must not trigger drift:
- key reordering;
- whitespace;
- equivalent number formatting (`0.50` and `0.5` under the result profile);
- a `\u` escape versus the literal code point;
- the same list split across pages differently.

### Replays (G3: 0 of 1,000 accepted)
Captured Episode Tokens and Call Proofs, for reads as well as payments, are replayed in Compose:
- verbatim;
- after `exp`;
- against a different `rid`;
- after the reservation leaves `Held`;
- with a malleated high-S signature (same `jti`);
- re-encoded with padding, the standard alphabet, or non-zero trailing bits, all rejected by the strict decoder;
- concurrently from N threads, where exactly one first use is accepted;
- after a PEP restart, with a key from the previous boot;
- after a broker restart, with a proof issued before the broker booted, including one issued in the broker's boot second;
- with `typ` and key confused: an Episode Token presented as a Call Proof, and the reverse.

**In-process, beside G3:** after the clock is stepped back, against the replay cache's injected clock (step 6).

### p99 (G4)
Measured as O1 defines it: the PEP plus the broker, with the PEP alone beside it. Reported with p50, p99.9, max, the CPU model and the load profile.

## 4. Containers
**Where Compose runs.** From a clone on WSL's own filesystem (for example `~/src/agent-authority-fabric`), never from `/mnt/c`:
- on `/mnt/c`, a chown to uid 20003 doesn't stick without the drvfs `metadata` mount option;
- the repo sits in OneDrive.

The broker credential lives in `$PEP_SECRETS_DIR`, outside the repo and outside OneDrive (for example `~/.config/pep-gate1/secrets`), so OneDrive never syncs it to the cloud. `.gitignore` lists `secrets/` as a backstop.

A Compose sketch (step 8 verifies every key against the Compose reference [80]):

```yaml
name: pep-gate1
services:
  agent:                       # Gate 1 test client (TS or Python SDK)
    user: "20001:20001"
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true", "seccomp=./seccomp-unix-only.json"]
    network_mode: "none"
    pids_limit: 256
    mem_limit: 1g
    tmpfs: ["/tmp:size=64m,mode=1777,nosuid,nodev,noexec"]
    volumes:
      - { type: volume, source: pep-sock, target: /run/pep, volume: { nocopy: true } }
    # pid: "service:pep"       # only if Q1 = (ii)
  probe:                       # C-UID attacks; `docker compose run --user` sets each uid:gid
    profiles: [gate1]
    user: "20009:20001"
    group_add: ["20001"]       # so every probe passes the socket's 0660 mode and reaches accept()
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true", "seccomp=./seccomp-unix-only.json"]
    network_mode: "none"
    volumes:
      - { type: volume, source: pep-sock, target: /run/pep, volume: { nocopy: true } }
  pep:
    user: "20002:20002"
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true", "seccomp=./seccomp-unix-only.json"]
    network_mode: "none"
    volumes:
      - { type: volume, source: pep-sock,    target: /run/pep,     volume: { nocopy: true } }
      - { type: volume, source: pep-ctl,     target: /run/pep-ctl, volume: { nocopy: true } }
      - { type: volume, source: pep-pub,     target: /run/pep-pub, volume: { nocopy: true } }
      - { type: volume, source: broker-sock, target: /run/broker,  volume: { nocopy: true } }
      - { type: volume, source: pep-state,   target: /var/lib/pep }   # R1 journal, decision log
      - { type: bind, source: ./config/pep, target: /etc/pep, read_only: true }
  broker:
    user: "20003:20003"
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    networks: [tools_net]
    volumes:
      - { type: volume, source: broker-sock,  target: /run/broker,     volume: { nocopy: true } }
      - { type: volume, source: pep-pub,      target: /run/pep-pub,    read_only: true, volume: { nocopy: true } }
      - { type: volume, source: broker-state, target: /var/lib/broker }   # broker log
      - { type: bind, source: "${PEP_SECRETS_DIR:?set PEP_SECRETS_DIR}/broker-credential", target: /run/credential, read_only: true }
  operator:                    # scripted operator (H1)
    user: "20004:20004"
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true", "seccomp=./seccomp-unix-only.json"]
    network_mode: "none"
    volumes:
      - { type: volume, source: pep-ctl, target: /run/pep-ctl, volume: { nocopy: true } }
  tool-a: &tool                # stub tool servers; any unprivileged uid
    user: "20005:20005"
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    networks: [tools_net]
    environment: { TOOL_SERVER_ID: "a" }
    volumes:
      - { type: volume, source: tool-a-state, target: /var/lib/tool }   # dedupe store, execution log
  tool-b:                      # second server, for mutations #12 and #25
    <<: *tool                  # `<<` replaces whole keys, so per-server keys are restated in full
    environment: { TOOL_SERVER_ID: "b" }
    volumes:
      - { type: volume, source: tool-b-state, target: /var/lib/tool }
volumes:
  pep-sock:     { driver: local, driver_opts: { type: tmpfs, device: tmpfs, o: "uid=20002,gid=20001,mode=2750" } }
  broker-sock:  { driver: local, driver_opts: { type: tmpfs, device: tmpfs, o: "uid=20003,gid=20002,mode=2750" } }
  pep-ctl:      { driver: local, driver_opts: { type: tmpfs, device: tmpfs, o: "uid=20002,gid=20004,mode=2750" } }
  pep-pub:      { driver: local, driver_opts: { type: tmpfs, device: tmpfs, o: "uid=20002,gid=20003,mode=2750" } }
  pep-state:    {}             # on disk; owner 20002 and mode 0700 come from the image's /var/lib/pep
  broker-state: {}
  tool-a-state: {}
  tool-b-state: {}
networks:
  tools_net: { internal: true }
```

- **Socket directories.** They must exist before the PEP starts, with the owners and modes above. Otherwise `bind_safe_listener` refuses: the parent must be owned by the euid with `mode & 0o027 == 0`, and setgid gives the socket the parent's group.
  - **Why named volumes.** A tmpfs-backed *named* volume is shared between containers. A per-service `tmpfs:` entry would give each container a private copy, which is what the agent's `/tmp` wants.
  - **`nocopy: true`.** It stops Docker copying image contents into a fresh volume. Some engines also copy the image directory's owner and mode even when it is empty, so step 8 checks owner and mode at start.
- **State volumes.** `pep-state` and the other `*-state` volumes are on disk, not tmpfs, so the journal and the tool servers' dedupe stores survive restarts. They take their owner and mode from the image's directory on first use, which step 8 checks.
- **Images:**
  - a real `/run` owned by root and not a symlink, because `bind_safe_listener` checks every ancestor;
  - B1 decides between static musl and a glibc-matched base.
- **The AF_UNIX-only seccomp profile** (`seccomp-unix-only.json`). Docker's default profile, minus every socket family except `AF_UNIX`. It applies to the agent, the PEP, the operator and the probe; the broker and the tool servers need inet and keep Docker's default. The denial returns `EAFNOSUPPORT` rather than killing the process, so SDKs fail cleanly.
- **Agent limits.** `pids_limit`, `mem_limit` and a private, size-capped `/tmp` (RV2). The root filesystem stays read-only.
- **Secrets:**
  - Compose ignores `uid`, `gid` and `mode` on file secrets [80], so the broker credential is a host file that is already 0400 and owned by 20003, bind-mounted read-only into the broker only;
  - the PEP's own keys are per-boot (R1), so they need no secret.
- **Host user 20004.** The operator uid is new. SPEC §1 gains it in step 2.

## 5. Forward constraints (decided now so Week 2 does not paint later weeks into a corner)
- **Week 3:**
  - Tokio reuses the sans-IO modules of §2a, and A1's per-episode actors become `EpisodeActor`s, so the std-threads binary is not rewritten.
  - SQLite replaces the R1 journal and the in-memory label store.
  - Reconciliation of `NeedsReconcile` replaces the P1 entity check.
- **Week 4:**
  - The agent reaches its LLM through N1's Unix-socket model proxy.
  - AgentDojo has its own tool runtime, so it needs an adapter.
  - The agent harness builds TypeScript clients pinned to `2026-07-28`, with undici's own `fetch` and `Agent`, and Python clients on an httpx2 `uds` transport with `trust_env=False` (D2).
  - Step-up approvals longer than 50 s need one of two things from the agent's client. Either it raises its request timeout, or it opts into `resetTimeoutOnProgress` and sends a `progressToken` that the PEP answers with progress notifications. `:` keep-alives alone do not stop the TypeScript SDK's 60 s timer (P1).
  - J1's choice shows up in Gate 2's utility figure.
- **Week 5:**
  - The PEP reaches the Txn-Token service and the PDP through N1's chosen egress path.
  - `tth` and the Week 5 claim values arrive.
  - Real tool servers may answer SSE, so the broker, not the PEP, gains an SSE reader.
  - `x-mcp-header` support, if a pinned server needs it, comes back with `Mcp-Param` checks.
- **Latency.** The worst-case 1 MiB request is measured separately (O1), because hashing cost grows with bytes × depth.

## 6. Proposed SPEC and CLAUDE.md wording
Nothing here is applied by this document.
- **SPEC.md:** each item is applied in step 2 when its decision closes, keeping CRLF.
- **CLAUDE.md:** owned by you, also CRLF; you apply it.

**SPEC.md:**
- **§1, containment (N1, H1, R1, Q1, T1):**
  - Name the Compose network model.
  - Add these sockets and directories:
    - the broker socket `/run/broker/broker.sock`, in a directory owned 20003:20002 with mode 2750;
    - the control socket `/run/pep-ctl/ctl.sock`, in a directory owned 20002:20004 with mode 2750, with operator uid 20004;
    - `/run/pep-pub` for the Call Proof public key;
    - under R1 (a), the PEP's journal on an on-disk volume that only the PEP mounts.
  - State that the socket directories are tmpfs-backed named volumes.
  - "The broker authenticates the PEP by `SO_PEERCRED` uid 20002 until SPIFFE (deferred)."
  - "The broker forwards `tools/call` only with a valid Call Proof. It forwards proof-less `tools/list` and `server/discover` from the PEP, for drift checks and lock scans, and no other proof-less method."
  - "Across PID namespaces, `SO_PEERPIDFD` proves only that the peer is alive; identity rests on the `SO_PEERCRED` uid and gid."
  - "The agent, the PEP and the operator run under an AF_UNIX-only seccomp profile."
  - "Vault credential injection is deferred; the Week 2 broker reads a credential file."
  - "The PEP rejects an upstream result with no `resultType`. This departs from MCP 2026-07-28's client rule for earlier-revision servers, because every pinned server implements 2026-07-28." (M2)
  - Append to the `pep` sidecar bullet: "Speaks MCP `2026-07-28` Streamable HTTP to the agent over that socket: a hand-rolled HTTP/1.1 subset (POST only, exact `Content-Length`, one request per connection), with no TCP listener; the Episode Token travels in `_meta` (§3.3)." (D2; applied 2026-11-03)
- **§3.3, Episode Token (E1, R1):**
  - "Minted by the PEP on the host `start_episode` call and revoked by `end_episode`; idle timeout 30 minutes; signed with a per-boot key, so a PEP restart invalidates every token; delivered to the agent on stdin."
  - "No `iss`, `aud`, `jti` or `nbf`: the PEP is the only issuer and verifier; the `typ` and key differ from the Call Proof's, which makes the two validations mutually exclusive."
- **§3.4, Call Proof (T1, R1):**
  - Replace "Call Proofs are issued only for `Held` reservations (…)" with "Every forwarded `tools/call` carries a Call Proof. Payment proofs add `rid` and are issued only for `Held` reservations (never for `AwaitingStepUp`, `Released` or `NeedsReconcile`)."
  - `typ` becomes `pep-callproof+jwt`.
  - "The protected header holds only `alg`, `typ` and `kid`; tokens are decoded as strict base64url."
  - Give concrete `iss` and `aud`, the server binding, and definitions of `budget`, `tool_schema_digest` and `prov` (the witness origin hashes).
  - List the checks the broker performs.
  - "Signatures use low-S; the broker rejects high-S."
  - "The broker rejects proofs whose `iat` is not after its boot second."
  - "The replay cache's capacity follows from the per-episode rate limit and the episode cap."
  - "`tth` is added in Week 5."
- **§4:**
  - **Week 2:** replace "Call Proof with `rid` for `Held` reservations only" with "Call Proof on every forwarded `tools/call`, with `rid` on payments, which must be `Held`". Week 2 also gains:
    - the binary;
    - the transport (D2; applied 2026-11-03);
    - Compose;
    - the stub broker and tool servers;
    - `pep-sidecar lock-scan` and `pepctl lock sign`;
    - strict argument schemas;
    - the R1 journal.
  - **Gate 1:**
    - "evaluated on the Compose profile, on the evaluation machine; ≥ 50 attack tests, with conformance checks run separately" (S1, G1);
    - "quarantined within the detection window T" (G2);
    - "added latency of the PEP plus the broker" (O1, G4).
  - **Week 3:** "SQLite replaces the Week 2 journal; reconciliation replaces the Week 2 `NeedsReconcile` entity check".

**CLAUDE.md** (wording for you to apply):
- **§2 (once `compose.yaml` exists):** add `docker compose config --quiet` to the loop.
- **§3, new rule "Binaries":** "Binaries log with `writeln!` to a locked `stderr` handle and return `std::process::ExitCode` from `main`. `print_stdout`, `print_stderr` and `exit` stay denied. Never log raw tokens, proofs or keys."
- **Two-Phase Budget, append (R1 (a)):** "Journal and fsync each payment reservation and each F-08 taint record before the call is forwarded; at boot, unresolved reservations return as `NeedsReconcile` and count against their intent."
- **F-11/F-12, append:** "Before unlinking or binding, take an exclusive `File::try_lock` on `<socket>.lock`, opened with `O_NOFOLLOW` (`nix::libc::O_NOFOLLOW` through `custom_flags`) and checked by fstat (regular file, mode 0600, owner euid, `nlink` 1), and hold it for the listener's lifetime."
- **F-13, replace the second sentence:** "Agent connection threads never hold `HostAuthority`; they send an episode's actor messages that cannot express approve, trusted input, end or abort. `approve_step_up`, `record_trusted_input` and `end_episode` run only for control-socket messages from the operator uid, and abort outcomes come only from the upstream leg." At step 10, also replace "(until the Week 2 lockfile pins full argument schemas)" with the rule the strict schemas set.
- **F-16, replace:** "Only bytes built by `forward::tools_call_request` from the engine's canonical tool name and arguments, with a PEP-built `_meta`, are sent downstream; never the agent's wire bytes, id or `_meta`."
- **§1:** change only if D1 = A.

## Out of scope (later weeks)
- **Week 3:**
  - the automaton;
  - SQLite persistence;
  - the Tokio runtime;
  - reconciliation of `NeedsReconcile`;
  - deferred entity scopes.
- **Week 4:**
  - the AgentDojo benchmark;
  - the model-provider egress proxy (chosen in N1, built in Week 4);
  - step-up approvals longer than 50 s (P1).
- **Week 5:**
  - RAR and ID-JAG exchange;
  - the Txn-Token service and `tth`;
  - AuthZEN, AP2 and Stripe;
  - SPIFFE identities;
  - Vault;
  - SSE from real tool servers, read by the broker.
- **Deferred by this plan:**
  - the same-host process profile and gVisor (S1);
  - cgroup-eBPF, Landlock and Yama (N1);
  - hot lockfile reload (L1);
  - `destructive` and `code_exec` tools (L1);
  - `x-mcp-header` and `Mcp-Param-*` support (L1);
  - upstream `subscriptions/listen` streams; the PEP polls instead (L1);
  - `leaf_index` matches in `prov` (T1);
  - dynamic sinks (`clearance_lookup`) and `role_contracts` (L1).

## Risks
- **Schedule.** RV2 sized the 31 Oct draft at two to three weeks of work. This draft adopts RV2's four cuts and adds the journal, so it is still more than one week. The order puts the security foundations first (steps 3–6), so a slip delays Gate 1 rather than weakening it.
- **User namespaces.** Under userns-remap or rootless Docker, uids are translated, so `require_peer` must compare uids as the PEP's user namespace sees them. The cross-namespace test showed this: a peer with uid 1000 appeared as uid 0 to a listener in a user namespace that maps 1000 to 0 (Appendix A). Test on the actual runtime (AP's Q2).
- **HTTP smuggling.** Only the strict parser stands between the agent and request smuggling, so any regression there is a security bug (C-HTTP).
- **A young MCP revision.** 2026-07-28 is three months old, and SDKs and servers may diverge from it, for example on the `subscriptions/listen` reply or on `resultType`. The spec itself is ambiguous on whether a server-closed subscription also needs `notifications/cancelled`; both SDKs misread a server that sends it (M1). The TypeScript SDK v2 still defaults to the 2025 handshake (D2). Re-check the Appendix A pages before Gate 1.
- **Restarts.**
  - Under R1 (a), a restart keeps budgets and taint, but voids every token, so the operator must start episodes again.
  - Under R1 (b), a restart refunds every budget, forgets every `NeedsReconcile` and in-flight payment, and forgets agent-write taint. That is an accepted Gate 1 risk, in those words.
- **Step-up timeouts.** Approvals that take longer than 50 s fail in Week 2 (P1).
- **Result fidelity.** JavaScript agents round big integers themselves, whatever J1 decides, and NFD strings cannot round-trip through the PEP (F-05).
- **The seccomp profile.** Blocking non-`AF_UNIX` sockets may break an SDK, or a library in the PEP's image, that opens an inet socket at start-up. The profile returns `EAFNOSUPPORT`, so such failures are visible.
- **Kernel drift.** CI's runner kernel (7.0, azure) is newer than this machine's (6.18.54) (Q1). Tests branch on version and record `uname -r`. `ubuntu-latest` moves to Ubuntu 26.04 in November 2026 [99]. CI pins `ubuntu-24.04`, so a kernel change there is a deliberate edit.
- **Young crates.**
  - p256 0.14.0 (2026-07) and crypto-bigint 0.7.x are recent.
  - p256's docs say its arithmetic was never independently audited.
  - That matters more for signing Call Proofs, where the secret key is used, than for verification.
  - Sign and verify take about 0.57 ms each on this machine, slower than RV's 0.34 ms. A1 keeps that cost off a shared thread.
- **OneDrive.** A credential created anywhere under the repo would sync to the cloud (§4).

## Appendix A. Verification notes (2026-10-31, re-checked 2026-11-03)
**Repo at `bb25e27`:**

| Claim | Evidence |
|---|---|
| `MAX_IN_FLIGHT` is 64 | `src/engine.rs:43` |
| Agents see only two codes | `src/engine.rs:271` (`to_agent_code`) |
| Four effect classes | `src/engine.rs:645` (`EffectClass`) |
| Two entity kinds; eight argument roles | `src/engine.rs:658` (`EntityKind`); `src/engine.rs:667-684` (`ArgRole`) |
| `AmountBinding` has five fields; trusted result pointers sit under `/structuredContent/` | `src/engine.rs:698-709`; `src/engine.rs:24` |
| `ToolPolicy` pins `output_label`, `trusted_fields` and result limits | `src/engine.rs:729-737` |
| `SeqPolicy` is a `PepEngine::new` parameter, apart from the intent and the pins | `src/engine.rs:1270-1275` |
| The test config sets `per_entity_max_uses: 2`; `pay_invoice` has a `Data` `/memo` | `src/engine.rs:2927`; `src/engine.rs:2817` |
| The label store is in memory | `src/engine.rs:585` (`InMemoryLabelStore`) |
| `Reservation` stores its entity | `src/engine.rs:873-890` |
| `HostAuthority` is claimed once and cannot be cloned | `src/engine.rs:1115-1131` |
| `Allowed` and `PendingApproval` carry `canonical_request` | `src/engine.rs:1068-1096` |
| `record_result_raw` never reads `resultType` | `src/engine.rs:1305` |
| `approve_step_up` takes only the reservation id | `src/engine.rs:1439` |
| `canonical_request` is the whole agent request | `src/engine.rs:1585` |
| `commit` leaves `in_flight` | `src/engine.rs:1766-1790` |
| `abort` removes `in_flight` | `src/engine.rs:1834` |
| `g_canon` allows only `name`, `arguments` and `_meta` in params, and checks only the reserved prefix in `_meta` | `src/engine.rs:2180-2202` |
| The reserved-prefix rule | `src/engine.rs:2225` (`is_reserved_meta`) |
| `g_budget` | `src/engine.rs:2425-2485` |
| `g_stepup` uses only the intent's threshold | `src/engine.rs:2545` |
| `witness_prov` yields at most two hashes (amount, currency) | `src/engine.rs:2550` |
| A non-reserved `_meta` member (`progressToken`) is forwarded | `src/engine.rs:4754` (test) |
| `require_peer_uid` checks the uid only | `src/peercred.rs:177` |
| `bind_safe_listener` | `src/peercred.rs:204` |
| The probe's two gaps, which a lock would close | `src/peercred.rs:307-318` |
| The socket must carry the parent's group | `src/peercred.rs:335` (`verify_bound`) |
| The request profile caps 8,192 values | `src/jcs.rs:22` |
| Number modes and parse profiles; results use `EcmaAny` | `src/jcs.rs:173-225` |
| F-13 contains "until the Week 2 lockfile pins full argument schemas" in the repo copy | `CLAUDE.md:85` (re-checked 2026-11-03) |
| `print_stdout`, `print_stderr` and `exit` are denied | `Cargo.toml`, `[lints.clippy]` |
| No dev-dependencies, so `cargo tree` sees no test-only getrandom | `Cargo.toml` |
| Allowed licences are MIT, Apache-2.0 and Unicode-3.0; `multiple-versions` and `yanked` are denied | `deny.toml` |
| SPEC.md and CLAUDE.md are CRLF; WEEK1_PLAN.md and this plan are LF; there is no `.gitattributes` | `file`, and a CRLF count |

**Dependencies:**
- **nix 0.31.3:**
  - `sockopt::PeerPidfd` is at `src/sys/socket/sockopt.rs:687`, and there is no `SO_PASSRIGHTS` sockopt;
  - `OFlag` requires the `fs` or `term` feature (`src/fcntl.rs:116-119`), but `O_NOFOLLOW` does not need it: nix re-exports libc unconditionally (`src/lib.rs:107`, `pub use libc;`), so `nix::libc::O_NOFOLLOW` works with std's `custom_flags`.
- **base64 0.23.1:** `URL_SAFE_NO_PAD` uses the `NO_PAD` config, which decodes with `DecodePaddingMode::RequireNone` (`src/engine/general_purpose/mod.rs:499-501`) and "does not allow trailing bits when decoding" (its doc).
- **p256 0.14.0 [78]:**
  - `default` = `arithmetic`, `ecdsa`, `pem`, `precomputed-tables` and `std`;
  - `std` enables `getrandom`;
  - `ecdsa` = `arithmetic`, `ecdsa-core/algorithm` and `sha256`.
- **elliptic-curve 0.14.3 [79]:** `getrandom` comes only through its own feature.

**p256 probe** (2026-11-03, a scratch crate outside the repo, `features = ["ecdsa"]`, `default-features = false`, built on both 1.97.1 and 1.99.1; it confirms RV2's build):
- `VerifyingKey::from_sec1_bytes`, `Signature::from_slice`, `Signature::from_der` and `Verifier::verify` all compile and work. ecdsa's `der` support comes with that one feature.
- An off-curve point is rejected.
- `verify` accepts the high-S RFC 6979 A.2.5 signature (P-256, SHA-256, "sample").
- `SigningKey` reproduces that signature exactly, high-S as it comes, and `normalize_s` changes it.
- The tree adds 23 crates to the repo's lock, as RV counted: crypto-bigint 0.7.10 and ctutils 0.4.8 (RV said 0.4.7), with no getrandom.
- The only new licence is `subtle`'s BSD-3-Clause. `ff` and `group` declare `MIT/Apache-2.0`.
- Every new crate declares rust-version ≤ 1.87.
- Mean sign and verify times on an AMD Ryzen 3 5300U, release: 0.57 ms and 0.56 ms on 1.97.1; 0.50 ms and 0.45 ms on 1.99.1.
- `cargo tree -i getrandom --target all` exits 101 when nothing matches. The fail-closed form in step 3 finds 0 `getrandom` lines.
- `cargo deny check` with the repo's `deny.toml`:
  - `subtle`'s BSD-3-Clause is the only rejection;
  - with BSD-3-Clause allowed, advisories, bans, licences and sources all pass, and `ff` and `group`'s slash syntax raises no warning;
  - the one warning is the probe's unused Unicode-3.0 allowance, which the real tree uses.

**Second pass (2026-11-03): RV2's external claims.** The fetch proxy refuses blog.rust-lang.org and github.com pages, so the Rust facts come from `RELEASES.md` on raw.githubusercontent.com [87] and from the GitHub REST API's issue and pull records. The Rust 1.98.1 post was found by search only [97]. The quotes came through a fetch tool that processes pages, so re-check exact wording on the live page before quoting it elsewhere.

| Claim | Verdict | Evidence |
|---|---|---|
| MCP: an absent `resultType` is treated as `complete` for earlier-revision servers | Confirmed, as a client MUST: "For backward compatibility with servers implementing earlier protocol versions, which do not include `resultType`, clients **MUST** treat an absent `resultType` as `"complete"`." Changelog item 8 says the same, and calls the field required | [67]; [66] |
| MCP: servers MUST rate-limit tool calls | Confirmed: "Servers **MUST**: Validate all tool inputs; Implement proper access controls; Rate limit tool invocations; Sanitize tool outputs". Clients SHOULD "Implement timeouts for tool calls" | [70], Security Considerations |
| undici's 300 s defaults | Confirmed. `headersTimeout`: "waits to receive the complete HTTP headers", default `300e3`. `bodyTimeout`: "Monitors the time between consecutive body chunks", default `300e3`. Node's `fetch` uses the global dispatcher, which is `new Agent()` with no options, and Agent passes its options through to its clients | [95] (undici `main`; a given Node release bundles its own undici version) |
| Python SDK: a 300 s read timeout | Confirmed as the default, not just an example. `MCP_DEFAULT_TIMEOUT = 30.0` and `MCP_DEFAULT_SSE_READ_TIMEOUT = 300.0` build `httpx2.Timeout(30.0, read=300.0)` when no client is passed. `ClientSession(read_timeout_seconds=None)` | [26]; [96] |
| TypeScript SDK: a 60 s request timeout | Confirmed for v1 1.32.2: `export const DEFAULT_REQUEST_TIMEOUT_MSEC = 60000;` and `const timeout = options?.timeout ?? DEFAULT_REQUEST_TIMEOUT_MSEC;`. Confirmed for v2 (`@modelcontextprotocol/client` 2.4.0, whose bundle inlines the protocol layer): `const DEFAULT_REQUEST_TIMEOUT_MSEC = 6e4;`. The v2 source at tag `@modelcontextprotocol/client@2.4.0` has `export const DEFAULT_REQUEST_TIMEOUT_MSEC = 60_000;` and, in `_requestWithSchemaViaCodec`, `const timeout = options?.timeout ?? DEFAULT_REQUEST_TIMEOUT_MSEC;` (third pass). `resetTimeoutOnProgress` defaults to false | [93]; [94]; [103] |
| httpx2 Unix sockets | The docs show `uds` on the synchronous `HTTPTransport` only. The 2.16.0 source settles the async side: `AsyncHTTPTransport` takes an optional `uds` path and passes it to httpcore2, which calls `connect_unix_socket`. `uds` is ignored when a proxy applies. It connects live (the SDK run below) | [92]; [102] |
| Rust 1.98.1 and 1.99.1 provenance | Traced. See the D1 table | [87]–[91] |

**FFI `bool` test** (rust-lang/rust#163911's reproducer, `--crate-type=cdylib -C opt-level=3 --target x86_64-unknown-linux-gnu`):

| Toolchain (LLVM) | LLVM IR | x86_64 assembly |
|---|---|---|
| 1.97.0 (22.1.6) | `define noundef zeroext i1` | `movl %edi, %eax; andb $1, %al; retq` |
| 1.97.1 (22.1.6) | `define noundef zeroext i1` | `movl %edi, %eax; andb $1, %al; retq` |
| 1.99.1 (23.1.1, fixed) | `define noundef zeroext i1` | `movl %edi, %eax; andb $1, %al; retq` |
| 1.99.0, per the issue (not installed here) | `noundef i1` | `movl %edi, %eax; retq` |

**Third pass (2026-11-03): the items still open after the second pass.**

*p256 with a prehash ≥ n.* Rust 1.97.1, with `PrehashSigner` and `PrehashVerifier` and the RFC 6979 A.2.5 key. It was checked against an independent pure-Python P-256 ECDSA and RFC 6979 implementation, which first reproduces A.2.5 exactly.

| Prehash e | z = e mod n | p256's deterministic signature equals Python's RFC 6979 | sign(e) = sign(e mod n) | Each accepts the other's signatures |
|---|---|---|---|---|
| SHA-256("sample") (control) | e | Yes | Yes | Yes |
| n − 1 (control) | n − 1 | Yes | Yes | Yes |
| n | 0 | Yes | Yes | Yes |
| n + 1 | 1 | Yes | Yes | Yes |
| 2^256 − 1 | 2^256 − 1 − n | Yes | Yes | Yes |

"Each accepts the other's" means Python verified p256's deterministic signature, and p256's `verify_prehash` accepted a Python signature made with a random k.

*`SO_PEERPIDFD` on this kernel* (6.18.54.1-microsoft-standard-WSL2). A Python listener reads `getsockopt(SOL_SOCKET, 77)`, `/proc/self/fdinfo` and `PIDFD_GET_INFO` (with the 64-byte v0 struct). For the "peer not visible" column, the listener runs in a new PID namespace inside a user namespace, through `unshare`, so it cannot see the peer, as in Compose.

| | Same namespace | Peer not visible (the Compose case) |
|---|---|---|
| `SO_PEERCRED` pid | The peer's pid | 0 |
| `SO_PEERPIDFD` while the peer lives | A pidfd; fdinfo `Pid:` is the peer's pid | A pidfd; fdinfo `Pid: 0` |
| `PIDFD_GET_INFO` while the peer lives | Succeeds, with the cgroup id | `EREMOTE` |
| The held pidfd after the peer is reaped | fdinfo `Pid: -1`; `PIDFD_GET_INFO` gives `ESRCH` | fdinfo `Pid: -1`; `PIDFD_GET_INFO` gives `EREMOTE` |
| A new `SO_PEERPIDFD` call after the reap | A stale pidfd (`Pid: -1`), no error | A stale pidfd (`Pid: -1`), no error |

The cross-namespace listener saw the peer's uid 1000 as 0, because its user namespace maps 1000 to 0.

*Web checks* (with the same fetch caveat as the second pass):

| Claim | Verdict | Evidence |
|---|---|---|
| `SO_PEERCGROUPID` in mainline | Absent. The uapi header at 7.4-rc1 ends at `SO_PEERPIDFD_THREAD` (87) | [98] |
| CI runner kernels | `ubuntu-24.04`: 7.0.0-1017-azure (image 20261026.354.1). `ubuntu-22.04`: 6.8.0-1070-azure. `ubuntu-26.04`: 7.0.0-1017-azure. `ubuntu-latest` moves to 26.04 in November 2026 | [99] |
| The `subscriptions/listen` reply | The acknowledgement comes first, with unsupported types omitted, then a completion result with `resultType: "complete"` and the subscription id. A `notifications/cancelled` MUST in cancellation.md conflicts with this | [73]; [71] |
| An MCP conformance suite | It exists (`modelcontextprotocol/conformance`), covers 2026-07-28, and checks every wire message against the schema. Its scenario index has no `subscriptions/listen` scenario | [100] |
| Invariant Labs' shadowing | Cross-server description injection, not a name collision | [101] |
| httpx2 async Unix sockets | Supported in the 2.16.0 source; ignored when a proxy applies | [102] |
| The TypeScript SDK v2 line that applies the default | Verbatim at tag `@modelcontextprotocol/client@2.4.0` | [103] |

Not done: `cargo deny` on a scratch copy of the repo with p256 added. The command was refused here, so step 3 runs it.

**Source re-check (2026-11-03): sources [1]–[65].** Each was checked to see that it resolves, and that it supports what the plan, or AP's facts that the plan carries, uses it for. Where a host was refused, a fallback was used: the GitHub REST API for issues and pull requests, the crates.io API, the crate's README, and OSV.

| Result | Sources |
|---|---|
| Resolves and supports its claim | [1] (with the two notes below), [2], [4]–[19], [23]–[30], [32]–[43], [45]–[50], [52]–[64]. Most GitHub items are small projects' own issues and PRs: they show what others met, not independent proof |
| Supports, through a fallback | [20] (socket.dev refused; p256's README says "has never been independently audited"); [21] (crates.io page empty; the API gives 0.14.0, 2026-07-03); [44] (vulners refused; the OSV record gives "fixed 0.7.6") |
| Supports in part | [3]: `-1` means reaped, with no task attached, not just exited. The page is also a snapshot from before the EREMOTE change. [56]: names the 6.18.14 and 6.19.10 backports, but the LTP patch itself was contested and not shown merged. [51]: a fork of [50]'s repo, last pushed in 2022, so [50] is the one to cite |
| Does not support the claim | [22]: it supports the advisory floor, but never mentions the 1.87 MSRV, so D1 now cites [23][104]. [31]: the commit changes `ESRCH` to `ENODATA` for an unconnected or non-AF_UNIX socket, and says nothing of reaped peers. Q1's errno list is corrected |
| Unreachable | [65], an old "[PATCH 0/8] Support unix domain sockets across namespaces" thread. No mirror reachable here holds it, and the plan does not rely on it |

Notes that changed or sharpened the plan:
- **[1]:** the spec never names batches; it requires a single request or notification per body. The 405 for GET or DELETE is a SHOULD. D2 is reworded.
- **RUSTSEC-2026-0385:** patched in ≥ 0.4.4, not 0.4.5. The 0.4.5 floor comes from crypto-bigint 0.7.6's `^0.4.5` [18][105].
- **crypto-bigint 0.7.x on crates.io:** 0.7.0–0.7.8 are yanked, and 0.7.6–0.7.8 are patched releases that were yanked for an unrelated semver break. 0.7.9 and 0.7.10 are the only usable ones, and both declare rust-version 1.87 [104]. p256 0.14.0 itself declares 1.85.
- **jsonwebtoken:** 11.1.0, the latest, still depends on p256 `^0.13.2`, optionally, through `rust_crypto` [52].
- **[5]:** systemd closed #43807 as "Not feasible". Its PR #43829, which would have admitted foreign-namespace peers as "nobody", was not merged.
- **[55]:** a patch proposed in October 2026 extends `EREMOTE` to the other pidfd ioctls for targets outside the caller's namespace.

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
| `subscriptions/listen`, with `notifications/cancelled` before the completion | `closed` resolved `'remote'` (an unexpected disconnect), and `onerror` reported "Received a response for an unknown message ID" for the completion result |
| A `tools/call` with a 1 s timeout against `slow` | `REQUEST_TIMEOUT`. The client aborted its HTTP request and sent no `notifications/cancelled`. The next call worked |
| `listChanged` configured | No subscription was auto-opened, because the PEP advertises no list-changed capability |
| The client closes an open subscription itself | It POSTs `notifications/cancelled` `{"requestId": "listen:0"}` with `MCP-Protocol-Version` but no `Mcp-Method`. Answered with 202: clean. Answered with 400: `onerror` fires ("Error POSTing to endpoint"), but `close()` resolves, `closed` is `'local'`, and later calls work |
| Node's built-in `fetch` with the undici 8.12.3 `Agent` | Failed: `UND_ERR_INVALID_ARG` "invalid onRequestStart method". Node 24.22.2 bundles undici 7.30.1 |

The stand-in, the clients and their pinned SDKs are in `spikes/d2-transport/`, and its `run.sh` reproduces every scenario. The original logs were lost with the session scratchpad; the spike's `results/` come from a `run.sh` run the same day, which matched every outcome above. Step 7's tests should rebuild the same checks against the real PEP.

**Week 1 verified plan:** "pep-sidecar Week 1_ Verified Plan and Partial Rust Code for JCS, Policy Engine and Peer Credentials" is at `C:\Users\mitam\AI & Cybersecurity\`, not in the parent folder. Its "Appendix: Gate 1 containment testbed (outline)" (lines 231–245) lists:
- TCP egress from uid 20001;
- UDP/53 and DoH;
- IPv6;
- raw and packet sockets;
- a different-uid connect;
- ptrace and `/proc/<pep>/mem`;
- a planted symlink;
- the cgroup-eBPF `connect4` hook.

**Five-Track report** (parent folder), by line:

| Lines | Content |
|---|---|
| 41 | nftables plus cgroup-eBPF |
| 197 | The resource server checks "that `release_epoch` is at or above its minimum" |
| 518–524 | Tier-1 containment (seccomp, Landlock, Yama); gVisor optional |
| 538 | Agent seccomp profile; `runsc` optional |
| 568 | The cgroup `connect4` hook |
| 616–658 (§3.6) | `start_episode`; the 30-minute idle timeout; dedupe on (eid, action_digest, idempotency_key); the upstream strips the Episode Token |
| 670–707 (§4.2) | Lockfile fields; 2 of 3 signers; six effect classes; `pepctl lock` |
| 678 | `min_accepted_epoch` 40 beside `release_epoch` 42 |
| 684 | Roles `authority_entity`, `amount`, `free_text` |
| 686 | `amount_binding` with three fields (`lookup_tool`, `from_arg`, `value_pointer`), and no `/structuredContent/` |
| 689 | A dynamic sink with `clearance_lookup` |
| 866–867 | Week 1 nftables and eBPF; Week 2 lockfile scan, sign and enforce, and a Vault broker |
| 875 | "zero bypasses in at least 50 attempts per profile" |

**External sources, fetched 2026-10-31:**

| Source | What it says |
|---|---|
| MCP pages [1][66]–[73] | As used in M1, M2, P1 and D2 |
| rfc8725bis-10 [74] | Dated 2026-08-21 |
| wimse-wpt-02 [75] | Dated 2026-08-27 |
| rust-lang/rust#159317 [76] | Milestone 1.99.0, merged 2026-07-27 |
| rust-lang/rust#163917 [77] | Milestone 1.99.1. Review comment: "the emitted LLVM IR returns to what was emitted in 1.98" |
| The Rust 1.99.1 post [6] | Three regressions "from prior releases", with no version named |
| The Compose reference [80] | File-secret `uid`, `gid` and `mode` are silently ignored; `network_mode` excludes `networks`; `volume.nocopy` |
| The Python SDK v2 transports page [26] | httpx2; no Unix-socket mention; custom transports allowed |

## Appendix B. To re-confirm

| Item | Why it is open | Settled at |
|---|---|---|
| `cargo deny` on the real tree with p256 | The probe tree passes the repo policy once BSD-3-Clause is allowed, and none of its 23 crates is already in the lock. A run on a scratch copy of the repo was refused here | Step 3 |
| Engines copying an image directory's owner and mode into an empty volume (RV, from moby [84][85]); `*-state` volumes taking the image's owner | Docker is not installed yet: step 1 needs your sudo | Step 8 |
| Whether the MCP conformance suite can run against the PEP | It takes an HTTP URL, and its scenarios may need fixture tools | Step 9 |
| Source [65] | No reachable mirror; the plan does not rely on it | — |

Settled on 2026-11-03 and removed from this table (Appendix A):
- the 31 Oct draft's row "`VerifyingKey::from_sec1_bytes` with only `["ecdsa"]`", by RV2's build and the probe;
- the client timeouts of undici, the Python SDK and the TypeScript SDK (v1 and v2);
- MCP's absent-`resultType` rule and its server rate-limit MUST;
- where the 1.98.1 and 1.99.1 regressions came from, with the FFI `bool` one tested on 1.97.1;
- p256 with a prehash ≥ n, against an independent implementation;
- the TypeScript SDK v2 line that applies the 60 s default;
- pidfd behaviour on this kernel, and CI's runner kernel;
- `SO_PEERCGROUPID`'s absence from mainline;
- the Invariant Labs taxonomy, which corrected mutation #12;
- the `subscriptions/listen` reply shape, and the existence of a conformance suite;
- sources [1]–[64], which led to corrections in D1, D2, Q1 and step 3;
- both SDKs over a Unix socket, and their handling of the `subscriptions/listen` reply and of client notifications, all run against a stand-in for the PEP. This closes the D2 spike.

## Appendix C. Corrections and disposition
**Step numbers.** The 31 Oct draft's steps map to this draft's as follows:

| 31 Oct draft | This draft |
|---|---|
| 1, 2 | 1, 2 |
| 3 (binary) | 7 |
| 4, 4b (Compose, nftables) | 8, 8b |
| 5 (kit) | 9 |
| 6 (p256) | 3 |
| 7 (pidfd) | 4 |
| 8 (lock file) | 5 |
| 9 (tokens) | 6 |
| 10 (lockfile) | 10 |
| 11 (`prov`) | Folded into 6 |
| 12 (Gate 1) | 11 |

**Corrections:**
- **AP:**
  - D1's case for option A: the 1.99.1 fix doesn't apply to 1.97.1.
  - uids 10001/10002 and directory mode 0750: they fail `verify_bound`'s group check, and SPEC uses 20001–20003.
  - `subscriptions/listen` → 404: it must be acknowledged.
  - `cargo audit`: redundant with `cargo deny`.
  - C-EPI "wrong `aud`": the Episode Token has no `aud`.
  - The C-UID gid test, with no gid check in the code.
  - "Repo files not reachable": all were checked for this plan.
- **MG:**
  - "eBPF isn't in any doc": see Five-Track lines 41, 518, 568 and 866, and the Week 1 verified plan's testbed appendix.
  - The "0700, operator uid" control socket: it contradicts itself (H1).
  - "engine.rs:836": the pass-through is `is_reserved_meta`, at line 2225.
  - "Anything else → 404": it breaks `server/discover` (a MUST) and `subscriptions/listen`.
  - nix `fs` + `Flock`: replaced by std `File::try_lock`.
- **RV: both corrections in the 31 Oct draft are withdrawn.**
  - **The F-13 phrase.** Each review was right about its own copy. The repo's `CLAUDE.md:85` contains "(until the Week 2 lockfile pins full argument schemas)" (re-checked 2026-11-03). The project copy that RV and RV2 read lacks it, so that copy is stale and needs re-uploading. WEEK2_PLAN.md is also uploaded to the project twice.
  - **The Week 1 testbed list.** It is in "pep-sidecar Week 1_ Verified Plan and Partial Rust Code…", whose "Appendix: Gate 1 containment testbed (outline)" lists every test RV cited, plus the cgroup-eBPF `connect4` hook (Appendix A). The 31 Oct draft searched only the parent folder.
- **This plan's own 31 Oct claims, corrected by RV2:**
  - **D1:** it called 1.97.1 "safe". The evidence covers one of 1.99.1's three fixes, so now it says that no fix released after 1.97.1 is known to apply to it.
  - **The TL;DR** called D1 settled while §1 had every decision OPEN.
  - **Step 8 (now 5):** it said `O_NOFOLLOW` would need nix's `fs` feature. It doesn't, and step 5 now uses it.
  - **Appendix A's nix row:** `OFlag` is not needed for `O_NOFOLLOW`.
  - **Appendix B, row 2:** settled.
  - **Contradictions:**
    - M1 gave -32602 for a wrong `protocolVersion`;
    - the router omitted `ttlMs` and `resultType`;
    - C-NET tested a PEP network address that N1 (a) removes;
    - C-JSON tested `canonical_request`, which §2a removes;
    - O1 measured the PEP alone;
    - §6 proposed no SPEC change for Q1.
- **Corrected by the 2026-11-03 checks (Appendix A):**
  - **Mutation #12** called a name collision "shadowing", a label carried from AP and RV. Invariant Labs' shadowing is cross-server description injection, so it is now #25, and #12 is named a name collision.
  - **Q1** said CI runners use older kernels than this machine. CI's `ubuntu-24.04` runner uses 7.0, which is newer.
  - **Q1's `SO_PEERCGROUPID`** was "unverified"; it is absent from mainline at 7.4-rc1.
  - **Q1's errno list** said `EINVAL` or `ESRCH` means a reaped peer. Its only source, [31], covers `ENODATA` for an unconnected socket. The list now rejects any other errno without naming a cause.
  - **Step 3's ctutils floor** said the advisory patches ≥ 0.4.5. The advisory says ≥ 0.4.4; 0.4.5 is crypto-bigint's own requirement.
  - **D1's MSRV citation** used [22], which never mentions the MSRV.
  - **D2** called the 405 for GET or DELETE a rule; it is a SHOULD.
  - **U1** answered every notification POST with 400. The TypeScript SDK posts `notifications/cancelled` when it closes a subscription, and a 400 surfaces there as a client error. That one notification now gets 202 and is ignored, and C-OUT gains an attack test proving it never releases a reservation.
- **Where this draft departs from RV2's wording:**
  - **The getrandom check:** fail-closed, instead of an inverted exit status, which would also pass when cargo itself fails.
  - **`O_NOFOLLOW`:** taken through nix's libc re-export instead of a direct libc dependency, so `Cargo.toml` doesn't change.
  - **The journal:** it also counts committed spend and records F-08 taint. Otherwise a restart would still refund committed spend and launder agent writes.
  - **J1:** NFC cannot be fixed on the result side, and (b) helps only agents that parse big integers exactly.
  - **Decision timing:** RV2 had T1, L1 and Q1 closing later. Its own reordering moves them into step 2.
  - **`tokens.rs`:** it moves before the binary along with p256, so that step 7 has no placeholder token checks.
  - **Step-up waits:** a 50 s cap rather than SSE keep-alives, which reset transport timers but not an SDK's request timer.

**Disposition of RV2:**

| RV2 item | Where it went |
|---|---|
| §1.1 R1 voids tokens but not budgets; B1 widens it | R1 (journal, or accepted risk); B1; C-OUT; Risks |
| §1.2 `ReconcilePending` keyed on the agent-controlled digest | P1; §2a reconcile check (entity); C-OUT |
| §1.3 which calls get a Call Proof; SPEC §1's exception; `lock scan` through a broker that admits only 20002 | T1 Call Proof scope; §2a PEP↔broker; L1 tooling (`pep-sidecar lock-scan`); §6 SPEC §1, §3.4 and §4 |
| §1.4 the oracle trusts the PEP's log; the join path | §2a bypass oracle and decision logs |
| §1.5 clock steps cannot run in Compose; the boot second | T1 replay cache (injected clock); R1 broker cutoff; G3; §3 replays |
| §1.6 step-up waits against client timeouts; late approvals | P1 (timeouts verified); C-CTL; §5 Week 4; Appendix A |
| §1.7 canonical result bytes change what the agent sees | J1 (new); step 10; mutation 23 |
| §1.8 G1 mixes attacks with checks; tests that can't run here; C-UID probes rejected before `accept()` | G1; §3 containment (attacks and checks); the `probe` service in §4 |
| §2 decision timing | §1 preamble and register; TL;DR |
| §2 version errors | M1 check order; U1 |
| §2 cache hints and `resultType` on PEP results | M1 router; C-MCP |
| §2 rejecting an absent `resultType` | M2 |
| §2 C-NET | C-NET |
| §2 C-JSON | C-JSON |
| §2 latency of the whole system | O1; G4 |
| §2 SPEC §1 on cross-namespace pidfds | Q1; §6 SPEC §1 |
| §3 p256 before the binary | Step 3 (and `tokens.rs` in step 6) |
| §3 steps 7–8 before the binary | Steps 4–5 |
| §3 one pins format | L1; §2a config; step 7 |
| §4 the mapping onto `ToolPolicy` (`amount_binding`, roles, `clearance_lookup`, `output_label`, `KeyPolicy`, result limits, `SeqPolicy`) | L1 mapping table |
| §4 tool names unique; digest over the upstream name | L1 tool names |
| §4 schema and `args` agree at load | L1 two schemas |
| §4 payment tools declare a currency | L1 payment tools |
| §4 one DSSE signature encoding | L1 DSSE (DER only) |
| §4 `min_accepted_epoch`'s two meanings | L1 epochs; M1 bindings; §2a config |
| §4 detection window; serve `tools/list` from the verified view | L1 drift detection; G2; M1 router |
| §5 reject `x-mcp-header` | M1; L1; C-MCP; mutation 19; Out of scope |
| §5 poll instead of `subscriptions/listen` | L1 drift detection; step 10; mutation 20 |
| §5 `prov` option 1 only | T1; step 6 |
| §5 JSON-only broker replies | M1 upstream responses; §2a PEP↔broker, modules (no `sse.rs`) and stubs; C-RES |
| §6 seccomp for the PEP and the operator; agent limits | N1; §4; C-POSTURE |
| §6 rate limits; replay cache capacity; clock skew | T1; U1; §2a config; C-OUT |
| §6 JOSE header allowlist; strict base64url | T1; C-EPI; §3 replays |
| §6 `end_episode`; the decision-log schema | E1; H1; §2a control protocol and decision logs; C-EPI; C-CTL |
| §6 one engine thread | A1 (new); O1 |
| §6 OneDrive and `/mnt/c` | Step 1; §4; Risks |
| §6 token on stdin; `<<: *tool`; the getrandom check | E1; C-PROC; §4; step 3; G5 |
| §7 the Week 1 testbed list | Corrections (above); Appendix A |
| §7 the F-13 phrase; duplicate uploads | Corrections (above). The uploads are yours to fix |
| §7 D1 | D1 (all four later fixes traced; one tested); TL;DR; Appendix A |
| §7 Appendix B, row 2 | Appendix A (probe); Appendix B |
| §7 step 8's `O_NOFOLLOW` reason | Step 5; Appendix A |

**Disposition of RV:**

| RV item | Where it went |
|---|---|
| §1.1 `server/discover` mandatory; never relay `instructions` | M1 router |
| §1.1 required `_meta`; add it on upstream requests | M1; C-MCP |
| §1.1 `resultType`, `ttlMs`, `cacheScope`, private filtered list | M1 router |
| §1.1 pagination | M1; step 10; mutation 24 |
| §1.1 `ping` and `logging/setLevel` gone; strip `logLevel` and `progressToken`; answer with JSON | M1; C-FWD |
| §1.2 non-complete results | M2; §2a results; C-RES |
| §1.3 a disconnect or timeout is never `DefinitelyNotExecuted` | P1 |
| §1.3 an explicit outcome field | P1; §2a PEP↔broker |
| §1.3 the dedupe after `Unknown` | P1 (now keyed on the entity, per RV2); §2a; C-OUT |
| §1.3 a declined or timed-out step-up is `DefinitelyNotExecuted` | P1; C-CTL |
| §1.3 `commit` leaves `in_flight` | P1 |
| §1.3 outcomes only from upstream | P1; §6 F-13 |
| §1.4 restarts: boot nonce, broker cutoff, tool dedupe, restart replays | R1 (per-boot keys instead of a nonce; RV2 adds the journal); §3 replays |
| §1.5 episode lifecycle | E1; §2a control protocol |
| §1.6 control socket; approval tuple; scripted operator | H1; §4; C-CTL |
| §1.7 prerequisites for #12, #19 and #20; a misbehaving stub; the oracle | §3 mutations; §2a stubs and oracle |
| §1.7 Vault broker | Deferred (a credential file in step 7); Out of scope |
| §2 eBPF | N1 records the deferral |
| §2 F-13 quote | The correction is withdrawn (above) |
| §2 open p99 points | O1 |
| §2 drift canonicalization | Step 10; J1; mutations 23–24 |
| §2 gate scope per profile | S1; G1 |
| §2 lock file: 0600, `O_NOFOLLOW`, fstat; drop the probe; std `try_lock` | Step 5 (`O_NOFOLLOW` through nix's libc re-export, plus fstat) |
| §3 JWT BCP | T1 |
| §3 WPT | T1 (`tth`, no raw logging) |
| §3 undefined Call Proof claims | T1; §6 SPEC §3.4 |
| §3 replay cache and clock; Episode Token cache; `/dev/urandom` | T1; R1 |
| §3 signing-key delivery | R1; §4 secrets |
| §3 DSSE | L1 |
| §3 lockfile fields | L1 |
| §3 lockfile tooling | L1; step 10 |
| §3 two schemas; ASCII names; serve pinned definitions | L1; M1 router |
| §4 container posture | C-POSTURE; §4 |
| §4 IPv6, raw and packet sockets, UDP/53, DoH, ptrace, `/proc` | C-NET; C-PROC; Q1 (argv) |
| §4 forwarding: no agent headers, `_meta` allowlist, reject notification POSTs, `Content-Encoding` and HTTP/2 | M1; C-FWD; C-HTTP |
| §4 results: id mismatch, duplicates, forged keys, unknown `resultType` | M1; C-RES |
| §4 header↔body after NFC | M1; C-MCP |
| §4 gid | Q1; C-UID |
| §4 uniform denials | U1; C-OUT |
| §5 `deny.toml`: BSD-3-Clause, optional bans | Step 3 |
| §5 `Cargo.toml`: p256, `panic`, `overflow-checks` | Step 3; B1 |
| §5 `rust-toolchain.toml` musl | B1 |
| §5 `.gitattributes` | Step 8 |
| §5 Compose: `nocopy`, seccomp | Step 8; §4 |
| §5 WSL `systemd`, `uname -r`, CI kernels | Step 1; step 9; Q1 |
| §5 CLAUDE.md: logging, Compose step, F-13, F-16 | §6 |
| §5 unsafe record | Step 3 |
| §6 model egress, AgentDojo and Python, Tokio sans-IO, Week 5 networking, 1 MiB latency | N1; D2; §2a; §5; O1 |
| §7 dependency tree, high-S, deterministic signing, speed | Step 3; Appendix A (probe); T1 (low-S) |
| §7 kernel options | Q1; Appendix B |
| §7 Rust 1.99.1 | D1 (now worded per RV2) |

**Disposition of MG:**

| MG item | Where it went |
|---|---|
| Docker in WSL | Step 1 (Docker Engine, not Docker Desktop) |
| Startup order: claim `HostAuthority` first | §2a `main.rs`; A1 |
| Config loader with `jcs`, no serde | §2a config |
| `HostAuthority` split: an engine thread, restricted messages | A1 (per-episode actors, two channels); §6 F-13 |
| Control socket "0700, operator uid" | Corrected; see H1 |
| Forwarder outcome mapping | P1, extended |
| F-16 forwarding change; canonical result bytes | §2a engine changes; §6 F-16; J1 |
| Upstream is the broker; the stub broker; `/run/broker` with a uid check | §2a PEP↔broker; §4 |
| Method routing, "anything else → 404" | Corrected; see M1 |
| Its Compose section (uids, hardening, tmpfs volumes, a real `/run`) | §4 |
| N1 | N1 |
| Item 5: test kit and CI job | Step 9 |
| Item 6: crate rules (jcs parsing, `=` pins, unsafe record, deny checks) | Context; step 3 |
| Item 8: the lock file kept with the listener | Step 5, with std locking |
| Item 9: tokens (`typ`, claims, bindings, -32020, `Held` only, replay cache, `tth`) | T1 (now a proof on every forwarded call, `rid` for `Held` payments); E1; M1 bindings; step 6 |
| Item 10: lockfile (`ToolPins`, `lockfile_digest`, strict schema) | L1; step 10 |
| Item 11: `prov` from `leaf_index` | T1 (witness hashes only, per RV2); step 6 |
| Docs: SPEC §1/§4 and the CLAUDE.md F-16 diff | §6 |
| Correction: D1 | D1 |
| Correction: D2 (the token is already in `_meta`) | D2 |
| Correction: Compose mode 0750 and uids | §4 |
| Correction: `aud`, `jti` and `nbf` only on Call Proofs | E1; C-EPI |
| The values MG resolved for AP's confirm markers: kernel 6.5, nix `PeerPidfd`, 1 MiB, the security role, "added latency", JCS drift, SPEC §4 format | Context; Q1; L1; O1; step 10 (drift now uses the result profile) |
| `deny.toml` already blocks an old crypto-bigint | G5; step 3 |
| The items MG skipped: crate choice, kernel checks, the old step ordering | Unchanged: p256 only, JWS and DSSE hand-rolled; Q1; §2 |
| MG's checks of the Week 1 report: N1 and `/run/pep` before start were kept; eBPF was skipped | N1; §4; the eBPF skip is corrected |
| The merged build order | §2 (reordered per RV2) |

## Sources
Sources [1]–[65] are carried from AP. All were re-checked on 2026-11-03 (Appendix A). [65] could not be reached, and the notes after [5], [20], [21], [22], [31], [44] and [51] record what the re-check found.

1. <https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http>
2. [\[PATCH\] pidfs: return -EREMOTE when... | Ratatoskr](https://ratatoskr.run/linux-fsdevel/2026/01/338598/t)
3. [pidfs.c source code \[linux/fs/pidfs.c\] - Codebrowser](https://codebrowser.dev/linux/linux/fs/pidfs.c.html)
4. [socket: peer\_cred returns none when the peer is in another PID namespace (containers), discarding a valid uid · Issue #329 · enghitalo/vanilla · GitHub](https://github.com/enghitalo/vanilla/issues/329)
5. [Allow Varlink peers from a different (ancestor) PID namespace, or make the peer-credential requirement configurable · Issue #43807 · systemd/systemd · GitHub](https://github.com/systemd/systemd/issues/43807) (re-checked: closed by its reporter as "Not feasible"; PR #43829 was not merged)
6. [Announcing Rust 1.99.1](https://blog.rust-lang.org/2026/10/15/Rust-1.99.1/)
7. [Rust 1.99.1 Released: Three Regressions Fixed](https://pbxscience.com/rust-1-99-1-released-three-regressions-fixed/)
8. [Announcing Rust 1.89.0](https://blog.rust-lang.org/2025/08/07/Rust-1.89.0/)
9. [File in std::fs - Rust](https://doc.rust-lang.org/beta/std/fs/struct.File.html)
10. [doc.rust-lang.org](https://doc.rust-lang.org/std/os/unix/net/struct.UnixStream.html)
11. [github.com](https://github.com/rust-lang/rust/issues/42839)
12. [Fix Clippy lint from Rust versions newer than 1.96 by kpreid · Pull Request #10575 · gfx-rs/wgpu · GitHub](https://github.com/gfx-rs/wgpu/pull/10575)
13. [ci: satisfy clippy lints introduced in Rust 1.98 and 1.99 by StephanMeijer · Pull Request #449 · docspec/docspec · GitHub](https://github.com/docspec/docspec/pull/449)
14. [chore(clippy): fix lints new in stable Rust 1.98 · Issue #340 · huttspawn/kessel · GitHub](https://github.com/huttspawn/kessel/issues/340)
15. [Restore strict Clippy on Rust 1.98 without suppressing the new lints · Issue #16 · Mik-pe/knipsa · GitHub](https://github.com/Mik-pe/knipsa/issues/16)
16. [Clippy Lints](https://clippy.rust-lang.org/rust-1.99.0/index.html)
17. [Keep clippy clean on Rust 1.99 by outragedevs · Pull Request #206 · outragedevs/repartee · GitHub](https://github.com/outragedevs/repartee/pull/206)
18. [fix(deps)!: crypto-bigint 0.7.6 + ctutils 0.4.5 + tokio 1.53.3 (RUSTSEC-2026-0385/0386/0387); MSRV 1.87 by ajit-zer07 · Pull Request #407 · agentcontextdistributionprotocol/acdp-rs · GitHub](https://github.com/agentcontextdistributionprotocol/acdp-rs/pull/407)
19. [fix(deps): crypto-bigint 0.7.6+ / MSRV 1.87 for RUSTSEC-2026-0387 and RUSTSEC-2026-0385 by frankxue831 · Pull Request #246 · frankxue831/gm-crypto-rs · GitHub](https://github.com/frankxue831/gm-crypto-rs/pull/246)
20. [p256 - crates.io Package Security Analysis - Socket](https://socket.dev/cargo/package/p256) (refused, HTTP 403; the p256 0.14.0 README at static.crates.io was read instead)
21. [p256 - crates.io: Rust Package Registry](https://crates.io/crates/p256) (the page is an empty shell; the crates.io API was read instead)
22. [Upgrade p256 to 0.14 to clear RUSTSEC-2026-0387 (crypto-bigint timing) · Issue #380 · Jolah1/ghostKey · GitHub](https://github.com/Jolah1/ghostKey/issues/380) (supports the advisory floor, not the 1.87 MSRV)
23. [Move to the elliptic-curve 0.14 crates (RUSTSEC-2026-0387); MSRV 1.87 by framefilter · Pull Request #212 · framefilter/keyroost · GitHub](https://github.com/framefilter/keyroost/pull/212)
24. [nix 0.31.3 - Docs.rs](https://docs.rs/crate/nix/latest)
25. [Release with the RustCrypto 0.14 crates to pick up the crypto-bigint fix (RUSTSEC-2026-0387) · Issue #1103 · ZcashFoundation/frost · GitHub](https://github.com/ZcashFoundation/frost/issues/1103)
26. [Client transports - MCP Python SDK](https://py.sdk.modelcontextprotocol.io/client/transports/)
27. [Connect to Any MCP Server in TypeScript Over stdio and HTTP, Then List Its Tools - DEV Community](https://dev.to/royalpinto007/connect-to-any-mcp-server-in-typescript-over-stdio-and-http-then-list-its-tools-1o4k)
28. [URL validation makes it impossible to implement unix domain socket transport · Issue #1119 · algesten/ureq · GitHub](https://github.com/algesten/ureq/issues/1119)
29. [nix::sys::socket::sockopt - Rust](https://docs.rs/nix/latest/nix/sys/socket/sockopt/index.html)
30. [nix/CHANGELOG.md at master · nix-rust/nix · GitHub](https://github.com/nix-rust/nix/blob/master/CHANGELOG.md)
31. [net/unix: use consistent error code in SO\_PEERPIDFD - linux/linux-stable.git - Linux kernel stable tree](https://git.sceen.net/linux/linux-stable.git/commit/net/core?id=b6f79e826fbd26e91e2fb28070484634cacdeb26) (re-read through the GitHub mirror API: it changes `ESRCH` to `ENODATA` for unconnected or non-AF_UNIX sockets; nothing on reaped peers)
32. [XP-03: platform identity primitives (process generation, session, peer credentials) by TheHalfMoon · Pull Request #360 · TheHalfMoon/Orcel · GitHub](https://github.com/TheHalfMoon/Orcel/pull/360)
33. [sk-queue: add SCM\_PIDFD / SO\_PASSPIDFD checkpoint/restore support by 3idey · Pull Request #3093 · checkpoint-restore/criu · GitHub](https://github.com/checkpoint-restore/criu/pull/3093)
34. [sandbox: fall back to fdinfo when PIDFD\_GET\_INFO is unavailable by Skyb0rg007 · Pull Request #51 · Skyb0rg007/defused · GitHub](https://github.com/Skyb0rg007/defused/pull/51)
35. [code: admin's dial accepts only the worker's own process, the run lock's holder read through a pidfd (#140) by toddwbucy · Pull Request #156 · toddwbucy/WeaverAgent · GitHub](https://github.com/toddwbucy/WeaverAgent/pull/156)
36. [flock in nix::fcntl - Rust](https://docs.rs/nix/latest/nix/fcntl/fn.flock.html)
37. [chore(ci): Update Rust crate nix to 0.31.0 by renovate\[bot\] · Pull Request #7140 · prefix-dev/pixi · GitHub](https://github.com/prefix-dev/pixi/pull/7140)
38. [nix::fcntl - Rust](https://docs.rs/nix/latest/nix/fcntl/index.html)
39. [Replace fs2 with std file locking (MSRV 1.89) and move to reqwest 0.13 by rcasatta-bot · Pull Request #3 · RCasatta/forge-sync · GitHub](https://github.com/RCasatta/forge-sync/pull/3)
40. [Replace fs4 identity locking with Rust's native file lock · Issue #241 · zulucode-design/second-brain · GitHub](https://github.com/zulucode-design/second-brain/issues/241)
41. [fix(deps): move p256 to 0.14 and ecdsa to 0.17 for RUSTSEC-2026-0387 by Rul1an · Pull Request #3413 · Rul1an/assay · GitHub](https://github.com/Rul1an/assay/pull/3413)
42. [Feature flags of P-256 crate // Lib.rs](https://lib.rs/crates/p256/features)
43. [RUSTSEC-2026-0387: crypto-bigint: Multiple timing variability issues in operations intended to be constant-time › RustSec Advisory Database](https://rustsec.org/advisories/RUSTSEC-2026-0387.html)
44. [RUSTSEC-2026-0387 Multiple timing variability issues in op... - vulnerability database](https://vulners.com/osv_rustsec/OSV:RUSTSEC-2026-0387) (refused, HTTP 403; https://api.osv.dev/v1/vulns/RUSTSEC-2026-0387 was read instead)
45. [Advisories in category 'crypto-failure' › RustSec Advisory Database](https://rustsec.org/categories/crypto-failure.html)
46. [Release v1.17.0: RUSTSEC-2026-0387/0385 fix, MSRV 1.87 · frankxue831/gm-crypto-rs · GitHub](https://github.com/frankxue831/gm-crypto-rs/releases/tag/v1.17.0)
47. [fix(deps): update rust crate pakery-crypto to v0.6.2 by renovate\[bot\] · Pull Request #45 · sjcl/jigsall · GitHub](https://github.com/sjcl/jigsall/pull/45)
48. [chore(deps): update crypto-bigint to 0.7.10 by houseme · Pull Request #8962 · rustfs/rustfs · GitHub](https://github.com/rustfs/rustfs/pull/8962)
49. [fix(security): clear RUSTSEC-2026-0385/0387 from the audit job by smunini · Pull Request #2232 · HeliosSoftware/hfs · GitHub](https://github.com/HeliosSoftware/hfs/pull/2232)
50. [dsse/protocol.md at v1.0.0 · secure-systems-lab/dsse · GitHub](https://github.com/secure-systems-lab/dsse/blob/v1.0.0/protocol.md)
51. [github.com](https://github.com/asraa/dsse/blob/master/envelope.md) (a 2022 fork of [50]'s repository; cite [50])
52. [update dependencies to mitigate RUSTSEC-2026-0387 · Issue #549 · Keats/jsonwebtoken · GitHub](https://github.com/Keats/jsonwebtoken/issues/549)
53. [socket\_peercred / SCM\_CREDENTIALS: UB when kernel returns pid 0 · Issue #1698 · bytecodealliance/rustix · GitHub](https://github.com/bytecodealliance/rustix/issues/1698)
54. [socket: peer\_cred keeps a peer from another PID namespace (#329) by enghitalo · Pull Request #346 · enghitalo/vanilla · GitHub](https://github.com/enghitalo/vanilla/pull/346)
55. [\[apparmor\] \[PATCH v3 1/4\] pidfd: restrict task access ioctls to the caller's pid namespace](http://www.mail-archive.com/apparmor@lists.ubuntu.com/msg13197.html)
56. [\[LTP\] \[PATCH 1/1\] ioctl\_pidfd06: Update kernel version](https://ratatoskr.run/ltp/2026/04/15589010/t)
57. [API socket admits a peer whose own PID is 0 or 1 · Issue #299 · dhm116/bearing · GitHub](https://github.com/dhm116/bearing/issues/299)
58. [\[RESEND PATCH net-next 0/6\] allow reaped pidfds receive in SCM\_PIDFD](https://lkml.rescloud.iu.edu/2506.3/09030.html)
59. [PID FDs: where we were, where we are and were we would like to go](https://lpc.events/event/18/contributions/1691/attachments/1499/3166/-LPC-2024-%20PID%20FDs-%20where%20we%20were,%20where%20we%20are%20and%20were%20we%20would%20like%20to%20go.pdf)
60. [@modelcontextprotocol/sdk - npm](https://www.npmjs.com/package/@modelcontextprotocol/sdk)
61. [Rust 1.99.1 Released: Three Critical Bugs Fixed in Record Two-Week Turnaround](https://www.linuxcompatible.org/story/rust-1991-released-three-critical-bugs-fixed-in-record-twoweek-turnaround)
62. [Stabilize "file\_lock" feature by cberner · Pull Request #142125 · rust-lang/rust · GitHub](https://github.com/rust-lang/rust/pull/142125)
63. [The 2026-07-28 Specification](https://blog.modelcontextprotocol.io/posts/2026-07-28/)
64. [Bump \`ctutils\`-dependent crates to MSRV 1.87 by tarcieri · Pull Request #2500 · RustCrypto/traits · GitHub](https://github.com/RustCrypto/traits/pull/2500)
65. [\[PATCH 0/8\] Support unix domain sockets across namespaces](https://containers.osdl.narkive.com/xsCg9yZu/patch-0-8-support-unix-domain-sockets-across-namespaces) (unreachable on 2026-11-03; not relied on)
66. [MCP 2026-07-28: Key Changes](https://modelcontextprotocol.io/specification/2026-07-28/changelog.md)
67. [MCP 2026-07-28: Base protocol overview](https://modelcontextprotocol.io/specification/2026-07-28/basic/index.md)
68. [MCP 2026-07-28: Discovery](https://modelcontextprotocol.io/specification/2026-07-28/server/discover.md)
69. [MCP 2026-07-28: Caching](https://modelcontextprotocol.io/specification/2026-07-28/server/utilities/caching.md)
70. [MCP 2026-07-28: Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools.md)
71. [MCP 2026-07-28: Cancellation](https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/cancellation.md)
72. [MCP 2026-07-28: Multi Round-Trip Requests](https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr.md)
73. [MCP 2026-07-28: Subscriptions](https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/subscriptions.md)
74. [draft-ietf-oauth-rfc8725bis-10 (2026-08-21)](https://ftp.kaist.ac.kr/ietf/draft-ietf-oauth-rfc8725bis-10.txt)
75. [draft-ietf-wimse-wpt-02 (2026-08-27)](https://ftp.kaist.ac.kr/ietf/draft-ietf-wimse-wpt-02.html)
76. [rust-lang/rust#159317: Fix `bool` calling convention for aarch64, etc.](https://github.com/rust-lang/rust/pull/159317)
77. [rust-lang/rust#163917: Re-enable extension of bool return values on x86_64](https://github.com/rust-lang/rust/pull/163917)
78. [p256 0.14.0 feature flags (docs.rs)](https://docs.rs/crate/p256/0.14.0/features)
79. [elliptic-curve feature flags (docs.rs, 0.14.3)](https://docs.rs/crate/elliptic-curve/latest/features)
80. [Docker Compose services reference](https://docs.docker.com/reference/compose-file/services/)
81. [LWN: SO_PEERCGROUPID patch series](https://lwn.net/Articles/1013591/) (from RV; not re-checked)
82. [uapi `socket.h` commit log](https://git.zx2c4.com/wireguard-linux/log/include/uapi/asm-generic/socket.h?showmsg=1) (from RV; not re-checked)
83. [httpcore developer interface (`uds`)](https://httpcore.readthedocs.io/en/latest/api.html)
84. [moby #40046: Compose secrets permissions](https://www.github.com/moby/moby/issues/40046) (from RV; not re-checked)
85. [moby `volumes_unix.go` (mirror)](https://git.causa-arcana.com/kotovalexarian-likes-github/moby--moby/raw/commit/26855c780184c528446957bd77821c6f4c74b343/daemon/volumes_unix.go) (from RV; not re-checked)
86. [time_namespaces(7), Linux manual page](https://man7.org/linux/man-pages/man7/time_namespaces.7.html)
87. [rust-lang/rust `RELEASES.md`](https://raw.githubusercontent.com/rust-lang/rust/master/RELEASES.md) (versions 1.97.1, 1.98.1 and 1.99.1)
88. [rust-lang/rust#161441: vacant vtable slot (Rust 1.98)](https://github.com/rust-lang/rust/issues/161441) (read through api.github.com, with #156742, #158993 and #161555)
89. [rust-lang/rust#163911: FFI `bool` return on x86_64](https://github.com/rust-lang/rust/issues/163911) (read through api.github.com, with #159317, #163917 and #142389)
90. [rust-lang/rust#163614: missing `wcslen`](https://github.com/rust-lang/rust/issues/163614) and its duplicate [#160827](https://github.com/rust-lang/rust/issues/160827) (read through api.github.com)
91. [rust-lang/rust#163947: macOS `rust-lld` and `libLLVM`](https://github.com/rust-lang/rust/issues/163947) (read through api.github.com, with #157205)
92. [httpx2: Transports](https://pydantic.dev/docs/httpx2/advanced/transports/)
93. [`@modelcontextprotocol/sdk` 1.32.2, `dist/esm/shared/protocol.js`](https://cdn.jsdelivr.net/npm/@modelcontextprotocol/sdk@1/dist/esm/shared/protocol.js)
94. [`@modelcontextprotocol/client` 2.4.0, `dist/src-CeKsbNLO.mjs`](https://cdn.jsdelivr.net/npm/@modelcontextprotocol/client@2.4.0/dist/src-CeKsbNLO.mjs)
95. [undici `Client.md`](https://raw.githubusercontent.com/nodejs/undici/main/docs/docs/api/Client.md), with [`lib/dispatcher/client.js`](https://raw.githubusercontent.com/nodejs/undici/main/lib/dispatcher/client.js), [`lib/global.js`](https://raw.githubusercontent.com/nodejs/undici/main/lib/global.js) and [`lib/dispatcher/agent.js`](https://raw.githubusercontent.com/nodejs/undici/main/lib/dispatcher/agent.js)
96. [MCP Python SDK `src/mcp/shared/_httpx_utils.py`](https://raw.githubusercontent.com/modelcontextprotocol/python-sdk/main/src/mcp/shared/_httpx_utils.py), with [`src/mcp/client/session.py`](https://raw.githubusercontent.com/modelcontextprotocol/python-sdk/main/src/mcp/client/session.py)
97. [Announcing Rust 1.98.1](https://blog.rust-lang.org/2026/09/03/Rust-1.98.1/) (found by search; the fetch proxy refuses this host)
98. [Linux `include/uapi/asm-generic/socket.h`](https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/asm-generic/socket.h) (master at 7.4-rc1)
99. [actions/runner-images: Ubuntu 24.04 readme](https://raw.githubusercontent.com/actions/runner-images/main/images/ubuntu/Ubuntu2404-Readme.md), with the [22.04](https://raw.githubusercontent.com/actions/runner-images/main/images/ubuntu/Ubuntu2204-Readme.md) and [26.04](https://raw.githubusercontent.com/actions/runner-images/main/images/ubuntu/Ubuntu2604-Readme.md) readmes
100. [modelcontextprotocol/conformance README](https://raw.githubusercontent.com/modelcontextprotocol/conformance/main/README.md), with [`src/scenarios/index.ts`](https://raw.githubusercontent.com/modelcontextprotocol/conformance/main/src/scenarios/index.ts)
101. [Invariant Labs: MCP Security Notification: Tool Poisoning Attacks (2025-04-01)](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)
102. [httpx2 2.16.0 `_transports/default.py`](https://cdn.jsdelivr.net/gh/pydantic/httpx2@2.16.0/src/httpx2/httpx2/_transports/default.py), with httpcore2's [`_async/connection.py`](https://cdn.jsdelivr.net/gh/pydantic/httpx2@2.16.0/src/httpcore2/httpcore2/_async/connection.py)
103. [TypeScript SDK `packages/core-internal/src/shared/protocol.ts` at tag `@modelcontextprotocol/client@2.4.0`](https://raw.githubusercontent.com/modelcontextprotocol/typescript-sdk/%40modelcontextprotocol/client%402.4.0/packages/core-internal/src/shared/protocol.ts)
104. [crates.io API: crypto-bigint versions](https://crates.io/api/v1/crates/crypto-bigint/versions) (yanked flags and rust-version for 0.7.0–0.7.10)
105. [RUSTSEC-2026-0385 (ctutils)](https://raw.githubusercontent.com/rustsec/advisory-db/main/crates/ctutils/RUSTSEC-2026-0385.md)
