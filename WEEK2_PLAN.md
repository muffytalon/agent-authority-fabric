# WEEK2_PLAN.md: pep-sidecar Week 2 (Gate 1)

Status: draft for review, 2026-10-31. Every decision in §1 stays OPEN until it is closed in build step 2. This plan supersedes two earlier drafts:
- **AP:** the attached Week 2 plan, "pep-sidecar Week 2 Plan: Toolchain, MCP Transport and Gate 1 Readiness", in the parent folder;
- **MG:** the 29 Oct merge notes.

It folds in **RV**, the 31 Oct review of MG, after checking each of RV's claims against:
- this repo at `bb25e27`;
- the Five-Track research report;
- the 28 Oct close-out note;
- the primary sources listed at the end.

Appendix C says where every RV and MG item went.

## TL;DR
- **What Gate 1 needs:** four things that do not exist yet:
  - the sidecar binary with its transport;
  - the Compose topology;
  - `lockfile.rs`;
  - `tokens.rs`.

  They are built in that order (§2), so every later step is tested in the real topology.
- **Open decisions:** 16 decisions (§1) must close before the steps they block. The largest are:
  - **M1:** the MCP 2026-07-28 surface beyond `tools/call`;
  - **M2:** results that are not `complete`;
  - **P1:** payment outcomes under MCP's rule that a disconnect is a cancellation;
  - **R1:** restarts while all state is in memory;
  - **E1:** who mints Episode Tokens.
- **D1 is settled by evidence.** The x86_64 FFI-`bool` miscompile fixed in Rust 1.99.1 was introduced in 1.99.0, so staying on 1.97.1 is safe.
- **The engine needs five changes** (§2a):
  - forwarded bytes are built by a new `forward` module;
  - `record_result_raw` accepts only `complete` results;
  - G_pin gains a quarantine check;
  - G_budget gains a `NeedsReconcile` dedupe;
  - step 10 adds the strict argument schema and per-tool step-up.

## Context
Week 2 ends at Gate 1 (SPEC §4). SPEC §4 lists `SO_PEERPIDFD`, `src/lockfile.rs`, `src/tokens.rs` and the Gate 1 containment suite. Gate 1 also presupposes three things that SPEC §4 assigns to no week:
- a running sidecar binary;
- its transport;
- the SPEC §1 containers.

This plan schedules all three first.

Facts this plan relies on (checked 2026-10-31; evidence in Appendix A):

| Topic | Fact |
|---|---|
| Toolchain | `rust-toolchain.toml` and `Cargo.toml` pin 1.97.1, which clears crypto-bigint's 1.87 floor and std `File::try_lock`'s 1.89. |
| Kernel | This machine runs WSL2 kernel 6.18.54.1. `SO_PEERPIDFD` needs ≥ 6.5. Across PID namespaces, `PIDFD_GET_INFO` returns `EREMOTE` (7.0, and backported to 6.18.14). |
| Parsing | All JSON is parsed with `jcs`, never serde: requests, results, JWS headers and claims, DSSE payloads, the lockfile and the config. This rejects duplicate keys and duplicate claims (F-03). |
| Limits | Request bodies are capped at 1 MiB, depth 64 and 8,192 values (`jcs` request profile). |
| Engine today | Every agent `_meta` member outside `dev.pep-sidecar/` is forwarded inside `canonical_request`.<br>`commit` leaves the call in `in_flight`.<br>`record_result_raw` never reads `resultType`.<br>`require_peer_uid` checks the uid only.<br>`EffectClass` has four variants. |
| MCP | Revision 2026-07-28: stateless, with per-request `_meta`. Servers MUST implement `server/discover`. A client disconnect is a cancellation, and streams cannot be resumed. |
| Unicode | Digests use Unicode 18.0.0 NFC (SPEC §2). The stub broker shares the PEP's `jcs` code, so it uses the same tables. |

## 0. Goal and Gate 1 exit criteria
**Goal:** a running `pep-sidecar` binary that mediates MCP tool calls from a network-less agent container. It does so over a bind-mounted Unix socket, with token and lockfile enforcement, and passes the Gate 1 suite (§3).

Gate 1 is evaluated on the release profile in the Compose topology (§4), not in unit harnesses.

| # | Criterion | Threshold |
|---|---|---|
| G1 | Containment tests passing, judged by the bypass oracle (§2a) | ≥ 50 per deployment profile in S1, 0 bypasses (§3 lists 96) |
| G2 | Rug-pull mutations quarantined | All of ≥ 20 (§3 lists 24), and 0 false positives on the negatives |
| G3 | Replays of captured Episode Tokens and Call Proofs rejected | 1,000 of 1,000, including restart and clock-step replays |
| G4 | p99 added latency, as defined in O1 | ≤ 25 ms. Release build, in Compose on this machine, with the CPU model recorded |
| G5 | Supply chain | `cargo deny check` clean, with no ignores. Exactly one crypto-bigint, ≥ 0.7.6. `cargo tree -i getrandom` reports no match. (`cargo audit` is dropped: `cargo deny` reads the same RustSec database.) |
| G6 | Decisions | Every §1 decision CLOSED, with its rationale recorded |

## 1. Decision register
Status: all OPEN. Each is closed in step 2, before the step it blocks. "Recommendation" is a label, not a decision.

| ID | Decision | Recommendation | Blocks step |
|---|---|---|---|
| D1 | Rust toolchain | B: stay on 1.97.1 | 3 |
| D2 | Agent-facing transport | (a) Streamable HTTP, as a POST/JSON subset over the Unix socket | 3 |
| N1 | Network model | (a) `network_mode: none` for the agent and the PEP, with the broker on an internal network | 4 |
| Q1 | Peer identity across PID namespaces; peer gid | (i) cross-namespace pidfd mode, plus a gid check | 7 |
| S1 | Deployment profiles in Gate 1 | Compose only | 5 |
| M1 | MCP 2026-07-28 surface | The PEP is a full 2026-07-28 server to the agent, and builds every upstream request itself | 3 |
| M2 | Results that are not `complete` | Never recorded. A payment becomes `abort(Unknown)` | 3 |
| P1 | Payment outcome mapping | The table in P1 | 3 |
| R1 | Restarts with in-memory state | Per-boot signing keys | 3, 9 |
| E1 | Episode lifecycle | `start_episode(intent)` on the control socket, with a 30-minute idle timeout | 3, 9 |
| H1 | Host control socket | `/run/pep-ctl` owned 20002:20004 with mode 2750, operator uid 20004 | 3 |
| T1 | Token profiles | rfc8725bis-10 rules, Call Proof `typ` `pep-callproof+jwt`, low-S | 9, 11 |
| L1 | Lockfile v1 content | Five-Track §4.2 fields mapped onto `ToolPins` | 10 |
| O1 | Latency definition | Bytes in to bytes out at the PEP, under open-loop load | 5 |
| B1 | Release build profile | `overflow-checks = true`; `panic = "abort"` only together with R1 | 4 |
| U1 | Wire shapes of denials and errors | One shape for every policy denial; MCP-mandated errors keep their codes | 3 |

### D1. Rust toolchain
- **Evidence:**
  - The repo pins 1.97.1 (`rust-version = "1.97.1"`).
  - crypto-bigint ≥ 0.7.6, which fixes RUSTSEC-2026-0387, declares rust-version 1.87 [22][23].
  - std `File::try_lock` is stable since 1.89 [8].
  - Rust 1.99.1 (2026-10-15) fixed three regressions [6]. One is the x86_64 FFI-`bool` miscompile (issue #163911).
    - It was exposed by rust-lang/rust#159317, milestone 1.99.0, merged 2026-07-27 [76].
    - The fix, #163917, restores "what was emitted in 1.98" [77].
    - So 1.97.1 and 1.98.x never had it.
- **Options:**
  - **A:** jump to 1.99.1. New clippy lints fire once. `rust-version = "1.99.1"` exactly, as CLAUDE.md §1 does now. Keep the `aarch64-apple-darwin` target.
  - **B:** stay on 1.97.1.
  - **C:** jump but declare a lower MSRV. Rejected: this is a binary with no downstream users, and C would cost a second CI job.
- **Recommendation:** B. AP recommended A because of the 1.99.1 fixes, but they don't apply to 1.97.1.

### D2. Agent-facing transport
- **Evidence (MCP 2026-07-28 Streamable HTTP [1]):**
  - **Messages:** one POST endpoint. Each body is a single request or notification. Batches are not valid bodies.
  - **Headers:**
    - `MCP-Protocol-Version`, `Mcp-Method` and, for `tools/call`, `Mcp-Name` are required.
    - Values that are not header-safe use `=?base64?…?=`, which servers decode before comparing.
    - A mismatch, or a missing standard header, gets 400 and -32020.
  - **Error codes:** an unsupported version gets 400 and -32022. An unknown method gets 404 and -32601. A present, invalid `Origin` gets 403.
  - **Legacy traffic:** legacy GET or DELETE gets 405.
  - **Streams:** a client disconnect is cancellation, and streams cannot be resumed.
- **Options:**
  - **(a)** that transport over the Unix socket.
  - **(b)** NDJSON JSON-RPC over the Unix socket. No SDK supports it. MG's correction applies: (b) would not move the token, which SPEC §3.3 already carries in `_meta`, with the header optional.
  - **(c)** a loopback-TCP shim. Rejected: peer credentials would identify the shim, not the agent.
- **Recommendation:** (a), hand-rolled (§2a), with no HTTP crate.
  - The Episode Token stays in `_meta["dev.pep-sidecar/episode"]`.
  - `Pep-Episode` is optional, and a mismatch gets 400 and -32020.
- **Closes when** a spike reaches a throwaway Unix-socket HTTP server with custom headers from:
  - **the TypeScript SDK v2:** a custom `fetch` with an undici `Agent({ connect: { socketPath } })`;
  - **the Python SDK v2,** which uses httpx2 and documents no Unix-socket support [26]. Two routes to try: httpx's `AsyncHTTPTransport(uds=…)` [83] may carry over (unverified), or the SDK accepts a custom transport.

### N1. Network model
- **Evidence:**
  - SPEC §1's nftables rule (`skuid 20001`) cannot work as a host rule. `skuid` matches only sockets in the network namespace where the rule is loaded, and Compose gives each container its own namespace (close-out note).
  - Compose rejects a file that sets both `network_mode` and `networks` [80].
- **Options:**
  - **(a)** `network_mode: none` for the agent and the PEP; the broker on an internal `tools_net`. Each private namespace has only `lo` with nothing listening, so loopback holes cannot exist. nftables becomes an optional backup, or the rule set for the same-host process deployment.
  - **(b)** the agent shares the PEP's namespace (`network_mode: "service:pep"`), and a helper with `NET_ADMIN` loads the rules there. nftables becomes mandatory, with tests for the rule set.
- **Decide now as well:**
  - **Week 4 model egress.** The agent needs an LLM, and under (a) it has no network. Recommended: a model proxy on a Unix socket with a host allowlist. The provider is recorded as an accepted exfiltration channel.
  - **Week 5 PEP egress.** The PEP must reach a Txn-Token service and a PDP. Recommended: route them through the broker, so SPEC §1 is amended once.
- **Containment layers.** Five-Track §3.2–§3.3 lists seccomp, Landlock, Yama, nftables and cgroup-eBPF connect hooks. Week 2 adopts:
  - an agent seccomp profile;
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
  - `SO_PEERPIDFD` still returns a pidfd. Its fdinfo shows `Pid: 0` while the peer lives, and `-1` once it has exited [3].
  - `PIDFD_GET_INFO` returns `ESRCH`, and `EREMOTE` since 7.0 (backported to 6.18.14 and 6.19.10), so the cgroup id cannot be read across namespaces [2][56].
  - `SO_PEERCGROUPID` was proposed but is not in mainline uapi (RV; [81][82], unverified).
  - nix 0.31.3 exposes `sockopt::PeerPidfd` in the `socket` feature that is already enabled; it returns an `OwnedFd`.
  - **Errors, each rejected fail-closed:**
    - `ENOPROTOOPT`: kernel older than 6.5;
    - `ENODATA`: no peer pid recorded;
    - `EINVAL` or `ESRCH`: the peer was reaped.
  - On recent kernels a reaped peer yields a stale pidfd (`Pid: -1`) instead of an error, so the fdinfo check is mandatory.
- **Options:**
  - **(i) Cross-namespace mode:** require that the pidfd was obtained, that fdinfo `Pid ≠ -1`, and that uid and gid match.
  - **(ii) Shared namespace** (`pid: "service:pep"` on the agent). The pid resolves, and `PIDFD_GET_INFO` gives the cgroup id. But the agent can then read `/proc/<pep>/cmdline`, so secrets stay out of argv and env. (Env is protected across uids by the ptrace check, but keep it clean anyway.)
  - **(iii) `pid: host`:** rejected.
- **The gid.** `require_peer_uid` checks only the uid, but SPEC §1 runs the agent as 20001:20001, and AP's C-UID test "uid right, gid wrong" expects a rejection. Add `require_peer(uid, gid)`. The agent cannot change its gid under `no-new-privileges` and `cap_drop: [ALL]`.
- **Recommendation:** (i) plus the gid check. Tests branch on kernel version, because CI runners use older kernels than this machine.

### S1. Deployment profiles in Gate 1
- **Evidence:**
  - SPEC §1 allows a "container/process" deployment.
  - Five-Track §5.3 says "zero bypasses in at least 50 attempts per profile".
  - Five-Track §3.3 lists gVisor `runsc` as optional.
- **Recommendation:** Gate 1 covers the Compose (runc) profile only, and SPEC §4 names it. The same-host process deployment and `runsc` are recorded as deferred; each needs its own ≥ 50 when added.

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
- **`subscriptions/listen`:** the server acknowledges the subset of notification types it supports, then may end the stream with a completion result.
- **`x-mcp-header`:** it mirrors primitive parameters into `Mcp-Param-{Name}`. Integers are compared numerically, and a client MUST drop a tool whose annotation is invalid.
- **Tool names:** they SHOULD be 1–128 characters of `[A-Za-z0-9_.-]`.
- **New error codes:** -32000 to -32019 is closed to new codes, so Five-Track's proposed `-32003 EPISODE_EXPIRED` cannot be used.

**Design** (recommendation):
- **Router:**

  | Method | Handling |
  |---|---|
  | `tools/call` | The engine. The transport parses the body once and builds the `ToolCall`. |
  | `tools/list` | Served by the PEP:<br>• a valid Episode Token is required;<br>• every upstream page is fetched, through the broker;<br>• it serves only definitions whose canonical digest matches the lockfile pin and that are not quarantined;<br>• tools with an invalid `x-mcp-header` are excluded;<br>• one page, `cacheScope: "private"`. |
  | `server/discover` | Answered by the PEP:<br>• no token needed;<br>• `supportedVersions: ["2026-07-28"]`;<br>• `capabilities: {"tools": {}}`;<br>• `cacheScope: "public"`;<br>• no upstream `instructions` unless the lockfile pins their text. |
  | `subscriptions/listen` | A PEP-generated SSE stream: `notifications/subscriptions/acknowledged` with an empty filter, then a graceful completion result. This is the only non-JSON reply. |
  | Anything else, `ping` included | 404 and -32601 |

- **Agent requests, checked in the transport, before the engine:**
  - **Header↔body checks:**
    - `Mcp-Name` and `Mcp-Param-*` are base64-decoded, NFC-normalized and compared with the canonical body. Integers are compared numerically.
    - A pinned `x-mcp-header` value present in the body requires its header.
    - An unknown `Mcp-Param-*` gets -32020.
  - **`_meta`:**
    - `protocolVersion` must be `2026-07-28`, and `clientCapabilities` must be an object; otherwise -32602 and 400.
    - Every other agent `_meta` member is dropped and never forwarded.
    - `g_canon` keeps its denial of reserved `dev.pep-sidecar/` members.
- **Episode Token bindings:**
  - its `eid` selects the engine;
  - `peer_uid` must equal the connection's uid;
  - `release_epoch` must equal the loaded lockfile's, which must be ≥ `min_accepted_epoch`;
  - `intent_digest` must equal the configured intent's.
- **Upstream requests, always built by the PEP:**
  - `forward::tools_call_request` builds the body: a PEP-assigned JSON-RPC id, the canonical name and arguments, and `_meta` = `protocolVersion`, `clientCapabilities: {}`, the PEP's `clientInfo` and the Call Proof.
  - Headers are derived from that body and the pinned `x-mcp-header` annotations.
  - Nothing the agent sent (headers, `_meta` members, id, `logLevel`, `progressToken`) is copied. The PEP is an MCP endpoint, not an HTTP intermediary.
- **Upstream responses:**
  - JSON or SSE, with byte and time caps;
  - exactly one response, whose id must match;
  - notifications are dropped;
  - an unknown `resultType` is invalid;
  - `_meta["dev.pep-sidecar/outcome"]` is trusted only on a connection whose peer uid is 20003; after it is read, the result's `_meta` is dropped.
- **Mutual peer checks:** the broker requires peer uid 20002, and the PEP requires 20003.

### M2. Results that are not `complete`
**Evidence:**
- A server may answer `tools/call` with `resultType: "input_required"`, carrying `inputRequests` and an opaque `requestState`.
- It may send only `requestState`, so this can happen even to a client that declares no capabilities.
- Extensions may add result types; the tasks extension can return a handle for work that runs later.
- Today, `record_result_raw` would record such a body as if it were a finished result. `g_canon` rejects a retry's `inputResponses` and `requestState` as `UnexpectedParam`, which fails closed only by accident.

**Recommendation:**
- Send empty `clientCapabilities` upstream, and advertise no extensions.
- `record_result_raw` accepts only `resultType == "complete"`.
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
| The explicit outcome is `refused`, never inferred from an HTTP status or `isError` | `record_result_raw` first, then `abort(DefinitelyNotExecuted)`. `abort` removes `in_flight`, so recording after it would fail | The recorded refusal |
| Broker timeout, disconnect, an ambiguous reply, or outcome `unknown` | `abort(Unknown)`. Nothing is recorded | `PEP_UNAVAILABLE` |
| The agent disconnects before the call is forwarded | `abort(DefinitelyNotExecuted)` | — |
| The agent disconnects after the call is forwarded | Nothing from the agent side. The upstream leg runs to completion or timeout, and its outcome applies | — |
| Step-up declined or timed out | `abort(DefinitelyNotExecuted)`: nothing was sent | `PEP_DENIED` |
| Any non-payment call | Record and forward. On a timeout or error, `abandon` | `PEP_UNAVAILABLE` on failure |

- **Outcome sources:** outcomes come only from the upstream side, never from anything the agent does.
- **Step-up waits:** the agent's request stays open while it waits for step-up, so its client timeout must exceed `step_up_timeout_ms`.
- **Retries after `Unknown`:**
  - A retry gets a new reservation id, and so a new F-07 key that the provider cannot dedupe.
  - Until Week 3's reconciliation, `g_budget` denies a payment whose `action_digest` matches a `NeedsReconcile` reservation (`ReconcilePending`; Five-Track §3.6).
- **In-flight accounting:** a unit test checks that `in_flight` drains to zero after a run.

### R1. Restarts with in-memory state
- **Evidence:**
  - A PEP restart forgets budgets, reservations (`NeedsReconcile` included) and spent ids. An Episode Token stays valid for up to 8 hours, so the same eid would get a fresh budget.
  - A broker restart empties its `jti` cache inside the 60-second Call Proof window.
- **Recommendation:**
  - **Per-boot keys.** The PEP generates its Episode Token key and Call Proof key at start-up, from `/dev/urandom` read through std, so no `getrandom` crate. A restart therefore voids every token and proof. This is equivalent to RV's boot nonce, with no new claim.
  - **Key delivery.** The PEP writes the Call Proof public key to `/run/pep-pub`, which the broker mounts read-only and re-reads per connection.
  - **Broker boot cutoff.** The broker rejects any proof whose `iat` is before its own boot time.
  - **Tool server dedupe.** The stub tool server dedupes on `Idempotency-Key`, and its store survives PEP and broker restarts.
  - **Replays.** Restart replays count in the 1,000.
- **Alternative:** persistent keys plus a boot-nonce claim, if keys must survive restarts.

### E1. Episode lifecycle
- **Evidence:** neither AP nor MG says who mints Episode Tokens. Five-Track §3.6 has the PEP mint them on a trusted `start_episode` call, with a 30-minute idle timeout that SPEC §3.3 dropped.
- **Recommendation:**
  - **Minting.** `start_episode(intent)` on the control socket (H1) mints the token: `typ` `pep-episode+jwt`, with SPEC §3.3's claims and `exp − iat ≤ 28800`.
  - **Idle timeout.** Restore the 30-minute idle timeout.
  - **Keys.** The Episode Token key is separate from the Call Proof key.
  - **Week 2 claim values.** Week 2 fills `sub`, `client_id`, `rar_digest` and `txn` from the configured intent; Week 5's RAR and Txn-Token values replace them.
  - **Why the token has no `iss`, `aud`, `jti` or `nbf`.** The PEP mints and verifies the token itself, and the distinct `typ` and key make Episode Token and Call Proof validation mutually exclusive (rfc8725bis-10 §3.12 [74]). Record this in SPEC §3.3.
  - **Getting the token to the agent.** The Gate 1 harness passes the token to the agent process as an argument or on stdin, never through a volume.

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
- **Principal.** In Week 2, one host principal both starts episodes and approves.
- **Gate 1** uses a scripted operator.

### T1. Token profiles
**JOSE rules** for both token types (rfc8725bis-10 [74]):
- an algorithm allowlist of ES256 only, with each key bound to one algorithm and one token type;
- reject any compact token containing a character outside `[A-Za-z0-9_-.]` before decoding;
- exact `typ`;
- AP's rules: reject `jku`, `jwk`, `x5u` and `crit`, and require a 64-byte r‖s signature;
- validation rules written so the two token types are mutually exclusive.

**Call Proof `typ`.**
- SPEC §3.4's `urn:pep-sidecar:evidence:jws-callproof:v1` contains no "/", so recipients read it as `application/urn:…`.
- Recommended: `pep-callproof+jwt`.
- If draft-lee needs the URN as an evidence type, carry it in a claim.

**Signatures.**
- The PEP normalizes its signatures to low-S.
- The broker rejects high-S Call Proofs.
- DSSE verification accepts high-S, because the signers are third-party tools.
- The replay cache is keyed on `jti`, never on signature bytes.

**Claims to define in SPEC §3.4:**
- `budget`;
- `tool_schema_digest`: the lockfile's pinned upstream digest;
- concrete `iss` and `aud` SPIFFE ids;
- the target-server binding: a claim, or the server inside `aud`;
- which claims the broker checks;
- `prov`, from two options:
  - the witness origin hashes `Allowed.prov` already holds: at most two, and exact;
  - those, plus `leaf_index` matches for role arguments: latest match only, capped. A value like `INV-1001` can match many records, so a match shows only that the value appeared in a result.

`tth` follows wimse-wpt-02 [75], as the hash of the Txn-Token, and waits for Week 5.

**Logging.** Raw tokens and proofs are never logged by default (wimse-wpt-02).

**Replay cache:**
- bounded, as `Mutex<HashMap<jti, exp>>` plus an expiry order;
- capacity ≥ maximum issue rate × (60 s + skew);
- a full cache with live entries rejects, never evicts;
- `exp` checks and eviction run against a clock high-water mark that never decreases, so a backward clock step cannot re-admit an evicted token;
- `jti` and nonces come from `/dev/urandom`;
- verified Episode Tokens are cached by a hash of their bytes, with `exp` and idle re-checked on every use.

### L1. Lockfile v1 content
From Five-Track §4.2, with the engine's `ToolPins` as the target:
- **Epochs:** `release_epoch` and `min_accepted_epoch` (rollback protection). There is no hot reload: a new epoch means a restart.
- **Per-server identity:** `server_id`, endpoint, identity and `protocol_version`. #12 (shadowing) needs it.
- **Signers:**
  - a threshold of distinct keys per role;
  - SPEC §4's security-role signature for payment tools, external sinks, and read-only tools that can authorize amounts;
  - whether Five-Track's 2-of-3 applies is part of this decision.
- **Effect classes:** reviewers assign six; the engine has four. Map:
  - `read` → `ReadOnly`;
  - `mutating_internal` → `MutatingInternal`;
  - `external_sink` → `MutatingExternal`;
  - `mutating_financial` → `Payment`.

  Reject `destructive` and `code_exec` in Week 2.
- **Per-tool `step_up_over_minor`:** the effective threshold is the smaller of the intent's and the tool's.
- **Two schemas per tool:**
  - the upstream definition's digest, for drift;
  - a strict subset for enforcement (F-13): `type`, `properties`, `required`, `additionalProperties: false`, `enum`, and length and range limits. Any other keyword is rejected.
- **Tool names:** ASCII, 1–128 characters of `[A-Za-z0-9_.-]`, checked at load. This removes the homoglyph class.
- **DSSE:**
  - the payload must already be JCS-canonical, so `lockfile_digest = digest(payload)` hashes exactly the signed bytes;
  - count distinct trusted keys per role;
  - a fixed `payloadType` (for example `application/vnd.pep-sidecar.lockfile.v1+json`);
  - PAE, both base64 alphabets, `keyid` only as a hint, DER signatures (AP item 4).
- **Tooling:** `pepctl lock scan` (`server/discover` plus `tools/list` through the broker, every page) and `pepctl lock sign`. Fixtures and the mutation suite need both.

### O1. Latency definition
- **Formula:** added latency = (first byte written upstream − first byte read from the agent) + (last byte written to the agent − last byte read from upstream). The timestamps are `Instant`s inside the PEP.
- **Also reported:** broker verification, separately, and an agent-side end-to-end figure.
- **Load:** open-loop, at fixed arrival rates, because a closed-loop harness hides queueing. A stated mix of reads, payments and lists, at a stated concurrency cap.
- **Exclusions:** step-up calls are excluded, since they wait for a human. 1 MiB requests are measured separately, because hashing cost grows with bytes × depth.
- **Method (AP):** 10,000 calls after 500 warm-up calls. Report p50, p99, p99.9 and max.

### B1. Release build profile
- **`overflow-checks = true`:** library code already denies unchecked arithmetic; this covers dependencies and binaries.
- **`panic = "abort"`:** only together with R1's per-boot keys, so a crash fails closed and voids every token.
- **musl:** add `x86_64-unknown-linux-musl` to `rust-toolchain.toml` only if the images are static (distroless or scratch). Otherwise build in an image whose glibc matches.

### U1. Wire shapes of denials and errors
- **Policy and token denials.** Every one gets the same shape, so the agent cannot tell which guard fired:
  - HTTP 200;
  - a JSON-RPC error with one application code outside -32768 to -32000;
  - the message `PEP_DENIED`;
  - no `data`.

  `PEP_UNAVAILABLE` gets its own single code. Both codes are chosen in step 2 and recorded in SPEC. Expired, idle and declined all get `PEP_DENIED`.
- **MCP-mandated errors keep their codes:**

  | Condition | Reply |
  |---|---|
  | Header mismatch, or a missing standard header | -32020, 400 |
  | Missing `_meta` field | -32602, 400 |
  | Unsupported version | -32022, 400 |
  | Unknown method | -32601, 404 |
  | Any `Origin` | 403 |
  | GET or DELETE | 405 |
  | Notification POST | 400 |

## 2. Build order
Every step ends with the CLAUDE.md §2 six-command loop green. Each step's decision IDs must be CLOSED before the step starts.

| Step | Decisions | Deliverables | Acceptance | Commit |
|---|---|---|---|---|
| 1 | — | Docker Engine inside WSL Ubuntu (yours: it needs sudo). Not Docker Desktop: its VM kernel differs, and Q1 depends on the kernel. Set `systemd=true` in `/etc/wsl.conf`. Record `uname -r` here: 6.18.54.1-microsoft-standard-WSL2 on 2026-10-31. | `docker run --rm hello-world` works inside WSL | — |
| 2 | all | Close §1. Apply the §6 SPEC wording as each decision closes; SPEC keeps CRLF. Hand the CLAUDE.md wording to you. If D1 = A, make the toolchain commit here. | No OPEN decision blocks step 3 | `docs: close Week 2 decisions; SPEC §1/§3/§4` |
| 3 | D1, D2, M1, M2, P1, R1, E1, H1, U1 | The binary, the stub broker, two stub tool servers, the scripted operator and the engine changes in §2a.<br>• Pins come from the config until step 10.<br>• Token checks are placeholders until step 9.<br>• The broker credential is a 0400 file owned by uid 20003; Vault is deferred.<br>• Every binary passes the macOS cross-lint, with Linux-only paths behind `cfg`.<br>• Binaries follow the logging rule in §6. | End to end over temp-directory sockets: a read, a payment, a step-up approval and a refusal, every P1 row, and every router row in M1 | `bin: std-threads sidecar, transport, stubs` (several commits) |
| 4 | N1, B1 | `compose.yaml`, Dockerfiles, `seccomp-agent.json` and `.gitattributes`, per §4.<br>• `.gitattributes` sets LF for `*.sh`, `Dockerfile*`, `compose.yaml`, `*.nft` and `seccomp*.json`; SPEC and CLAUDE.md keep CRLF.<br>• B1's `Cargo.toml` and toolchain changes land here too. | The topology starts. Volume owners and modes match §4. Posture checks pass. The step 3 flows pass in Compose | `compose: SPEC §1 topology` |
| 4b | N1 | nftables rules, only if N1 = (b) | Rule-set tests pass | `net: nftables rules` |
| 5 | S1, O1 | The bypass kit with the oracle (§2a), the open-loop latency harness, and a CI job that runs the kit in Compose and branches on kernel version | The kit runs in CI; the first latency report exists | `test: Gate 1 kit and harness` |
| 6 | — | `p256 = { version = "=0.14.0", default-features = false, features = ["ecdsa"] }`. In the same commit:<br>• BSD-3-Clause in `deny.toml`, for `subtle`. Not earlier: an unused allowance makes `cargo deny` warn.<br>• Unsafe-record rows for each new crate, and the changed feature sets of `hybrid-array` and `digest`.<br>• A CI check that getrandom is absent.<br>• Optional bans (getrandom, serde and serde_json until Week 5, openssl, ring), only if `cargo deny check` stays warning-free.<br>• `reports/Week2 crypto crate check.md` re-confirms RV's probe on this machine:<br>  – the tree;<br>  – MSRV ≤ 1.87;<br>  – verify accepts high-S;<br>  – RFC 6979 A.2.5 vectors, including prehash ≥ n;<br>  – sign and verify timings.<br>• Advisory facts (AP item 3):<br>  – RUSTSEC-2026-0387: crypto-bigint timing variability, patched in ≥ 0.7.6. 0.7.0–0.7.8 are yanked, so expect 0.7.10.<br>  – RUSTSEC-2026-0385: ctutils, patched in ≥ 0.4.5.<br>  – The jsonwebtoken crate is rejected: its RustCrypto backend was still on crypto-bigint 0.5.5. | The ES256 API surface compiles with exactly `["ecdsa"]`:<br>• `Signature::from_slice` for JWS r‖s;<br>• `Signature::from_der` for DSSE;<br>• `VerifyingKey::from_sec1_bytes`;<br>• `Verifier::verify`.<br>If `from_sec1_bytes` needs `sec1`, add the smallest feature that provides it and record why.<br>JWK parsing is hand-rolled, because elliptic-curve 0.14 dropped its `jwk` feature: decode `x` and `y`, check that each is 32 bytes, then build SEC1 `04‖x‖y`; `from_sec1_bytes` rejects off-curve points.<br>G5 holds | `deps: p256 0.14 (ecdsa only); deny BSD-3-Clause; unsafe record` |
| 7 | Q1 | `SO_PEERPIDFD`, fail-closed per Q1, and `require_peer(uid, gid)` | C-PID and C-UID pass on this kernel; CI branches on its kernel | `peercred: SO_PEERPIDFD fail-closed; gid check` |
| 8 | — | The lock file:<br>• std `File::try_lock`, not nix `fs`; this supersedes the `Flock` plan in AP, MG and WEEK1_PLAN §1.<br>• `<sock>.lock` is created in the checked parent with mode 0600 and owner euid.<br>• An lstat before open and an fstat after require a regular file with `nlink` 1 and the same dev and inode. `O_NOFOLLOW` would need nix `fs`; the parent check already rules out a planted symlink.<br>• The lock is taken before any existing socket is unlinked.<br>• `bind_safe_listener` returns `BoundListener { listener, lock }`.<br>• `socket_is_live` and `PROBE_TIMEOUT` are removed: with the lock held, any existing socket is stale, which also closes the macOS backlog gap.<br>• flock semantics (AP item 2):<br>  – the lock belongs to the open file description, and does not interact with fcntl or OFD locks;<br>  – it works on overlayfs and on local named volumes;<br>  – NFS is forbidden for the socket volume, because flock there is emulated or unreliable. | C-LOCK passes, including "the agent cannot open the lock file" (the agent's group can read `/run/pep`, and flock works on a read-only descriptor) | `peercred: lock file held with the listener` |
| 9 | T1, R1, E1 | `src/tokens.rs`: the Episode Token and the Call Proof (issued only for `Held` reservations), plus the replay cache. The PEP and the stub broker share it. | Unit vectors: alg confusion, `typ` swap, charset, expiry, idle timeout, a full cache that fails closed, high-S rejected by the broker, the clock high-water mark | `tokens: Episode Token, Call Proof, ReplayCache` |
| 10 | L1 | `src/lockfile.rs` and `pepctl lock scan/sign`.<br>• Drift hashing uses the result number profile with larger caps; the request profile rejects ordinary schema values such as `"minimum": 0.5` and caps 8,192 nodes.<br>• Definitions containing integers beyond ±(2^53−1) are quarantined, because RFC 8785 rounding would hide changes to them.<br>• Every upstream page is fetched.<br>• The PEP holds an upstream `subscriptions/listen` (`toolsListChanged`), or polls with jitter and backoff.<br>• The strict argument schema, per-tool step-up, and a review of the F-13 read-only exception. | The 24 mutations and the negatives (§3) | `lockfile: DSSE verify, drift quarantine, pepctl lock` |
| 11 | T1 | `prov`, as T1 defines it | Unit tests on witness and match caps | `tokens: prov claim` |
| 12 | all G-criteria | The Gate 1 suite, run on the release profile in Compose | G1–G6 | `gate1: results` |

## 2a. Interfaces (proposals)
**Engine changes** (`src/engine.rs`; each with tests and under every CLAUDE.md §3 lint):
- **Forwarding (F-16).**
  - `Allowed` and `PendingApproval` replace `canonical_request` with `tool: String` and canonical `arguments: JcsValue`.
  - A new `forward::tools_call_request(upstream_id, tool, arguments, meta) -> Vec<u8>` builds the only bytes sent downstream, from the same pair that `action_digest` hashes, so the broker recomputes the same digest.
  - The agent's id and `_meta` never leave the PEP.
- **Results (M2).**
  - `record_result_raw(..) -> Result<Vec<u8>, PepError>` requires `resultType == "complete"`; otherwise it returns a new `PepError::IncompleteResult`, which maps to `PEP_UNAVAILABLE`.
  - It drops the result's top-level `_meta` before labelling.
  - It returns exactly the canonical bytes it recorded. Those are the only result bytes the agent receives.
- **Quarantine.** G_pin denies a tool in a shared `Arc<QuarantineSet>` (new `PolicyError::ToolQuarantined`). Because it is a guard, F-09's ratchet still runs.
- **Reconcile dedupe (P1).** `g_budget` receives the call's `action_digest`. It denies with a new `PolicyError::ReconcilePending` when a `NeedsReconcile` reservation has the same digest. This is pure validation, so F-06 holds.
- **Step 10:**
  - `ToolPolicy.step_up_over_minor: Option<u64>`, used by `g_stepup` as the smaller of the intent's and the tool's thresholds;
  - the strict argument schema, checked in `g_canon` (new `PolicyError::SchemaViolation`).
- **peercred:**
  - `require_peer(socket, uid, gid)`;
  - `BoundListener { listener, lock }`;
  - new `PeerError` variants for pidfd and lock failures.

**Module layout.** The core is sans-IO: pure functions over byte buffers, so that Week 3's Tokio runtime reuses it.

| Module | Role |
|---|---|
| `src/http.rs` | The strict HTTP/1.1 subset (kept from AP):<br>• request line plus headers ≤ 16 KiB and ≤ 64 fields;<br>• an exact `Content-Length` only;<br>• reject `Transfer-Encoding`, duplicate or conflicting `Content-Length`, `Content-Encoding`, obs-fold, bare CR or LF, HTTP/1.0 and HTTP/2 prefaces;<br>• one request per connection (`Connection: close`);<br>• body ≤ 1 MiB;<br>• header and body deadlines through `set_read_timeout`. |
| `src/mcp.rs` | Header↔body checks, `_meta` checks, the method router, error bodies (U1) |
| `src/sse.rs` | The upstream SSE reader: `data:` lines, `:` comment keep-alives, notifications dropped, byte and time caps |
| `src/forward.rs` | Upstream request bodies and headers |
| `src/config.rs` | The config, parsed with `jcs` |
| `src/control.rs` | Control-socket messages |
| `src/tokens.rs`, `src/lockfile.rs` | Steps 9 and 10 |
| `src/main.rs` | The `pep-sidecar` binary. Std threads with a bounded connection count. One engine thread owns the eid→`PepEngine` registry, `HostAuthority`, Episode Token minting and Call Proof signing. Connection threads verify Episode Tokens and send messages that cannot express approve, trusted input or abort. |
| `src/bin/pepctl.rs` | `lock scan`, `lock sign` (keys from `/dev/urandom`); Week 6 adds `explain` and `replay` |
| `src/bin/` stubs | The stub broker, the stub tool server and the scripted operator, under the same lints |

**Config** (JSON parsed by `jcs`, safe integers only; keys as SEC1 or JWK):

| Section | Fields |
|---|---|
| `agent` | `uid`, `gid`, `socket` |
| `operator` | `uid`, `socket` |
| `broker` | `uid`, `socket` |
| `pep` | `spiffe_id`, `pubkey_dir` |
| `lockfile` | `path`, `signers` (`role`, `key`), `min_accepted_epoch` |
| `intents` | name → `PepIntent`; the Week 2 stand-in for RAR |
| `limits` | `connections`, `header_bytes`, `body_bytes`, `read_timeout_ms`, `upstream_timeout_ms`, `step_up_timeout_ms`, `episode_idle_ms` |
| `pins` | Used until step 10 replaces it with the lockfile |

**Control protocol** (H1, E1). The same HTTP subset carries one JSON request per connection, and the peer uid must be 20004.

| Call | Parameters | Result |
|---|---|---|
| `start_episode` | `intent` | `eid`, `episode_token`, `exp` |
| `trusted_input` | `eid`, `input_id`, `value`, `conf` | — |
| `pending` | — | Awaiting approvals: `eid`, `rid`, `tool`, `arguments`, `action_digest`, `amount_minor` |
| `approve` / `decline` | `eid`, `rid`, `action_digest`, `amount_minor`, all matched against the `AwaitingStepUp` reservation | — |

**PEP↔broker.**
- **Transport:** Streamable HTTP over `/run/broker/broker.sock`, with mutual peer-uid checks (the broker requires 20002, the PEP requires 20003); SPIFFE is deferred.
- **What it carries:** only PEP-built requests: `tools/call` with a Call Proof, and `tools/list` and `server/discover` for drift checks.
- **Routing:** `/mcp/{server_id}`, from the lockfile.
- **Broker duties:**
  - verify the Call Proof;
  - recompute `action_digest` and the F-07 key;
  - inject the credential and `Idempotency-Key`;
  - forward to the tool server over `tools_net`.
- **Outcomes.** For payments, the broker adds `_meta["dev.pep-sidecar/outcome"]` (`executed`, `refused` or `unknown`), after stripping any `dev.pep-sidecar/*` key the tool server sent.

**Stub tool servers** (two servers, for shadowing):
- **Tools:** the Week 1 test set: a bound lookup (`get_invoice`), a payment (`pay_invoice`), a sink, and a store writer.
- **Payment status.** Payment results carry an explicit `status` (`executed`, `declined` or `pending`), which the broker maps to the outcome.
- **Bookkeeping:**
  - `Idempotency-Key` dedupe, in a store that survives PEP and broker restarts;
  - a JSONL execution log.
- **Misbehaviour modes** come from the server's own start-up config, never from the agent:
  - wrong or duplicate response ids;
  - SSE notifications before the result;
  - oversized and endless responses;
  - `input_required`;
  - list changes;
  - `x-mcp-header` annotations.

**Bypass oracle.**
- **The join:** every execution in the stub logs must join exactly one PEP Allow decision on (`action_digest`, `jti`).
- **Payments:** every payment's `Idempotency-Key` must equal the F-07 key of a reservation the PEP held.
- **Bypasses:** an execution with no match, or a match against a denied call, is a bypass.

## 3. Gate 1 suite
### Containment (96 tests; G1 needs ≥ 50 per S1 profile with 0 bypasses)

| Category | Count | Tests |
|---|---|---|
| C-UID | 5 | • wrong uid;<br>• root;<br>• overflow uid 65534;<br>• uid right but gid wrong (rejected under Q1);<br>• socketpair self-connect |
| C-PID | 6 | • a getsockopt error rejects;<br>• fdinfo `Pid: -1` rejects;<br>• the peer exits between accept and check;<br>• `Pid: 0` is handled per Q1;<br>• `ENOPROTOOPT` (kernel < 6.5) rejects;<br>• no pidfd leaks (cloexec) |
| C-LOCK | 6 | • a second instance is blocked;<br>• a stale socket is replaced only under the lock;<br>• the lock is released on a crash;<br>• a read-only lock directory fails;<br>• a symlinked socket path is refused;<br>• the agent cannot open the lock file |
| C-NET | 8 | From the agent:<br>• no route;<br>• no DNS;<br>• no TCP to the PEP's network address;<br>• only `lo` present;<br>• no IPv6;<br>• raw and packet sockets fail;<br>• UDP/53 fails;<br>• DoH (TCP/443 to a resolver) fails |
| C-PROC | 3 | • ptrace of the PEP fails, or, under Q1 (i), the PEP pid is not visible;<br>• `/proc/<pep>/mem` is unreadable;<br>• the PEP's argv and env hold no key or credential |
| C-POSTURE | 4 | • every container has CapEff 0;<br>• NoNewPrivs 1;<br>• Seccomp 2;<br>• no container mounts `docker.sock` |
| C-HTTP | 17 | • CL+TE;<br>• TE only;<br>• duplicate CL;<br>• CL mismatch;<br>• obs-fold;<br>• bare LF;<br>• header over the cap;<br>• body over the cap;<br>• slowloris headers;<br>• slow body;<br>• a pipelined second request;<br>• HTTP/1.0;<br>• GET → 405;<br>• DELETE → 405;<br>• `Content-Encoding` rejected;<br>• an HTTP/2 preface rejected;<br>• a notification POST → 400 |
| C-MCP | 18 | -32020 and 400:<br>• missing `MCP-Protocol-Version`;<br>• the version header differs from `_meta`;<br>• `Mcp-Method` differs from the body;<br>• `Mcp-Name` differs from the body;<br>• a base64-sentinel `Mcp-Name` mismatch.<br><br>Other replies:<br>• a batch array body → 400;<br>• a JSON-RPC response as the body → 400;<br>• any `Origin` → 403;<br>• an unknown version → -32022 and 400;<br>• `Accept` without `text/event-stream` → 400;<br>• missing `_meta` `protocolVersion` → -32602 and 400;<br>• missing `_meta` `clientCapabilities` → -32602 and 400;<br>• `server/discover` answered without upstream `instructions`;<br>• `subscriptions/listen` acknowledged empty, then closed.<br><br>`Mcp-Param` and `Mcp-Name` checks:<br>• `Mcp-Name` base64 with NFC compared correctly;<br>• `Mcp-Param` integers compared numerically;<br>• a missing pinned `Mcp-Param` → -32020;<br>• an unknown `Mcp-Param` → -32020 |
| C-FWD | 4 | • no agent header (`Authorization`, `Idempotency-Key`, `Mcp-Param-*`, `Pep-Episode`) reaches upstream;<br>• upstream `_meta` holds only PEP-built keys (the agent's `traceparent`, `logLevel`, `progressToken` and unknown keys are absent);<br>• the upstream id is PEP-assigned;<br>• the upstream body equals the `forward::tools_call_request` output byte for byte |
| C-RES | 5 | • a response id mismatch;<br>• duplicate responses;<br>• an `outcome` key forged by the tool server, which is stripped and never trusted;<br>• an unknown `resultType`;<br>• `input_required`, which is not recorded, and a payment's reservation is `NeedsReconcile` |
| C-JSON | 6 | • duplicate keys (`name` twice) against `canonical_request`;<br>• NaN or Infinity;<br>• lone surrogates;<br>• a depth bomb;<br>• a huge number;<br>• a BOM |
| C-EPI | 6 | Episode Token:<br>• missing;<br>• malformed (charset);<br>• forged signature;<br>• expired or idle;<br>• `peer_uid` mismatch (replacing AP's "wrong `aud`": the token has no `aud`);<br>• a Call Proof presented as an Episode Token |
| C-CRED | 2 | • the agent and the PEP cannot read the broker credential;<br>• the tool server rejects calls without it |
| C-CTL | 3 | • the agent cannot reach `/run/pep-ctl`;<br>• an approval with any of (eid, rid, `action_digest`, amount) mismatched is refused;<br>• a declined step-up leaves the reservation `Released`, and the agent gets `PEP_DENIED` |
| C-OUT | 3 | • an agent disconnect after forwarding never releases the reservation;<br>• a retry after `Unknown` with the same `action_digest` → `ReconcilePending`;<br>• denials from every guard have identical wire bytes apart from the id |

### Rug-pull mutations (G2: every one quarantined)
Each mutation must lead to quarantine: the tool is hidden from `tools/list` and its calls are denied (`ToolQuarantined`). The model is Invariant Labs' "Tool Poisoning Attacks" (2025-04-01): a server that changes a tool after approval, `<IMPORTANT>` payloads, and shadowing. The mutations:
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
12. same name on a second server (shadowing). This needs two stub servers and per-server identity in the lockfile;
13. `readOnlyHint` true→false;
14. `destructiveHint` false→true;
15. `idempotentHint` or `openWorldHint` flipped;
16. Cyrillic homoglyph in the name. The ASCII-name rule rejects it at load;
17. zero-width joiner in the description;
18. bidi override in the description;
19. `x-mcp-header` annotation added (header mirroring changes). This needs `x-mcp-header` support in the stub;
20. `notifications/tools/list_changed` followed by a changed definition. This needs the upstream listen stream, or polling;
21. title or icon change on a security-role tool;
22. default value injected into the schema;
23. an integer beyond ±(2^53−1) changed; definitions with such integers are quarantined;
24. a definition changed on page 2 only.

**Negatives**, which must not trigger drift:
- key reordering;
- whitespace;
- equivalent number formatting (`0.50` and `0.5` under the result profile);
- a `\u` escape versus the literal code point;
- the same list split across pages differently.

### Replays (G3: 0 of 1,000 accepted)
Captured Episode Tokens and Call Proofs are replayed:
- verbatim;
- after `exp`;
- against a different `rid`;
- after the reservation leaves `Held`;
- with a malleated high-S signature (same `jti`);
- re-encoded (padding, standard versus URL-safe alphabet);
- concurrently from N threads, where exactly one first use is accepted;
- after a PEP restart, with a key from the previous boot;
- after a broker restart, with a proof issued before the broker booted;
- after the clock is stepped back;
- with `typ` and key confused: an Episode Token presented as a Call Proof, and the reverse.

### p99 (G4)
Measured as O1 defines it, and reported with p50, p99.9, max, the CPU model and the load profile.

## 4. Containers
A Compose sketch (step 4 verifies every key against the Compose reference [80]):

```yaml
name: pep-gate1
services:
  agent:                       # Gate 1 test client (TS or Python SDK)
    user: "20001:20001"
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true", "seccomp=./seccomp-agent.json"]
    network_mode: "none"
    volumes:
      - { type: volume, source: pep-sock, target: /run/pep, volume: { nocopy: true } }
    # pid: "service:pep"       # only if Q1 = (ii)
  pep:
    user: "20002:20002"
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    network_mode: "none"
    volumes:
      - { type: volume, source: pep-sock,    target: /run/pep,     volume: { nocopy: true } }
      - { type: volume, source: pep-ctl,     target: /run/pep-ctl, volume: { nocopy: true } }
      - { type: volume, source: pep-pub,     target: /run/pep-pub, volume: { nocopy: true } }
      - { type: volume, source: broker-sock, target: /run/broker,  volume: { nocopy: true } }
      - { type: bind, source: ./config/pep, target: /etc/pep, read_only: true }
  broker:
    user: "20003:20003"
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    networks: [tools_net]
    volumes:
      - { type: volume, source: broker-sock, target: /run/broker,  volume: { nocopy: true } }
      - { type: volume, source: pep-pub,     target: /run/pep-pub, read_only: true, volume: { nocopy: true } }
      - { type: bind, source: ./secrets/broker-credential, target: /run/credential, read_only: true }
  operator:                    # scripted operator (H1)
    user: "20004:20004"
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    network_mode: "none"
    volumes:
      - { type: volume, source: pep-ctl, target: /run/pep-ctl, volume: { nocopy: true } }
  tool-a: &tool              # stub tool servers; any unprivileged uid
    user: "20005:20005"
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    networks: [tools_net]
  tool-b: *tool                # second server, for shadowing (#12)
volumes:
  pep-sock:    { driver: local, driver_opts: { type: tmpfs, device: tmpfs, o: "uid=20002,gid=20001,mode=2750" } }
  broker-sock: { driver: local, driver_opts: { type: tmpfs, device: tmpfs, o: "uid=20003,gid=20002,mode=2750" } }
  pep-ctl:     { driver: local, driver_opts: { type: tmpfs, device: tmpfs, o: "uid=20002,gid=20004,mode=2750" } }
  pep-pub:     { driver: local, driver_opts: { type: tmpfs, device: tmpfs, o: "uid=20002,gid=20003,mode=2750" } }
networks:
  tools_net: { internal: true }
```

- **Socket directories.** They must exist before the PEP starts, with the owners and modes above. Otherwise `bind_safe_listener` refuses: the parent must be owned by the euid with `mode & 0o027 == 0`, and setgid gives the socket the parent's group.
  - **Why named volumes.** A tmpfs-backed *named* volume is shared between containers. A per-service `tmpfs:` entry would give each container a private copy.
  - **`nocopy: true`.** It stops Docker copying image contents into a fresh volume. Some engines also copy the image directory's owner and mode even when it is empty, so step 4 checks owner and mode at start.
- **Images:**
  - a real `/run` owned by root and not a symlink, because `bind_safe_listener` checks every ancestor;
  - B1 decides between static musl and a glibc-matched base.
- **Agent seccomp profile.** Docker's default, minus every socket family except `AF_UNIX`. The denial returns `EAFNOSUPPORT` rather than killing the process, so SDKs fail cleanly.
- **Secrets:**
  - Compose ignores `uid`, `gid` and `mode` on file secrets [80], so the broker credential is a host file that is already 0400 and owned by 20003, bind-mounted read-only into the broker only;
  - the PEP's own keys are per-boot (R1), so they need no secret.
- **Host user 20004.** The operator uid is new. SPEC §1 gains it in step 2.

## 5. Forward constraints (decided now so Week 2 does not paint later weeks into a corner)
- **Week 3:**
  - Tokio reuses the sans-IO modules of §2a, so the std-threads binary is not rewritten.
  - SQLite persistence revisits R1.
  - Reconciliation of `NeedsReconcile` replaces the P1 dedupe.
- **Week 4:**
  - The agent reaches its LLM through N1's Unix-socket model proxy.
  - AgentDojo has its own tool runtime, so it needs an adapter.
  - Validate D2 against the Python SDK (httpx2) as well as TypeScript.
- **Week 5.** The PEP reaches the Txn-Token service and the PDP through N1's chosen egress path. `tth` and the Week 5 claim values arrive.
- **Latency.** The worst-case 1 MiB request is measured separately (O1), because hashing cost grows with bytes × depth.

## 6. Proposed SPEC and CLAUDE.md wording
Nothing here is applied by this document.
- **SPEC.md:** each item is applied in step 2 when its decision closes, keeping CRLF.
- **CLAUDE.md:** owned by you, also CRLF; you apply it.

**SPEC.md:**
- **§1, containment (N1, H1, R1):**
  - Name the Compose network model.
  - Add these sockets and directories:
    - the broker socket `/run/broker/broker.sock`, in a directory owned 20003:20002 with mode 2750;
    - the control socket `/run/pep-ctl/ctl.sock`, in a directory owned 20002:20004 with mode 2750, with operator uid 20004;
    - `/run/pep-pub` for the Call Proof public key.
  - State that the socket directories are tmpfs-backed named volumes.
  - "The broker authenticates the PEP by `SO_PEERCRED` uid 20002 until SPIFFE (deferred)."
  - "Vault credential injection is deferred; the Week 2 broker reads a credential file."
- **§3.3, Episode Token (E1, R1):**
  - "Minted by the PEP on the host `start_episode` call; idle timeout 30 minutes; signed with a per-boot key, so a PEP restart invalidates every token."
  - "No `iss`, `aud`, `jti` or `nbf`: the PEP is the only issuer and verifier; the `typ` and key differ from the Call Proof's, which makes the two validations mutually exclusive."
- **§3.4, Call Proof (T1, R1):**
  - `typ` becomes `pep-callproof+jwt`.
  - Give concrete `iss` and `aud`, the server binding, and definitions of `budget`, `tool_schema_digest` and `prov`.
  - List the checks the broker performs.
  - "Signatures use low-S; the broker rejects high-S."
  - "The broker rejects proofs issued before its boot."
  - "`tth` is added in Week 5."
- **§4:**
  - **Week 2** gains:
    - the binary;
    - the transport (D2);
    - Compose;
    - the stub broker and tool servers;
    - `pepctl lock scan/sign`;
    - strict argument schemas;
    - `prov`.
  - **Gate 1:** "evaluated on the Compose profile" (S1), with O1's latency definition.
  - **Week 3:** "reconciliation replaces the Week 2 `NeedsReconcile` dedupe".

**CLAUDE.md** (wording for you to apply):
- **§2 (once `compose.yaml` exists):** add `docker compose config --quiet` to the loop.
- **§3, new rule "Binaries":** "Binaries log with `writeln!` to a locked `stderr` handle and return `std::process::ExitCode` from `main`. `print_stdout`, `print_stderr` and `exit` stay denied. Never log raw tokens, proofs or keys."
- **F-11/F-12, append:** "Before unlinking or binding, take an exclusive `File::try_lock` on `<socket>.lock` (mode 0600, owner euid, checked by lstat before and fstat after), and hold it for the listener's lifetime."
- **F-13, replace the second sentence:** "Agent connection threads never hold `HostAuthority`; they send the engine thread messages that cannot express approve, trusted input or abort. `approve_step_up` and `record_trusted_input` run only for control-socket messages from the operator uid, and abort outcomes come only from the upstream leg." At step 10, also replace "(until the Week 2 lockfile pins full argument schemas)" with the rule the strict schemas set.
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
  - the model-provider egress proxy (chosen in N1, built in Week 4).
- **Week 5:**
  - RAR and ID-JAG exchange;
  - the Txn-Token service and `tth`;
  - AuthZEN, AP2 and Stripe;
  - SPIFFE identities;
  - Vault.
- **Deferred by this plan:**
  - the same-host process profile and gVisor (S1);
  - cgroup-eBPF, Landlock and Yama (N1);
  - hot lockfile reload (L1);
  - `destructive` and `code_exec` tools (L1).

## Risks
- **User namespaces.** Under userns-remap or rootless Docker, uids are translated, so `require_peer` must compare uids as the PEP's user namespace sees them. Test on the actual runtime (AP's Q2).
- **HTTP smuggling.** Only the strict parser stands between the agent and request smuggling, so any regression there is a security bug (C-HTTP).
- **A young MCP revision.** 2026-07-28 is three months old, and SDKs and servers may diverge from it, for example on the `subscriptions/listen` reply or `x-mcp-header`. Re-check the Appendix A pages before Gate 1.
- **In-memory state.** Until Week 3, a PEP restart voids every episode (R1), and the operator must start them again.
- **The seccomp profile.** Blocking non-`AF_UNIX` sockets may break an SDK that opens an inet socket at start-up. The profile returns `EAFNOSUPPORT`, so such failures are visible.
- **Kernel drift.** pidfd behaviour differs between this kernel and CI kernels (Q1). Tests branch on version and record `uname -r`.
- **Young crates.**
  - p256 0.14.0 (2026-07) and crypto-bigint 0.7.x are recent.
  - p256's docs say its arithmetic was never independently audited.
  - That matters more for signing Call Proofs, where the secret key is used, than for verification.

## Appendix A. Verification notes (2026-10-31)
**Repo at `bb25e27`:**

| Claim | Evidence |
|---|---|
| `MAX_IN_FLIGHT` is 64 | `src/engine.rs:43` |
| Agents see only two codes | `src/engine.rs:271` (`to_agent_code`) |
| Four effect classes | `src/engine.rs:645` (`EffectClass`) |
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
| Number modes and parse profiles | `src/jcs.rs:173-225` |
| F-13 contains "until the Week 2 lockfile pins full argument schemas" | `CLAUDE.md:85` |
| `print_stdout`, `print_stderr` and `exit` are denied | `Cargo.toml`, `[lints.clippy]` |
| Allowed licences are MIT, Apache-2.0 and Unicode-3.0; `multiple-versions` and `yanked` are denied | `deny.toml` |
| SPEC.md and CLAUDE.md are CRLF; WEEK1_PLAN.md is LF; there is no `.gitattributes` | `file`, and a CRLF count |

**Dependencies:**
- **nix 0.31.3:**
  - `sockopt::PeerPidfd` is at `src/sys/socket/sockopt.rs:687`, and there is no `SO_PASSRIGHTS` sockopt;
  - `OFlag` (needed for `O_NOFOLLOW`) requires the `fs` or `term` feature (`src/fcntl.rs:116-119`).
- **p256 0.14.0 [78]:**
  - `default` = `arithmetic`, `ecdsa`, `pem`, `precomputed-tables` and `std`;
  - `std` enables `getrandom`;
  - `ecdsa` = `arithmetic`, `ecdsa-core/algorithm` and `sha256`.
- **elliptic-curve 0.14.3 [79]:** `getrandom` comes only through its own feature.

**Five-Track report** (parent folder), by line:

| Lines | Content |
|---|---|
| 41 | nftables plus cgroup-eBPF |
| 518–524 | Tier-1 containment (seccomp, Landlock, Yama); gVisor optional |
| 538 | Agent seccomp profile; `runsc` optional |
| 568 | The cgroup `connect4` hook |
| 616–658 (§3.6) | `start_episode`; the 30-minute idle timeout; dedupe on (eid, action_digest, idempotency_key); the upstream strips the Episode Token |
| 670–707 (§4.2) | Lockfile fields; 2 of 3 signers; six effect classes; `pepctl lock` |
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
| The p256 0.14.0 tree:<br>• new crates and versions (RV: 23 new crates, crypto-bigint 0.7.10, ctutils 0.4.7);<br>• licences (RV: only `subtle`'s BSD-3-Clause is new);<br>• MSRV ≤ 1.87;<br>• RV's probe: high-S, RFC 6979, about 0.34 ms p50 for sign and verify | Needs `cargo` resolution and a build | Step 6 |
| `VerifyingKey::from_sec1_bytes` with only `["ecdsa"]` | The feature path through `ecdsa-core/algorithm` is unverified | Step 6 |
| Engines copying an image directory's owner and mode into an empty volume (RV, from moby [84][85]) | Not reproduced | Step 4 |
| httpx2 `AsyncHTTPTransport(uds=…)` | httpx2's docs don't mention it | D2 spike |
| Kernel versions: stale-pidfd behaviour, `EINVAL`→`ESRCH`, CI runner kernels | Carried from AP Appendix B | Step 7 |
| The `subscriptions/listen` reply, against an MCP conformance suite if one exists | Only the spec pages were checked | Step 3 |
| `SO_PEERCGROUPID` not in mainline uapi [81][82] | Secondary sources only | Only if Q1 = (ii) |
| The Invariant Labs tool-poisoning text against the mutation list | Carried from AP Appendix B | Step 10 |
| Sources [1]–[65] | Carried from AP, not re-checked | As cited |

## Appendix C. Corrections and disposition
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
  - "eBPF isn't in any doc": see Five-Track lines 41, 518, 568 and 866.
  - The "0700, operator uid" control socket: it contradicts itself (H1).
  - "engine.rs:836": the pass-through is `is_reserved_meta`, at line 2225.
  - "Anything else → 404": it breaks `server/discover` (a MUST) and `subscriptions/listen`.
  - nix `fs` + `Flock`: replaced by std `File::try_lock`.
- **RV:**
  - The F-13 quote claim is wrong: CLAUDE.md line 85 contains the phrase.
  - The "Week 1 verified plan's testbed appendix" and the "Week 1 list" (IPv6, raw and packet sockets, UDP/53, DoH, ptrace) are in no project doc. The eBPF point stands on Five-Track, and the tests are kept on merit.

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
| §1.3 the dedupe after `Unknown` | P1; §2a; C-OUT |
| §1.3 a declined or timed-out step-up is `DefinitelyNotExecuted` | P1; C-CTL |
| §1.3 `commit` leaves `in_flight` | P1 |
| §1.3 outcomes only from upstream | P1; §6 F-13 |
| §1.4 restarts: boot nonce, broker cutoff, tool dedupe, restart replays | R1 (per-boot keys instead of a nonce); §3 replays |
| §1.5 episode lifecycle | E1; §2a control protocol |
| §1.6 control socket; approval tuple; scripted operator | H1; §4; C-CTL |
| §1.7 prerequisites for #12, #19 and #20; a misbehaving stub; the oracle | §3 mutations; §2a stubs and oracle |
| §1.7 Vault broker | Deferred (a credential file in step 3); Out of scope |
| §2 eBPF | N1 records the deferral |
| §2 F-13 quote | Corrected (above) |
| §2 open p99 points | O1 |
| §2 drift canonicalization | Step 10; mutations 23–24 |
| §2 gate scope per profile | S1; G1 |
| §2 lock file: 0600, `O_NOFOLLOW`, fstat; drop the probe; std `try_lock` | Step 8 (lstat/fstat instead of `O_NOFOLLOW`) |
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
| §5 `deny.toml`: BSD-3-Clause, optional bans | Step 6 |
| §5 `Cargo.toml`: p256, `panic`, `overflow-checks` | Step 6; B1 |
| §5 `rust-toolchain.toml` musl | B1 |
| §5 `.gitattributes` | Step 4 |
| §5 Compose: `nocopy`, seccomp | Step 4; §4 |
| §5 WSL `systemd`, `uname -r`, CI kernels | Step 1; step 5; Q1 |
| §5 CLAUDE.md: logging, Compose step, F-13, F-16 | §6 |
| §5 unsafe record | Step 6 |
| §6 model egress, AgentDojo and Python, Tokio sans-IO, Week 5 networking, 1 MiB latency | N1; D2; §2a; §5; O1 |
| §7 dependency tree, high-S, deterministic signing, speed | Step 6 (re-confirmed locally); T1 (low-S) |
| §7 kernel options | Q1; Appendix B |
| §7 Rust 1.99.1 | D1 (confirmed on primary evidence) |

**Disposition of MG:**

| MG item | Where it went |
|---|---|
| Docker in WSL | Step 1 (Docker Engine, not Docker Desktop) |
| Startup order: claim `HostAuthority` first | §2a `main.rs` |
| Config loader with `jcs`, no serde | §2a config |
| `HostAuthority` split: an engine thread, restricted messages | §2a; §6 F-13 |
| Control socket "0700, operator uid" | Corrected; see H1 |
| Forwarder outcome mapping | P1, extended |
| F-16 forwarding change; canonical result bytes | §2a engine changes; §6 F-16 |
| Upstream is the broker; the stub broker; `/run/broker` with a uid check | §2a PEP↔broker; §4 |
| Method routing, "anything else → 404" | Corrected; see M1 |
| Its Compose section (uids, hardening, tmpfs volumes, a real `/run`) | §4 |
| N1 | N1 |
| Item 5: test kit and CI job | Step 5 |
| Item 6: crate rules (jcs parsing, `=` pins, unsafe record, deny checks) | Context; step 6 |
| Item 8: the lock file kept with the listener | Step 8, with std locking |
| Item 9: tokens (`typ`, claims, bindings, -32020, `Held` only, replay cache, `tth`) | T1; E1; M1 bindings; step 9 |
| Item 10: lockfile (`ToolPins`, `lockfile_digest`, strict schema) | L1; step 10 |
| Item 11: `prov` from `leaf_index` | T1 (two options); step 11 |
| Docs: SPEC §1/§4 and the CLAUDE.md F-16 diff | §6 |
| Correction: D1 | D1 |
| Correction: D2 (the token is already in `_meta`) | D2 |
| Correction: Compose mode 0750 and uids | §4 |
| Correction: `aud`, `jti` and `nbf` only on Call Proofs | E1; C-EPI |
| The values MG resolved for AP's confirm markers: kernel 6.5, nix `PeerPidfd`, 1 MiB, the security role, "added latency", JCS drift, SPEC §4 format | Context; Q1; L1; O1; step 10 (drift now uses the result profile) |
| `deny.toml` already blocks an old crypto-bigint | G5; step 6 |
| The items MG skipped: crate choice, kernel checks, the old step ordering | Unchanged: p256 only, JWS and DSSE hand-rolled; Q1; §2 |
| MG's checks of the Week 1 report: N1 and `/run/pep` before start were kept; eBPF was skipped | N1; §4; the eBPF skip is corrected |
| The merged build order | §2 |

## Sources
Sources [1]–[65] are carried from AP and were not re-checked for this plan, except [1], [6] and [26], which Appendix A covers.

1. <https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http>
2. [\[PATCH\] pidfs: return -EREMOTE when... | Ratatoskr](https://ratatoskr.run/linux-fsdevel/2026/01/338598/t)
3. [pidfs.c source code \[linux/fs/pidfs.c\] - Codebrowser](https://codebrowser.dev/linux/linux/fs/pidfs.c.html)
4. [socket: peer\_cred returns none when the peer is in another PID namespace (containers), discarding a valid uid · Issue #329 · enghitalo/vanilla · GitHub](https://github.com/enghitalo/vanilla/issues/329)
5. [Allow Varlink peers from a different (ancestor) PID namespace, or make the peer-credential requirement configurable · Issue #43807 · systemd/systemd · GitHub](https://github.com/systemd/systemd/issues/43807)
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
20. [p256 - crates.io Package Security Analysis - Socket](https://socket.dev/cargo/package/p256)
21. [p256 - crates.io: Rust Package Registry](https://crates.io/crates/p256)
22. [Upgrade p256 to 0.14 to clear RUSTSEC-2026-0387 (crypto-bigint timing) · Issue #380 · Jolah1/ghostKey · GitHub](https://github.com/Jolah1/ghostKey/issues/380)
23. [Move to the elliptic-curve 0.14 crates (RUSTSEC-2026-0387); MSRV 1.87 by framefilter · Pull Request #212 · framefilter/keyroost · GitHub](https://github.com/framefilter/keyroost/pull/212)
24. [nix 0.31.3 - Docs.rs](https://docs.rs/crate/nix/latest)
25. [Release with the RustCrypto 0.14 crates to pick up the crypto-bigint fix (RUSTSEC-2026-0387) · Issue #1103 · ZcashFoundation/frost · GitHub](https://github.com/ZcashFoundation/frost/issues/1103)
26. [Client transports - MCP Python SDK](https://py.sdk.modelcontextprotocol.io/client/transports/)
27. [Connect to Any MCP Server in TypeScript Over stdio and HTTP, Then List Its Tools - DEV Community](https://dev.to/royalpinto007/connect-to-any-mcp-server-in-typescript-over-stdio-and-http-then-list-its-tools-1o4k)
28. [URL validation makes it impossible to implement unix domain socket transport · Issue #1119 · algesten/ureq · GitHub](https://github.com/algesten/ureq/issues/1119)
29. [nix::sys::socket::sockopt - Rust](https://docs.rs/nix/latest/nix/sys/socket/sockopt/index.html)
30. [nix/CHANGELOG.md at master · nix-rust/nix · GitHub](https://github.com/nix-rust/nix/blob/master/CHANGELOG.md)
31. [net/unix: use consistent error code in SO\_PEERPIDFD - linux/linux-stable.git - Linux kernel stable tree](https://git.sceen.net/linux/linux-stable.git/commit/net/core?id=b6f79e826fbd26e91e2fb28070484634cacdeb26)
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
44. [RUSTSEC-2026-0387 Multiple timing variability issues in op... - vulnerability database](https://vulners.com/osv_rustsec/OSV:RUSTSEC-2026-0387)
45. [Advisories in category 'crypto-failure' › RustSec Advisory Database](https://rustsec.org/categories/crypto-failure.html)
46. [Release v1.17.0: RUSTSEC-2026-0387/0385 fix, MSRV 1.87 · frankxue831/gm-crypto-rs · GitHub](https://github.com/frankxue831/gm-crypto-rs/releases/tag/v1.17.0)
47. [fix(deps): update rust crate pakery-crypto to v0.6.2 by renovate\[bot\] · Pull Request #45 · sjcl/jigsall · GitHub](https://github.com/sjcl/jigsall/pull/45)
48. [chore(deps): update crypto-bigint to 0.7.10 by houseme · Pull Request #8962 · rustfs/rustfs · GitHub](https://github.com/rustfs/rustfs/pull/8962)
49. [fix(security): clear RUSTSEC-2026-0385/0387 from the audit job by smunini · Pull Request #2232 · HeliosSoftware/hfs · GitHub](https://github.com/HeliosSoftware/hfs/pull/2232)
50. [dsse/protocol.md at v1.0.0 · secure-systems-lab/dsse · GitHub](https://github.com/secure-systems-lab/dsse/blob/v1.0.0/protocol.md)
51. [github.com](https://github.com/asraa/dsse/blob/master/envelope.md)
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
65. [\[PATCH 0/8\] Support unix domain sockets across namespaces](https://containers.osdl.narkive.com/xsCg9yZu/patch-0-8-support-unix-domain-sockets-across-namespaces)
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
