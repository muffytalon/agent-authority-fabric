# SPEC.md — OAuth-Native Provenance & Intent Enforcement Sidecar Specification

## 1. Core Architecture & OS Containment Boundary
- **Process & UID Isolation:**
  - `agent` container/process: `UID 20001:20001`, read-only rootfs, `cap_drop: [ALL]`, `no-new-privileges: true`, zero direct IPv4/IPv6 egress (`nftables` drops all packets from `skuid 20001`; no loopback TCP holes).
  - `pep` sidecar: `UID 20002:20002`, listens on `unix:///run/pep/mcp.sock` (parent `/run/pep` owned by `20002:20001` mode `2750` (setgid, so the socket inherits group `20001`); `mcp.sock` `20002:20001` mode `0660`). Verifies peer identity via `SO_PEERCRED` + `SO_PEERPIDFD` (Linux) or `getpeereid` + `LOCAL_PEERPID` (macOS), and requires both the peer's uid and its gid. Across PID namespaces, `SO_PEERPIDFD` proves only that the peer is alive; identity rests on the `SO_PEERCRED` uid and gid. Speaks MCP `2026-07-28` Streamable HTTP to the agent over that socket, with no TCP listener: a hand-rolled HTTP/1.1 subset with one request per connection. Requests are POSTs with an exact `Content-Length`; any other method gets 405. JSON replies carry `Content-Length`, the one SSE reply (`subscriptions/listen`) ends when the connection closes, and every reply sends `Connection: close`. The Episode Token travels in `_meta` (§3.3).
    - **Replies:** every policy or token denial is HTTP 200 with JSON-RPC error code `-31403` and message `PEP_DENIED`; every unavailability, rate limiting included, is HTTP 200 with `-31503` and `PEP_UNAVAILABLE`. Neither carries `data`. MCP-mandated errors keep their own codes.
    - **Upstream results:** the PEP records, and returns to the agent, only results whose `resultType` is `complete`. It rejects an upstream result with no `resultType`. This departs from MCP `2026-07-28`'s client rule for earlier-revision servers, because every pinned server implements `2026-07-28`.
    - **State:** the journal of payment reservations, F-08 taint, the F-09 ratchet and server quarantines (`/var/lib/pep/journal.jsonl`) is on an on-disk volume that only the PEP mounts. A ratchet rise is durable before any reply that depends on it. A quarantine is journaled by (`server_id`, `lockfile_digest`), so only a lockfile with a different digest lifts it, and every server's first poll completes before the agent socket binds. The PEP's decision log is on its own size-capped volume.
    - **Keys:** the Episode Token key and the Call Proof key are generated at every boot (§3.3, §3.4). The PEP writes the Call Proof public key to `/run/pep-pub` (owned by `20002:20003` mode `2750`), which the broker mounts read-only.
  - `operator` (host control): `UID 20004:20004`. The PEP listens for it on `unix:///run/pep-ctl/ctl.sock` (parent `/run/pep-ctl` owned by `20002:20004` mode `2750`), which is never mounted into the agent. The PEP requires peer uid and gid `20004`, gives this socket its own connection limit, and serves its messages before agent traffic. Only this socket starts and ends episodes, records trusted inputs, and approves or declines step-ups (§3.3).
  - `broker` egress proxy: `UID 20003:20003`, listens on `unix:///run/broker/broker.sock` (parent `/run/broker` owned by `20003:20002` mode `2750`). The broker authenticates the PEP by `SO_PEERCRED` uid and gid `20002` until SPIFFE (deferred), and the PEP requires peer uid and gid `20003` of the broker. The broker forwards `tools/call` only with a valid ES256 Call Proof (§3.4). It forwards proof-less `tools/list` and `server/discover` from the PEP, for drift checks and lock scans, and no other proof-less method. It routes by a static `server_id` → endpoint table in its own config, and loads the same lockfile as the PEP, read-only, for §3.4's checks. It recomputes `action_digest` with the same `JCS_strict_NFC` profile pinned to Unicode 18.0.0 (§2), recomputes the F-07 `Idempotency-Key` from `eid`, `rid`, and its own `action_digest`, and injects the target server's own credential + `Idempotency-Key`. Each tool server has its own credential and its own network, so one server cannot use what it sees to call another. Vault credential injection is deferred; the Week 2 broker reads credential files.

## 2. Cryptographic Digest Conventions (`src/jcs.rs`)
- `digest(x) = "sha-256:" + base64url_no_pad(SHA-256(JCS_strict_NFC(x)))`
- `action_digest = digest({"method": "tools/call", "name": tool_name, "arguments": args})`
- `origin_hash = digest({"source_call_id": cid, "tool": tool, "query_digest": qd, "result_pointer": ptr, "value": val})`
- **`JCS_strict_NFC` Profile (RFC 8785 + I-JSON + Unicode NFC):**
  - Input at most 1 MiB, depth at most 64, no BOM, no trailing data.
  - NFC on strings and keys before UTF-16 sorting; record the Unicode version the pinned `unicode-normalization` crate implements (`unicode-normalization = "=0.1.26"`, Unicode 18.0.0, i.e. `unicode_normalization::UNICODE_VERSION == (18, 0, 0)`). The broker, and any other component that recomputes a digest, is pinned to the same Unicode 18.0.0: NFC output, and so every digest and F-07 key, differs between Unicode versions for newly encoded characters. A Unicode upgrade therefore ships to the PEP and the broker in one release.
  - Duplicate keys rejected after NFC.
  - Integers within `±(2^53 - 1)` (`[-9007199254740991, 9007199254740991]`); `-0` becomes `0`.
  - Tool results and tool definitions use a result number profile: numbers are formatted per RFC 8785, except that a plain integer token (no fraction or exponent) outside `±(2^53 - 1)` keeps its original digits. Result and definition digests therefore depart from RFC 8785 for those integers only. Requests, whose digests the broker recomputes, never contain them. The lockfile payload, `lockfile_digest` and each `tool_schema_digest` use the same number profile, with larger size and value caps (the definition profile).
  - Key order differs from the RFC 8785 `U+FB33` example because of NFC (`U+FB33` decomposes to `U+05D3 U+05BC` before UTF-16 sorting).
  - Conformance vectors: see **Conformance Vectors** below.
- **`origin_hash` Inputs & `episode_id`:**
  - `cid`: the JCS serialization of the PEP-assigned JSON-RPC id (a ULID string). The agent's own id is only echoed on the reply.
  - `qd`: the `action_digest` of the call that produced the value.
  - `ptr`: an RFC 6901 pointer into the JSON-RPC `result`.
  - `episode_id`: a ULID matching `^[0-9A-HJKMNP-TV-Z]{26}$`, first character at most `7`; F-07 hashes its 128-bit value big-endian.
- **Conformance Vectors:** the unit tests assert each value. All were recomputed independently on 2026-10-28 from the rules above, in Python 3.14.4 (whose `unicodedata` implements Unicode 16.0.0), and all match. No vector uses a character newer than U+1F600 (Unicode 6.1), so they hold unchanged under Unicode 18.0.0.

  | Vector | Expected |
  |---|---|
  | `digest(b"{}")` (known-answer test) | `sha-256:RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o` |
  | `action_digest("pay_invoice", {"amount":5000,"currency":"USD","recipient_id":"rcpt_123"})` | `sha-256:j3XfycsYi2G8jSVocXUTiPN2JWbcwQfOK1L4pLAdI1E` |
  | `action_digest("get_invoice", {"invoice_id":"inv_42"})`, the `qd` of the next row | `sha-256:bdmNQo66RS-48sR_0n8pP5jmbo0a0Sh00gUWv8nEDNU` |
  | `origin_hash` with `cid` `"7"`, `tool` `get_invoice`, that `qd`, `ptr` `/total_minor`, `val` `5000` | `sha-256:2pEVfWny8jku05UQCRDDarGnSs_F2tZB7_YtsC-7SYU` |
  | F-07 key: `episode_id` `0x0192d4e07c3a7b2e9f103c4d5e6f7a8b`, `rid` 1, the `pay_invoice` `action_digest` (75 hashed bytes) | `pep-UhReNoSbXP-SykKxyF9adQ4g5F1oTTAKAJPlYrbk9V0` |
  | The same with `rid` 2 | `pep-xi_53ViTWcbekOTZepC96vxdqaHXZyIGrok6uJGrvPA` |
  | The RFC 8785 §3.2.3 sorting object (keys U+20AC, CR, U+FB33, `1`, U+1F600, U+0080, U+00F6), NFC-adjusted, 181 canonical bytes | `sha-256:mgPbgbBjohAvazT5LBgyJA_w6YmlxvrHDvBHwIx3EZ8` |
  | UTF-16 versus code-point order: keys U+E000, U+1F600, U+20AC, which sort as U+20AC, U+1F600, U+E000 | `sha-256:jNh0WYS4ffXX2aXqkhvL-ODli8yRoW9Hl5cJkVcLwgU` |
  | `episode_id` as a ULID: 0 / 1 / 2^128 − 1 / the F-07 `episode_id` | `00000000000000000000000000` / `00000000000000000000000001` / `7ZZZZZZZZZZZZZZZZZZZZZZZZZ` / `01JBAE0Z1TFCQ9Y41W9NF6YYMB` |

## 3. Standard OAuth, WIMSE, MCP & Payment Artifacts
1. **RFC 9396 RAR `authorization_details` (`type: "https://schemas.pep-sidecar.dev/rar/agent-payment-intent/v1"`):**
   - Carried inside ID-JAG (`draft-ietf-oauth-identity-assertion-authz-grant-04`, `typ: "oauth-id-jag+jwt"`).
   - Fields: `actions`, `locations`, and `pep_intent: {episode_id, intent_digest, release_epoch, lockfile_digest, limits: {currency, per_call_max_minor, cumulative_max_minor, max_calls, step_up_over_minor}, entities: {recipient_ids | invoice_ids | entity_set_digest, resolution, per_entity_max_uses}}`.
   - **Limits Semantics:** `max_calls` counts all payment reservations, aborted ones included. Step-up applies when the amount is strictly greater than `step_up_over_minor` (`amount > step_up_over_minor`).
2. **Transaction Token (`draft-ietf-oauth-transaction-tokens-11`):**
   - Requested via RFC 8693 (`requested_token_type=urn:ietf:params:oauth:token-type:txn_token`).
   - Required claims: `txn` (set to `episode_id`), `sub`, `scope`, `aud`, `iat`, `exp`, `req_wl` (`spiffe://corp.example/pep`).
   - Immutable `tctx.pep_intent` holds the session envelope; `agentic_ctx` (`draft-araut-oauth-transaction-tokens-for-agents-02`) holds `{current_actor, originator, chain_metadata, prov}`.
3. **Stateless MCP `2026-07-28` Episode Token (`typ: "pep-episode+jwt"`):**
   - ES256 JWS carried in `_meta["dev.pep-sidecar/episode"]` (and optional matching `Pep-Episode` header; mismatch returns JSON-RPC error `-32020`).
   - Claims: `{eid, intent_digest, sub, client_id, peer_uid, release_epoch, rar_digest, txn, iat, exp}` with `exp - iat <= 28800` (8 hours).
   - Minted by the PEP on the host `start_episode` call and revoked by `end_episode`; idle timeout 30 minutes; signed with a per-boot key, so a PEP restart invalidates every token; delivered to the agent on stdin.
   - Each `start_episode` mints a fresh `eid`, which is also `txn` (§3.2) and the engine's `episode_id`. An intent has at most one live episode. Revocation and idle state are keyed by `eid`. The PEP rejects high-S signatures, and applies §3.4's header and encoding rules.
   - Required on `tools/call`, in `_meta`, where a matching `Pep-Episode` header is optional. On `tools/list`, it may come in `_meta` or as a `Pep-Episode` header alone, because SDKs send their own `tools/list` without caller `_meta`; if both are present they must match. Its `peer_uid` must equal the connection's uid, its `release_epoch` the loaded lockfile's, and its `intent_digest` the configured intent's.
   - A token is delivered only to a fresh agent container: each episode runs in its own container, removed when the episode ends, and episodes after a PEP restart get new ones. A fresh process in a reused container is not enough, because files and helper processes survive it.
   - No `iss`, `aud`, `jti` or `nbf`: the PEP is the only issuer and verifier; the `typ` and key differ from the Call Proof's, which makes the two validations mutually exclusive.
4. **Per-Call WIMSE Call Proof (`draft-lee-wimse-local-tool-call-proof-01`):**
   - ES256 JWS (`typ: "pep-callproof+jwt"`, 60s TTL) carried upstream in `_meta["dev.pep-sidecar/call-proof"]`, signed with a per-boot key separate from the Episode Token's (§1, `/run/pep-pub`).
   - The protected header holds only `alg`, `typ` and `kid`, where `kid` is the RFC 7638 thumbprint of the current boot's key; tokens are decoded as strict base64url. Signatures use low-S; the broker rejects high-S.
   - Every forwarded `tools/call` carries a Call Proof. Payment proofs add `rid` and are issued only for `Held` reservations (never for `AwaitingStepUp`, `Released` or `NeedsReconcile`).
   - Claims: `{iss, aud, jti, iat, exp, eid, server_id, action_digest, release_epoch, tool_schema_digest}` on every proof, plus `{rid, prov, budget}` exactly on payment proofs. `tth` is added in Week 5.
     - `iss` is `spiffe://corp.example/pep`; `aud` is `spiffe://corp.example/broker`, a single string.
     - `server_id` is the target server's `server_id` in the lockfile.
     - `tool_schema_digest` is the lockfile's pinned digest of the tool's upstream definition.
     - `rid` carries the reservation ID, so the broker can recompute the F-07 `Idempotency-Key` from `eid`, `rid`, and its own `action_digest`.
     - `prov` lists the `origin_hash`es (§2) of the payment's witness leaves (the amount, and the currency when bound): at most two, exactly as the engine matched them.
     - `budget` is `{currency, amount_minor, reserved_minor, committed_minor}`: the reserved amount, and the intent's totals right after this reservation (`reserved_minor` includes it).
   - **Broker checks**, each failing closed:
     - the token is three strict base64url parts, with no character outside `[A-Za-z0-9_.-]`;
     - the header is exactly `{"alg": "ES256", "typ": "pep-callproof+jwt", "kid": …}`, with the `kid` of the key in `/run/pep-pub`, and the 64-byte r‖s signature is low-S and verifies;
     - `iss` and `aud` match exactly; `iat` is after the broker's boot second; `exp - iat <= 60`; `iat` is at most 2 s in the future and `exp` at most 2 s in the past (clock skew);
     - `jti` is unseen;
     - `server_id` equals the route's server (`/mcp/{server_id}`), which pins the tool; `release_epoch` and `tool_schema_digest` equal the broker's lockfile;
     - `action_digest` equals the broker's own recomputation from the forwarded body;
     - `rid`, `prov` and `budget` are present exactly when the lockfile marks the tool as a payment, and `budget`'s `amount_minor` and `currency` equal the forwarded arguments.
   - The replay cache is keyed by `jti`. Its capacity follows from the per-episode rate limit and the episode cap; a full cache rejects.
5. **AuthZEN 1.0 (`POST /access/v1/evaluation`) & AgentCore Mapping:**
   - AuthZEN payload: `subject`, `action`, `resource`, and `context: {episode_id, intent, args, prov, labels, budget, automaton, release_epoch}`.
   - AWS AgentCore (no AuthZEN): map into JWT claim tags (`principal.getTag()`), `context.input._pep`, and `x-amzn-bedrock-agentcore-policy-session-id`.
6. **AP2 v0.2 & Stripe Bindings:**
   - PEP never signs AP2 mandates (`kb+sd-jwt`); it verifies `transaction_id == b64url(H(checkout_jwt))`, provenance-bound amounts, and stateful open-mandate budgets (`mandate.payment.open.1`).
   - Stripe metadata keys (<= 40 chars, values <= 500 chars): `pep_v`, `pep_eid`, `pep_ad`, `pep_int`, `pep_rel`, `pep_rcpt`, `pep_tlog`, `pep_ap2tx`, `pep_prov`.

## 4. Six-Week Roadmap & Go/Kill Gates
- **Week 1 (Complete, 2026-10-28):** `src/jcs.rs`, `src/engine.rs`, `src/peercred.rs`, `src/lib.rs`, strict Clippy verification.
- **Week 2 (Gate 1):** the `pep-sidecar` binary, the agent-facing transport (MCP `2026-07-28` Streamable HTTP over the Unix socket; D2), the Compose topology, the stub broker and tool servers, `SO_PEERPIDFD` upgrade, `src/lockfile.rs` (`PinnedToolLockfile` v1 DSSE verifier & MCP `2026-07-28` drift quarantine; per-tool lockfile fields include `trusted_fields`, `amount_binding`, and store URI/key policy; a configured threshold of distinct signer keys per role, each key in exactly one role; security-role signature required for payment tools, external sinks, and any read-only tool entry that can authorize payment amounts via `Trusted` output, `trusted_fields`, or `amount_binding`), `pep-sidecar lock-scan` and `pepctl lock sign`, strict argument schemas, the restart journal (§1), `src/tokens.rs` (Episode Token, Call Proof on every forwarded `tools/call`, with `rid` on payments, which must be `Held`, bounded `ReplayCache`), Gate 1 containment suite.
  - *Gate 1 Criteria:* 0 bypasses across >=50 containment tests; 100% of 20 rug-pull mutations quarantined within the detection window T (10 s); 0/1,000 replays accepted; p99 added latency <= 25 ms.
- **Week 3:** `src/automaton.rs` (Sapien Thompson NFA with `Shuffle` and `Defer(LookupSpec)` holes), `src/store.rs` (SQLite WAL persistence, single-writer Tokio `EpisodeActor`, and reconciliation of `NeedsReconcile` reservations). SQLite replaces the Week 2 journal; reconciliation replaces the Week 2 `NeedsReconcile` entity check.
- **Week 4 (Gate 2):** `agentdojo-payments` benchmark (`agentdojo==0.1.35`, 14 tools, 40 tasks, 8 injection classes).
  - *Gate 2 Criteria:* Dollar-weighted ASR <= 2%, targeted ASR <= 5%, benign utility drop <= 5 pts, leak rate <= 2%, analytical security >= 95%.
- **Week 5:** RFC 8693 RAR/ID-JAG exchange, Txn-Token service, AuthZEN client (OPA/Cedar), AP2 verifier, Stripe test mode.
- **Week 6 (Gate 3):** ES256 OpenTelemetry GenAI receipts (`execute_tool {gen_ai.tool.name}`), Rekor transparency log anchoring, `pepctl explain` and `pepctl replay`.