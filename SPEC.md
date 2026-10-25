# SPEC.md — OAuth-Native Provenance & Intent Enforcement Sidecar Specification

## 1. Core Architecture & OS Containment Boundary
- **Process & UID Isolation:**
  - `agent` container/process: `UID 20001:20001`, read-only rootfs, `cap_drop: [ALL]`, `no-new-privileges: true`, zero direct IPv4/IPv6 egress (`nftables` drops all packets from `skuid 20001`; no loopback TCP holes).
  - `pep` sidecar: `UID 20002:20002`, listens on `unix:///run/pep/mcp.sock` (parent `/run/pep` owned by `20002:20001` mode `2750` (setgid, so the socket inherits group `20001`); `mcp.sock` `20002:20001` mode `0660`). Verifies peer identity via `SO_PEERCRED` + `SO_PEERPIDFD` (Linux) or `getpeereid` + `LOCAL_PEERPID` (macOS).
  - `broker` egress proxy: `UID 20003:20003`, accepts calls only from the PEP's SPIFFE ID carrying a valid ES256 Call Proof, recomputes `action_digest`, recomputes the F-07 `Idempotency-Key` from `eid`, `rid`, and its own `action_digest`, and injects vaulted credentials + `Idempotency-Key`.

## 2. Cryptographic Digest Conventions (`src/jcs.rs`)
- `digest(x) = "sha-256:" + base64url_no_pad(SHA-256(JCS_strict_NFC(x)))`
- `action_digest = digest({"method": "tools/call", "name": tool_name, "arguments": args})`
- `origin_hash = digest({"source_call_id": cid, "tool": tool, "query_digest": qd, "result_pointer": ptr, "value": val})`
- **`JCS_strict_NFC` Profile (RFC 8785 + I-JSON + Unicode NFC):**
  - Input at most 1 MiB, depth at most 64, no BOM, no trailing data.
  - NFC on strings and keys before UTF-16 sorting; record the Unicode version the pinned `unicode-normalization` crate implements (`unicode-normalization = "=0.1.26"`, Unicode 16.0).
  - Duplicate keys rejected after NFC.
  - Integers within `±(2^53 - 1)` (`[-9007199254740991, 9007199254740991]`); `-0` becomes `0`.
  - Key order differs from the RFC 8785 `U+FB33` example because of NFC (`U+FB33` decomposes to `U+05D3 U+05BC` before UTF-16 sorting).
  - Conformance vectors: copy `WEEK1_PLAN.md` §6 in as conformance vectors (each recomputed independently in Python and all match).
- **`origin_hash` Inputs & `episode_id`:**
  - `cid`: the JCS serialization of the JSON-RPC `id`, kept as a string, so `1` and `"1"` differ.
  - `qd`: the `action_digest` of the call that produced the value.
  - `ptr`: an RFC 6901 pointer into the JSON-RPC `result`.
  - `episode_id`: a ULID matching `^[0-9A-HJKMNP-TV-Z]{26}$`, first character at most `7`; F-07 hashes its 128-bit value big-endian.
- **Known-Answer Test Vector:**
  - `digest(b"{}") == "sha-256:RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o"`

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
4. **Per-Call WIMSE Call Proof (`draft-lee-wimse-local-tool-call-proof-01`):**
   - ES256 JWS (`typ: "urn:pep-sidecar:evidence:jws-callproof:v1"`, 60s TTL) carried upstream in `_meta["dev.pep-sidecar/call-proof"]`.
   - Claims: `{iss, aud, jti, iat, exp, eid, rid, tth, action_digest, release_epoch, tool_schema_digest, prov, budget}` (`rid` carries the reservation ID on payment Call Proofs so the broker can recompute the F-07 `Idempotency-Key` from `eid`, `rid`, and its own `action_digest`).
   - Call Proofs are issued only for `Held` reservations (never for `AwaitingStepUp`, `Released`, or `NeedsReconcile`).
5. **AuthZEN 1.0 (`POST /access/v1/evaluation`) & AgentCore Mapping:**
   - AuthZEN payload: `subject`, `action`, `resource`, and `context: {episode_id, intent, args, prov, labels, budget, automaton, release_epoch}`.
   - AWS AgentCore (no AuthZEN): map into JWT claim tags (`principal.getTag()`), `context.input._pep`, and `x-amzn-bedrock-agentcore-policy-session-id`.
6. **AP2 v0.2 & Stripe Bindings:**
   - PEP never signs AP2 mandates (`kb+sd-jwt`); it verifies `transaction_id == b64url(H(checkout_jwt))`, provenance-bound amounts, and stateful open-mandate budgets (`mandate.payment.open.1`).
   - Stripe metadata keys (<= 40 chars, values <= 500 chars): `pep_v`, `pep_eid`, `pep_ad`, `pep_int`, `pep_rel`, `pep_rcpt`, `pep_tlog`, `pep_ap2tx`, `pep_prov`.

## 4. Six-Week Roadmap & Go/Kill Gates
- **Week 1 (In Progress):** `src/jcs.rs`, `src/engine.rs`, `src/peercred.rs`, `src/lib.rs`, strict Clippy verification.
- **Week 2 (Gate 1):** `SO_PEERPIDFD` upgrade, `src/lockfile.rs` (`PinnedToolLockfile` v1 DSSE verifier & MCP `2026-07-28` drift quarantine; per-tool lockfile fields include `trusted_fields`, `amount_binding`, and store URI/key policy; security-role signature required for payment tools, external sinks, and any read-only tool entry that can authorize payment amounts via `Trusted` output, `trusted_fields`, or `amount_binding`), `src/tokens.rs` (Episode Token, Call Proof with `rid` for `Held` reservations only, bounded `ReplayCache`), Gate 1 containment suite.
  - *Gate 1 Criteria:* 0 bypasses across >=50 containment tests; 100% of 20 rug-pull mutations quarantined; 0/1,000 replays accepted; p99 added latency <= 25 ms.
- **Week 3:** `src/automaton.rs` (Sapien Thompson NFA with `Shuffle` and `Defer(LookupSpec)` holes), `src/store.rs` (SQLite WAL persistence, single-writer Tokio `EpisodeActor`, and reconciliation of `NeedsReconcile` reservations).
- **Week 4 (Gate 2):** `agentdojo-payments` benchmark (`agentdojo==0.1.35`, 14 tools, 40 tasks, 8 injection classes).
  - *Gate 2 Criteria:* Dollar-weighted ASR <= 2%, targeted ASR <= 5%, benign utility drop <= 5 pts, leak rate <= 2%, analytical security >= 95%.
- **Week 5:** RFC 8693 RAR/ID-JAG exchange, Txn-Token service, AuthZEN client (OPA/Cedar), AP2 verifier, Stripe test mode.
- **Week 6 (Gate 3):** ES256 OpenTelemetry GenAI receipts (`execute_tool {gen_ai.tool.name}`), Rekor transparency log anchoring, `pepctl explain` and `pepctl replay`.