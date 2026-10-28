# SPEC.md — OAuth-Native Provenance & Intent Enforcement Sidecar Specification

## 1. Core Architecture & OS Containment Boundary
- **Process & UID Isolation:**
  - `agent` container/process: `UID 20001:20001`, read-only rootfs, `cap_drop: [ALL]`, `no-new-privileges: true`, zero direct IPv4/IPv6 egress (`nftables` drops all packets from `skuid 20001`; no loopback TCP holes).
  - `pep` sidecar: `UID 20002:20002`, listens on `unix:///run/pep/mcp.sock` (parent `/run/pep` owned by `20002:20001` mode `2750` (setgid, so the socket inherits group `20001`); `mcp.sock` `20002:20001` mode `0660`). Verifies peer identity via `SO_PEERCRED` + `SO_PEERPIDFD` (Linux) or `getpeereid` + `LOCAL_PEERPID` (macOS).
  - `broker` egress proxy: `UID 20003:20003`, accepts calls only from the PEP's SPIFFE ID carrying a valid ES256 Call Proof, recomputes `action_digest` with the same `JCS_strict_NFC` profile pinned to Unicode 18.0.0 (§2), recomputes the F-07 `Idempotency-Key` from `eid`, `rid`, and its own `action_digest`, and injects vaulted credentials + `Idempotency-Key`.

## 2. Cryptographic Digest Conventions (`src/jcs.rs`)
- `digest(x) = "sha-256:" + base64url_no_pad(SHA-256(JCS_strict_NFC(x)))`
- `action_digest = digest({"method": "tools/call", "name": tool_name, "arguments": args})`
- `origin_hash = digest({"source_call_id": cid, "tool": tool, "query_digest": qd, "result_pointer": ptr, "value": val})`
- **`JCS_strict_NFC` Profile (RFC 8785 + I-JSON + Unicode NFC):**
  - Input at most 1 MiB, depth at most 64, no BOM, no trailing data.
  - NFC on strings and keys before UTF-16 sorting; record the Unicode version the pinned `unicode-normalization` crate implements (`unicode-normalization = "=0.1.26"`, Unicode 18.0.0, i.e. `unicode_normalization::UNICODE_VERSION == (18, 0, 0)`). The broker, and any other component that recomputes a digest, is pinned to the same Unicode 18.0.0: NFC output, and so every digest and F-07 key, differs between Unicode versions for newly encoded characters. A Unicode upgrade therefore ships to the PEP and the broker in one release.
  - Duplicate keys rejected after NFC.
  - Integers within `±(2^53 - 1)` (`[-9007199254740991, 9007199254740991]`); `-0` becomes `0`.
  - Key order differs from the RFC 8785 `U+FB33` example because of NFC (`U+FB33` decomposes to `U+05D3 U+05BC` before UTF-16 sorting).
  - Conformance vectors: see **Conformance Vectors** below.
- **`origin_hash` Inputs & `episode_id`:**
  - `cid`: the JCS serialization of the JSON-RPC `id`, kept as a string, so `1` and `"1"` differ.
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
- **Week 1 (Complete, 2026-10-28):** `src/jcs.rs`, `src/engine.rs`, `src/peercred.rs`, `src/lib.rs`, strict Clippy verification.
- **Week 2 (Gate 1):** `SO_PEERPIDFD` upgrade, `src/lockfile.rs` (`PinnedToolLockfile` v1 DSSE verifier & MCP `2026-07-28` drift quarantine; per-tool lockfile fields include `trusted_fields`, `amount_binding`, and store URI/key policy; security-role signature required for payment tools, external sinks, and any read-only tool entry that can authorize payment amounts via `Trusted` output, `trusted_fields`, or `amount_binding`), `src/tokens.rs` (Episode Token, Call Proof with `rid` for `Held` reservations only, bounded `ReplayCache`), Gate 1 containment suite.
  - *Gate 1 Criteria:* 0 bypasses across >=50 containment tests; 100% of 20 rug-pull mutations quarantined; 0/1,000 replays accepted; p99 added latency <= 25 ms.
- **Week 3:** `src/automaton.rs` (Sapien Thompson NFA with `Shuffle` and `Defer(LookupSpec)` holes), `src/store.rs` (SQLite WAL persistence, single-writer Tokio `EpisodeActor`, and reconciliation of `NeedsReconcile` reservations).
- **Week 4 (Gate 2):** `agentdojo-payments` benchmark (`agentdojo==0.1.35`, 14 tools, 40 tasks, 8 injection classes).
  - *Gate 2 Criteria:* Dollar-weighted ASR <= 2%, targeted ASR <= 5%, benign utility drop <= 5 pts, leak rate <= 2%, analytical security >= 95%.
- **Week 5:** RFC 8693 RAR/ID-JAG exchange, Txn-Token service, AuthZEN client (OPA/Cedar), AP2 verifier, Stripe test mode.
- **Week 6 (Gate 3):** ES256 OpenTelemetry GenAI receipts (`execute_tool {gen_ai.tool.name}`), Rekor transparency log anchoring, `pepctl explain` and `pepctl replay`.