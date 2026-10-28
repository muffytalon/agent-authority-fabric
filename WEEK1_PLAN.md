# WEEK1_PLAN.md: pep-sidecar Week 1

Status: approved 2026-10-24. Updated 2026-10-28 to match the code after the 27 Oct review fixes (`claude/pep-sidecar-week1-code-review.md`) and the 27 Oct crate re-verification. Revised 2026-10-28 to match the code after the review fixes.

## Context
Week 1 delivers a single crate, `pep-sidecar`, with four library modules: `lib`, `jcs`, `engine` and `peercred`. They must pass all six commands of the CLAUDE.md §2 loop (the fifth is the macOS cross-lint, the sixth `cargo deny check`).

Decisions:
| Topic | Decision |
|---|---|
| Engine types | SPEC.md has no "Track 2.4" section, so the names come from CLAUDE.md. ✅ means the name appears in CLAUDE.md or SPEC.md, or was specified in review. ◇ means provisional. No other traits are added. |
| `lenient-numbers` | Controls the **request** number profile only. The default build accepts integers only; with the feature, RFC 8785 fractions and exponents are accepted too. Both cap every magnitude at 2^53-1 (F-04). Tool **results** always use the result profile (§3), so `ryu-js` is a normal dependency. |
| Build environment | WSL2 Ubuntu. `peercred` only builds on Unix. |
| Provenance | The PEP finds origins itself from its recorded results; the agent supplies no `_meta` claims. A Payment Amount must trace to the **latest** lookup of the same Entity, or to the latest trusted-input pair for it. One lookup or trusted input funds one payment: until that reservation is `Released`, `G_prov` denies another (`ProvenanceConsumed`). An index keyed on canonical bytes keeps leaf origins for the Week 2 `prov` claim. It does not join labels. |
| Taint indexing | • **Location** `StoreKey` always matches, whatever the value's type.<br>• Keys may name nested records: a write to `a/b` also taints reads of `a` and `a/b/c`, but not of `a/c` (`TaintIndex::Below`). Keys are capped at 1 KiB and 32 segments.<br>• **Content digests** are recorded on agent writes for objects, non-empty arrays and strings of at least 16 bytes. They are looked up **only** for results of tools whose output label is not Trusted (notes, tickets, mail, web).<br>• Results of Trusted tools get location taint only.<br>• Every entry records the episode that wrote it, and each episode has a write quota. |
| Amount / entity trust | • **With `amount_binding`:** the latest recorded `lookup_tool` call for this Entity must show this Amount at `result_amount_pointer` and `Limits.currency` at `result_currency_pointer`, and both leaves must be Trusted.<br>• **Without a binding:** the latest `pep/trusted-input` record `{entity, amount_minor}` for this Entity must show this Amount.<br>• **Entity authorization** comes only from the signed intent's `EntitySet` (G_entity), typed by `EntityKind`. |
| Host-only functions | `record_trusted_input`, `approve_step_up` and `Engine::abort` take `&HostAuthority`, because each acts on a claim the agent must never make (what the user typed, that a human approved, that a payment did not run). That value can't be copied or cloned, and the process can obtain it only once. |
| Step-up | `ResState` = `Held`, `AwaitingStepUp`, `Committed`, `Released`, `NeedsReconcile`. When G_stepup triggers, the reservation goes in as `AwaitingStepUp`, still counted in `budget.reserved`. `commit` returns `Err(PepError::InvalidTransition)` until `approve_step_up(&host, reservation_id)` moves it to `Held`. `abort` accepts both `Held` and `AwaitingStepUp`. |

| Sink clearance | Checked for **every** tool. It is set per destination through `ArgRole::SinkDestination`, and a destination not in the map gets `Public`. Internal tools are pinned with `sink_clearance = Secret`, so their behaviour doesn't change. |
| Undeclared arguments | Every argument must be declared in `args`, at every depth, and a member on a declared path must really be a container. The only exception is a read-only tool with no `trusted_fields`, that is not a sink and whose declared arguments are all `Data`: it may take extra flags such as `verbose`. Free text is declared as `Data`. |
| `max_calls` | Counts **Payment reservations** only. An aborted payment still counts. |
| `episode_id` | `u128`, so the F-07 key hashes 16 + 8 + len(action_digest) bytes. On the wire it is a 26-character Crockford Base32 ULID (`^[0-9A-HJKMNP-TV-Z]{26}$`), converted with `encode_ulid` / `decode_ulid`. |
| Engine scope | One `PepEngine` per episode, which matches the single-writer `EpisodeActor` planned for Week 3. The `LabelStore` is shared across episodes through `Arc`. |
| Deferred entity scopes | **Deliberately not in Week 1.** `entity_set_digest`, `resolution`, list reads and list-shaped `trusted_fields` arrive in Week 3 with `Defer(LookupSpec)`. Intents like "refund all open invoices for X" are knowingly unsupported until then. `EntitySet` has no variant for them, so they can't be represented and can't be silently ignored. |

**Notation.** In this document, `\u{XXXX}` stands for the six-character JSON escape: a backslash, `u` and four hex digits. The Rust tests build these escapes at run time, so the parser receives the backslash and the hex digits exactly as written.

## 0. Build environment
- All checks run in WSL2 Ubuntu through `wsl.exe`. `rust-toolchain.toml` makes rustup fetch 1.97.1, clippy, rustfmt and the `aarch64-apple-darwin` target.
- Every cargo command exports `CARGO_TARGET_DIR=~/.cargo-target/pep-sidecar`, which keeps `target/` out of the OneDrive folder.
- It also exports `RUSTFLAGS='-D warnings'`. Windows env vars don't reach WSL, so without this the `RUSTFLAGS` in settings.json would be lost.
- `.claude/settings.json` runs `cargo check --all-targets` through `wsl.exe` after every edit, and allow-lists the verification commands.

## 1. `rust-toolchain.toml` + `Cargo.toml`
- The toolchain is pinned to `1.97.1` with clippy, rustfmt and `aarch64-apple-darwin`. The 1.97.1 point release (2026-07-16) only fixes an LLVM miscompilation that 1.97.0 made more likely (rust-lang/rust#159035).
- Dependencies, all with exact versions checked on crates.io on 2026-10-24 and re-verified on 2026-10-27 (each is still the latest stable release, none is yanked, and every call site matches the real API):

  | Crate | Version | Note |
  |---|---|---|
  | `base64` | `=0.23.1` | |
  | `ryu-js` | `=1.0.3` | |
  | `sha2` | `=0.11.1` | MSRV 1.88 |
  | `thiserror` | `=2.0.21` | |
  | `unicode-normalization` | `=0.1.26` |Unicode 18.0.0 tables (test `nfc_tables_are_unicode_18_0_0`); licence `(MIT OR Apache-2.0) AND Unicode-3.0` |
  | `nix` | `=0.31.3` | Linux and macOS only, features `socket` and `user`; Week 2 adds `fs` for `Flock` |


- `[lints.rust]`: `unsafe_code = "forbid"`, `missing_docs`, `missing_debug_implementations`, `unreachable_pub`, `unused_qualifications`, trivial casts, `let_underscore_drop`, `rust_2018_idioms`.
- `[lints.clippy]`: `all` and `pedantic`, plus these deny-level lints:
  - the CLAUDE.md §3 set: `unwrap_used`, `expect_used`, `panic`, `todo`, `unimplemented`, `indexing_slicing`, `arithmetic_side_effects`;
  - extra hardening: `as_conversions`, `string_slice`, `unreachable`, `unwrap_in_result`, `float_arithmetic`, `dbg_macro`, `print_stdout`, `print_stderr`, `exit`, `mem_forget`.
- Approved opt-outs: `module_name_repetitions` and `too_many_lines`.
- No serde or serde_json in Week 1. No dev-dependencies. `Cargo.lock` is committed.

## 2. `src/lib.rs`
`#![forbid(unsafe_code)]`; `pub mod engine; pub mod jcs;` plus `pub mod peercred` for Linux and macOS only. `jcs` and `engine` are platform-neutral.

## 3. `src/jcs.rs`: JCS-strict-NFC
**Public API**
| Item | Notes |
|---|---|
| ✅ `JcsError` | Every variant carries only `offset: usize`. Variants: `UnexpectedEof`, `UnexpectedByte`, `TrailingData`, `ByteOrderMark`, `InvalidUtf8`, `ControlCharInString`, `InvalidEscape`, `LoneSurrogate`, `Noncharacter`, `LeadingZero`, `NumberOutOfRange`, `NonIntegerNumber`, `NumberNotFinite`, `DuplicateKey`, `DepthExceeded`, `InputTooLarge`, `NodeLimitExceeded` |
| `MAX_SAFE_INTEGER` | `9_007_199_254_740_991` |
| ◇ `NumberMode` | `SafeInteger`: no fraction or exponent, `\|v\| ≤ 2^53-1`. `EcmaSafe`: RFC 8785 fractions and exponents, `\|v\| ≤ 2^53-1`. `EcmaAny`: any finite double, with `int = Some` only for safe integers |
| ◇ `ParseOptions { numbers, max_bytes, max_depth, max_nodes, reject_noncharacters }` | No `Default`. `ParseOptions::request()` uses `SafeInteger` (`EcmaSafe` with `lenient-numbers`), 1 MiB, depth 64 and 8192 nodes, and rejects noncharacters (I-JSON, RFC 7493 §2.1). `ParseOptions::result(max_bytes, max_nodes)` uses `EcmaAny` and depth 64, and accepts noncharacters |
| ◇ `JcsString` | Newtype guaranteed to hold NFC text. The only constructors are the parser and `JcsString::new`, and both apply NFC |
| ◇ `JcsValue` | `Null`, `Bool`, `Number(JcsNumber)`, `String(JcsString)`, `Array`, `Object(JcsObject)`. `PartialEq` means canonical equality. Accessors include RFC 6901 `pointer`, `leaves()`, `nodes()` and `walk()` (which builds no pointers) |
| ◇ `JcsNumber` | Private `canonical` + `int: Option<i64>` (`Some` only for a safe integer) |
| ◇ `JcsObject` | Members kept sorted by UTF-16 code units. `from_entries()` sorts and rejects duplicates |
| `parse`, `parse_with`, ✅ `canonicalize`, `digest`, `digest_value`, ✅ `action_digest`, ✅ `origin_hash` | `digest(x) = "sha-256:" + b64url_nopad(SHA-256(JCS(x)))` |

**Parser.** A byte cursor that only uses `.get()` and `checked_add`, never indexing or raw arithmetic.
- **Error offsets:**
  - Byte rule: the first invalid byte, or `buf.len()` at end of input.
  - Escape rule: the `\` that starts the bad escape. A noncharacter is reported at its first byte, or at the `\` of its escape.
  - Token rule: the start of the number, the start of the later duplicate key, or the start of the value that goes over the node limit.
- **Input:** whitespace is limited to SP, HT, LF and CR. A BOM or trailing data is rejected.
- **Strings:** UTF-8 is validated per sequence. Raw control bytes are rejected. `\uXXXX` pairs are decoded with `char::decode_utf16`, and each hex digit is checked one by one (`u16::from_str_radix` would accept `+`). Every string is converted to NFC with the Unicode 18.0.0 tables.
- **Objects:** sorted by UTF-16 code units. Duplicates are detected after NFC.
- **Numbers:** `-?(0|[1-9][0-9]*)` in `SafeInteger` mode. `-0` becomes `"0"`. Ecma modes parse as f64, normalize `-0.0`, and format with `ryu_js`.
- **Serializer:** escapes only `"`, `\` and controls below U+0020, using `\b \t \n \f \r` or lowercase `\u00xx`.
- **Deliberate divergence:** U+FB33 in the RFC 8785 sorting example decomposes under NFC. A U+E000 vector covers UTF-16-vs-code-point ordering instead.

**Parser error table** (request profile, default build). The full table is test `error_offsets`, plus `noncharacters_rejected_in_requests`.
| Input | Result |
|---|---|
| empty input / three spaces | `UnexpectedEof{0}` / `UnexpectedEof{3}` |
| `EF BB BF {}` | `ByteOrderMark{0}` |
| `{} x` | `TrailingData{3}` |
| `{"a":1,}` / `[1,]` | `UnexpectedByte{7}` / `UnexpectedByte{3}` |
| `{"a" 1}` / `{"a":1 "b":2}` | `UnexpectedByte{5}` / `UnexpectedByte{7}` |
| `{"a":1,"a":2}` / `{"e\u{0301}":1,"\u{00e9}":2}` | `DuplicateKey{7}` / `DuplicateKey{13}` |
| `"\u12"` / `"\u+123"` / `"\x"` | `InvalidEscape{1}` |
| `"\u{d800}"` / `"\u{d800}\u{0041}"` / `"\u{dc00}"` | `LoneSurrogate{1}` |
| `"\u{ffff}"` / `"a\u{fdd0}"` / `"\u{d83f}\u{dffe}"` (U+1FFFE) / `{"\u{fffe}":1}` | `Noncharacter{1}` / `Noncharacter{2}` / `Noncharacter{1}` / `Noncharacter{2}` |
| `"<EF BF BF>"` / `"x<F4 8F BF BF>"` | `Noncharacter{1}` / `Noncharacter{2}` |
| `"a<01>"` | `ControlCharInString{2}` |
| `"<C0 AF>"` / `"<ED A0 80>"` / `"<F4 90 80 80>"` / `"<80>"` | `InvalidUtf8{1}` |
| `"abc` | `UnexpectedEof{4}` |
| `00` / `-01` / `-` / `+1` / `.5` | `LeadingZero{1}` / `LeadingZero{2}` / `UnexpectedEof{1}` / `UnexpectedByte{0}` / `UnexpectedByte{0}` |
| `1.5` / `1e2` | `NonIntegerNumber{1}` |
| `±9007199254740992` | `NumberOutOfRange{0}` |
| `[` × 65 | `DepthExceeded{64}` |
| `tru` / `trux` | `UnexpectedEof{3}` / `UnexpectedByte{3}` |
| `-0` / `[-0,{"a":-0}]` | `0` / `[0,{"a":0}]` |

## 4. `src/engine.rs`: PEP engine
**Traits and entry points**
- ✅ `trait Engine { evaluate, commit, abort }`; `abort` takes `&HostAuthority`
- ✅ `trait LabelStore { record(&TaintIndex, LabelEntry), lookup(&TaintIndex) }`. It is shared across episodes.
- `ContentDigest::of` applies `is_taint_indexable` (objects, non-empty arrays, strings of at least 16 bytes), so every store implementation is gated.
- ✅ `PepEngine`:
  - `new`, ✅ `evaluate_raw`;
  - `record_result_raw` (the JSON-RPC `result`, an MCP `CallToolResult`);
  - `record_trusted_input(&mut self, _host: &HostAuthority, input_id, raw, conf)`;
  - ✅ `approve_step_up(&mut self, _host: &HostAuthority, reservation_id: u64) -> Result<(), PepError>`;
  - `ticket`, `abandon`, `state`.
- `HostAuthority::claim() -> Option<HostAuthority>`: `Some` on the first call in a process, `None` afterwards.
- `PepError::to_agent_code()` returns only `"PEP_DENIED"` or `"PEP_UNAVAILABLE"`.
- `idempotency_key`, `encode_ulid`, `decode_ulid`.

**Types.** None derive `Default`; each has explicit constructors.
- Errors: `PepError` (`Malformed`, `Denied{guard, reason}`, `Store`, `InvalidConfig`, `InvalidTransition`, `UnknownReservation`, `UnknownCall`), `PolicyError`, `ConfigError` and `StoreError`.
- Tools: `EffectClass`, `ArgRole` (`Amount`, `Currency`, `Entity(EntityKind)`, `SinkDestination`, `StoreUri`, `StoreKey`, `StoreWrite`, `Data`), `ToolPolicy` (with `store_uri`, `trusted_fields`, `amount_binding` and per-tool result limits), and `ToolPins` with per-store `KeyPolicy`.
- Labels and budget: `Confidentiality`, `Integrity`, `Label`, `Budget::empty()`, `ResState`, `AbortOutcome`, and `Reservation` (with `call_id` and `witness_seq`).
- Episode state: `EpisodeState` with ordered `Recorded` entries (`seq`), `leaf_index`, `in_flight`, and the node and label quotas.

**Construction checks** (each failure is `PepError::InvalidConfig`):
- Limits: `0 < per_call_max ≤ cumulative_max` and `max_calls ≥ 1`. The currency must match `^[A-Z]{3}$`.
- Stores are known and normalized, and no two pinned stores overlap (one inside the other would escape nested-key taint).
- Every tool is pinned under its own NFC name, outside the reserved `pep/` namespace.
- A `MutatingInternal` tool declares a `StoreKey`, so its writes can be location-tainted.

- `trusted_fields` and binding pointers start with `/structuredContent/`.
- Bindings:
  - only on Payment tools;
  - the lookup tool is read-only and Trusted, has a fixed `store_uri` and is keyed by the entity (its `StoreKey` argument is `lookup_entity_pointer`), and lists the amount and currency pointers in its `trusted_fields`.
- Payment tools declare exactly one Entity and one Amount argument.

**Recording a result**
1. Parse `raw_result` with the result profile, inside the tool's own limits, the episode node budget and the pointer budgets (4 MiB per result, 16 MiB per episode). Going over gives `CapacityExceeded`; the caller must not forward that result.
2. Label the leaves. Leaves at `trusted_fields` get the tool's output label, unless the result has an `isError` other than `false`; every other leaf is at least UntrustedExternal.

3. Apply taint:
   - Location taint applies to every leaf.
   - Content taint is used only for tools that are not Trusted. Containers are content-indexed down to `MAX_INDEX_DEPTH = 8`; strings at any depth.
4. Store the record:
   - assign the next `seq`;
   - add the leaves to `leaf_index`;
   - remove the `in_flight` entry;
   - ratchet `context_conf`.

**Pipeline** (F-06). Every guard gets only shared access to `EpisodeState`, so none of them can change state.
0. A pre-pass that cannot fail computes `call_max_conf`.
1. `G_pin`
2. `G_canon`: request shape, call id (at most 128 bytes, never reused in the episode), reserved `_meta` members (only the Episode Token may be sent), undeclared arguments at every depth, role argument types, `StoreKey` normalization (no default-ignorable characters; ASCII only on case-insensitive stores), `action_digest`.
3. `G_prov`: a lookup or trusted input for this Entity must exist and must not already fund a live reservation.

4. `G_entity`: `EntityKind`, membership in `EntitySet`, and uses.
5. `G_amount`: positive safe integer, per-call limit, currency, and the latest witness's amount and currency.
6. `G_seq`
7. `G_budget`: cumulative limit, `max_calls`, the label quota, at most 64 calls in flight and 4,096 call ids per episode. Everything is computed but nothing is applied.
8. `G_label`, for every tool: the clearance check, and Trusted integrity of the witness leaves for Payment tools.
9. `G_stepup`: cannot deny.

On any error from steps 1–8, `context_conf` is raised to `call_max_conf`. Mutation happens only after 1–8 pass:
- first the fallible `LabelStore::record` calls;
- then the infallible budget plan, the reservation insert (`AwaitingStepUp` or `Held`), `in_flight` and `last_tool`.

**Reservation state machine**
| From | Call | To |
|---|---|---|
| AwaitingStepUp | `approve_step_up` | Held |
| AwaitingStepUp | `commit` | `InvalidTransition` (state unchanged) |
| AwaitingStepUp / Held | `abort(DefinitelyNotExecuted)` | Released (`reserved` and the entity use are released; `in_flight` is cleared) |
| AwaitingStepUp / Held | `abort(Unknown)` | NeedsReconcile (still counted; `in_flight` is cleared) |
| Held | `commit` | Committed |
| other | any | `InvalidTransition` |
| in-flight non-payment call | `abandon(call_id)` | entry removed |

`approve_step_up` and `abort` need the `&HostAuthority`; `commit` and `abandon` do not.

## 5. `src/peercred.rs` (Linux and macOS)
- `peer_cred` uses `SO_PEERCRED` on Linux, and `getpeereid` + `LOCAL_PEERPID` on macOS. `require_peer_uid` checks the peer's uid.
- `bind_safe_listener` works in four steps:
  1. The path must be absolute and have no `..` component.
  2. The parent must not be a symlink, must be a directory owned by the euid, and must have `mode & 0o027 == 0`. Every ancestor of its canonical path must be owned by root or the euid and not writable by group or others unless sticky, and the parent's dev/ino is re-checked.
  3. An existing file is unlinked only if it is a socket owned by the euid that no process listens on (a connect probe with a 2 s timeout, else `SocketInUse`).
  4. Bind under the canonical path, then `chmod 0660`, then re-check the socket's owner, mode and group. It must get the parent's group, so the parent must be setgid `2750` (SPEC §1). Any failure after the bind removes the socket.
- It avoids TOCTOU races because no non-root principal can change the parent directory's entries. Two gaps remain until Week 2's `Flock` lock file: two same-user instances starting at once on one stale socket can both bind, and on macOS a live socket with a full backlog looks stale.

- Two gaps remain, documented on `socket_is_live`. On macOS a full backlog is refused at once, so a busy live socket looks stale. And the probe and the unlink are not atomic, so two instances of the same user starting on one stale socket can orphan a listener. An exclusive `nix::fcntl::Flock` on a sibling lock file, held for the listener's lifetime, would close both; it needs nix's `fs` feature.

## 6. Known-answer vectors
Computed on 2026-10-24 with .NET and independently in Python. Tests assert these as fixed constants.
| Vector | Expected |
|---|---|
| `digest({})` (SPEC §2) | `sha-256:RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o` |
| `pay_invoice` `action_digest` (args `{"amount":5000,"currency":"USD","recipient_id":"rcpt_123"}`) | `sha-256:j3XfycsYi2G8jSVocXUTiPN2JWbcwQfOK1L4pLAdI1E` |
| `query_digest` = `action_digest("get_invoice", {"invoice_id":"inv_42"})` | `sha-256:bdmNQo66RS-48sR_0n8pP5jmbo0a0Sh00gUWv8nEDNU` |
| `origin_hash{"7", get_invoice, <query_digest>, "/total_minor", 5000}` | `sha-256:2pEVfWny8jku05UQCRDDarGnSs_F2tZB7_YtsC-7SYU` |
| F-07 key: eid `0x0192d4e07c3a7b2e9f103c4d5e6f7a8b`, rid 1, `pay_invoice` action_digest (75-byte input) | `pep-UhReNoSbXP-SykKxyF9adQ4g5F1oTTAKAJPlYrbk9V0` |
| the same with rid 2 | `pep-xi_53ViTWcbekOTZepC96vxdqaHXZyIGrok6uJGrvPA` |
| RFC 8785 §3.2.3 sort, NFC-adjusted (181 bytes) | `sha-256:mgPbgbBjohAvazT5LBgyJA_w6YmlxvrHDvBHwIx3EZ8` |
| UTF-16 vs code-point order (`€`, U+1F600, U+E000) | `sha-256:jNh0WYS4ffXX2aXqkhvL-ODli8yRoW9Hl5cJkVcLwgU` |
| `encode_ulid`: 0 / 1 / `u128::MAX` / F-07 eid | `00000000000000000000000000` / `00000000000000000000000001` / `7ZZZZZZZZZZZZZZZZZZZZZZZZZ` / `01JBAE0Z1TFCQ9Y41W9NF6YYMB` |

## Out of scope (later weeks)
- Week 2: Episode Token and Call Proof verification (including `-32020`), `SO_PEERPIDFD`, the `Flock` lock file for the listener (nix `fs` feature), the DSSE lockfile, JSON Schema validation of arguments, and `prov` from `leaf_index`.
- Week 3: the automaton, SQLite, Tokio, reconciliation, deferred entity scopes, list reads and list-shaped `trusted_fields`, and how long LabelStore entries are kept.
- Week 5: RAR → `PepIntent` conversion and any serde layer.

## Verification
```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test -- --nocapture
cargo clippy --all-targets --features lenient-numbers -- -D warnings && cargo test --features lenient-numbers
cargo clippy --all-targets --target aarch64-apple-darwin -- -D warnings
cargo deny check
```

## Risks
- **Flooding through content taint (residual).** An agent can still write many strings of 16 bytes or more that later appear in untrusted results, which raises `context_conf` for any episode that reads them. The per-episode quota caps this, and each entry records the episode that wrote it.
- **Big numbers in results lose precision** in canonical form (`18446744073709551615` becomes `18446744073709552000`, as RFC 8785 specifies). They have `int = None` and are never an Amount.
- **Case-insensitive stores take ASCII keys only.** A collation such as `utf8mb4_0900_ai_ci` also folds accents and width, which the PEP can't reproduce, so non-ASCII keys are rejected there.
- **Short-value laundering through a backend copy** to a different location isn't caught by taint. The value must still be the latest Trusted lookup for the Entity, in the right currency.
- **Remaining limits:** low-entropy long strings can still be content-indexed; bindings accept only the exact amount; hashing costs O(bytes × depth). All three are to be measured in Weeks 2 and 4.
- **Unicode version skew.** Every digest and F-07 key depends on the NFC tables, which are Unicode 18.0.0 in `unicode-normalization 0.1.26`. A peer that recomputes `action_digest` with older Unicode data, such as the broker (SPEC §1), produces different bytes for strings containing characters newer than its tables, and so rejects legitimate calls. A crate bump changes digests in the same way. The test `nfc_tables_are_unicode_18_0_0` makes a bump fail loudly, and `default_ignorable_matches_unicode_18_0_0` pins the hand-written ignorable list to the same Unicode 18.0.0 data. SPEC §1–§2 now pin the broker to Unicode 18.0.0 and make a Unicode upgrade ship to the PEP and the broker together; any other peer that recomputes digests needs the same pin. The Unicode version of the Python used for the §6 cross-check is not recorded.
- **Young releases.** On 2026-10-28, `unicode-normalization 0.1.26` is 12 days old and `sha2 0.11.1` is 16 days old. All six pins were re-verified against crates.io on 2026-10-27 (`reports/Pep sidecar crate API verification.md`).

Resolved since approval:
- `approve_step_up` was not capability-gated. It now takes `&HostAuthority`, like `record_trusted_input`, and so does `abort`.
- `KeyPolicy` used `to_lowercase()` rather than full Unicode case folding. Case-insensitive stores now accept only ASCII keys and lower-case them with `to_ascii_lowercase()`, because the backend's collation may also fold accents, width or ligatures, which the PEP cannot reproduce.
- `Cargo.toml` declared `rust-version = "1.88"`, but no verification command ever compiled with 1.88. The claim is dropped: `rust-version` is now 1.97.1, the toolchain `rust-toolchain.toml` pins, so every verification command checks it.
- The two root-only `peercred` tests had never run. On 2026-10-28 all three ignored tests passed in one run as root on rustc 1.97.1.
- The ULID regex was missing from SPEC.md. SPEC.md §2 now gives `^[0-9A-HJKMNP-TV-Z]{26}$`, with a first character of at most `7`.
