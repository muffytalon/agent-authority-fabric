# CLAUDE.md — pep-sidecar Operational & Security Rules

## 1. Project Overview
`pep-sidecar` is an OS-isolated, stateful OAuth-native Policy Enforcement Point (PEP) sidecar for AI agent payments and tool execution, written in Rust `1.97.0` (Edition `2024`, MSRV `1.88`). Everything architectural is specified in `@SPEC.md`.

## 2. Mandatory Verification Loop (Run After Every Edit)
Never declare a task complete until all four commands pass with zero warnings:
```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test -- --nocapture
cargo clippy --all-targets --features lenient-numbers -- -D warnings && cargo test --features lenient-numbers

3. Strict Rust & Clippy Coding Rules (NEVER Violate)

Cargo.toml enforces [lints.rust] and [lints.clippy] with -D warnings. Do NOT weaken or remove lints in Cargo.toml.

    Zero Unsafe (unsafe_code = "forbid"): Never use unsafe blocks. Use safe nix 0.31.3 wrappers (AsFd, OwnedFd) for all Unix socket operations.

    100% Public Documentation (missing_docs = "warn" + -D warnings): Every pub module, struct, struct field, enum, enum variant, trait, type alias, const, and function MUST have a /// rustdoc comment.

    Zero Indexing (indexing_slicing = "deny"): Never write slice[i] or &slice[a..b] in library code. Always use .get(i) or .get(a..b) with explicit error handling.

    Zero Unchecked Arithmetic (arithmetic_side_effects = "deny"): Never use +, -, *, /, +=, or -= on integers in library code. Always use .checked_add(), .checked_sub(), .saturating_add(), .saturating_sub(), or .wrapping_add().

    Zero Panics or Unwraps (unwrap_used = "deny", panic = "deny"): Never use .unwrap(), .expect(), panic!(), todo!(), or unimplemented!() in library code. Return typed Result<T, JcsError | PepError | PeerError | PolicyError | StoreError>.

    Unit Test Lint Attribute (F-02): Because --all-targets lints unit tests and assert_eq! expands to a panic branch, EVERY #[cfg(test)] module MUST start with:
    Rust

    #[cfg(test)]
    #[allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]
    mod tests { ... }

    No Default on Policy Types: Never derive or implement Default on Budget, Limits, or policy structs. Use explicit constructors like Budget::empty().

4. Non-Negotiable Security Invariants (F-03 to F-12)

    Wire-Level JCS Parsing (F-03, F-04, F-05):

        serde_json silently drops duplicate keys and rounds integers > 2^53 - 1. Always parse raw wire bytes via jcs::canonicalize / PepEngine::evaluate_raw(&[u8]) BEFORE converting to serde_json::Value.

        Canonicalize "-0" to "0" per RFC 8785 §3.2.2.3; reject leading zeros ("00", "-01"), lone UTF-16 surrogates, and integers outside [-(2^53 - 1), +(2^53 - 1)].

        Normalize strings and keys to Unicode NFC before UTF-16 code-unit sorting and reject post-NFC duplicate keys.

    Guard Evaluation Order & Deferred Mutation (F-06):

        Inside Engine::evaluate, execute pure validation for G_pin (1) -> G_canon (2) -> G_prov (3) -> G_entity (4) -> G_amount (5) -> G_seq (6) -> G_budget (7) -> G_label (8) -> G_stepup (9).

        CRITICAL: Never mutate budget.reserved, budget.calls, budget.entity_uses, or insert a Held reservation in G_budget before G_label succeeds. Mutate state ONLY after all guards (1–8) pass.

    Collision-Resistant Idempotency Key (F-07):

        Compute downstream payment idempotency keys as "pep-" + b64url(SHA-256(episode_id.to_be_bytes() || reservation_id.to_be_bytes() || action_digest.as_bytes())).

    Two-Phase Budget & Ambiguous Aborts:

        AbortOutcome::DefinitelyNotExecuted releases the reservation and decrements reserved.

        AbortOutcome::Unknown (e.g., network timeout) transitions the reservation to ResState::NeedsReconcile and MUST keep the amount counted inside budget.reserved (fail closed).

    Cross-Episode Taint & Causality Laundering (F-08, F-09):

        Agent writes (EffectClass::MutatingInternal / ArgRole::StoreWrite) record Integrity::UntrustedAgentWrite in LabelStore. Subsequent reads matching (uri, key) or content_digest join that taint label.

        Whenever a guard denies a call involving confidential inputs, ratchet episode.context_conf upward (state.context_conf = state.context_conf.max(call_max_conf)) and return only "PEP_DENIED" or "PEP_UNAVAILABLE" via PepError::to_agent_code().

    TOCTOU-Safe Socket Binding (F-11, F-12):

        Before unlinking an existing socket or calling UnixListener::bind(path), verify via symlink_metadata that the parent directory is a real directory owned by geteuid() with mode (mode & 0o027) == 0 (0750 or tighter), and any existing file at path is a socket (is_socket()) owned by geteuid(). Set socket permissions to 0660.