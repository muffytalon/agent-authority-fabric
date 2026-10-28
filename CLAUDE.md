# CLAUDE.md — pep-sidecar Operational & Security Rules

## 1. Project Overview
`pep-sidecar` is an OS-isolated, stateful OAuth-native Policy Enforcement Point (PEP) sidecar for AI agent payments and tool execution, written in Rust `1.97.1` (Edition `2024`, MSRV `1.88`). Everything architectural is specified in `@SPEC.md`.
## 2. Mandatory Verification Loop (Run After Every Edit)
`cargo` is not installed on Windows; run all `cargo` commands inside WSL2 (`wsl.exe`) with `CARGO_TARGET_DIR=$HOME/.cargo-target/pep-sidecar` and `RUSTFLAGS='-D warnings'`.
Never declare a task complete until all five commands pass with zero warnings:
```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test -- --nocapture
cargo clippy --all-targets --features lenient-numbers -- -D warnings && cargo test --features lenient-numbers
cargo clippy --all-targets --target aarch64-apple-darwin -- -D warnings
```

## 3. Strict Rust & Clippy Coding Rules (NEVER Violate)

Cargo.toml enforces [lints.rust] and [lints.clippy] with -D warnings. Do NOT weaken or remove lints in Cargo.toml, and never add #[allow(...)] or #[expect(...)] in library code without explicit approval and a documented reason.

    Zero Unsafe (unsafe_code = "forbid"): Never use unsafe blocks. Use safe nix 0.31.3 wrappers (AsFd, OwnedFd) for all Unix socket operations.

    100% Public Documentation (missing_docs = "warn" + -D warnings): Every pub module, struct, struct field, enum, enum variant, trait, type alias, const, and function MUST have a /// rustdoc comment.

    Zero Indexing (indexing_slicing = "deny"): Never write slice[i] or &slice[a..b] in library code. Always use .get(i) or .get(a..b) with explicit error handling.

    Zero Unchecked Arithmetic (arithmetic_side_effects = "deny"): Never use +, -, *, /, +=, or -= on integers in library code. Require checked_* (with None meaning deny) for all amounts, budgets, counters, and IDs. Allow saturating_* or wrapping_* math only where the result cannot affect a policy decision, accompanied by a comment explaining why.

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

## 4. Non-Negotiable Security Invariants (F-03 to F-16)

    Wire-Level JCS Parsing (F-03, F-04, F-05):

        serde_json silently drops duplicate keys, and while serde_json keeps 64-bit integers exact, I-JSON and JavaScript peers round integers outside [-(2^53 - 1), +(2^53 - 1)], causing peers to read different numbers. Always parse raw wire bytes via jcs::canonicalize / PepEngine::evaluate_raw(&[u8]) BEFORE any downstream processing.

        Canonicalize "-0" to "0" per RFC 8785 §3.2.2.3; reject leading zeros ("00", "-01"), lone UTF-16 surrogates, and integers outside [-(2^53 - 1), +(2^53 - 1)] on requests and on values that authorize decisions (keep the lenient-numbers cargo feature for general RFC 8785 float formatting in tool results).

        Normalize strings and keys to Unicode NFC before UTF-16 code-unit sorting and reject post-NFC duplicate keys.

    Guard Evaluation Order & Deferred Mutation (F-06):

        Inside Engine::evaluate, execute pure validation for G_pin (1) -> G_canon (2) -> G_prov (3) -> G_entity (4) -> G_amount (5) -> G_seq (6) -> G_budget (7) -> G_label (8) -> G_stepup (9).

        CRITICAL: Never mutate budget.reserved, budget.calls, budget.entity_uses, or insert a Held reservation in G_budget before G_label succeeds. Mutate state ONLY after all guards (1–8) pass. The only state change allowed on a denial is the F-09 ratchet.

    Collision-Resistant Idempotency Key (F-07):

        Compute downstream payment idempotency keys as "pep-" + b64url(SHA-256(episode_id.to_be_bytes() || reservation_id.to_be_bytes() || action_digest.as_bytes())).

    Two-Phase Budget & Ambiguous Aborts:

        AbortOutcome::DefinitelyNotExecuted releases the reservation and decrements reserved.

        AbortOutcome::Unknown (e.g., network timeout) transitions the reservation to ResState::NeedsReconcile and MUST keep the amount counted inside budget.reserved (fail closed).

    Cross-Episode Taint & Causality Laundering (F-08, F-09):

        F-08: Agent writes (MutatingInternal tools, StoreWrite arguments) record UntrustedAgentWrite at decision time under the normalized (uri, key) and under content digests of values accepted by is_taint_indexable. Location taint applies to leaves of every type (and trusted tools use location-only taint); bare numbers, booleans, null, and short strings are never content-indexed.

        F-09: Whenever a guard denies a call involving confidential inputs, ratchet episode.context_conf upward (state.context_conf = state.context_conf.max(call_max_conf)) and return only "PEP_DENIED" or "PEP_UNAVAILABLE" via PepError::to_agent_code().

    TOCTOU-Safe Socket Binding (F-11, F-12):

        Before unlinking an existing socket or calling UnixListener::bind(path), verify via symlink_metadata that the parent directory is a real directory owned by geteuid() with mode (mode & 0o027) == 0 (0750 or 2750 setgid, or tighter), and any existing file at path is a socket (is_socket()) owned by geteuid(). Set socket permissions to 0660, and verify after bind that the socket is owned by geteuid(), has mode 0660, and has a group (gid) equal to the parent directory's group.

    Trusted Values & Host Authority (F-13):

        Trusted values come only from record_trusted_input (which requires &HostAuthority) or from the signed trusted_fields of a tool pinned as Trusted, with no taint. Code reachable from the agent socket never receives HostAuthority and never calls approve_step_up. Undeclared arguments not present in the tool's pinned argument policy are rejected.

    Payment Amount Witness & Binding (F-14):

        Each payment amount (and currency, when bound) needs a Trusted witness: either the latest bound lookup (amount_binding) of the same entity or a host trusted input. A matching value anywhere else never authorizes a payment.

    Step-Up Gate (F-15):

        A reservation in AwaitingStepUp stays counted in reserved, and gets no commit, Ticket, or Call Proof until it is approved via approve_step_up.

    Canonical Forwarding (F-16):

        Only canonical_request is sent downstream, never the agent's original wire bytes.