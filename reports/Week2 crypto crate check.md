# Week 2 crypto crate check: p256 0.14.0

**p256 0.14.0 with only its `ecdsa` feature adds 23 crates. The real tree passes `cargo deny` once BSD-3-Clause is allowed, and contains no getrandom on any target.** This report records WEEK2_PLAN step 3. It covers the pin itself, `cargo deny` on the repo's own tree (which the 2026-11-03 probe could not cover), the two RustSec advisories that set the version floors, and the ES256 behaviour that the probe established. The `unsafe` survey of the new crates is in `reports/Dependency unsafe record.md`.

- **Date:** 2026-11-03.
- **Toolchain:** Rust 1.97.1 (`rust-toolchain.toml`), with cargo-deny 0.20.2.
- **Machine:** WSL2, kernel 6.18.54.1-microsoft-standard-WSL2.

## 1. The pin

```toml
p256 = { version = "=0.14.0", default-features = false, features = ["ecdsa"] }   # 2026-07-03, MSRV 1.85
```

p256 0.14.0's features, from its `Cargo.toml`:
- `default` = `arithmetic`, `ecdsa`, `pem`, `precomputed-tables` and `std`;
- `std` enables `alloc` and `getrandom`, so turning the defaults back on would bring in getrandom;
- `ecdsa` = `arithmetic`, `ecdsa-core/algorithm` and `sha256`, and `sha256` = `digest` and `sha2`.

So `default-features = false` with `["ecdsa"]` gives verification, signing, DER signatures and SHA-256, and nothing else. p256's `sha2` dependency resolves to the sidecar's own sha2 0.11.1, so no second version appears.

## 2. The real tree

**New crates (23):** base16ct 1.0.0, cmov 0.5.4, const-oid 0.10.2, cpubits 0.1.1, crypto-bigint 0.7.10, ctutils 0.4.8, der 0.8.3, ecdsa 0.17.0, elliptic-curve 0.14.3, ff 0.14.0, group 0.14.0, hmac 0.13.0, num-traits 0.2.19, p256 0.14.0, primefield 0.14.0, primeorder 0.14.0, rand_core 0.10.1, rfc6979 0.6.0, sec1 0.8.1, signature 3.0.0, subtle 2.6.1, wnaf 0.14.1 and zeroize 1.9.1. This is the probe's list exactly.

| Check | Result |
|---|---|
| Crates resolved per target (`x86_64-unknown-linux-gnu`, `aarch64-apple-darwin`) | 47 on each, up from 24, with identical feature sets |
| Second versions of any crate | None (`multiple-versions = "deny"` holds) |
| Features newly turned on in existing crates | digest: `mac` and `oid`; hybrid-array: `subtle` and `zeroize`; crypto-common: `rand_core` |
| getrandom | Absent. `cargo tree --locked --target all --all-features --prefix none` succeeds and prints 101 lines, none starting `getrandom v` |
| Declared `rust-version` | crypto-bigint, ctutils and elliptic-curve declare 1.87; num-traits 1.60; the other 18 declare 1.85; subtle 2.6.1 declares none (the probe's summary, "every new crate declares ≤ 1.87", missed that) |
| Licences | Every new crate is `Apache-2.0 OR MIT` or `MIT OR Apache-2.0`, except subtle (`BSD-3-Clause`) and ff and group (`MIT/Apache-2.0`, the old slash syntax) |

## 3. `cargo deny` on the real tree

| Run | Result |
|---|---|
| Before allowing BSD-3-Clause | `licenses FAILED`. The only error is subtle 2.6.1: "license is not explicitly allowed". Advisories, bans and sources pass |
| With BSD-3-Clause allowed | `advisories ok, bans ok, licenses ok, sources ok`, with no warnings. ff's and group's slash syntax raises none |
| With the bans added | Still no warnings. `deny.toml` bans getrandom, serde, serde_json, openssl, openssl-sys and ring, none of which is in the tree |
| A negative check of the bans | A scratch copy of `deny.toml` that also banned zeroize failed with `error[banned]: crate 'zeroize = 1.9.1' is explicitly banned`, so the list is enforced rather than ignored |

**CI.** The `verify` job gains a fail-closed getrandom step. It writes the whole tree to a file, fails if `cargo tree` fails, then fails on any line starting with `getrandom v`. Three local runs gave the expected results:
- the real tree passes;
- running outside the workspace fails, with cargo's exit status 101;
- a tree with a `getrandom v0.3.4` line added fails, and prints that line.

## 4. Advisories and version floors

Read from cargo-deny's local copy of the RustSec database and from Cargo's crates.io index cache on 2026-11-03.

| Advisory | Patched | Our tree |
|---|---|---|
| RUSTSEC-2026-0387, crypto-bigint timing variability (2026-10-23) | `>= 0.7.6` | 0.7.10. elliptic-curve 0.14.3 requires `^0.7.8`, and primefield and rfc6979 require `^0.7.5` |
| RUSTSEC-2026-0385, ctutils (2026-10-23) | `>= 0.4.4` | 0.4.8. crypto-bigint 0.7.10 requires `^0.4.6` |

- **crypto-bigint yanks:** 0.7.0 to 0.7.8 are all yanked, including the patched 0.7.6 to 0.7.8. Only 0.7.9 and 0.7.10 are usable, and both declare rust-version 1.87.
- **The MSRV gap:** p256 0.14.0 declares rust-version 1.85, below crypto-bigint's 1.87. That matters only to a toolchain older than 1.87; the pinned 1.97.1 resolves 0.7.10.
- **jsonwebtoken** stays rejected, as the plan says: its latest release, 11.1.0, still takes p256 `^0.13.2`, which pulls crypto-bigint 0.5.5 (WEEK2_PLAN source [52]; not re-checked here).

## 5. The ES256 surface (the 2026-11-03 probe)

The probe was a scratch crate outside the repo, with the same pin, built on Rust 1.97.1 and 1.99.1 (WEEK2_PLAN Appendix A). Nothing in the repo calls p256 yet. Step 6's unit vectors repeat these checks in-repo.

- `VerifyingKey::from_sec1_bytes`, `Signature::from_slice` (JWS r‖s), `Signature::from_der` (DSSE) and `Verifier::verify` all compile and work with `["ecdsa"]` alone.
- An off-curve point is rejected by `from_sec1_bytes`. JWK keys are therefore parsed by hand: decode `x` and `y`, require 32 bytes each, build SEC1 `04‖x‖y`, and let `from_sec1_bytes` reject points off the curve. elliptic-curve 0.14 has no `jwk` feature.
- `verify` accepts the high-S RFC 6979 A.2.5 signature (P-256, SHA-256, "sample"). So the PEP's Episode Token verifier and the broker's Call Proof verifier must reject high-S themselves (T1).
- `SigningKey` reproduces that signature exactly, high-S as it comes, and `normalize_s` changes it. So the PEP must normalize every signature it makes (T1).
- **Prehash ≥ n,** checked against an independent pure-Python P-256 ECDSA and RFC 6979 implementation:

  | Prehash e | z = e mod n | Same deterministic signature as Python | sign(e) = sign(e mod n) | Each accepts the other's |
  |---|---|---|---|---|
  | SHA-256("sample") | e | Yes | Yes | Yes |
  | n − 1 | n − 1 | Yes | Yes | Yes |
  | n | 0 | Yes | Yes | Yes |
  | n + 1 | 1 | Yes | Yes | Yes |
  | 2^256 − 1 | 2^256 − 1 − n | Yes | Yes | Yes |

- **Cost,** mean on an AMD Ryzen 3 5300U, release: 0.57 ms to sign and 0.56 ms to verify on 1.97.1 (0.50 and 0.45 ms on 1.99.1).

## 6. What this does not cover

- **Audits.** p256's README says its arithmetic has never been independently audited. This report checks versions, licences, features and advisories, not the soundness of the cryptography.
- **`unsafe`.** Surveyed separately, in `reports/Dependency unsafe record.md`. The constant-time core is cmov's `asm!`. crypto-bigint, elliptic-curve, der, subtle and zeroize add small, commented `unsafe` blocks.
- **Reachability.** Until step 6, none of the 23 crates' code is reachable from pep-sidecar.
