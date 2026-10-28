# sha2 (RustCrypto): real API vs. pep-sidecar's pin `sha2 = { version = "=0.11.1", default-features = false }` and its one call site (as of 2026-10-27)

Provenance: web facts come from the crates.io JSON API, docs.rs (rendered pages and published sources), and the official RustCrypto GitHub repos. All of them were read through a summarizing fetch tool, so "verbatim" means verbatim as that tool returned it. Where the tool returned lines without indentation, I restored indentation and closing braces in the code blocks and say so. Independent cross-check: the SHA-256 checksums of sha2 0.11.1, digest 0.11.3 and hybrid-array 0.4.15 are identical in the crates.io API, in the upstream RustCrypto/hashes `Cargo.lock`, and in the project's local `Cargo.lock`. That corroborates the extracted data.

Call site under test ([src/jcs.rs, local](<C:\Users\mitam\OneDrive\Documents\Cryptographic Biscuits\agent-authority-fabric\src\jcs.rs>), lines 8-10 and 599-603):

```rust
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest as _, Sha256};

/// Unpadded base64url of SHA-256 over raw bytes.
#[must_use]
pub fn sha256_b64url(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(data))
}
```

Manifest line ([Cargo.toml, local](<C:\Users\mitam\OneDrive\Documents\Cryptographic Biscuits\agent-authority-fabric\Cargo.toml>), line 18): `sha2 = { version = "=0.11.1", default-features = false }  # 2026-10-12, MSRV 1.88`. The package has `edition = "2024"` and `rust-version = "1.88"` (lines 4-5).

## Q1. Does sha2 0.11.1 exist as a stable, non-yanked release? When was it published? What are the latest stable version and the newest 0.10.x?

### Takeaway
Yes. 0.11.1 is a real, non-yanked stable release published on 2026-10-12. As of 2026-10-27 it is the latest stable version and also the newest version overall, so the exact `=0.11.1` pin resolves. Stable 0.11.x does exist (0.11.0 and 0.11.1). The newest 0.10.x is 0.10.9 (2025-04-30).

### Cited Findings
- The crates.io entry for 0.11.1 shows `"created_at": "2026-10-12T18:58:22.836567Z"`, `"yanked": false`, `"rust_version": "1.88"`, `"edition": "2024"` and `"checksum": "47d7069beb7d6ac7b9acd1039986e73443f24234f41074da099d6f994ac9ad19"`. — [crates.io versions API](https://crates.io/api/v1/crates/sha2/versions)
- Crate-level fields: `"max_version": "0.11.1"`, `"max_stable_version": "0.11.1"`, `"newest_version": "0.11.1"`, `"default_version": "0.11.1"`, `"updated_at": "2026-10-12T18:58:22.836567Z"`. There are 51 versions in total, and `"repository": "https://github.com/RustCrypto/hashes"`. — [crates.io crate API](https://crates.io/api/v1/crates/sha2)
- Stable 0.11.x releases (non-pre-release):

  | version | created_at | yanked | rust_version |
  |---|---|---|---|
  | 0.11.1 | 2026-10-12T18:58:22.836567Z | false | 1.88 |
  | 0.11.0 | 2026-03-25T15:05:27.949444Z | false | 1.85 |

  — [crates.io versions API](https://crates.io/api/v1/crates/sha2/versions)
- Pre-releases are listed separately because none of them counts as stable. None is yanked:

  | version | created_at | rust_version |
  |---|---|---|
  | 0.11.0-rc.5 | 2026-02-02T17:13:45.044660Z | 1.85 |
  | 0.11.0-rc.4 | 2026-01-24T17:24:47.342672Z | 1.85 |
  | 0.11.0-rc.3 | 2025-11-05T17:32:14.175790Z | 1.85 |
  | 0.11.0-rc.2 | 2025-09-02T23:08:02.228378Z | 1.85 |
  | 0.11.0-rc.0 | 2025-05-29T14:06:53.977487Z | 1.85 |
  | 0.11.0-pre.5 | 2025-03-05T21:18:11.496292Z | 1.85 |
  | 0.11.0-pre.4 | 2024-07-26T21:12:31.812624Z | 1.72 |
  | 0.11.0-pre.3 | 2024-02-01T18:49:59.287316Z | 1.72 |
  | 0.11.0-pre.2 | 2024-01-17T15:47:31.768437Z | 1.72 |
  | 0.11.0-pre.1 | 2024-01-10T18:49:57.526286Z | 1.71 |
  | 0.11.0-pre.0 | 2024-01-08T20:33:57.075383Z | 1.71 |

  — [crates.io versions API](https://crates.io/api/v1/crates/sha2/versions)
- The upstream CHANGELOG headings are `## 0.11.1 (2026-10-12)` and `## 0.11.0 (2026-03-25)`. — [sha2 CHANGELOG.md (RustCrypto/hashes master)](https://raw.githubusercontent.com/RustCrypto/hashes/master/sha2/CHANGELOG.md)
- The newest 0.10.x is 0.10.9: `"created_at": "2025-04-30T14:38:09.894118Z"`, `"yanked": false`, `"rust_version": null`, `"edition": "2018"`, `"checksum": "a7507d819769d01a365ab707794a4084392c824f54a7a6a7862f8c3d0892b283"`, `"license": "MIT OR Apache-2.0"`. — [crates.io sha2 0.10.9 API](https://crates.io/api/v1/crates/sha2/0.10.9)
- The project's lockfile records `name = "sha2"`, `version = "0.11.1"`, `checksum = "47d7069beb7d6ac7b9acd1039986e73443f24234f41074da099d6f994ac9ad19"`, with dependencies `"cfg-if"`, `"cpufeatures"` and `"digest"`. The checksum is byte-identical to crates.io. — [Cargo.lock, local](<C:\Users\mitam\OneDrive\Documents\Cryptographic Biscuits\agent-authority-fabric\Cargo.lock>) (lines 145-154); [crates.io versions API](https://crates.io/api/v1/crates/sha2/versions)
- In the upstream workspace lock, `sha2` `0.11.1` is a path member (no source or checksum) with dependencies `"cfg-if"`, `"cpufeatures"`, `"digest"` and `"hex-literal"` (hex-literal is a dev-dependency). — [RustCrypto/hashes Cargo.lock (master)](https://raw.githubusercontent.com/RustCrypto/hashes/master/Cargo.lock)

### Inferences
- The `=0.11.1` pin resolves on crates.io. The Cargo.toml comment ("2026-10-12, MSRV 1.88") matches the registry's publish date and `rust_version` exactly, so all three claims the user treated as unverified are correct.
- A model cannot guess a SHA-256 checksum, so the lockfile entry must have been produced from (or copied from) the real registry.
- On 2026-10-27, 0.11.1 is 15 days old. The note in `WEEK1_PLAN.md:218` that it is "less than two weeks old" is now out of date, which matters only if a release-age policy applies.

### Gaps
- `0.11.0-rc.1` did not appear in the extracted version list. I did not confirm whether it exists or was skipped. This does not affect the pin.

## Q2. What are the MSRV (`rust-version`) and edition for 0.11.x and 0.10.x? Is the MSRV at most 1.88?

### Takeaway
sha2 0.11.1 declares `rust-version = "1.88"` and `edition = "2024"`. That equals the project's `rust-version = "1.88"` and is below the 1.97.0 toolchain, so it passes. 0.11.0 declared 1.85. 0.10.9 declares no `rust-version` and uses edition 2018. sha2's own dependencies digest 0.11.3 and hybrid-array 0.4.15 declare 1.85. One stale artifact exists: the README badge in 0.11.1 still says "rustc-1.85+".

### Cited Findings
- The published 0.11.1 manifest contains `edition = "2024"`, `rust-version = "1.88"`, `name = "sha2"` and `version = "0.11.1"`. — [docs.rs: sha2 0.11.1 Cargo.toml source](https://docs.rs/crate/sha2/0.11.1/source/Cargo.toml). crates.io agrees: `"rust_version": "1.88"`, `"edition": "2024"`. — [crates.io versions API](https://crates.io/api/v1/crates/sha2/versions)
- sha2 0.11.1 CHANGELOG, "Changed": "MSRV bumped to 1.88 ([#926])". — [sha2 CHANGELOG.md](https://raw.githubusercontent.com/RustCrypto/hashes/master/sha2/CHANGELOG.md)
- sha2 0.11.0 CHANGELOG, "Changed": "Edition changed to 2024 and MSRV bumped to 1.85 ([#652])" and "Relax MSRV policy and allow MSRV bumps in patch releases". — [sha2 CHANGELOG.md](https://raw.githubusercontent.com/RustCrypto/hashes/master/sha2/CHANGELOG.md)
- 0.11.0 has `"rust_version": "1.85"`. The pre-releases have 1.85 (rc.*, pre.5), 1.72 (pre.2 to pre.4) and 1.71 (pre.0, pre.1). — [crates.io versions API](https://crates.io/api/v1/crates/sha2/versions)
- 0.10.9 has `"rust_version": null` and `"edition": "2018"`. — [crates.io sha2 0.10.9 API](https://crates.io/api/v1/crates/sha2/0.10.9)
- Conflict: the 0.11.1 README badge URL is `https://img.shields.io/badge/rustc-1.85+-blue.svg`, and the docs.rs crate page shows a `rustc-1.85+` badge. — [docs.rs: sha2 0.11.1 README.md source](https://docs.rs/crate/sha2/0.11.1/source/README.md); [docs.rs sha2 0.11.1 crate root](https://docs.rs/sha2/0.11.1/sha2/). Both are contradicted by `rust-version = "1.88"` in the [published manifest](https://docs.rs/crate/sha2/0.11.1/source/Cargo.toml) and by the 0.11.1 CHANGELOG line "MSRV bumped to 1.88 ([#926])" ([sha2 CHANGELOG.md](https://raw.githubusercontent.com/RustCrypto/hashes/master/sha2/CHANGELOG.md)).
- digest 0.11.3 has `"rust_version": "1.85"` and `"edition": "2024"`. — [crates.io digest versions API](https://crates.io/api/v1/crates/digest/versions)
- hybrid-array 0.4.15 has `"rust_version": "1.85"` and `"edition": "2024"`. — [crates.io hybrid-array API](https://crates.io/api/v1/crates/hybrid-array)
- The project declares `edition = "2024"` and `rust-version = "1.88"`. — [Cargo.toml, local](<C:\Users\mitam\OneDrive\Documents\Cryptographic Biscuits\agent-authority-fabric\Cargo.toml>)

### Inferences
- The chain is 1.88 (sha2 0.11.1) ≤ 1.88 (project `rust-version`) ≤ 1.97.0 (toolchain), so there is no MSRV conflict. The README badge is simply stale. Cargo enforces the manifest's `rust-version`, not the badge.
- Under the relaxed policy ("allow MSRV bumps in patch releases"), a future sha2 0.11.x could raise the MSRV above 1.88. The exact `=` pin blocks that drift. Any future bump of the pin must be re-checked against the project's `rust-version = "1.88"`.

### Gaps
- I did not fetch the `rust_version` of the transitive crates crypto-common 0.2.2, block-buffer 0.12.1 and cpufeatures 0.3.1. They share a workspace lock with sha2 0.11.1 (which declares 1.88) upstream, which suggests they are ≤ 1.88. That is unverified.

## Q3. What are the default features in 0.11? What does `default-features = false` turn off? Are `Digest` and `Sha256::digest` available without default features?

### Takeaway
sha2 0.11.1 has exactly three features: `alloc`, `oid` and `zeroize`, with `default = ["alloc", "oid"]`. `default-features = false` turns off `alloc` (which forwards to `digest/alloc`) and `oid` (which forwards to `digest/oid`, removing the `AssociatedOid` impl). `zeroize` is off either way. The 0.10-era features `asm`, `asm-aarch64`, `force-soft`, `force-soft-compact`, `loongarch64_asm`, `compress` and `std` no longer exist. `Digest` and `Sha256::digest` are not feature-gated, so they are available with no features.

### Cited Findings
- The crates.io features map for 0.11.1 is quoted below. — [crates.io versions API](https://crates.io/api/v1/crates/sha2/versions)
  ```json
  {"alloc":["digest/alloc"],"default":["alloc","oid"],"oid":["digest/oid"],"zeroize":["digest/zeroize"]}
  ```
- The docs.rs features page lists the same three features. `alloc` ("digest/alloc (default)") and `oid` ("digest/oid (default)") are defaults, `zeroize` is non-default, and no optional dependencies are listed. — [docs.rs sha2 0.11.1 features](https://docs.rs/crate/sha2/0.11.1/features)
- The published manifest `[features]` section is quoted below. — [docs.rs: sha2 0.11.1 Cargo.toml source](https://docs.rs/crate/sha2/0.11.1/source/Cargo.toml)
  ```toml
  alloc = ["digest/alloc"]
  default = ["alloc", "oid"]
  oid = ["digest/oid"]
  zeroize = ["digest/zeroize"]
  ```
- On the docs.rs `Sha256` page only two impls are feature-gated: `impl AssociatedOid for Sha256` ("available on crate feature `oid` only") and `impl ZeroizeOnDrop for Sha256` ("available on crate feature `zeroize` only"). `Default`, `FixedOutput`, `Update` and `HashMarker`, the four bounds of the `Digest` blanket impl, carry no gate. — [docs.rs sha2::Sha256 (0.11.1)](https://docs.rs/sha2/0.11.1/sha2/struct.Sha256.html)
- sha2 0.11.0 CHANGELOG, "Removed": "`asm`, `asm-aarch64`, `loongarch64_asm`, and `compress` crate features ([#542])"; "`soft` crate feature ([#615])"; "`force-soft-compact` crate feature ([#686])"; "`std` crate feature ([#678])". "Added": "`alloc` crate feature ([#678])". — [sha2 CHANGELOG.md](https://raw.githubusercontent.com/RustCrypto/hashes/master/sha2/CHANGELOG.md)
- The sha2 0.10.9 features map is quoted below. — [crates.io sha2 0.10.9 API](https://crates.io/api/v1/crates/sha2/0.10.9)
  ```json
  {"asm":["sha2-asm"],"asm-aarch64":["asm"],"compress":[],"default":["std"],"force-soft":[],"force-soft-compact":[],"loongarch64_asm":[],"oid":["digest/oid"],"std":["digest/std"]}
  ```
- Naming discrepancy: the 0.11.0 CHANGELOG says the "`soft` crate feature" was removed ([sha2 CHANGELOG.md](https://raw.githubusercontent.com/RustCrypto/hashes/master/sha2/CHANGELOG.md)), but the 0.10.9 manifest has a `force-soft` feature and no `soft` feature ([crates.io sha2 0.10.9 API](https://crates.io/api/v1/crates/sha2/0.10.9)). Neither name exists in 0.11.1 ([crates.io versions API](https://crates.io/api/v1/crates/sha2/versions)).
- The digest 0.11.3 features map (the features that sha2's flags forward to) is quoted below. — [crates.io digest versions API](https://crates.io/api/v1/crates/digest/versions)
  ```json
  {"alloc":[],"block-api":["dep:block-buffer"],"default":["block-api"],"dev":["blobby"],"getrandom":["common/getrandom","rand_core"],"mac":["dep:ctutils"],"oid":["dep:const-oid"],"rand_core":["common/rand_core"],"zeroize":["dep:zeroize","block-buffer?/zeroize"]}
  ```
- The project's lockfile has no `const-oid`, `zeroize`, `ctutils` or `blobby` packages, and its `digest` entry depends only on `"block-buffer"` and `"crypto-common"`. — [Cargo.lock, local](<C:\Users\mitam\OneDrive\Documents\Cryptographic Biscuits\agent-authority-fabric\Cargo.lock>) (lines 62-70)

### Inferences
- With `default-features = false` and no features enabled, the project still gets `sha2::Sha256` plus the blanket `Digest` impl, which is everything the call site uses. It loses `AssociatedOid` (the OID constant) and whatever `digest/alloc` gates, and the project uses neither.
- The local lockfile matches a build with `oid`, `zeroize` and `mac` all off: `const-oid`, `zeroize` and `ctutils` are absent. That is consistent with `default-features = false`.
- There is no `asm` or `force-soft` flag to set or unset. Backend choice moved to `--cfg` flags (see Q7).

### Gaps
- I did not fetch which digest 0.11.3 items `digest/alloc` gates (for example, boxed or dynamic-digest helpers). It is irrelevant to the call site.
- The extracted sha2 manifest did not show whether sha2's `digest` dependency sets `default-features = false`. The lockfile shows `block-buffer` present, so digest's `block-api` is active either way. sha2 needs it for `digest::block_api::CtOutWrapper`.

## Q4. What exactly is `sha2::Sha256` in 0.11? Is `sha2::Digest` a re-export of `digest::Digest`? Which `digest` version does sha2 depend on?

### Takeaway
In 0.11.1, `Sha256` is a newtype struct generated by `digest::buffer_fixed!` around `CtOutWrapper<block_api::Sha256VarCore, U32>`. It is no longer a `CoreWrapper<...>` type alias: 0.11.0 replaced the type aliases with newtypes, and digest 0.11 removed `CoreWrapper`. `sha2::Digest` is a re-export via `pub use digest::{self, Digest};`. sha2 requires `digest = "0.11"`. digest 0.11.0 and 0.11.1 are yanked, so this resolves to digest 0.11.3, the newest stable version, which the project lockfile pins with the registry's exact checksum.

### Cited Findings
- From sha2 0.11.1 `src/lib.rs`, the re-export. — [docs.rs: sha2 0.11.1 src/lib.rs](https://docs.rs/crate/sha2/0.11.1/source/src/lib.rs)
  ```rust
  pub use digest::{self, Digest};
  ```
- From sha2 0.11.1 `src/lib.rs`, the `Sha256` definition and its imports. — [docs.rs: sha2 0.11.1 src/lib.rs](https://docs.rs/crate/sha2/0.11.1/source/src/lib.rs)
  ```rust
  use digest::{
      block_api::CtOutWrapper,
      consts::{U28, U32, U48, U64},
  };

  digest::buffer_fixed!(
      /// SHA-256 hasher.
      pub struct Sha256(CtOutWrapper<block_api::Sha256VarCore, U32>);
      oid: "2.16.840.1.101.3.4.2.1";
      impl: FixedHashTraits;
  );
  ```
- Crate-level attributes in sha2 0.11.1 `src/lib.rs` (the extracted source has no `#![forbid(unsafe_code)]` and no `extern crate alloc`). — [docs.rs: sha2 0.11.1 src/lib.rs](https://docs.rs/crate/sha2/0.11.1/source/src/lib.rs)
  ```rust
  #![no_std]
  #![doc = include_str!("../README.md")]
  #![cfg_attr(docsrs, feature(doc_cfg))]
  ```
- The docs.rs crate root lists `Sha224`, `Sha256`, `Sha384`, `Sha512`, `Sha512_224` and `Sha512_256` under **Structs**, `Sha256` with the text "SHA-256 hasher.". Under **Traits** it lists `Digest` ("Convenience wrapper trait covering functionality of cryptographic hash functions with fixed output size."). It lists one module, `block_api` ("Block-level types"), plus the `digest` re-export, and no type aliases. — [docs.rs sha2 0.11.1 crate root](https://docs.rs/sha2/0.11.1/sha2/)
- The docs.rs `Sha256` page shows the struct declaration below. Its impls are AlgorithmName, AssociatedOid (oid), BlockSizeUser, Clone, CoreProxy, Debug, Default, FixedOutput, FixedOutputReset, HashMarker, OutputSizeUser, Reset, SerializableState, Update and ZeroizeOnDrop (zeroize). The impls link to `src/sha2/lib.rs.html#34-39`. — [docs.rs sha2::Sha256 (0.11.1)](https://docs.rs/sha2/0.11.1/sha2/struct.Sha256.html)
  ```rust
  pub struct Sha256 { /* private fields */ }
  ```
- The blanket `Digest` impl as it appears on the `Sha256` page. — [docs.rs sha2::Sha256 (0.11.1)](https://docs.rs/sha2/0.11.1/sha2/struct.Sha256.html)
  ```rust
  impl<D> Digest for D
  where
      D: FixedOutput + Default + Update + HashMarker,
  ```
- sha2 0.11.0 CHANGELOG, "Changed": "Update to `digest` v0.11"; "Replace type aliases with newtypes ([#678])"; "`compress256` and `compress512` are moved to the `block_api` module ([#678])"; "Implementation of the `SerializableState` trait ([#716])". — [sha2 CHANGELOG.md](https://raw.githubusercontent.com/RustCrypto/hashes/master/sha2/CHANGELOG.md)
- digest 0.11.0 CHANGELOG. "Changed": "`digest::core_api` renamed to `digest::block_api` ([#1799])"; "`CtVariableCoreWrapper` renamed to `CtOutWrapper` ([#1799])"; "Removed the OID type parameter from `CtOutWrapper` ([#1799])". "Added": "`buffer_fixed`, `buffer_ct_variable`, `buffer_rt_variable`, and `buffer_xof` macros ([#1799])". "Removed": "`CoreWrapper`, `RtVariableCoreWrapper`, and `XofReaderCoreWrapper` types ([#1799])". — [digest CHANGELOG.md (RustCrypto/traits master)](https://raw.githubusercontent.com/RustCrypto/traits/master/digest/CHANGELOG.md)
- The published sha2 0.11.1 manifest has these dependencies: `[dependencies.digest]` `version = "0.11"`, `[dependencies.cfg-if]` `version = "1"`, and `[target.'cfg(any(target_arch = "aarch64", target_arch = "x86_64", target_arch = "x86"))'.dependencies.cpufeatures]` `version = "0.3"`. Its dev-dependencies are digest `0.11` with `features = ["dev"]` and hex-literal `1`. — [docs.rs: sha2 0.11.1 Cargo.toml source](https://docs.rs/crate/sha2/0.11.1/source/Cargo.toml)
- digest release status on crates.io:

  | version | created_at | yanked | rust_version | edition | checksum |
  |---|---|---|---|---|---|
  | 0.11.3 | 2026-05-03T12:54:48.023505Z | false | 1.85 | 2024 | f1dd6dbb5841937940781866fa1281a1ff7bd3bf827091440879f9994983d5c2 |
  | 0.11.2 | 2026-03-13T16:47:07.383460Z | false | 1.85 | 2024 | 4850db49bf08e663084f7fb5c87d202ef91a3907271aff24a94eb97ff039153c |
  | 0.11.1 | 2026-02-25T15:11:45.195474Z | **true** | 1.85 | 2024 | 285743a676ccb6b3e116bc14cc69319b957867930ae9c4822f8e0f54509d7243 |
  | 0.11.0 | 2026-02-13T07:43:55.038819Z | **true** | 1.85 | 2024 | f8bf3682cdec91817be507e4aa104314898b95b84d74f3d43882210101a545b6 |
  | 0.10.7 (newest 0.10.x) | 2023-05-19T17:11:30.893794Z | false | null | 2018 | 9ed9a281f7bc9b7576e61468ba615a66a5c8cfdff42420a70aa82701a3b1e292 |

  The newest non-pre-release, non-yanked version is 0.11.3. — [crates.io digest versions API](https://crates.io/api/v1/crates/digest/versions)
- Yank notes. digest 0.11.0: "Note: this version was yanked because v0.11.1 introduces breaking changes." / "Users should migrate to `digest` v0.11.1 and `crypto-common` v0.2.1 using `cargo update`." digest 0.11.1: "Note: this version was yanked because v0.11.2 introduces minor breaking changes" / "affecting only pre-release versions of downstream crates." — [digest CHANGELOG.md](https://raw.githubusercontent.com/RustCrypto/traits/master/digest/CHANGELOG.md)
- Date conflict for digest 0.11.3: the CHANGELOG heading reads "0.11.3 (2026-04-03)" ([digest CHANGELOG.md](https://raw.githubusercontent.com/RustCrypto/traits/master/digest/CHANGELOG.md)), but crates.io has `"created_at": "2026-05-03T12:54:48.023505Z"` ([crates.io digest versions API](https://crates.io/api/v1/crates/digest/versions)). This does not affect compilation.
- Lockfile cross-check, comparing the project lock with the upstream workspace lock (all upstream entries have source `registry+https://github.com/rust-lang/crates.io-index`, and none is a git source):

  | crate | project Cargo.lock | upstream RustCrypto/hashes Cargo.lock |
  |---|---|---|
  | digest | 0.11.3, `f1dd6dbb…d5c2` | 0.11.3, `f1dd6dbb…d5c2` |
  | crypto-common | 0.2.2, `ce6e4c96…f1453` | 0.2.2, `ce6e4c96…f1453` |
  | block-buffer | 0.12.1, `d2f6c7db…60aa` | 0.12.1, `d2f6c7db…60aa` |
  | hybrid-array | 0.4.15, `27f864f1…9a17` | 0.4.15, `27f864f1…9a17` |
  | cpufeatures | 0.3.1, `5ca28b0a…7566` | 0.3.1, `5ca28b0a…7566` |
  | cfg-if | 1.0.5, `4e764817…4600` | 1.0.5, `4e764817…4600` |
  | typenum | 1.20.1, `b6f5e870…dda20` | 1.20.1, `b6f5e870…dda20` |
  | libc | **0.2.191**, `65cd87c9…240a` | **0.2.190**, `ce5d3ddc…be78` |

  — [Cargo.lock, local](<C:\Users\mitam\OneDrive\Documents\Cryptographic Biscuits\agent-authority-fabric\Cargo.lock>); [RustCrypto/hashes Cargo.lock (master)](https://raw.githubusercontent.com/RustCrypto/hashes/master/Cargo.lock)

### Inferences
- `sha2::{Digest, Sha256}` are the real public paths of the real crate. No "stand-in" API is involved.
- Cargo skips yanked versions in a fresh resolution, so `digest = "0.11"` resolves to 0.11.3 today. This is general Cargo behavior and I did not fetch a citation for it. The local lockfile already pins 0.11.3.
- Every lockfile entry in sha2's dependency subtree except libc is byte-identical to upstream's registry entries, so the lockfile is internally consistent with the real registry for this subtree.

### Gaps
- I did not verify that libc 0.2.191, the project lockfile's version, exists. Upstream locks 0.2.190. libc is shared with `nix`, which is the nix researcher's scope, and cpufeatures needs it on the targets that matter here.

## Q5. What is the exact signature of `Digest::digest`? What is `Output<Self>` concretely? Does it implement `AsRef<[u8]>` and `Deref<Target = [u8]>`?

### Takeaway
In digest 0.11.3 the signature is `fn digest(data: impl AsRef<[u8]>) -> Output<Self>;`, where `Output<T> = Array<u8, <T as OutputSizeUser>::OutputSize>`. That is the hybrid-array `Array`, defined in crypto-common and re-exported by digest. For `Sha256` it is `Array<u8, U32>`, a 32-byte array. hybrid-array 0.4.15 has `impl<T, U> AsRef<[T]> for Array<T, U> where U: ArraySize` and `impl<T, U> Deref for Array<T, U> where U: ArraySize` with `type Target = [T]`. So the digest output is `AsRef<[u8]>` and derefs to `[u8]`.

### Cited Findings
- The `Digest` trait in digest 0.11.3, assembled from the method lines the docs page shows. The doc text for `digest` is "Compute hash of `data`." The Implementors section shows the single blanket impl quoted after the trait. — [docs.rs digest::Digest (0.11.3)](https://docs.rs/digest/0.11.3/digest/trait.Digest.html)
  ```rust
  pub trait Digest: OutputSizeUser {
      fn new() -> Self;
      fn new_with_prefix(data: impl AsRef<[u8]>) -> Self;
      fn update(&mut self, data: impl AsRef<[u8]>);
      fn chain_update(self, data: impl AsRef<[u8]>) -> Self;
      fn finalize(self) -> Output<Self>;
      fn finalize_into(self, out: &mut Output<Self>);
      fn finalize_reset(&mut self) -> Output<Self> where Self: FixedOutputReset;
      fn finalize_into_reset(&mut self, out: &mut Output<Self>) where Self: FixedOutputReset;
      fn reset(&mut self) where Self: Reset;
      fn output_size() -> usize;
      fn digest(data: impl AsRef<[u8]>) -> Output<Self>;
  }
  ```
  ```rust
  impl<D: FixedOutput + Default + Update + HashMarker> Digest for D
  ```
- The `Output` alias in digest 0.11.3, followed by the "Aliased Type" shown on the page. The source link points to crypto-common 0.2.1 `src/lib.rs` line 41, and the linked `ArraySize` is `hybrid_array::traits::ArraySize` (docs.rs built this page against hybrid_array 0.4.11). — [docs.rs digest::Output (0.11.3)](https://docs.rs/digest/0.11.3/digest/type.Output.html)
  ```rust
  pub type Output<T> = Array<u8, <T as OutputSizeUser>::OutputSize>;
  ```
  ```rust
  #[repr(transparent)]pub struct Output<T>(pub <<T as OutputSizeUser>::OutputSize as ArraySize>::ArrayType<u8>);
  ```
- digest 0.11.0 CHANGELOG, "Changed": "Replaced `generic-array` with `hybrid-array` ([#1358])"; "`crypto-common` dependency bumped to v0.2 ([#1173])"; "Re-export of `crypto-common` moved to `digest::common` ([#2237])". — [digest CHANGELOG.md](https://raw.githubusercontent.com/RustCrypto/traits/master/digest/CHANGELOG.md)
- Sha256's output size is `U32`: the definition is `pub struct Sha256(CtOutWrapper<block_api::Sha256VarCore, U32>);` ([docs.rs: sha2 0.11.1 src/lib.rs](https://docs.rs/crate/sha2/0.11.1/source/src/lib.rs)), and the docs.rs `OutputSizeUser` impl renders `OutputSize` as `<CtOutWrapper<Sha256VarCore, UInt<...>>>::OutputSize` (the typenum form of U32) ([docs.rs sha2::Sha256 (0.11.1)](https://docs.rs/sha2/0.11.1/sha2/struct.Sha256.html)).
- The `Array` struct in hybrid-array 0.4.15, as rendered on docs.rs. — [docs.rs hybrid_array::Array (0.4.15)](https://docs.rs/hybrid-array/0.4.15/hybrid_array/struct.Array.html)
  ```rust
  #[repr(transparent)]pub struct Array<T, U: ArraySize>(pub U::ArrayType<T>);
  ```
  The same declaration in the published source, with attributes. — [docs.rs: hybrid-array 0.4.15 src/lib.rs](https://docs.rs/crate/hybrid-array/0.4.15/source/src/lib.rs)
  ```rust
  #[cfg_attr(
      feature = "zerocopy",
      derive(IntoBytes, FromBytes, Immutable, Unaligned, KnownLayout)
  )]
  #[repr(transparent)]
  pub struct Array<T, U: ArraySize>(pub U::ArrayType<T>);
  ```
- The `AsRef<[T]>` impl that the call site relies on. Lines are as extracted, with indentation and closing braces restored. — [docs.rs: hybrid-array 0.4.15 src/lib.rs](https://docs.rs/crate/hybrid-array/0.4.15/source/src/lib.rs)
  ```rust
  impl<T, U> AsRef<[T]> for Array<T, U>
  where
      U: ArraySize,
  {
      #[inline]
      fn as_ref(&self) -> &[T] {
          self.0.as_ref()
      }
  }
  ```
- The `Deref` impl, quoted the same way. — [docs.rs: hybrid-array 0.4.15 src/lib.rs](https://docs.rs/crate/hybrid-array/0.4.15/source/src/lib.rs)
  ```rust
  impl<T, U> Deref for Array<T, U>
  where
      U: ArraySize,
  {
      type Target = [T];

      #[inline]
      fn deref(&self) -> &[T] {
          self.0.as_ref()
      }
  }
  ```
- Related impl headings in the same source. — [docs.rs: hybrid-array 0.4.15 src/lib.rs](https://docs.rs/crate/hybrid-array/0.4.15/source/src/lib.rs)
  ```rust
  impl<T, U> Borrow<[T]> for Array<T, U>
  impl<T, U, const N: usize> AsRef<[T; N]> for Array<T, U>
  where
      U: ArraySize<ArrayType<T> = [T; N]>,
  ```
- The docs.rs `Array` page sidebar lists these Trait Implementations: `AsRef<[T]>`, `AsRef<Array<T, U>>`, `AsRef<[T; N]>`, `Borrow<[T]>`, `Deref`, `From<Array<T, U>>` (for `[T; N]`), `PartialEq`, `PartialEq<Array<T, U>>` and `PartialEq<[T; N]>`. It also shows the inherent method `pub const fn as_slice(&self) -> &[T]`. — [docs.rs hybrid_array::Array (0.4.15)](https://docs.rs/hybrid-array/0.4.15/hybrid_array/struct.Array.html)
- hybrid-array 0.4.15 is the newest and the max stable version (`"max_stable_version": "0.4.15"`, no 0.5.x), with `"created_at": "2026-09-08T18:21:39.618460Z"`, `"yanked": false` and `"checksum": "27f864f10dfb56725ce5ce5472bc52252c8f93a4ab86327122cebf62c5f59a17"`. That checksum matches the local lockfile. — [crates.io hybrid-array API](https://crates.io/api/v1/crates/hybrid-array); [Cargo.lock, local](<C:\Users\mitam\OneDrive\Documents\Cryptographic Biscuits\agent-authority-fabric\Cargo.lock>) (lines 72-79)
- The official 0.11.1 docs example uses exactly this one-shot form. — [docs.rs sha2 0.11.1 crate root](https://docs.rs/sha2/0.11.1/sha2/)
  ```rust
  use sha2::{Sha256, Digest};
  use hex_literal::hex;

  let hash = Sha256::digest(b"hello world");
  assert_eq!(hash, hex!("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"));
  ```

### Inferences
- `data: &[u8]` satisfies `impl AsRef<[u8]>`, because `[u8]: AsRef<[u8]>` and `&T: AsRef<U>` when `T: AsRef<U>`. This is standard-library behavior and is not cited here.
- For a bound `T: AsRef<[u8]>`, exactly one impl applies to `Array<u8, U32>`, namely `AsRef<[T]>`. The other `AsRef` impls target `[T; N]` and `Array<T, U>`, not `[u8]`, so type inference is unambiguous.
- The README's own example uses `Sha256::digest`, so this is the intended, supported 0.11.1 API.

### Gaps
- I did not explicitly confirm that `Digest::digest` lacks a `#[deprecated]` attribute in digest 0.11.3. The extracted doc text is only "Compute hash of `data`.", and the official 0.11.1 example uses the method, which makes a deprecation unlikely. A deprecation would matter, because `-D warnings` turns it into an error.
- I did not fetch the 0.10.x (`digest` 0.10.7) `Digest::digest` signature for a side-by-side comparison.

## Q6. Which breaking changes from 0.10 to 0.11 matter here, and do any of them affect `Sha256::digest(data)` passed as `AsRef<[u8]>`?

### Takeaway
0.11 brings many breaking changes: generic-array is replaced by hybrid-array, type aliases become newtypes, `core_api` is renamed `block_api`, `CoreWrapper` is removed, the `std`, `asm` and `force-soft*` features are removed, the `io::Write`/`Read` impls are removed, the edition moves to 2024 and the MSRV to 1.85 and then 1.88. None of them breaks this call site. `Digest::digest` still takes `impl AsRef<[u8]>` and returns `Output<Self>`, and the new output type `hybrid_array::Array<u8, U32>` implements `AsRef<[u8]>`.

### Cited Findings
- sha2 0.11.0, "Changed": "Edition changed to 2024 and MSRV bumped to 1.85 ([#652])"; "Relax MSRV policy and allow MSRV bumps in patch releases"; "Update to `digest` v0.11"; "Replace type aliases with newtypes ([#678])"; "`compress256` and `compress512` are moved to the `block_api` module ([#678])"; "Implementation of the `SerializableState` trait ([#716])"; "Configuration flags for backend selection ([#614], [#615], [#686], [#802])". "Added": "`alloc` crate feature ([#678])"; "RISC-V scalar crypto extension support ([#614])". "Removed": the four feature bullets quoted in Q3. — [sha2 CHANGELOG.md](https://raw.githubusercontent.com/RustCrypto/hashes/master/sha2/CHANGELOG.md)
- sha2 0.11.1, "Changed": "Removed workaround for unaligned loads in `riscv-zknh` backend ([#879])"; "`riscv-zknh` backends no longer require `zbkb` (or `zbb`) target feature ([#879])"; "MSRV bumped to 1.88 ([#926])". "Fixed": "Loading of round constants in AArch64 backends to satisfy the Stacked Borrows model ([#922])". — [sha2 CHANGELOG.md](https://raw.githubusercontent.com/RustCrypto/hashes/master/sha2/CHANGELOG.md)
- sha2 0.10.9, "Added": "`force-soft-compact` crate feature to enable compact software backend (backport of [#686]) [#687]". — [sha2 CHANGELOG.md](https://raw.githubusercontent.com/RustCrypto/hashes/master/sha2/CHANGELOG.md)
- digest 0.11.0, "Changed" (excerpt): "Replaced `generic-array` with `hybrid-array` ([#1358])"; "Edition changed to 2024 and MSRV bumped to 1.85 ([#1759])"; "`digest::core_api` renamed to `digest::block_api` ([#1799])"; "`CtVariableCoreWrapper` renamed to `CtOutWrapper` ([#1799])"; "Bump `block-buffer` to v0.11 ([#2082])"; "Re-export of `crypto-common` moved to `digest::common` ([#2237])"; "Replace `subtle` with `ctutils` ([#2301])". "Removed": "`Mac::new`, `Mac::new_from_slice`, and `Mac::generate_key` methods ([#1173])"; "`CoreWrapper`, `RtVariableCoreWrapper`, and `XofReaderCoreWrapper` types ([#1799])"; "`io::Write/Read` implementations in favor of the `digest_io::IoWrapper` type ([#1809])"; "`VariableOutput` trait ([#2043])"; "Implementation of `subtle::ConstantTimeEq` for `CtOutput`…". — [digest CHANGELOG.md](https://raw.githubusercontent.com/RustCrypto/traits/master/digest/CHANGELOG.md)
- digest 0.11.2, "Changed": "Do not implement `Clone` as part of `(Reset)MacTraits` in the `buffer_fixed!` macro ([#2341])"; "`EagerHash` trait to be a sub-trait of `Clone` ([#2341])". digest 0.11.3, "Added": "`dev::initialized_mac_test` function ([#2367])"; "`TryCustomizedInit` trait ([#2395])". — [digest CHANGELOG.md](https://raw.githubusercontent.com/RustCrypto/traits/master/digest/CHANGELOG.md)
- The current `Digest::digest` signature is `fn digest(data: impl AsRef<[u8]>) -> Output<Self>;`. — [docs.rs digest::Digest (0.11.3)](https://docs.rs/digest/0.11.3/digest/trait.Digest.html)

### Inferences
- Impact of each change on the call site:
  - **generic-array → hybrid-array.** The output type is now `hybrid_array::Array<u8, U32>`. This breaks code that names `GenericArray` or uses generic-array-only APIs. It does not break the call site, because `Array: AsRef<[T]>` (Q5).
  - **Type aliases → newtypes, `CoreWrapper` removed, `core_api` → `block_api`, `compress256` moved.** This breaks code that names `CoreWrapper<…>`, `Sha256VarCore` or `sha2::compress256`. It does not break the call site, which only names `sha2::Sha256` and `sha2::Digest`.
  - **`std`, `asm`, `asm-aarch64`, `force-soft` (`soft`), `force-soft-compact`, `loongarch64_asm` and `compress` removed.** These would break a manifest that enables them. The project enables none (`default-features = false` and no `features`).
  - **`io::Write` impls removed.** This breaks patterns like `std::io::copy(&mut r, &mut hasher)`. The call site does not use it.
  - **Edition 2024 and MSRV 1.88.** Covered in Q2. The project complies.
  - **digest 0.11.2/0.11.3 changes** affect MACs and `buffer_fixed!` internals only, not `Digest::digest`.

### Gaps
- I did not fetch sha2 0.10.9's exact `digest` requirement or the digest 0.10.7 `Digest` page for a side-by-side comparison of the old signature.

## Q7. Are there target-specific concerns for aarch64-apple-darwin (and x86_64-unknown-linux-gnu)?

### Takeaway
There are no asm or SHA-extension features left to configure. On aarch64, sha2 automatically uses its `aarch64-sha2` backend when the required CPU features are detected at runtime, and falls back to `soft` otherwise. Detection uses `cpufeatures` 0.3, a dependency only on aarch64, x86 and x86_64, which pulls in `libc`. You can override the backend only through `--cfg` flags, and the project does not need to. sha2's own manifest declares no C toolchain or asm dependency. 0.11.1 also contains an AArch64 fix.

### Cited Findings
- The target-specific dependency in the published manifest is `[target.'cfg(any(target_arch = "aarch64", target_arch = "x86_64", target_arch = "x86"))'.dependencies.cpufeatures]` with `version = "0.3"`. It is the only target-specific section, and there is none for loongarch64. — [docs.rs: sha2 0.11.1 Cargo.toml source](https://docs.rs/crate/sha2/0.11.1/source/Cargo.toml)
- The manifest's `[lints.rust.unexpected_cfgs]` has `level = "warn"`, `priority = 0`, and a `check-cfg` list that includes `'cfg(sha2_256_backend, values("aarch64-sha2", "soft", "riscv-zknh", "x86-sha"))'`. — [docs.rs: sha2 0.11.1 Cargo.toml source](https://docs.rs/crate/sha2/0.11.1/source/Cargo.toml)
- The 0.11.1 README on the default backend: "`target_arch = "aarch64"`: use `aarch64-sha2` and `aarch64-sha3`" "when the required target features are detected at runtime". Otherwise it falls back to `soft`. — [docs.rs: sha2 0.11.1 README.md source](https://docs.rs/crate/sha2/0.11.1/source/README.md)
- The 0.11.1 README on override flags:
  - `sha2_backend`: "Supported values: `soft`, `riscv-zknh`."
  - `sha2_256_backend`: "Supported values: `aarch64-sha2`, `soft`, `riscv-zknh`, `x86-sha`."
  - `sha2_512_backend`: "Supported values: `aarch64-sha3`, `soft`, `riscv-zknh`, `x86-avx2`."
  - "Note that `sha2_backend` has a higher priority than `sha2_256_backend` and `sha2_512_backend`."
  - Compact mode: `sha2_backend_soft = "compact"` and `sha2_backend_riscv_zknh = "compact"`.

  The README makes no statement about Apple, macOS or aarch64-apple-darwin. — [docs.rs: sha2 0.11.1 README.md source](https://docs.rs/crate/sha2/0.11.1/source/README.md)
- sha2 0.11.1, "Fixed": "Loading of round constants in AArch64 backends to satisfy the Stacked Borrows model ([#922])". 0.11.0, "Removed": "`asm`, `asm-aarch64`, `loongarch64_asm`, and `compress` crate features ([#542])". — [sha2 CHANGELOG.md](https://raw.githubusercontent.com/RustCrypto/hashes/master/sha2/CHANGELOG.md)
- In both the project lock and the upstream lock, `cpufeatures` 0.3.1 depends on `libc`, with checksum `5ca28b0ae3115b884660db4118d803791fd6756b6e88f39c0f3f7859060d7566`. — [Cargo.lock, local](<C:\Users\mitam\OneDrive\Documents\Cryptographic Biscuits\agent-authority-fabric\Cargo.lock>) (lines 44-51); [RustCrypto/hashes Cargo.lock (master)](https://raw.githubusercontent.com/RustCrypto/hashes/master/Cargo.lock)
- In 0.10.9, `asm` pulled in `sha2-asm`: `"asm":["sha2-asm"]`. — [crates.io sha2 0.10.9 API](https://crates.io/api/v1/crates/sha2/0.10.9)

### Inferences
- Both of the project's targets (x86_64-unknown-linux-gnu and aarch64-apple-darwin) compile `cpufeatures` and `libc` as part of sha2. Neither needs a `--cfg` flag, and the project's `RUSTFLAGS='-D warnings'` sets none, so default runtime detection applies.
- sha2 0.11.1 depends only on `cfg-if`, `digest` and `cpufeatures`, and the local lockfile has no `cc`. The 0.10-era `sha2-asm` path is gone. So `cargo clippy --target aarch64-apple-darwin` should need only the `aarch64-apple-darwin` rust-std component, with no C cross-compiler or linker for this subtree, since clippy and check do not link.
- Lints that fire inside sha2, including its own `unexpected_cfgs` configuration, should not fail the project's `-D warnings` build, because Cargo caps lint levels for registry dependencies. This is general Cargo behavior and I did not fetch a citation for it.

### Gaps
- I did not fetch how `cpufeatures` 0.3.1 detects the SHA-2 extension on aarch64-apple-darwin (for example, sysctl versus compile-time `target_feature`).
- The extracted README text gave the runtime-detection rule only for aarch64. I did not explicitly confirm the corresponding x86_64 `x86-sha` detection wording.

## Verdict: does `URL_SAFE_NO_PAD.encode(Sha256::digest(data))` compile against the real sha2 0.11.1, and what must change?

### Takeaway
**Compiles as-is.** Neither the `sha2 = { version = "=0.11.1", default-features = false }` line in Cargo.toml nor `sha256_b64url` in `src/jcs.rs` needs to change. The pinned version exists, is not yanked and is the latest stable release. Its MSRV (1.88) matches the project's, and the call site uses only real, ungated public API. This holds provided the base64 researcher confirms that `base64 =0.23.1`'s `Engine::encode` accepts `T: AsRef<[u8]>`.

### Cited Findings
- Version resolution: 0.11.1 exists, `"yanked": false`, and `"max_stable_version": "0.11.1"`. — [crates.io versions API](https://crates.io/api/v1/crates/sha2/versions); [crates.io crate API](https://crates.io/api/v1/crates/sha2)
- MSRV and edition: `rust-version = "1.88"`, `edition = "2024"`. — [docs.rs: sha2 0.11.1 Cargo.toml source](https://docs.rs/crate/sha2/0.11.1/source/Cargo.toml)
- The import `sha2::Digest` resolves through `pub use digest::{self, Digest};`. — [docs.rs: sha2 0.11.1 src/lib.rs](https://docs.rs/crate/sha2/0.11.1/source/src/lib.rs)
- The import `sha2::Sha256` resolves to `pub struct Sha256 { /* private fields */ }`. — [docs.rs sha2::Sha256 (0.11.1)](https://docs.rs/sha2/0.11.1/sha2/struct.Sha256.html)
- `Sha256: Digest` holds through `impl<D: FixedOutput + Default + Update + HashMarker> Digest for D`, and the four bound impls are not feature-gated. — [docs.rs digest::Digest (0.11.3)](https://docs.rs/digest/0.11.3/digest/trait.Digest.html); [docs.rs sha2::Sha256 (0.11.1)](https://docs.rs/sha2/0.11.1/sha2/struct.Sha256.html)
- The signature is `fn digest(data: impl AsRef<[u8]>) -> Output<Self>;`, with `pub type Output<T> = Array<u8, <T as OutputSizeUser>::OutputSize>;`. — [docs.rs digest::Digest (0.11.3)](https://docs.rs/digest/0.11.3/digest/trait.Digest.html); [docs.rs digest::Output (0.11.3)](https://docs.rs/digest/0.11.3/digest/type.Output.html)
- The output is `AsRef<[u8]>` through `impl<T, U> AsRef<[T]> for Array<T, U> where U: ArraySize`. — [docs.rs: hybrid-array 0.4.15 src/lib.rs](https://docs.rs/crate/hybrid-array/0.4.15/source/src/lib.rs)

### Inferences
- The type chain is: `&[u8]` → `impl AsRef<[u8]>` → `Sha256::digest` returns `Output<Sha256>` = `hybrid_array::Array<u8, U32>`, which implements `AsRef<[u8]>` and satisfies `Engine::encode<T: AsRef<[u8]>>`. That returns `String`, matching the function's return type.
- `use sha2::Digest as _;` puts the trait in scope without binding its name. That is enough for the type-relative call `Sha256::digest(data)`. This is a general Rust name-resolution rule, uncited here. It also does not clash with the module's own `pub fn digest(input: &[u8])` in `jcs.rs`. The type-relative path `Sha256::digest` is resolved through `Sha256`'s impls and the traits in scope, not through module-level names, and the project never imports the `sha2::digest` module re-export.
- Replacement code: **none required.** As a purely optional spelling, `URL_SAFE_NO_PAD.encode(Sha256::digest(data).as_slice())` also compiles, because `pub const fn as_slice(&self) -> &[T]` exists on `Array` ([docs.rs hybrid_array::Array (0.4.15)](https://docs.rs/hybrid-array/0.4.15/hybrid_array/struct.Array.html)). It adds nothing.
- There is no reason to move the pin to 0.10.9: 0.11.1 works, and the project's own lockfile and plan are built around 0.11.1. I did not verify 0.10.9's output type or impls in this research. Any future upgrade to 0.11.2 or later must be re-checked against MSRV 1.88, because patch-level MSRV bumps are allowed.

### Gaps
- Not verified here: the `base64 =0.23.1` `Engine::encode` signature. The base64 researcher covers it, and the verdict depends on it accepting `T: AsRef<[u8]>`.
- Not verified here: whether libc 0.2.191 exists (see Q4).
- I did not compile the code during this research, because cargo is not installed on Windows and the WSL verification loop was not run. The definitive confirmation is the CLAUDE.md §2 loop in WSL2: `cargo clippy --all-targets -- -D warnings` and `cargo clippy --all-targets --target aarch64-apple-darwin -- -D warnings`.
