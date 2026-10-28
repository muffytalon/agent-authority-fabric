# base64 crate: real API vs. pep-sidecar's `=0.23.1` pin and its one call site (as of 2026-10-27)

Scope: `base64` only (sha2 is covered by another researcher). Sources: crates.io, docs.rs, github.com/marshallpierce/rust-base64, plus the two local project files. All web pages were read through a fetch tool that returns model-summarized text. Anything marked as a quote is what the tool returned as verbatim. Source-file line numbers reported by the tool were counted by the tool (docs.rs did not display them), so treat them as approximate.

## 1. Does 0.23.1 exist on crates.io, is it yanked, when was it published, and what is the latest stable version?

### Takeaway
Yes. `base64 0.23.1` exists. It is not yanked and was published 2026-08-04T12:34:31Z by `marshallpierce`. It is also the latest stable version, the newest version of any kind, and the crate's default version as of 2026-10-27. The `=0.23.1` pin resolves, and the project's `# 2026-08-04` comment is accurate. The pinned version and the latest version are the same, so every "pinned vs. latest" answer below is a single answer.

### Cited Findings
- Crate object fields: `"max_version": "0.23.1"`, `"max_stable_version": "0.23.1"`, `"newest_version": "0.23.1"`, `"default_version": "0.23.1"`, `"yanked": false`, `"updated_at": "2026-08-04T12:34:31.976297Z"`, `"repository": "https://github.com/marshallpierce/rust-base64"`, `"documentation": "https://docs.rs/base64"` — [crates.io API /api/v1/crates/base64](https://crates.io/api/v1/crates/base64)
- 0.23.1 record: `"created_at": "2026-08-04T12:34:31.976297Z"`, `"yanked": false`, `"yank_message": null`, `"rust_version": "1.71.0"`, `"edition": "2021"`, `"license": "MIT OR Apache-2.0"`, `"crate_size": 93605`, `"checksum": "ac07cdecf99051d9a5238b80f35af32cdeba5b336e55d957b318b50137e18da5"`, published by `marshallpierce` — [crates.io API](https://crates.io/api/v1/crates/base64)
- 0.23.0 record: `"created_at": "2026-07-23T13:57:30.129591Z"`, `"yanked": false`, `"rust_version": "1.71.0"`, `"edition": "2021"`, `"checksum": "b25655df2c3cdd83c5e5b293b88acd880332b2ddadd7c30ac43144fdc0033da9"` — [crates.io API](https://crates.io/api/v1/crates/base64)
- 0.22.1 record (last release before 0.23): `"created_at": "2024-04-30T23:16:40.343739Z"`, `"yanked": false`, `"rust_version": "1.48.0"`, `"edition": "2018"` — [crates.io API](https://crates.io/api/v1/crates/base64)
- The versions endpoint lists 45 versions. The only 0.23.x versions are 0.23.0 and 0.23.1, and all 45 report `yanked = false` — [crates.io versions API](https://crates.io/api/v1/crates/base64/versions)
- No version newer than 0.23.1 appears, pre-releases such as a 0.24.0-alpha included — [crates.io API](https://crates.io/api/v1/crates/base64)
- Pre-releases, listed separately (all older than stable 0.21.0): `0.21.0-rc.1` (2023-01-01T19:01:39Z), `0.21.0-beta.2` (2022-12-29T15:36:19Z), `0.21.0-beta.1` (2022-12-18T14:11:42Z), `0.20.0-alpha.1` (2021-12-14T01:34:01Z) — [crates.io versions API](https://crates.io/api/v1/crates/base64/versions)
- Stable timeline before 0.23: 0.22.0 (2024-03-02), 0.21.7 (2024-01-11), 0.21.6 (2024-01-08), 0.21.5 (2023-10-23), 0.21.4 (2023-09-10), 0.21.3 (2023-08-26), 0.21.2 (2023-05-25), 0.21.1 (2023-05-22), 0.21.0 (2023-01-08) — [crates.io versions API](https://crates.io/api/v1/crates/base64/versions)
- docs.rs serves rendered API docs for 0.23.1 (page headers read "base64 0.23.1") — [docs.rs Engine trait, 0.23.1](https://docs.rs/base64/0.23.1/base64/engine/trait.Engine.html)

### Inferences
- `=0.23.1` resolves: the version exists and is not yanked. Cargo.lock should record checksum `ac07cdec…e18da5`.
- For base64, the model-generated Cargo.toml line is factually correct: the version is real and the commented date matches crates.io's `created_at`. The "unverified" concern does not apply to this dependency.

### Gaps
- I did not check GitHub tags or releases for a `v0.23.1` tag. crates.io is the authority for Cargo resolution, so this does not affect the verdict.

## 2. What is the crate's `rust-version` (MSRV) for the pinned and latest versions? Is it at most 1.88?

### Takeaway
For 0.23.1 (pinned = latest), `rust-version = "1.71.0"`. That is at most 1.88 and below the 1.97.0 toolchain. 0.23.0 raised the MSRV from 1.48.0 (0.22.x) to 1.71.0.

### Cited Findings
- Published Cargo.toml of 0.23.1: `version = "0.23.1"`, `edition = "2021"`, `rust-version = "1.71.0"` — [docs.rs source: Cargo.toml, 0.23.1](https://docs.rs/crate/base64/0.23.1/source/Cargo.toml)
- crates.io `rust_version`: 0.23.1 = "1.71.0", 0.23.0 = "1.71.0", 0.22.1 = "1.48.0" — [crates.io API](https://crates.io/api/v1/crates/base64)
- MSRV history per crates.io: 0.21.0 = 1.57.0, 0.21.1 = 1.60.0, 0.21.2 = 1.57.0, 0.21.3 through 0.21.7 = 1.48.0, 0.22.0 and 0.22.1 = 1.48.0, 0.23.0 and 0.23.1 = 1.71.0 — [crates.io versions API](https://crates.io/api/v1/crates/base64/versions)
- 0.23.0 release note: "Update MSRV to 1.71.0" — [RELEASE-NOTES.md (master)](https://raw.githubusercontent.com/marshallpierce/rust-base64/master/RELEASE-NOTES.md)
- 0.21.1 release note: "Update MSRV to 1.60.0". Per the fetch tool's paraphrase, 0.21.2 rolled back to 1.57.0 because only dev-dependencies needed 1.60, and 0.21.3 rolled back to 1.48.0 — [RELEASE-NOTES.md (GitHub)](https://github.com/marshallpierce/rust-base64/blob/master/RELEASE-NOTES.md)
- 0.23.1 has no `[dependencies]` section (zero runtime dependencies), so no transitive dependency can raise its MSRV — [docs.rs source: Cargo.toml, 0.23.1](https://docs.rs/crate/base64/0.23.1/source/Cargo.toml)

### Inferences
- 1.71.0 ≤ 1.88 (the project's `rust-version`) ≤ 1.97.0 (the toolchain), so the pin compiles with both. base64 uses edition 2021 and pep-sidecar uses 2024; crates on different editions link together normally.

### Gaps
- None material.

## 3. What features exist? With `default-features = false, features = ["alloc"]`, is `Engine::encode` (returning `String`) available, and which feature gates it?

### Takeaway
0.23.1 has three features: `alloc = []`, `std = ["alloc"]` and the new `simd-unsafe = []`, with `default = ["std", "simd-unsafe"]`. `Engine::encode` is gated by `#[cfg(any(feature = "alloc", test))]`, as are `encode_string`, `decode` and `decode_vec`. With `default-features = false, features = ["alloc"]`, `encode -> String` is available. Turning off the defaults also drops `simd-unsafe`, so base64 compiles as `no_std` + `alloc` under `#![forbid(unsafe_code)]`.

### Cited Findings
- Verbatim `[features]` from the published Cargo.toml:
  ```toml
  [features]
  alloc = []
  default = [
      "std",
      "simd-unsafe",
  ]
  simd-unsafe = []
  std = ["alloc"]
  ```
  — [docs.rs source: Cargo.toml, 0.23.1](https://docs.rs/crate/base64/0.23.1/source/Cargo.toml)
- crates.io features: 0.23.1 and 0.23.0 = `{"alloc":[],"default":["std","simd-unsafe"],"simd-unsafe":[],"std":["alloc"]}`; 0.22.1 = `{"alloc":[],"default":["std"],"std":["alloc"]}` — [crates.io API](https://crates.io/api/v1/crates/base64)
- docs.rs features page: "This version has **3** feature flags, **3** of them enabled by **default**." It lists `simd-unsafe` (default), `std` (default; enables `alloc`) and `alloc` (default, via `std`) — [docs.rs features, 0.23.1](https://docs.rs/crate/base64/0.23.1/features)
- Gate on `encode` in `src/engine/mod.rs` (about line 146 by the tool's count):
  ```rust
  #[cfg(any(feature = "alloc", test))]
  #[inline]
  fn encode<T: AsRef<[u8]>>(&self, input: T) -> String {
  ```
  The same `#[cfg(any(feature = "alloc", test))]` sits on `encode_string`, `decode` and `decode_vec`. The imports `use alloc::vec::Vec;` and `use alloc::{string::String, vec};` carry the same cfg — [docs.rs source: src/engine/mod.rs, 0.23.1](https://docs.rs/crate/base64/0.23.1/source/src/engine/mod.rs)
- Crate root: `#[cfg(any(feature = "alloc", test))] extern crate alloc;` and `#![cfg_attr(not(any(feature = "std", test)), no_std)]` — [docs.rs source: src/lib.rs, 0.23.1](https://docs.rs/crate/base64/0.23.1/source/src/lib.rs)
- Crate docs on features: "`alloc`: enables the allocating APIs (e.g. [`Engine::encode`], [`Engine::decode`]) in a" / "`no_std` build." and "`std` (default): enables `std::io` integration, [`std::error::Error`] impls, and heap" / "allocation. Implies `alloc`." — [docs.rs source: src/lib.rs, 0.23.1](https://docs.rs/crate/base64/0.23.1/source/src/lib.rs)
- Unsafe-code attributes in lib.rs:
  ```rust
  #![cfg_attr(not(feature = "simd-unsafe"), forbid(unsafe_code))]
  #![cfg_attr(feature = "simd-unsafe", deny(unsafe_code))]
  ```
  Crate docs: "`simd-unsafe`: enables the SIMD-accelerated engines. It is on by default and is the only" / "feature that introduces `unsafe` code; with it disabled the crate is" / "`#![forbid(unsafe_code)]`." — [docs.rs source: src/lib.rs, 0.23.1](https://docs.rs/crate/base64/0.23.1/source/src/lib.rs)
- SIMD gating in `src/engine/mod.rs`:
  - `pub mod simd;` requires `#[cfg(all(feature = "simd-unsafe", any(target_arch = "x86_64", all(target_arch = "aarch64", target_feature = "neon"))))]`.
  - `pub use simd::Simd;` also requires `feature = "std"`.
  - `pub use simd::Avx2;` requires `#[cfg(all(feature = "simd-unsafe", target_arch = "x86_64"))]`.
  - `pub use simd::Neon;` requires `simd-unsafe` + `aarch64` + `neon`.

  — [docs.rs source: src/engine/mod.rs, 0.23.1](https://docs.rs/crate/base64/0.23.1/source/src/engine/mod.rs)
- docs.rs `Engine` implementors: `Avx2` (x86-64 only), `GeneralPurpose` (no restriction), `Simd` ("crate feature `std` and (AArch64 or x86-64)") — [docs.rs Engine trait, 0.23.1](https://docs.rs/base64/0.23.1/base64/engine/trait.Engine.html)
- The rendered `Engine` page shows no "Available on crate feature alloc only" badges — [docs.rs Engine trait, 0.23.1](https://docs.rs/base64/0.23.1/base64/engine/trait.Engine.html)

### Inferences
- Under the project's settings, `alloc` is on and both `std` and `simd-unsafe` are off. base64 builds as `no_std` + `alloc` with `#![forbid(unsafe_code)]`. `Engine::encode` exists, the `Simd`, `Avx2` and `Neon` engines don't, and the scalar `GeneralPurpose` engine is available on both x86_64-unknown-linux-gnu and aarch64-apple-darwin. This fits pep-sidecar's zero-unsafe stance; the project's own `unsafe_code = "forbid"` covers only its own crate.
- docs.rs builds with default features and shows no feature badges, so the rendered docs can't reveal the `alloc` gate. The source view is authoritative.
- Cargo feature unification: if another crate in the dependency graph pulled in base64 with default features, `std` and `simd-unsafe` would be enabled for the whole build. pep-sidecar's Cargo.toml has no other base64 consumer and no `[dev-dependencies]` ([Cargo.toml (local)](file:///C:/Users/mitam/OneDrive/Documents/Cryptographic%20Biscuits/agent-authority-fabric/Cargo.toml)), but I did not inspect the transitive graph (`cargo tree -e features -i base64` would). Even in that case the call site still compiles; only the "no unsafe in base64" property would change.

### Gaps
- The docs.rs features page doesn't state the build status. I inferred a successful 0.23.1 docs build from the rendered 0.23.1 API pages.
- The transitive dependency graph (feature unification) was not checked.

## 4. What are the exact path and type of `base64::engine::general_purpose::URL_SAFE_NO_PAD` in the pinned and latest versions? Is there a `base64::prelude` equivalent?

### Takeaway
In 0.23.1 (= latest), `base64::engine::general_purpose::URL_SAFE_NO_PAD` is `pub const URL_SAFE_NO_PAD: GeneralPurpose`, defined as `GeneralPurpose::new(&alphabet::URL_SAFE, NO_PAD)`. Neither the constant nor its module has a cfg or feature gate. The prelude re-exports it as `base64::prelude::BASE64_URL_SAFE_NO_PAD` and also re-exports `Engine`.

### Cited Findings
- Rendered declaration:
  ```rust
  pub const URL_SAFE_NO_PAD: GeneralPurpose;
  ```
  Doc text: "A GeneralPurpose engine using the alphabet::URL_SAFE base64 alphabet and NO_PAD config." / "Does not allow trailing bits when decoding." No feature requirement is shown — [docs.rs constant URL_SAFE_NO_PAD, 0.23.1](https://docs.rs/base64/0.23.1/base64/engine/general_purpose/constant.URL_SAFE_NO_PAD.html)
- Source declaration, with no `#[cfg]` on it or on `GeneralPurpose`, `GeneralPurpose::new` or the `Engine` impl:
  ```rust
  /// A [`GeneralPurpose`] engine using the [`alphabet::URL_SAFE`] base64 alphabet and [`NO_PAD`] config.
  ///
  /// Does not allow trailing bits when decoding.
  pub const URL_SAFE_NO_PAD: GeneralPurpose = GeneralPurpose::new(&alphabet::URL_SAFE, NO_PAD);
  ```
  — [docs.rs source: src/engine/general_purpose/mod.rs, 0.23.1](https://docs.rs/crate/base64/0.23.1/source/src/engine/general_purpose/mod.rs)
- Sibling constants (source): `pub const URL_SAFE: GeneralPurpose = GeneralPurpose::new(&alphabet::URL_SAFE, PAD);`, `pub const STANDARD: GeneralPurpose = GeneralPurpose::new(&alphabet::STANDARD, PAD);`, `pub const STANDARD_NO_PAD: GeneralPurpose = GeneralPurpose::new(&alphabet::STANDARD, NO_PAD);`, `pub const PAD: GeneralPurposeConfig = GeneralPurposeConfig::new();` — [docs.rs source: src/engine/general_purpose/mod.rs, 0.23.1](https://docs.rs/crate/base64/0.23.1/source/src/engine/general_purpose/mod.rs)
- Module paths: lib.rs declares `pub mod engine;` and `pub use engine::Engine;` (no cfg) — [docs.rs source: src/lib.rs, 0.23.1](https://docs.rs/crate/base64/0.23.1/source/src/lib.rs). engine/mod.rs declares `pub mod general_purpose;` (no cfg) and `pub use general_purpose::{GeneralPurpose, GeneralPurposeConfig, Scalar};` — [docs.rs source: src/engine/mod.rs, 0.23.1](https://docs.rs/crate/base64/0.23.1/source/src/engine/mod.rs)
- Contents of the `general_purpose` module page:
  - Structs: `GeneralPurpose`, `GeneralPurposeConfig`.
  - Constants: `NO_PAD`, `NO_PAD_INDIFFERENT`, `PAD`, `PAD_INDIFFERENT`, `STANDARD`, `STANDARD_NO_PAD`, `STANDARD_NO_PAD_INDIFFERENT`, `STANDARD_PAD_INDIFFERENT`, `URL_SAFE`, `URL_SAFE_NO_PAD`, `URL_SAFE_NO_PAD_INDIFFERENT`, `URL_SAFE_PAD_INDIFFERENT`.
  - Type alias: `Scalar`.
  - No functions.

  — [docs.rs engine::general_purpose, 0.23.1](https://docs.rs/base64/0.23.1/base64/engine/general_purpose/index.html)
- `Scalar` (new in 0.23): `pub type Scalar = GeneralPurpose;`, documented as "A purely scalar base64 engine that never uses hardware-specific vector instructions." — [docs.rs source: src/engine/general_purpose/mod.rs, 0.23.1](https://docs.rs/crate/base64/0.23.1/source/src/engine/general_purpose/mod.rs)
- The `GeneralPurpose` struct as rendered:
  ```rust
  pub struct GeneralPurpose { /* private fields */ }
  ```
  Its only inherent method is:
  ```rust
  pub const fn new(alphabet: &Alphabet, config: GeneralPurposeConfig) -> Self
  ```
  It implements the traits Clone, Debug and Engine, and the auto traits include Send and Sync — [docs.rs struct GeneralPurpose, 0.23.1](https://docs.rs/base64/0.23.1/base64/engine/general_purpose/struct.GeneralPurpose.html)
- The `Engine` impl in source:
  ```rust
  impl super::Engine for GeneralPurpose {
      type Config = GeneralPurposeConfig;
      type DecodeEstimate = GeneralPurposeEstimate;
  ```
  — [docs.rs source: src/engine/general_purpose/mod.rs, 0.23.1](https://docs.rs/crate/base64/0.23.1/source/src/engine/general_purpose/mod.rs)
- Prelude re-exports as rendered:
  ```rust
  pub use crate::engine::Engine;
  pub use crate::engine::general_purpose::STANDARD as BASE64_STANDARD;
  pub use crate::engine::general_purpose::STANDARD_NO_PAD as BASE64_STANDARD_NO_PAD;
  pub use crate::engine::general_purpose::URL_SAFE as BASE64_URL_SAFE;
  pub use crate::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_SAFE_NO_PAD;
  ```
  The prelude example is `use base64::prelude::{Engine as _, BASE64_STANDARD_NO_PAD};` — [docs.rs prelude, 0.23.1](https://docs.rs/base64/0.23.1/base64/prelude/index.html)
- These constants date from 0.21.0-beta.1: "Predefined engine consts `engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD}`" — [RELEASE-NOTES.md (GitHub)](https://github.com/marshallpierce/rust-base64/blob/master/RELEASE-NOTES.md)

### Inferences
- `GeneralPurpose` has no inherent `encode`, so `URL_SAFE_NO_PAD.encode(..)` can only resolve to `Engine::encode`. No inherent method shadows the trait method.
- The `*_INDIFFERENT` constants are probably what the 0.23.0 note "Added more consts for preconfigured configs and engines" refers to. I did not diff this against the 0.22.1 docs.

### Gaps
- I did not fetch the 0.22.1 `general_purpose` docs to diff the constant lists.

## 5. What is the exact signature of `Engine::encode`, including its generic bound? Must `Engine` be in scope?

### Takeaway
`fn encode<T: AsRef<[u8]>>(&self, input: T) -> String` is a provided method of `pub trait Engine: Send + Sync`, which is re-exported as `base64::Engine`. The input bound is exactly `T: AsRef<[u8]>`, and the input is taken by value. `GeneralPurpose` has no inherent `encode`, so `Engine` must be in scope to call it; the crate's own examples import it as `Engine as _`.

### Cited Findings
- docs.rs signatures (0.23.1):
  ```rust
  pub trait Engine: Send + Sync {
  ```
  ```rust
  fn encode<T: AsRef<[u8]>>(&self, input: T) -> String { ... }
  ```
  ```rust
  fn encode_string<T: AsRef<[u8]>>(&self, input: T, output_buf: &mut String) { ... }
  ```
  ```rust
  fn encode_slice<T: AsRef<[u8]>>(
      &self,
      input: T,
      output_buf: &mut [u8],
  ) -> Result<usize, EncodeSliceError> { ... }
  ```
  The required associated types are `type Config: Config;` and `type DecodeEstimate: DecodeEstimate;`, and the page says the trait is not dyn compatible — [docs.rs Engine trait, 0.23.1](https://docs.rs/base64/0.23.1/base64/engine/trait.Engine.html)
- The doc comment on `encode` reads "Encode arbitrary octets as base64 using the provided `Engine`. Returns a `String`." Its example:
  ```rust
  use base64::{Engine as _, engine::{self, general_purpose}, alphabet};

  let b64 = general_purpose::STANDARD.encode(b"hello world~");
  ```
  — [docs.rs Engine trait, 0.23.1](https://docs.rs/base64/0.23.1/base64/engine/trait.Engine.html)
- The full source of `encode`:
  ```rust
  #[cfg(any(feature = "alloc", test))]
  #[inline]
  fn encode<T: AsRef<[u8]>>(&self, input: T) -> String {
      fn inner<E>(engine: &E, input_bytes: &[u8]) -> String
      where
          E: Engine + ?Sized,
      {
          let encoded_size = encoded_len(input_bytes.len(), engine.config().encode_padding())
              .expect("integer overflow when calculating buffer size");

          let mut buf = vec![0; encoded_size];

          encode_with_padding(input_bytes, &mut buf[..], engine, encoded_size);

          String::from_utf8(buf).expect("Invalid UTF8")
      }

      inner(self, input.as_ref())
  }
  ```
  — [docs.rs source: src/engine/mod.rs, 0.23.1](https://docs.rs/crate/base64/0.23.1/source/src/engine/mod.rs)
- The crate root has `pub use engine::Engine;` with no cfg — [docs.rs source: src/lib.rs, 0.23.1](https://docs.rs/crate/base64/0.23.1/source/src/lib.rs)
- On `GeneralPurpose`, `encode`, `encode_string` and `encode_slice` appear only under the `Engine` trait impl; the only inherent method is `new` — [docs.rs struct GeneralPurpose, 0.23.1](https://docs.rs/base64/0.23.1/base64/engine/general_purpose/struct.GeneralPurpose.html)
- The deprecated free functions still exist: `#[allow(deprecated)]` + `#[cfg(any(feature = "alloc", test))]` + `pub use crate::encode::{encode, encode_engine, encode_engine_string};` — [docs.rs source: src/lib.rs, 0.23.1](https://docs.rs/crate/base64/0.23.1/source/src/lib.rs)

### Inferences
- `use base64::Engine as _;` imports the trait anonymously, so it cannot clash with pep-sidecar's own `pub trait Engine` (local `src/engine.rs`, line 1144).
- The two `.expect(..)` calls inside `encode` live in base64, not in project code, so the project's `expect_used = "deny"` does not apply to them. A 32-byte SHA-256 digest always encodes to 43 characters without padding (40 for 30 bytes, plus 3 for the last 2 bytes), so the overflow branch is unreachable at this call site.
- The call site does not use the deprecated free `base64::encode`, so no deprecation warning arises under `-D warnings`.

### Gaps
- None.

## 6. Which breaking changes between 0.21, 0.22 and 0.23.x affect `Engine::encode`, `general_purpose::URL_SAFE_NO_PAD`, feature names or MSRV?

### Takeaway
No change from 0.21.0 through 0.23.1 alters `Engine::encode`'s signature, the `general_purpose::URL_SAFE_NO_PAD` path, or the `alloc`/`std` feature names. 0.22.0 changed only decoding. 0.23.0 made additive changes (a new default-on `simd-unsafe` feature, more constants, custom padding symbols), changed one `DecodeError` variant, and raised the MSRV to 1.71.0. 0.23.1 is a test-build fix.

### Cited Findings
- 0.23.1: "Make the tests build again on non-SIMD architectures" — [RELEASE-NOTES.md (master)](https://raw.githubusercontent.com/marshallpierce/rust-base64/master/RELEASE-NOTES.md)
- 0.23.0 bullets, verbatim (the SIMD bullet came back in fragments and is rejoined here):
  - "Added more consts for preconfigured configs and engines"
  - "Make DecodeError::InvalidLastSymbol more clear by including the decoded value"
  - "Added SIMD-accelerated engines behind the default-on `simd-unsafe` feature: `Simd` picks the best instruction set at runtime (AVX2 on `x86_64`, NEON on `aarch64`) and falls back to the scalar `GeneralPurpose` engine, while `Avx2` and `Neon` target one instruction set with no runtime detection and work in `no_std`. The engines support the standard and URL-safe alphabets."
  - "Update MSRV to 1.71.0"
  - "Add support for custom padding symbols"

  — [RELEASE-NOTES.md (master)](https://raw.githubusercontent.com/marshallpierce/rust-base64/master/RELEASE-NOTES.md)
- 0.22.1: "Correct the symbols used for the predefined `alphabet::BIN_HEX`." — [RELEASE-NOTES.md (master)](https://raw.githubusercontent.com/marshallpierce/rust-base64/master/RELEASE-NOTES.md)
- 0.22.0, verbatim:
  - "`DecodeSliceError::OutputSliceTooSmall` is now conservative rather than precise. That is, the error will only occur if the decoded output _cannot_ fit, meaning that `Engine::decode_slice` can now be used with exactly-sized output slices. As part of this, `Engine::internal_decode` now returns `DecodeSliceError` instead of `DecodeError`, but that is not expected to affect any external callers."
  - "`DecodeError::InvalidLength` now refers specifically to the _number of valid symbols_ being invalid (i.e. `len % 4 == 1`), rather than just the number of input bytes. This avoids confusing scenarios when based on interpretation you could make a case for either `InvalidLength` or `InvalidByte` being appropriate."
  - "Decoding is somewhat faster (5-10%)"

  — [RELEASE-NOTES.md (master)](https://raw.githubusercontent.com/marshallpierce/rust-base64/master/RELEASE-NOTES.md)
- According to the fetch tool, no bullet in 0.22.0 through 0.23.1 mentions `Engine::encode`, `encode_string`, `encode_slice`, `URL_SAFE_NO_PAD`, `general_purpose`, `alloc`, `std`, `unsafe` or `forbid` — [RELEASE-NOTES.md (master)](https://raw.githubusercontent.com/marshallpierce/rust-base64/master/RELEASE-NOTES.md)
- 0.21.x background (the tool paraphrased this except for the quoted parts):
  - 0.21.0-beta.1: "`encode*` and `decode*` top level functions are now methods on `Engine`."
  - The 0.21.0 migration table maps `encode_config()` to `engine.encode()`, `encode_config_buf()` to `engine.encode_string()`, and `encode_config_slice()` to `engine.encode_slice()`.
  - "`DEFAULT_ENGINE` was replaced by `engine::general_purpose::STANDARD`", and `FastPortable` was renamed to `GeneralPurpose`.
  - 0.21.0-beta.2 moved the preconfigured-engine re-exports to `base64::prelude`, and 0.21.0-rc.1 added `Engine` to the prelude.
  - 0.21.1: "Update MSRV to 1.60.0", later rolled back (see section 2).

  — [RELEASE-NOTES.md (GitHub)](https://github.com/marshallpierce/rust-base64/blob/master/RELEASE-NOTES.md)
- Feature-set change: 0.22.1 `{"alloc":[],"default":["std"],"std":["alloc"]}` became `{"alloc":[],"default":["std","simd-unsafe"],"simd-unsafe":[],"std":["alloc"]}` in 0.23.x — [crates.io API](https://crates.io/api/v1/crates/base64)

### Inferences
- Code written for the 0.21/0.22 Engine API (`Engine as _` plus `general_purpose::URL_SAFE_NO_PAD.encode(..)`) works unchanged on 0.23.1.
- For consumers on default features, the notable 0.23 change is that `simd-unsafe` now brings `unsafe` code into the build by default. pep-sidecar's `default-features = false` opts out of it.
- The `DecodeError::InvalidLastSymbol` change matters only to code that matches on that variant's fields. pep-sidecar only encodes.

### Gaps
- The 0.21.x entries were partly paraphrased by the fetch tool, and the full 0.21.0 migration guide was not captured verbatim. It is not needed for the verdict.
- Release notes were read from the `master` branch, not a tag snapshot. I did not read the GitHub Releases page or a `v0.22.1...v0.23.1` compare view.

## 7. Does URL_SAFE_NO_PAD use the RFC 4648 §5 URL-safe alphabet (`-` and `_`) with no `=` padding?

### Takeaway
Yes. `URL_SAFE_NO_PAD` combines `alphabet::URL_SAFE` ("with `-` and `_`", RFC 4648 §5) with the `NO_PAD` config, which emits no padding when encoding and rejects padding when decoding.

### Cited Findings
- The constant is rendered as `pub const URL_SAFE: Alphabet;`, documented as "The URL-safe alphabet (with `-` and `_`) specified in [RFC 4648](https://datatracker.ietf.org/doc/html/rfc4648#section-5)." — [docs.rs alphabet::URL_SAFE, 0.23.1](https://docs.rs/base64/0.23.1/base64/alphabet/constant.URL_SAFE.html)
- `NO_PAD` in source:
  ```rust
  pub const NO_PAD: GeneralPurposeConfig = GeneralPurposeConfig::new()
      .with_encode_padding(false)
      .with_decode_padding_mode(DecodePaddingMode::RequireNone);
  ```
  — [docs.rs source: src/engine/general_purpose/mod.rs, 0.23.1](https://docs.rs/crate/base64/0.23.1/source/src/engine/general_purpose/mod.rs). The module page describes `NO_PAD` as "Don't add padding when encoding, and require that there is no padding when decoding." — [docs.rs engine::general_purpose, 0.23.1](https://docs.rs/base64/0.23.1/base64/engine/general_purpose/index.html)
- `URL_SAFE_NO_PAD = GeneralPurpose::new(&alphabet::URL_SAFE, NO_PAD)` — [docs.rs source: src/engine/general_purpose/mod.rs, 0.23.1](https://docs.rs/crate/base64/0.23.1/source/src/engine/general_purpose/mod.rs)
- 0.23.0 added "Add support for custom padding symbols" — [RELEASE-NOTES.md (master)](https://raw.githubusercontent.com/marshallpierce/rust-base64/master/RELEASE-NOTES.md)

### Inferences
- `sha256_b64url` returns 43 characters drawn from `A–Z a–z 0–9 - _`, with no `=`. That matches the unpadded base64url the project's F-07 idempotency key (`"pep-" + b64url(SHA-256(...))`) and `jcs::digest` (`"sha-256:" + base64url_no_pad(...)`) expect. Custom padding symbols are irrelevant because `NO_PAD` writes no padding.

### Gaps
- The exact 64-character alphabet string was not shown on the docs.rs page; it is at `alphabet.rs.html#259-262`, which I did not fetch. The RFC 4648 §5 reference and the "with `-` and `_`" statement are sufficient.

## 8. Verdict: does the `src/jcs.rs` call site compile against the real `base64 =0.23.1`?

### Takeaway
**Compiles as-is. No change is needed** in Cargo.toml or `src/jcs.rs` for base64. The `=0.23.1` pin exists, is not yanked, and is the latest stable release. Its MSRV is 1.71.0. The crate-root `Engine` re-export, the `engine::general_purpose::URL_SAFE_NO_PAD` constant and `Engine::encode -> String` are all present under `default-features = false, features = ["alloc"]` on both targets. One external condition remains: the argument `Sha256::digest(data)` must implement `AsRef<[u8]>`. hybrid-array's `Array<T, U>` lists an `AsRef<[T]>` impl, so the condition holds if the sha2 researcher confirms that sha2 0.11.1's output is `hybrid_array::Array<u8, U32>`.

### Cited Findings
- Project pin (Cargo.toml line 16): `base64 = { version = "=0.23.1", default-features = false, features = ["alloc"] } # 2026-08-04`, under the line 14 comment "# Versions verified on crates.io 2026-10-24." — [Cargo.toml (local)](file:///C:/Users/mitam/OneDrive/Documents/Cryptographic%20Biscuits/agent-authority-fabric/Cargo.toml)
- Call site (`src/jcs.rs` lines 8–9 and 601–603): `use base64::Engine as _;`, `use base64::engine::general_purpose::URL_SAFE_NO_PAD;` and `pub fn sha256_b64url(data: &[u8]) -> String { URL_SAFE_NO_PAD.encode(Sha256::digest(data)) }` (with `#[must_use]`) — [src/jcs.rs (local)](file:///C:/Users/mitam/OneDrive/Documents/Cryptographic%20Biscuits/agent-authority-fabric/src/jcs.rs)
- Check 1, resolution: 0.23.1 exists, `"yanked": false`, and is `max_stable_version` — [crates.io API](https://crates.io/api/v1/crates/base64)
- Check 2, `use base64::Engine as _;`: lib.rs has `pub use engine::Engine;` with no cfg — [docs.rs source: src/lib.rs, 0.23.1](https://docs.rs/crate/base64/0.23.1/source/src/lib.rs)
- Check 3, `use base64::engine::general_purpose::URL_SAFE_NO_PAD;`: `pub mod engine;` (lib.rs), `pub mod general_purpose;` (engine/mod.rs) and `pub const URL_SAFE_NO_PAD: GeneralPurpose = GeneralPurpose::new(&alphabet::URL_SAFE, NO_PAD);`, none of them gated — [lib.rs](https://docs.rs/crate/base64/0.23.1/source/src/lib.rs), [engine/mod.rs](https://docs.rs/crate/base64/0.23.1/source/src/engine/mod.rs), [general_purpose/mod.rs](https://docs.rs/crate/base64/0.23.1/source/src/engine/general_purpose/mod.rs)
- Check 4, `.encode(..) -> String`: `#[cfg(any(feature = "alloc", test))] fn encode<T: AsRef<[u8]>>(&self, input: T) -> String`, which the project's `features = ["alloc"]` satisfies — [docs.rs source: src/engine/mod.rs, 0.23.1](https://docs.rs/crate/base64/0.23.1/source/src/engine/mod.rs); [docs.rs Engine trait, 0.23.1](https://docs.rs/base64/0.23.1/base64/engine/trait.Engine.html)
- Check 5, no shadowing: `GeneralPurpose`'s only inherent method is `new` — [docs.rs struct GeneralPurpose, 0.23.1](https://docs.rs/base64/0.23.1/base64/engine/general_purpose/struct.GeneralPurpose.html)
- Check 6, the argument type (sha2 side, given for completeness): hybrid-array 0.4.15 declares `#[repr(transparent)]pub struct Array<T, U: ArraySize>(pub U::ArrayType<T>);`, and its trait-implementation list includes "AsRef<[T]>", "Borrow<[T]>" and "Deref". The impl's where clause was not visible — [docs.rs hybrid-array Array (latest = 0.4.15)](https://docs.rs/hybrid-array/latest/hybrid_array/struct.Array.html)
- Check 7, targets: `GeneralPurpose` has no platform restriction. The SIMD modules exist only with `simd-unsafe` on x86_64 or aarch64+neon, which the project's feature set disables — [docs.rs Engine trait, 0.23.1](https://docs.rs/base64/0.23.1/base64/engine/trait.Engine.html); [docs.rs source: src/engine/mod.rs, 0.23.1](https://docs.rs/crate/base64/0.23.1/source/src/engine/mod.rs)
- Check 8, MSRV: `rust-version = "1.71.0"` ≤ 1.88 — [docs.rs source: Cargo.toml, 0.23.1](https://docs.rs/crate/base64/0.23.1/source/Cargo.toml)

### Inferences
- The code was written against the real base64 API, not a stand-in. Every imported path and the method signature match 0.23.1 exactly.
- `Sha256::digest(data)` is passed by value as `T`. With `T = Array<u8, U32>` and `Array<T, U>: AsRef<[T]>`, the bound `T: AsRef<[u8]>` is met. Because the call passes the value without borrowing, Clippy's needless-borrow lint for generic arguments has nothing to flag.
- An equivalent spelling, not required, is `use base64::prelude::{Engine as _, BASE64_URL_SAFE_NO_PAD};` followed by `BASE64_URL_SAFE_NO_PAD.encode(...)`.
- Contingency, only if the sha2 researcher finds that the digest output type does not implement `AsRef<[u8]>`: any `&[u8]` view satisfies the bound, e.g. `let digest = Sha256::digest(data); URL_SAFE_NO_PAD.encode(&*digest)`, relying on `Deref` to `[u8]`. This was not compiled here and is not expected to be needed.

### Gaps
- Nothing was compiled during this research. The project's mandatory verification loop (fmt, clippy, tests, and the `aarch64-apple-darwin` clippy run in WSL) is still the final confirmation.
- The where clause on hybrid-array's `AsRef<[T]>` impl was not visible. I fetched hybrid-array's latest docs (0.4.15) without confirming which hybrid-array version sha2 0.11.1 → digest 0.11 actually resolves to; that belongs to the sha2 researcher.
- I did not confirm from the allowed sources that Cargo caps lints in registry dependencies (so `RUSTFLAGS='-D warnings'` cannot fail the build on lints inside base64). It is general Cargo behavior and does not change the verdict.
