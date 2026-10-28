# Six real crates leave nothing to migrate

**This codebase contains no stand-ins, and no call site breaks against the real crates.** All six dependencies are imported by their real paths. Each exact pin is a real, unyanked crates.io release that is also the newest stable version as of 2026-10-27: base64 0.23.1, ryu-js 1.0.3, sha2 0.11.1, thiserror 2.0.21, unicode-normalization 0.1.26 and nix 0.31.3. Every import, method call, trait bound and return type in `src/jcs.rs`, `src/engine.rs` and `src/peercred.rs` matches docs.rs and the published source. So the production `Cargo.toml` is the one already on disk, features included, and no crate API needs an adapter, a deleted module or a refactored function. The lockfile alone rules out the stand-in theory. Its SHA-256 checksums for base64, the sha2 subtree, ryu-js, thiserror and unicode-normalization match the registry's byte for byte, and only a real resolution against crates.io produces that. A WSL build (offline, locked, `-D warnings`) passed two clippy gates and the targeted ryu-js tests. Clippy lints the whole package, so by inference that build also type-checked the other five crates' call sites on Linux and macOS. **On 2026-10-28 the full five-command verification loop in CLAUDE.md §2 passed in every configuration with zero warnings** (Section 5). The only defect found lay outside the crate APIs: SPEC.md line 15 recorded Unicode 16.0, but the pinned crate implements **Unicode 18.0.0**. That line is now corrected, and two new tests pin the NFC tables and the hand-written default-ignorable list to Unicode 18.0.0. Planned work adds exactly one nix feature, `fs`, for `Flock`.

## 1. Production `Cargo.toml` Specification

### Today's lines 14–23 are already the production block

Every version string, feature list and date comment in the manifest checks out against crates.io. The production `[dependencies]` block and the target-specific nix block are therefore lines 14–23 of `Cargo.toml` exactly as they stand ([Cargo.toml](file:///C:/Users/mitam/OneDrive/Documents/Cryptographic%20Biscuits/agent-authority-fabric/Cargo.toml)). The target `cfg` matches `src/lib.rs`, which compiles `peercred` only on Linux and macOS ([lib.rs](file:///C:/Users/mitam/OneDrive/Documents/Cryptographic%20Biscuits/agent-authority-fabric/src/lib.rs)).

```toml
# Versions verified on crates.io 2026-10-24.
[dependencies]
base64 = { version = "=0.23.1", default-features = false, features = ["alloc"] } # 2026-08-04
ryu-js = { version = "=1.0.3", default-features = false }                        # 2026-07-10
sha2 = { version = "=0.11.1", default-features = false }                         # 2026-10-12, MSRV 1.88
thiserror = "=2.0.21"                                                            # 2026-09-23
unicode-normalization = "=0.1.26"                                                # 2026-10-16

[target.'cfg(any(target_os = "linux", target_os = "macos"))'.dependencies]
nix = { version = "=0.31.3", default-features = false, features = ["socket", "user"] } # 2026-05-11
```

Every pinned version is also the latest stable release, and every date comment matches the crates.io `created_at` date (UTC). The only edits worth considering are to comments: the header could carry 2026-10-27, the date of this re-verification, and line 20 could note Unicode 18.0.0 (Section 4).

| Crate | Pin = latest stable | Published (UTC) | `rust-version`, edition | Licence | Features the code needs |
|---|---|---|---|---|---|
| base64 | [`=0.23.1`](https://crates.io/api/v1/crates/base64) | 2026-08-04 | 1.71.0, 2021 | MIT OR Apache-2.0 | `alloc`, defaults off |
| ryu-js | [`=1.0.3`](https://crates.io/api/v1/crates/ryu-js/versions) | 2026-07-10 | 1.71, 2021 | Apache-2.0 OR BSL-1.0 | none (the crate has no default features) |
| sha2 | [`=0.11.1`](https://crates.io/api/v1/crates/sha2/versions) | 2026-10-12 | 1.88, 2024 | not captured in the notes | none, defaults off |
| thiserror | [`=2.0.21`](https://crates.io/api/v1/crates/thiserror/versions) | 2026-09-23 | 1.77, 2021 | MIT OR Apache-2.0 | default `std` |
| unicode-normalization | [`=0.1.26`](https://crates.io/api/v1/crates/unicode-normalization/versions?per_page=100) | 2026-10-16 | 1.36, 2018 | (MIT OR Apache-2.0) AND Unicode-3.0 | default `std` |
| nix (Linux and macOS only) | [`=0.31.3`](https://crates.io/api/v1/crates/nix/0.31.3) | 2026-05-11 | 1.69, 2021 | MIT | `socket` and `user`, defaults off |

**Two crates need a feature turned on, and both features are load-bearing.** base64 compiles `Engine::encode`, `encode_string`, `decode` and `decode_vec` only under `#[cfg(any(feature = "alloc", test))]`, so without `alloc` the call in `sha256_b64url` would not exist ([engine/mod.rs source](https://docs.rs/crate/base64/0.23.1/source/src/engine/mod.rs)). Turning base64's defaults off also removes the default-on `simd-unsafe` feature added in 0.23.0, which is the only feature that brings `unsafe` into the crate. So base64 builds as `no_std` + `alloc` under `#![forbid(unsafe_code)]` ([lib.rs source](https://docs.rs/crate/base64/0.23.1/source/src/lib.rs)). Feature unification could re-enable `simd-unsafe` only if another crate asked for base64's defaults, and Cargo.lock lists pep-sidecar as base64's only dependent ([Cargo.lock](file:///C:/Users/mitam/OneDrive/Documents/Cryptographic%20Biscuits/agent-authority-fabric/Cargo.lock)). nix needs both of its features. `getsockopt` and every sockopt require `socket`. `geteuid`, `Uid` and `Gid` require `user`. And macOS `getpeereid` sits inside `feature! { #![all(feature = "socket", feature = "user")] }` under `#[cfg(bsd)]` ([unistd.rs @ v0.31.3](https://raw.githubusercontent.com/nix-rust/nix/v0.31.3/src/unistd.rs)). nix's `default` feature list is empty, so its `default-features = false` is redundant but harmless ([crates.io](https://crates.io/api/v1/crates/nix/0.31.3)).

The other four crates need nothing beyond what is written. sha2 0.11.1 has exactly three features, `alloc`, `oid` and `zeroize`, with `default = ["alloc", "oid"]`. Neither `Digest` nor `Sha256::digest` is feature-gated, so `default-features = false` costs the call site nothing ([crates.io](https://crates.io/api/v1/crates/sha2/versions)). The 0.10-era `asm`, `asm-aarch64`, `force-soft`, `std` and related features no longer exist. On aarch64, sha2 picks its `aarch64-sha2` backend when runtime detection finds the CPU features and falls back to `soft` otherwise. Overrides exist only as `--cfg` flags, so neither target needs configuration ([sha2 CHANGELOG](https://raw.githubusercontent.com/RustCrypto/hashes/master/sha2/CHANGELOG.md); [README](https://docs.rs/crate/sha2/0.11.1/source/README.md)). ryu-js has only `small` and the implicit `no-panic` feature, and neither is on by default, so its `default-features = false` is a no-op ([docs.rs features](https://docs.rs/crate/ryu-js/1.0.3/features)). A locked `cargo tree -i ryu-js -e features` run in WSL confirmed that no ryu-js feature is enabled ([ryu-js notes](file:///C:/Users/mitam/OneDrive/Documents/Cryptographic%20Biscuits/agent-authority-fabric/research_notes/Pep%20sidecar%20crate%20API%20verification/ryu_js.md)). Leave `no-panic` off, because upstream exercises it only in nightly release builds ([CI workflow](https://github.com/boa-dev/ryu-js/blob/main/.github/workflows/ci.yml)). thiserror and unicode-normalization keep their default `std` feature. With `std`, thiserror's derive implements `std::error::Error` ([lib.rs source](https://docs.rs/crate/thiserror/2.0.21/source/src/lib.rs)). unicode-normalization's `std = []` only switches `no_std` off, because the crate needs `alloc` in every configuration ([Cargo.toml.orig](https://docs.rs/crate/unicode-normalization/0.1.26/source/Cargo.toml.orig)).

### Outside the crate APIs: planned work adds one nix feature, for `Flock` only

The Week 2 `SO_PEERPIDFD` upgrade, anticipated by SPEC.md line 6 and the `peercred` module docs, needs **no manifest change**. `nix::sys::socket::sockopt::PeerPidfd` has existed since 0.30.0. It is gated by the `socket` feature the project already enables, and it compiles only under `#[cfg(target_os = "linux")]` ([docs.rs](https://docs.rs/nix/0.31.3/nix/sys/socket/sockopt/struct.PeerPidfd.html); [sockopt.rs @ v0.31.3](https://raw.githubusercontent.com/nix-rust/nix/v0.31.3/src/sys/socket/sockopt.rs); [CHANGELOG](https://raw.githubusercontent.com/nix-rust/nix/master/CHANGELOG.md)). The doc comment on `socket_is_live` (peercred.rs lines 313–318) proposes a sibling lock file, and that does need a manifest change: `nix::fcntl::Flock` is "Available on crate feature `fs` only" ([docs.rs](https://docs.rs/nix/0.31.3/nix/fcntl/struct.Flock.html)). Add `fs` in the same change as the `Flock` code. The target block then becomes:

```toml
[target.'cfg(any(target_os = "linux", target_os = "macos"))'.dependencies]
nix = { version = "=0.31.3", default-features = false, features = ["fs", "socket", "user"] } # 2026-05-11
```

No current or planned item needs nix's `process` or `net` features.

### Outside the crate APIs: licence, MSRV and release-age facts that matter in production

**Every dependency's MSRV is at or below the project's `rust-version = "1.88"`, and sha2's is exactly 1.88.** sha2 raised its MSRV to 1.88 in the 0.11.1 patch release, under a policy adopted in 0.11.0 that allows "MSRV bumps in patch releases" ([sha2 CHANGELOG](https://raw.githubusercontent.com/RustCrypto/hashes/master/sha2/CHANGELOG.md)). thiserror's MSRV also rose within 2.0.x patch releases: 1.61, then 1.68, 1.71 and finally 1.77 ([crates.io](https://crates.io/api/v1/crates/thiserror/versions)). The exact `=` pins are what stop either crate from drifting past 1.88. The 0.11.1 README badge still reads "rustc-1.85+", but Cargo enforces the manifest's `rust-version = "1.88"` ([README](https://docs.rs/crate/sha2/0.11.1/source/README.md); [published Cargo.toml](https://docs.rs/crate/sha2/0.11.1/source/Cargo.toml)). The project's own MSRV is a claim its loop never tests. `rust-toolchain.toml` pins `channel = "1.97.0"`, so all five §2 commands compile with 1.97.0 and none with 1.88 ([rust-toolchain.toml](file:///C:/Users/mitam/OneDrive/Documents/Cryptographic%20Biscuits/agent-authority-fabric/rust-toolchain.toml)). Transitive MSRVs carry no guarantee either. nix warns that its MSRV "is not guaranteed to work with all versions of all dependencies" ([CHANGELOG](https://raw.githubusercontent.com/nix-rust/nix/master/CHANGELOG.md)). unicode-normalization's README notes that building on Rust 1.36 needs `tinyvec` ≤ 1.6.0, while the lockfile resolves tinyvec 1.13.3, which declares no `rust-version` ([README](https://github.com/unicode-rs/unicode-normalization/blob/v0.1.26/README.md); [crates.io](https://crates.io/api/v1/crates/tinyvec/versions)). thiserror requires `thiserror-impl = "=2.0.21"` exactly. The lock holds both at 2.0.21, alongside syn 3.0.9, whose MSRV is 1.71 ([published Cargo.toml](https://docs.rs/crate/thiserror/2.0.21/source/Cargo.toml); [crates.io](https://crates.io/api/v1/crates/syn/3.0.9)).

On licensing, **unicode-normalization 0.1.26 changed its licence to `(MIT OR Apache-2.0) AND Unicode-3.0`** and added a `LICENSE-UNICODE` file for the Unicode data ([PR #116](https://github.com/unicode-rs/unicode-normalization/pull/116); [crates.io](https://crates.io/api/v1/crates/unicode-normalization/versions?per_page=100)). The repository has no `deny.toml` today, so nothing fails yet. Any future cargo-deny or cargo-about allowlist must admit Unicode-3.0. The project's `unsafe_code = "forbid"` applies only to its own crate. ryu-js's `format_finite` writes through raw pointers and calls `str::from_utf8_unchecked` ([buffer/mod.rs](https://docs.rs/ryu-js/1.0.3/src/ryu_js/buffer/mod.rs.html)). unicode-normalization uses commented `char::from_u32_unchecked` calls on its Hangul paths ([normalize.rs](https://github.com/unicode-rs/unicode-normalization/blob/v0.1.26/src/normalize.rs)). nix wraps its libc calls in `unsafe` ([unistd.rs @ v0.31.3](https://raw.githubusercontent.com/nix-rust/nix/v0.31.3/src/unistd.rs)). A dependency audit should record all three. Finally, WEEK1_PLAN.md line 218 says sha2 0.11.1 and unicode-normalization 0.1.26 are "less than two weeks old". On 2026-10-27 that is still true of unicode-normalization (11 days old) but no longer of sha2 (15 days old) ([WEEK1_PLAN.md](file:///C:/Users/mitam/OneDrive/Documents/Cryptographic%20Biscuits/agent-authority-fabric/WEEK1_PLAN.md)).

## 2. Stand-In vs. Real API Gap Analysis (All 6 Crates)

The coordinator searched `src/` and found no mock, stub, stand-in, fake or shim code, and no local module named after any of the six crates. `src/lib.rs` declares only `engine`, `jcs` and `peercred` ([lib.rs](file:///C:/Users/mitam/OneDrive/Documents/Cryptographic%20Biscuits/agent-authority-fabric/src/lib.rs)). There is no stand-in side to the comparison, so each table below sets the code as written against the real crate. `src/engine.rs` uses thiserror directly. It reaches base64 and sha2 only through `jcs::sha256_b64url`, which builds the F-07 idempotency key at line 2656 ([engine.rs](file:///C:/Users/mitam/OneDrive/Documents/Cryptographic%20Biscuits/agent-authority-fabric/src/engine.rs)). **Across all six crates, no method call, trait impl or return type breaks.**

### base64 0.23.1: both imports and the one `encode` call resolve under `alloc`

| Call site as written (`src/jcs.rs`) | Real 0.23.1 API | Breaks? |
|---|---|---|
| `use base64::Engine as _;` (line 8) | crate-root `pub use engine::Engine;`, no `cfg`; `pub trait Engine: Send + Sync` with associated types `Config` and `DecodeEstimate` (not dyn-compatible) | No |
| `use base64::engine::general_purpose::URL_SAFE_NO_PAD;` (line 9) | `pub const URL_SAFE_NO_PAD: GeneralPurpose = GeneralPurpose::new(&alphabet::URL_SAFE, NO_PAD);`, with no `cfg` on the constant, its module or the `Engine` impl | No |
| `URL_SAFE_NO_PAD.encode(Sha256::digest(data))` returning `String` (line 602) | provided method `fn encode<T: AsRef<[u8]>>(&self, input: T) -> String` under `#[cfg(any(feature = "alloc", test))]`, which `features = ["alloc"]` satisfies | No |
| method lookup on `GeneralPurpose` | its only inherent method is `pub const fn new(alphabet: &Alphabet, config: GeneralPurposeConfig) -> Self`, so `.encode` can only resolve to `Engine::encode` | No |

Sources: [Engine trait](https://docs.rs/base64/0.23.1/base64/engine/trait.Engine.html), [general_purpose source](https://docs.rs/crate/base64/0.23.1/source/src/engine/general_purpose/mod.rs), [GeneralPurpose](https://docs.rs/base64/0.23.1/base64/engine/general_purpose/struct.GeneralPurpose.html), [lib.rs source](https://docs.rs/crate/base64/0.23.1/source/src/lib.rs).

No release from 0.21.0 through 0.23.1 changes `Engine::encode`, the constant's path or the `alloc` and `std` feature names. 0.22.0 changed only decoding. 0.23.0 added SIMD engines, more constants and custom padding symbols, made `DecodeError::InvalidLastSymbol` carry the decoded value, and raised the MSRV to 1.71.0 ([RELEASE-NOTES](https://raw.githubusercontent.com/marshallpierce/rust-base64/master/RELEASE-NOTES.md)). Because the import is anonymous (`Engine as _`), it cannot collide with the project's own `pub trait Engine` at engine.rs line 1144. The output has the shape that F-07 and SPEC.md's `digest()` require. `alphabet::URL_SAFE` is the RFC 4648 §5 alphabet "with `-` and `_`" ([docs.rs](https://docs.rs/base64/0.23.1/base64/alphabet/constant.URL_SAFE.html)), and `NO_PAD` writes no `=`, so a 32-byte digest becomes 43 characters. Inside base64, `encode` calls `.expect(...)` twice ([engine/mod.rs source](https://docs.rs/crate/base64/0.23.1/source/src/engine/mod.rs)). Those calls are outside the scope of the project's `expect_used` lint and cannot fire here, because a 32-byte input cannot overflow the encoded-length calculation.

### sha2 0.11.1: the new hybrid-array output still satisfies `AsRef<[u8]>`

| Call site as written (`src/jcs.rs`) | Real sha2 0.11.1 / digest 0.11.3 API | Breaks? |
|---|---|---|
| `use sha2::{Digest as _, Sha256};` (line 10) | `pub use digest::{self, Digest};` and `pub struct Sha256 { /* private fields */ }`, a newtype that `digest::buffer_fixed!` generates around `CtOutWrapper<block_api::Sha256VarCore, U32>` | No |
| `Sha256: Digest` with `default-features = false` | blanket `impl<D: FixedOutput + Default + Update + HashMarker> Digest for D`; none of the four bound impls on `Sha256` is gated (only `AssociatedOid` needs `oid`, and `ZeroizeOnDrop` needs `zeroize`) | No |
| `Sha256::digest(data)` with `data: &[u8]` (line 602) | `fn digest(data: impl AsRef<[u8]>) -> Output<Self>;` on `pub trait Digest: OutputSizeUser` | No |
| result passed to `encode<T: AsRef<[u8]>>` | `pub type Output<T> = Array<u8, <T as OutputSizeUser>::OutputSize>;`, which for `Sha256` is `hybrid_array::Array<u8, U32>`; hybrid-array 0.4.15 has `impl<T, U> AsRef<[T]> for Array<T, U> where U: ArraySize` and `impl<T, U> Deref for Array<T, U>` with `Target = [T]` | No |

Sources: [sha2 lib.rs source](https://docs.rs/crate/sha2/0.11.1/source/src/lib.rs), [Sha256](https://docs.rs/sha2/0.11.1/sha2/struct.Sha256.html), [Digest](https://docs.rs/digest/0.11.3/digest/trait.Digest.html), [Output](https://docs.rs/digest/0.11.3/digest/type.Output.html), [hybrid-array source](https://docs.rs/crate/hybrid-array/0.4.15/source/src/lib.rs).

sha2 0.11 is a breaking release, but not for this line. It replaces generic-array with hybrid-array, replaces the old type aliases with newtypes (digest 0.11 removed `CoreWrapper`), renames `core_api` to `block_api`, moves `compress256` into `block_api`, drops the `io::Write` impls, and removes the `std`, `asm` and `force-soft*` features ([sha2 CHANGELOG](https://raw.githubusercontent.com/RustCrypto/hashes/master/sha2/CHANGELOG.md); [digest CHANGELOG](https://raw.githubusercontent.com/RustCrypto/traits/master/digest/CHANGELOG.md)). Those changes break code that names `GenericArray`, `CoreWrapper<…>` or `sha2::compress256`, or that feeds a hasher through `std::io::copy`. This call site does none of that. Of digest's 0.11 releases, 0.11.0 and 0.11.1 are yanked, so `digest = "0.11"` resolves to 0.11.3, which Cargo.lock pins with the registry's checksum ([crates.io](https://crates.io/api/v1/crates/digest/versions)).

### unicode-normalization 0.1.26: there is no `String` impl, and autoderef makes that irrelevant

| Call site as written (`src/jcs.rs`) | Real 0.1.26 API | Breaks? |
|---|---|---|
| `use unicode_normalization::{IsNormalized, UnicodeNormalization as _, is_nfc_quick};` (line 11) | all three are crate-root re-exports | No |
| `is_nfc_quick(text.chars())` (line 645) | `pub fn is_nfc_quick<I: Iterator<Item = char>>(s: I) -> IsNormalized` | No |
| `matches!(…, IsNormalized::Yes)` (line 645) | `pub enum IsNormalized { Yes, No, Maybe }`, which derives only `Debug`, `Eq` and `PartialEq`; `matches!` needs none of them | No |
| `text.nfc()` on `text: String` (line 648) | `pub trait UnicodeNormalization<I: Iterator<Item = char>>` with `fn nfc(self) -> Recompositions<I>`; the only implementors are `impl<'a> UnicodeNormalization<Chars<'a>> for &'a str`, `impl UnicodeNormalization<IntoIter<char>> for char` and `impl<I: Iterator<Item = char>> UnicodeNormalization<I> for I`, with no impl for `String` | No |
| `.collect()` into the `String` return type (line 648) | `impl<I: Iterator<Item = char>> Iterator for Recompositions<I>` with `type Item = char` | No |

Sources: [is_nfc_quick](https://docs.rs/unicode-normalization/0.1.26/unicode_normalization/fn.is_nfc_quick.html), [IsNormalized](https://docs.rs/unicode-normalization/0.1.26/unicode_normalization/enum.IsNormalized.html), [UnicodeNormalization](https://docs.rs/unicode-normalization/0.1.26/unicode_normalization/trait.UnicodeNormalization.html), [Recompositions](https://docs.rs/unicode-normalization/0.1.26/unicode_normalization/struct.Recompositions.html), [impl blocks @ v0.1.26](https://github.com/unicode-rs/unicode-normalization/blob/v0.1.26/src/lib.rs#L138-L232).

The missing `String` impl is the one place where the code relies on more than a signature. `text.nfc()` compiles because method resolution derefs `String` to `str` and then autorefs it to `&str`. That selects the `&'a str` impl and yields a `Recompositions<Chars<'_>>` that borrows `text`. From 0.1.22 to 0.1.26 the crate moved its Unicode data from 15.0 to 18.0, added public iterator constructors and `FusedIterator` impls, declared an MSRV, and changed its licence metadata and CI. The trait and impl signatures the call site uses did not change ([compare v0.1.24...v0.1.26](https://github.com/unicode-rs/unicode-normalization/compare/v0.1.24...v0.1.26)). The function is also semantically correct. Only `IsNormalized::Yes` returns the input unchanged, while `No` and `Maybe` both run the full `nfc()`, following the crate's UAX #15 quick-check ([quick_check.rs](https://github.com/unicode-rs/unicode-normalization/blob/v0.1.26/src/quick_check.rs#L22-L69)). The researcher found no tracker issue where `is_nfc_quick` wrongly returns `Yes`. The one open NFC discrepancy, issue #105, came from a difference in Unicode versions, not a bug ([issue #105](https://github.com/unicode-rs/unicode-normalization/issues/105)).

### ryu-js 1.0.3: the one crate whose output an actual build confirmed

| Call site as written (`src/jcs.rs`) | Real 1.0.3 API | Breaks? |
|---|---|---|
| `let mut buffer = ryu_js::Buffer::new();` (line 848) | `pub struct Buffer { /* private fields */ }`; `pub fn new() -> Self`, not a `const fn`; implements `Copy`, `Clone` and `Default`, but not `Debug` | No |
| `buffer.format_finite(value).to_owned()` with `value: f64` (line 849) | `pub fn format_finite<F: Float>(&mut self, f: F) -> &str`, which elides to `<'a>(&'a mut self, f: F) -> &'a str`; `pub trait Float: Sealed {}` is implemented only for `f32` and `f64` | No |
| NaN or ±∞ reaching `format_finite` | documented to print "some correctly formatted but unspecified numerical value"; line 835 rejects `!parsed.is_finite()` before the call | Unreachable |
| −0.0, mapped to `0.0` at lines 843–847 | `format64` returns `"0"` before it writes any sign, and the crate's tests assert `pretty(-0.0) == "0"` | No |

Sources: [Buffer](https://docs.rs/ryu-js/1.0.3/ryu_js/struct.Buffer.html), [Float](https://docs.rs/ryu-js/1.0.3/ryu_js/trait.Float.html), [buffer/mod.rs](https://docs.rs/ryu-js/1.0.3/src/ryu_js/buffer/mod.rs.html), [pretty/mod.rs](https://docs.rs/ryu-js/1.0.3/src/ryu_js/pretty/mod.rs.html).

The `.to_owned()` copies the borrowed slice in the same statement, so the mutable borrow of `buffer` ends immediately. The project's tests assert nine input-to-output pairs, and all of them passed in WSL: `1.0`→`1`, `1e2`→`100`, `1E-7`→`1e-7`, `-0.0`→`0`, `123.456e2`→`12345.6`, `0.1`→`0.1`, `12.5`→`12.5`, `18446744073709551615`→`18446744073709552000` and `30000.0`→`30000`. The crate's own test suite asserts four of these outputs verbatim: `1`, `1e-7`, `0` for both signed zeros, and `0.1` ([d2s_test.rs](https://docs.rs/crate/ryu-js/1.0.3/source/tests/d2s_test.rs)). The other five rest on `format64`'s ECMAScript branch thresholds and on analogous crate assertions. Within 1.0.x, consumers see only two changes, both in 1.0.3: the MSRV rose from 1.64 to 1.71, and a panic fix landed in `format64_to_fixed`, which only `format_to_fixed` uses ([CHANGELOG](https://docs.rs/crate/ryu-js/1.0.3/source/CHANGELOG.md)).

### thiserror 2.0.21: six derive sites, and none uses a 2.0 breaking pattern

| Usage as written | Real 2.0.21 behaviour | Breaks? |
|---|---|---|
| `#[derive(…, thiserror::Error)]` with no `use` (engine.rs lines 91, 193, 224, 238; jcs.rs line 38; peercred.rs line 44) | the derive sits at the crate root (`pub use thiserror_impl::*;`), with helper attributes `#[backtrace]`, `#[error]`, `#[from]` and `#[source]`; 2.0 requires a direct, non-renamed dependency because the expansion uses absolute `::thiserror::__private21::…` paths, and `thiserror = "=2.0.21"` is one | No |
| unit variants with `#[error("literal")]`; named fields `{offset}`, `{owner}`, `{expected}`, `{actual}`; tuple `{0}` | documented shorthand `{var}` ⟶ `write!("{}", self.var)` and `{0}` ⟶ `write!("{}", self.0)` | No |
| `#[error("denied by {guard:?}: {reason}")]` (engine.rs line 244) | a trailing `?` selects `Debug`, which `GuardId` derives; `{reason}` needs `PolicyError: Display`, which its own derive generates | No |
| `{mode:o}` on `mode: u32` (peercred.rs lines 70, 95, 115) | a trailing `o` selects `Trait::Octal`, which `u32` implements; output is `750`, not `0750` | No |
| `Malformed(#[from] JcsError)`, `Store(#[from] StoreError)`, `InvalidConfig(#[from] ConfigError)` on a `Copy` enum (engine.rs lines 242, 253, 256) | `#[from]` generates `fn from(source: T) -> Self` and implies `#[source]`; the derive emits only `Error`, `Display` and `From` impls and adds no fields and no `Drop`, so `Copy` and `const fn to_agent_code(self)` are unaffected | No |
| `Sys(#[from] nix::Error)`, `Io(#[from] io::Error)` (peercred.rs lines 48, 51) | the generated `source()` returns `Option<&(dyn Error + 'static)>`, so a source must be `Error + 'static`; `nix::Error` is `Errno`, which implements `Error`, `Display` and `Debug`, and `#[from] io::Error` is the crate's own first doc example | No |

Sources: [derive.Error](https://docs.rs/thiserror/2.0.21/thiserror/derive.Error.html), [lib.rs source](https://docs.rs/crate/thiserror/2.0.21/source/src/lib.rs), [expand.rs](https://docs.rs/crate/thiserror-impl/2.0.21/source/src/expand.rs), [fmt.rs](https://docs.rs/crate/thiserror-impl/2.0.21/source/src/fmt.rs), [build.rs](https://docs.rs/crate/thiserror/2.0.21/source/build.rs), [Errno](https://docs.rs/nix/0.31.3/nix/errno/enum.Errno.html).

The trait the derive implements is `::thiserror::__private21::Error`, a re-export of `core::error::Error`. With the default `std` feature, thiserror aliases `core` to `std`, so on Rust 1.81 and later this is the same trait as `std::error::Error` ([private.rs](https://docs.rs/crate/thiserror/2.0.21/source/src/private.rs)). None of the 2.0.0 breaking changes appears in the code. There are no raw-identifier references like `{r#type}`, no named arguments that shadow a field, no `{0}` mixed with extra positional arguments, and thiserror is a direct, non-renamed dependency ([release 2.0.0](https://github.com/dtolnay/thiserror/releases/tag/2.0.0)). No field is named `source` and no field type is named `Backtrace`, so the derive picks up no source or backtrace by accident. `Denied`'s `reason` field is not a source, because thiserror chooses sources only by attribute or by that name. The generated impls carry their own `#[allow]`s for `unused_qualifications`, `deprecated`, `clippy::used_underscore_binding` and `clippy::redundant_field_names`, and they contain no casts, `unsafe`, panics or unwraps ([expand.rs](https://docs.rs/crate/thiserror-impl/2.0.21/source/src/expand.rs); [test_lints.rs](https://docs.rs/crate/thiserror/2.0.21/source/tests/test_lints.rs)). From the source alone, the researcher could not rule out `elided_lifetimes_in_paths` (part of `rust_2018_idioms`) firing on the generated `&mut ::core::fmt::Formatter`. The passing clippy runs show that it did not fire on 1.97.0, but that conclusion is an inference.

### nix 0.31.3: the post-0.28 `AsFd` API matches both platform branches

| Call site as written (`src/peercred.rs`) | Real 0.31.3 API | Breaks? |
|---|---|---|
| `use nix::sys::socket::{getsockopt, sockopt};` (line 27) | `pub fn getsockopt<F: AsFd, O: GetSockOpt>(fd: &F, opt: O) -> Result<O::Val>`, feature `socket` | No |
| `use nix::unistd::geteuid;` and `geteuid().as_raw()`, compared with `MetadataExt::uid()` (lines 28, 219) | `pub fn geteuid() -> Uid`, feature `user`; `pub const fn as_raw(self) -> uid_t`, where `uid_t` is `u32` | No |
| Linux: `getsockopt(socket, sockopt::PeerCredentials)?`, then `uid()`, `gid()` and `Some(pid())` (lines 151–159) | `#[cfg(linux_android)]` `pub struct PeerCredentials;` with `type Val = UnixCredentials`; `pub fn uid(&self) -> uid_t`, `gid(&self) -> gid_t` and `pid(&self) -> pid_t` fit `u32`, `u32` and `Option<i32>` | No |
| macOS: `nix::unistd::getpeereid(socket.as_fd())?`, then `uid.as_raw()` and `gid.as_raw()` (lines 163, 166–167) | `#[cfg(bsd)] pub fn getpeereid<F: AsFd>(fd: F) -> Result<(Uid, Gid)>`, features `socket` and `user`; it takes `F` by value, and `BorrowedFd<'_>` implements `AsFd` | No |
| macOS: `getsockopt(socket, sockopt::LocalPeerPid)?`, stored as `Some(pid)` (lines 164, 168) | `#[cfg(apple_targets)]` `pub struct LocalPeerPid;` with `type Val = libc::c_int`, which is `i32` | No |
| `Sys(#[from] nix::Error)` (line 48) | `pub type Error = Errno;`, where `Errno` is a `#[non_exhaustive] #[repr(i32)] pub enum` that implements `Debug`, `Display` and `Error` on the Linux and macOS builds | No |

Sources: [getsockopt](https://docs.rs/nix/0.31.3/nix/sys/socket/fn.getsockopt.html), [PeerCredentials](https://docs.rs/nix/0.31.3/nix/sys/socket/sockopt/struct.PeerCredentials.html), [UnixCredentials](https://docs.rs/nix/0.31.3/nix/sys/socket/struct.UnixCredentials.html), [getpeereid (macOS)](https://docs.rs/nix/0.31.3/x86_64-apple-darwin/nix/unistd/fn.getpeereid.html), [LocalPeerPid (macOS)](https://docs.rs/nix/0.31.3/x86_64-apple-darwin/nix/sys/socket/sockopt/struct.LocalPeerPid.html), [geteuid](https://docs.rs/nix/0.31.3/nix/unistd/fn.geteuid.html), [Uid](https://docs.rs/nix/0.31.3/nix/unistd/struct.Uid.html), [Error](https://docs.rs/nix/0.31.3/nix/type.Error.html), [Errno (macOS)](https://docs.rs/nix/0.31.3/x86_64-apple-darwin/nix/errno/enum.Errno.html).

Code written for nix 0.27 or earlier, such as `getpeereid(fd.as_raw_fd())`, would break: 0.28.0 moved `getpeereid` from `RawFd` to `AsFd` and raised the MSRV to 1.69 ([CHANGELOG](https://raw.githubusercontent.com/nix-rust/nix/master/CHANGELOG.md)). The project already uses the I/O-safe style, and nothing in 0.31.0 through 0.31.3 touches these items. docs.rs does not build nix for aarch64-apple-darwin, and the per-target pages return 404 ([docs.rs](https://docs.rs/nix/0.31.3/aarch64-apple-darwin/nix/unistd/fn.getpeereid.html)). So the macOS rows come from the x86_64-apple-darwin build, and they describe aarch64 exactly, because the `bsd` and `apple_targets` cfg aliases test `target_os = "macos"`, not the architecture ([build.rs @ v0.31.3](https://raw.githubusercontent.com/nix-rust/nix/v0.31.3/build.rs)). The aarch64 clippy gate that passed in WSL compiled this branch.

### Three grades of evidence, and a verification loop that has not run

The verdicts above rest on evidence of three different strengths, and this report keeps them separate.

| Grade | What it establishes | Limits |
|---|---|---|
| **Verified by researchers from crates.io, docs.rs or published source** | For all six pins: existence, yank status, latest-stable status, publish date, MSRV, edition, licence and features. Every signature, `cfg` gate and trait impl in the tables above. Lockfile checksums equal to the registry's for sha2, digest and hybrid-array (checked against crates.io), for crypto-common, block-buffer, cpufeatures, cfg-if and typenum (checked against the upstream RustCrypto lockfile), and for ryu-js, thiserror, thiserror-impl, syn and unicode-normalization. For base64, this report compared the lockfile with the checksum the researcher took from crates.io | Most pages were read through a summarising fetch tool, so "verbatim" means verbatim as the tool returned it, and base64 line numbers are approximate. The unicode-normalization research (published tarballs downloaded, checksummed and diffed) and the ryu-js research (the cached `.crate` checksummed and its source read locally) rest on primary sources |
| **Confirmed by an actual build** | In WSL with cargo and rustc 1.97.0, `CARGO_TARGET_DIR=$HOME/.cargo-target/pep-sidecar`, `RUSTFLAGS='-D warnings'`, `--locked --offline`: `cargo clippy --all-targets --features lenient-numbers -- -D warnings` and `cargo clippy --all-targets --target aarch64-apple-darwin -- -D warnings` both exited 0. `cargo test --features lenient-numbers --lib -- lenient_request_numbers result_profile_numbers` passed 2 of 2, and `cargo test --lib -- result_profile_numbers` passed 1 of 1 ([ryu-js notes](file:///C:/Users/mitam/OneDrive/Documents/Cryptographic%20Biscuits/agent-authority-fabric/research_notes/Pep%20sidecar%20crate%20API%20verification/ryu_js.md)) | aarch64-apple-darwin was type-checked and linted, not linked or run. Upstream ryu-js CI has no macOS runner |
| **Inferred from that build, not separately verified** | Clippy checks the whole package, so the same two runs also type-checked and linted every base64, sha2, unicode-normalization, thiserror and nix call site: the Linux `PeerCredentials` branch on the host with `lenient-numbers`, and the macOS `getpeereid` and `LocalPeerPid` branch with default features. That also shows `Digest::digest` raises no deprecation warning, thiserror's generated code trips no `rust_2018_idioms` lint on 1.97.0, and nix with its libc subtree cross-checks for aarch64-apple-darwin from WSL. The runs compiled libc 0.2.191 from Cargo's cache under its locked checksum, so that version was downloaded from crates.io, even though upstream RustCrypto locks 0.2.190 | Covered two of the three clippy configurations in §2. Superseded on 2026-10-28: all five commands now pass (Section 5) |

**Still unverified:** the minimum Linux kernel for `SO_PEERPIDFD` (background knowledge says 6.5, unconfirmed) and how the call fails on older kernels; the name of `Flock`'s non-blocking `FlockArg` variant; how to read a PID from a pidfd; and the MSRVs of transitive crates such as memoffset, crypto-common, block-buffer, cpufeatures and tinyvec. Also unverified: Cargo's capping of lints in registry dependencies, which every researcher relied on as general Cargo behaviour without a citation, although the passing builds are consistent with it; Unicode's normalization stability policy; and the Unicode version of the Python `unicodedata` that SPEC.md line 19 says recomputed the conformance vectors. Three items formerly on this list were checked on 2026-10-28 (Section 5): the libc 0.2.191 yank status, the nix 0.31.3 lockfile checksum and Unicode 18's `DerivedCoreProperties.txt`.

When this report was first written, the full five-command loop in CLAUDE.md §2 had not been run, so under the project's own rule the work could not yet be declared complete ([CLAUDE.md](file:///C:/Users/mitam/OneDrive/Documents/Cryptographic%20Biscuits/agent-authority-fabric/CLAUDE.md)). That gap is now closed. This is the coverage as of 2026-10-28 (details in Section 5):

| CLAUDE.md §2 command | Status |
|---|---|
| `cargo fmt --check` | Exit 0 |
| `cargo clippy --all-targets -- -D warnings` | Exit 0 |
| `cargo test -- --nocapture` | 145 passed, 0 failed, 3 ignored; 1 doctest passed |
| `cargo clippy --all-targets --features lenient-numbers -- -D warnings && cargo test --features lenient-numbers` | Clippy exit 0; 145 passed, 0 failed, 3 ignored; 1 doctest passed |
| `cargo clippy --all-targets --target aarch64-apple-darwin -- -D warnings` | Exit 0 |

## 3. Drop-In Adapter / Migration Strategy

### No mismatch exists, so neither option A nor option B applies

Option (A) assumes a call site that disagrees with the real API. Option (B) assumes a real API shape worth bridging. The gap analysis found neither for any crate, so for each one the decision is to change nothing. An unneeded wrapper would carry a cost under this project's lints. A `pub` adapter needs rustdoc under `missing_docs`. A private one fails `dead_code` under `-D warnings` once its last caller goes. And any layer between the code and the crate would absorb the very breakage that a future pin bump ought to surface at the call site.

| Crate | Real mismatch | Decision | Reason |
|---|---|---|---|
| base64 | None | Neither; keep jcs.rs lines 8–9 and 601–603 | The path, the `T: AsRef<[u8]>` bound and the `String` return all match 0.23.1. The prelude spelling `base64::prelude::BASE64_URL_SAFE_NO_PAD` is equivalent and gains nothing |
| sha2 | None | Neither; keep lines 10 and 602 | `Output<Sha256>` already implements `AsRef<[u8]>`, so adding `.as_slice()` would be redundant |
| unicode-normalization | None | Neither; keep line 11 and `fn nfc` (lines 644–650) | Autoderef reaches the `&'a str` impl |
| ryu-js | None (build-confirmed) | Neither; keep lines 843–849, including the −0.0 mapping | `format_finite`'s API docs never promise that −0.0 prints as `"0"`; only the tests, the source and the 0.2.0 changelog do. The mapping is cheap insurance |
| thiserror | None | Neither; keep all six derives | No 2.0 breaking pattern is present. Changing to `{mode:04o}` would be cosmetic only |
| nix | None | Neither; keep peercred.rs lines 27–28, 48, 151–170 and 219 | The post-0.28 `AsFd` API matches on both targets |

### Planned nix work takes option A at its call sites

Both planned nix items need only direct code at their call sites. `getsockopt(socket, sockopt::PeerPidfd)` already returns `nix::Result<OwnedFd>`, and the existing `Sys(#[from] nix::Error)` variant absorbs its error, so one call is the whole integration. nix performs the `OwnedFd::from_raw_fd` conversion inside its own `unsafe` block ([sockopt.rs @ v0.31.3](https://raw.githubusercontent.com/nix-rust/nix/v0.31.3/src/sys/socket/sockopt.rs)). `Flock` needs one explicit conversion. `pub fn lock(t: T, args: FlockArg) -> Result<Self, (T, Errno)>` returns the unlocked file inside the error, so `?` cannot convert it through `From<Errno>` ([docs.rs](https://docs.rs/nix/0.31.3/nix/fcntl/struct.Flock.html)). A zero-cost option (B), `impl From<(File, Errno)> for PeerError`, would make `?` work. But it would add a public conversion to a public error type for a single call site, and it would hide the dropped file inside a trait impl. A one-line `map_err` closure at the call site is clearer, so (A) wins. Implementing `Flockable` for a project type is not an option. It is declared `pub unsafe trait Flockable: AsRawFd {}`, so implementing it needs `unsafe impl`, which `unsafe_code = "forbid"` rejects. nix already implements it for `File` and `OwnedFd` ([Flockable](https://docs.rs/nix/0.31.3/x86_64-apple-darwin/nix/fcntl/trait.Flockable.html)).

### Future pin bumps, not today's code, carry the migration risk

The exact `=` pins are what keep this gap analysis true, so the migration strategy that matters is how pins get bumped. Any sha2 or thiserror bump must recheck `rust-version` against 1.88, because both crates have raised their MSRV in patch releases. Any base64 change must keep `default-features = false`, or `simd-unsafe` comes back. A unicode-normalization bump is a canonicalization change, not a routine upgrade. Releases 0.1.22 through 0.1.26 differ only in Unicode data, which changes NFC output for newly encoded characters. That changes every `sha-256:` digest and F-07 key computed over such characters, so each bump needs the conformance vectors rerun and SPEC.md updated ([compare v0.1.24...v0.1.26](https://github.com/unicode-rs/unicode-normalization/compare/v0.1.24...v0.1.26)). The same skew applies between processes. Issue #105 shows two correct normalizers on different Unicode versions producing different bytes ([issue #105](https://github.com/unicode-rs/unicode-normalization/issues/105)). SPEC.md line 7 has the broker recompute `action_digest` ([SPEC.md](file:///C:/Users/mitam/OneDrive/Documents/Cryptographic%20Biscuits/agent-authority-fabric/SPEC.md)). By this report's inference from that line, the broker must normalize with the same Unicode 18.0.0 tables, or it will reject legitimate calls whose strings contain characters newer than its tables.

## 4. Targeted Code Replacements & Diffs

### Crate APIs: no imports to add, no stand-ins to delete, nothing to refactor

For all six crates, there are **no new `use` imports, no stand-in lines or modules to delete, and no refactored functions or adapters**. No stand-in code exists, so there is nothing to delete. The import lines (jcs.rs lines 8–11; peercred.rs lines 19 and 27–28), the call sites (jcs.rs lines 602, 645–648 and 848–849; peercred.rs lines 153, 163–164 and 219) and the six `thiserror::Error` derives stay exactly as written. The notes mention three optional edits, and none is needed. Changing `{mode:o}` to `{mode:04o}` in `PeerError` would print `0750` instead of `750`, which is purely cosmetic. Dropping ryu-js's `default-features = false` would change nothing, because the crate has no default features. Dropping the −0.0 mapping is not recommended, for the reason given in Section 3.

### Outside the crate APIs: correct SPEC.md line 15 to Unicode 18.0.0

*Applied 2026-10-28: the SPEC.md diff, the guard test and the `Cargo.toml` comment below are all in place (Section 5).*

The pinned crate's generated tables declare `pub const UNICODE_VERSION: (u8, u8, u8) = (18, 0, 0);`, and the crate re-exports that constant at its root ([tables.rs](https://docs.rs/crate/unicode-normalization/0.1.26/source/src/tables.rs); [docs.rs](https://docs.rs/unicode-normalization/0.1.26/unicode_normalization/constant.UNICODE_VERSION.html)). Unicode 16.0.0 was the data in 0.1.24. 0.1.26 moved to 18.0.0 through PR #117 ([PR #117](https://github.com/unicode-rs/unicode-normalization/pull/117)). This is the one required fix the research found, and it is to documentation, not code ([SPEC.md](file:///C:/Users/mitam/OneDrive/Documents/Cryptographic%20Biscuits/agent-authority-fabric/SPEC.md)):

```diff
-  - NFC on strings and keys before UTF-16 sorting; record the Unicode version the pinned `unicode-normalization` crate implements (`unicode-normalization = "=0.1.26"`, Unicode 16.0).
+  - NFC on strings and keys before UTF-16 sorting; record the Unicode version the pinned `unicode-normalization` crate implements (`unicode-normalization = "=0.1.26"`, Unicode 18.0.0, i.e. `unicode_normalization::UNICODE_VERSION == (18, 0, 0)`).
```

An optional guard test enforces the requirement automatically: a crate bump that changes the tables then fails CI instead of silently changing digests. Put it in the existing `mod tests` of `src/jcs.rs`. That module already opens with the F-02 `#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects)]` header (lines 1234–1241) and with `use super::*;` (line 1243), so the test needs no new attribute ([jcs.rs](file:///C:/Users/mitam/OneDrive/Documents/Cryptographic%20Biscuits/agent-authority-fabric/src/jcs.rs)). The full path is required because `UNICODE_VERSION` is not imported, so `unused_qualifications` stays quiet.

```rust
    /// Pins the NFC tables to the Unicode version `SPEC.md` records, so a crate bump that
    /// changes them fails here instead of silently changing digests.
    #[test]
    fn nfc_tables_are_unicode_18_0_0() {
        assert_eq!(unicode_normalization::UNICODE_VERSION, (18, 0, 0));
    }
```

Optionally, extend the comment on `Cargo.toml` line 20 from `# 2026-10-16` to `# 2026-10-16, Unicode 18.0.0`.

### Outside the crate APIs: sketches for `SO_PEERPIDFD` and the `Flock` lock file

These sketches are for planned work and do not belong in the current code. Each must land together with its caller, because an uncalled private function fails `dead_code` under `-D warnings` in every clippy gate. The Week 2 pidfd read goes in `src/peercred.rs`, next to the Linux `os_peer_cred`:

```rust
/// Opens a pidfd for the peer process (`SO_PEERPIDFD`). Unlike a PID, a pidfd stays bound
/// to one process, so it cannot be recycled to name another.
#[cfg(target_os = "linux")]
fn os_peer_pidfd<F: AsFd>(socket: &F) -> Result<std::os::fd::OwnedFd, PeerError> {
    getsockopt(socket, sockopt::PeerPidfd).map_err(PeerError::Sys)
}
```

The full `std::os::fd::OwnedFd` path is deliberate. A top-level `use std::os::fd::OwnedFd;` would be unused on macOS and would fail command 5 of the §2 loop. The `cfg` is `target_os = "linux"` rather than `linux_android`, to match nix's own gate ([sockopt.rs @ v0.31.3](https://raw.githubusercontent.com/nix-rust/nix/v0.31.3/src/sys/socket/sockopt.rs)). The pidfd mechanism exists because "PIDs are inherently racy, leading to confused deputy problems" ([nix PR #2620](https://github.com/nix-rust/nix/pull/2620)). Three points around it remain unverified. The minimum kernel is unconfirmed; background knowledge says Linux 6.5. On older kernels the call is expected to fail with an `ENOPROTOOPT`-style error, which the caller must treat as a denial, so the check fails closed. And deriving `PeerCred.pid` from the pidfd may need code outside nix.

The lock-file fix for `socket_is_live` needs the `fs` feature from Section 1 and a `std::fs::File` opened next to the socket:

```rust
let lock = nix::fcntl::Flock::lock(lock_file, nix::fcntl::FlockArg::LockExclusive)
    .map_err(|(_file, errno)| PeerError::Sys(errno))?;
```

`Flock` releases the lock when it is dropped ([CHANGELOG, 0.28.0](https://raw.githubusercontent.com/nix-rust/nix/master/CHANGELOG.md)). So `lock` must live as long as the `UnixListener`, which means returning or storing it alongside the listener. That requires a signature change to `bind_safe_listener` that the research did not design. `LockExclusive` blocks while another instance holds the lock, and the name of the non-blocking variant was not verified.

### Outside the crate APIs: `is_default_ignorable` stopped at Unicode 17 (resolved: unchanged in 18.0.0)

*Resolved 2026-10-28. Unicode 18.0.0 adds no `Default_Ignorable_Code_Point`, so the 17 arms stay as they are. Only the doc comment changed, and a new test checks every code point against the 27 published lines (Section 5).*

This item is the coordinator's own observation. Neither the researchers nor this report examined Unicode 18 data. The hand-written property list in `src/engine.rs` says it is current only through Unicode 17 (lines 430–431):

```rust
/// Unicode `Default_Ignorable_Code_Point` (`DerivedCoreProperties.txt`, unchanged through
/// Unicode 17): invisible characters such as U+00AD SOFT HYPHEN, U+200B ZERO WIDTH SPACE, the
```

The pinned NFC tables are now at Unicode 18.0.0, and the two Unicode versions meet on every store key. `StoreKey::new` first normalizes the key with `jcs::JcsString::new`, which applies unicode-normalization's NFC. It then rejects the key if `clean_text` finds a character that `is_default_ignorable` matches (engine.rs lines 378–381). The doc comment at lines 355–365 gives the reason: a backend collation can give an invisible character no weight and resolve the key to another key's record ([engine.rs](file:///C:/Users/mitam/OneDrive/Documents/Cryptographic%20Biscuits/agent-authority-fabric/src/engine.rs)). If Unicode 18 added a `Default_Ignorable_Code_Point`, a key containing it would pass the check. That would reopen the location-taint gap F-08 exists to close. This assessment of the stakes is this report's inference from the local code. The fix is to check the 17 entries at lines 437–453 against Unicode 18.0.0's `DerivedCoreProperties.txt`. If the property is unchanged, change "through Unicode 17" to "through Unicode 18". If code points were added, add them to the `matches!` arms and add a test for one of them. No diff is proposed here, because nobody has read the Unicode 18 data.

### Only the verification loop stands between this code and production

The stand-in hypothesis predicted invented paths and drifted signatures. The code instead targets APIs that exist only in recent releases, such as nix's post-0.28 I/O-safe `getpeereid` and base64's post-0.21 `Engine` methods. So the remaining risk is not API migration. It lies in two places that a compiler does not police. The first is Unicode data, which has to agree across SPEC.md, the NFC tables, the hand-written ignorable list and every peer that recomputes digests. The second is configurations nobody has exercised: `cargo fmt`, default-feature host clippy, the full test suites and the declared 1.88 MSRV. The order of work follows from that. First, run all five §2 commands to completion. Next, fix SPEC.md line 15 and optionally add the guard test. Then re-check `is_default_ignorable` against Unicode 18. Finally, add the `fs` feature only in the same change as the `Flock` code that needs it. As of 2026-10-28 the first three steps are done, and the fourth waits on the `Flock` work.

## 5. Completion Status (2026-10-28)

### The verification loop passes in every configuration

All five CLAUDE.md §2 commands ran in WSL with cargo and rustc 1.97.0, `CARGO_TARGET_DIR=$HOME/.cargo-target/pep-sidecar` and `RUSTFLAGS='-D warnings'`, each with `--locked` added (stricter than §2 requires). The loop passed before the edits below (143 tests) and again after them (145 tests). After `rust-toolchain.toml` moved to 1.97.1, it passed again on rustc 1.97.1 (145 tests, zero warnings).

| CLAUDE.md §2 command | Result after the edits |
|---|---|
| `cargo fmt --check` | Exit 0 |
| `cargo clippy --all-targets -- -D warnings` | Exit 0, no warnings |
| `cargo test -- --nocapture` | 145 passed, 0 failed, 3 ignored. The one doctest, the `compile_fail` proof that `HostAuthority { _sealed: () }` cannot be forged outside the crate, passed; its log shows the expected `E0451` |
| `cargo clippy --all-targets --features lenient-numbers -- -D warnings && cargo test --features lenient-numbers` | Clippy exit 0; 145 passed, 0 failed, 3 ignored; doctest passed |
| `cargo clippy --all-targets --target aarch64-apple-darwin -- -D warnings` | Exit 0 |

The three ignored tests then ran once together, on rustc 1.97.1. The unit-test binary was built as the normal user, and only that binary ran as root (`wsl -u root`, `ulimit -n 8192`, `--ignored --exact`), so no build file became root-owned. `full_backlog_counts_as_live`, `parent_owner_mismatch_rejected` and `socket_group_must_match_parent` all passed (3 passed, 0 failed). aarch64-apple-darwin is still linted and type-checked only: nothing was linked or run on macOS.

### Edits applied

No guard, parser or policy logic changed.

| File | Change |
|---|---|
| `SPEC.md` line 15 | Unicode 16.0 replaced by Unicode 18.0.0 and `UNICODE_VERSION == (18, 0, 0)`, the diff from Section 4 |
| `src/jcs.rs` tests | New test `nfc_tables_are_unicode_18_0_0`, after `known_answer_digest`. Its doc comment says that a crate upgrade which changes the tables changes digests, so it must come with a SPEC.md update and a rerun of the conformance vectors |
| `src/engine.rs` | The doc comment on `is_default_ignorable` now cites `DerivedCoreProperties-18.0.0.txt` and the test that checks it. New test `default_ignorable_matches_unicode_18_0_0` keeps the 27 published lines as a constant (`DEFAULT_IGNORABLE_18_0_0`, in file order, so it can be diffed against the file). It checks every Unicode scalar value against them, so a missing, extra or shifted code point fails. It checks the 4,174 total twice, as the count of matches and as the sum of the lines. Finally it checks that the lines merge into the 17 arms, that both ends of each arm are ignorable, and that the scalar values just outside each arm are not |
| `Cargo.toml` line 20 | Comment extended to `# 2026-10-16, Unicode 18.0.0` |

### Unicode 18.0.0 `Default_Ignorable_Code_Point` equals the hand-written list

Source: [`DerivedCoreProperties-18.0.0.txt`](https://www.unicode.org/Public/18.0.0/ucd/DerivedCoreProperties.txt), dated 2026-08-07. Its `Default_Ignorable_Code_Point` section has 27 data lines and ends with `# Total code points: 4174`. The file splits ranges by general category, so the 27 lines merge into exactly the 17 arms of `is_default_ignorable`:

- `180B..180D` (Mn), `180E` (Cf) and `180F` (Mn) merge to `180B..180F`.
- `2060..2064` (Cf), `2065` (Cn) and `2066..206F` (Cf) merge to `2060..206F`.
- `E0000`, `E0001`, `E0002..E001F`, `E0020..E007F`, `E0080..E00FF`, `E0100..E01EF` and `E01F0..E0FFF` merge to `E0000..E0FFF`.
- The other 14 lines are identical to the remaining 14 arms.

The file was read through the summarising fetch tool, so two consistency checks back the extraction. First, the per-line counts it returned sum to 4,174, the file's own total. Second, the new test checks every Unicode scalar value against the 27 lines as transcribed, and confirms that the `matches!` arms cover exactly those 4,174 code points. Unicode 18 therefore adds no invisible character that a store key could carry past `clean_text`, and the F-08 location-taint concern from Section 4 does not arise.

### Formerly unverified lockfile facts, now checked

- **nix 0.31.3**: the crates.io checksum `cf20d2fde8ff38632c426f1165ed7436270b44f199fc55284c38276f9db47c3d` equals `Cargo.lock` line 100. The version is not yanked ([crates.io](https://crates.io/api/v1/crates/nix/0.31.3)).
- **libc 0.2.191**: published 2026-10-16T22:56:46Z, not yanked, `rust_version` 1.65. The checksum `65cd87c9a6d60536580b316ad985726104730a5151c99845f2490428ef91240a` equals `Cargo.lock` line 85 ([crates.io](https://crates.io/api/v1/crates/libc/0.2.191)).

### Still open

- **Week 2 facts**: the minimum kernel for `SO_PEERPIDFD` and its failure mode on older kernels, the non-blocking `FlockArg` variant, and how to read a PID from a pidfd.
- **The Unicode version of the Python `unicodedata`** used for the conformance vectors.

Closed after this section was first written:

- **MSRV.** The untested `rust-version = "1.88"` is dropped. `rust-version` is now 1.97.1, the pinned toolchain, so every command checks it. Transitive MSRVs only matter if a dependency needs a newer compiler, and then the build fails.
- **Root-only `peercred` tests.** All three ignored tests passed in one run (above).
- **Broker Unicode version.** SPEC.md §1 and §2 pin the broker to Unicode 18.0.0, and a Unicode upgrade ships to the PEP and the broker together.
- **Stale WEEK1_PLAN.md lines.** Both are corrected.
- **Licence policy and dependency `unsafe`.** `deny.toml` allows `MIT`, `Apache-2.0` and `Unicode-3.0`, and [Dependency unsafe record.md](Dependency%20unsafe%20record.md) lists where every dependency uses `unsafe`.
