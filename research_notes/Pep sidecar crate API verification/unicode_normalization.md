# unicode-normalization (unicode-rs): real API vs. pep-sidecar's `=0.1.26` pin and `src/jcs.rs::nfc` (verified 2026-10-27)

Method: version metadata came from the crates.io JSON API. The published `.crate` tarballs for 0.1.22 to 0.1.26 were downloaded from static.crates.io and diffed locally; these are the sources Cargo actually compiles. The rendered declarations were taken from the raw docs.rs HTML for 0.1.26. History and issues came from the GitHub REST API for `unicode-rs/unicode-normalization`. Project context was read from the local `Cargo.toml` (line 20), `src/jcs.rs` (lines 11 and 644-650), `SPEC.md` (line 15) and `Cargo.lock` (lines 188-191 and 206-209). **The pinned version is also the latest stable version**, so every "latest" fact below is the same as the pinned fact.

## 1. Does 0.1.26 exist, is it yanked, when was it published, and what is the latest stable version as of 2026-10-27?

### Takeaway
Yes. 0.1.26 exists on crates.io, is **not yanked**, and was published **2026-10-16T23:28:29Z (UTC)**. It is also the **latest stable version, and the newest version overall**, as of 2026-10-27, and the crate has **no pre-releases**. The exact pin `=0.1.26` resolves, and the checksum already in the project's `Cargo.lock` matches the registry byte for byte.

### Cited Findings
- Crate record: `max_version`, `max_stable_version`, `newest_version` and `default_version` are all `0.1.26`. The crate shows `yanked: false`, `updated_at: 2026-10-16T23:28:29.955206Z` and `repository: https://github.com/unicode-rs/unicode-normalization`. — [crates.io API: crate](https://crates.io/api/v1/crates/unicode-normalization)
- Version 0.1.26 record:
  - `created_at: 2026-10-16T23:28:29.955206Z`
  - `yanked: false`, with an empty `yank_message`
  - `checksum: 75cd3fb03d5288b3ba9a1ee103ac7e9cbb59f0b03d64f8ddfcc04dd42758a85d`
  - `crate_size: 130122`
  - `has_lib: true`
  - `published_by: Manishearth`

  — [crates.io API: 0.1.26](https://crates.io/api/v1/crates/unicode-normalization/0.1.26)
- The crate has 30 versions in total, from 0.0.1 to 0.1.26. None is yanked and none has a pre-release suffix, so the pre-release list is empty. The recent versions are below. — [crates.io API: versions](https://crates.io/api/v1/crates/unicode-normalization/versions?per_page=100)

| Version | Published (UTC) | `rust_version` | `edition` | `license` |
|---|---|---|---|---|
| 0.1.26 | 2026-10-16T23:28:29Z | 1.36 | 2018 | (MIT OR Apache-2.0) AND Unicode-3.0 |
| 0.1.25 | 2025-10-30T16:06:38Z | 1.36 | 2018 | MIT OR Apache-2.0 |
| 0.1.24 | 2024-09-17T15:27:12Z | 1.36 | 2018 | MIT/Apache-2.0 |
| 0.1.23 | 2024-02-20T15:51:23Z | (not declared) | 2018 | MIT/Apache-2.0 |
| 0.1.22 | 2022-09-16T15:37:14Z | (not declared) | 2018 | MIT/Apache-2.0 |

- The SHA-256 of the downloaded 0.1.26 tarball is `75cd3fb03d5288b3ba9a1ee103ac7e9cbb59f0b03d64f8ddfcc04dd42758a85d`, the same as the registry checksum. — [static.crates.io 0.1.26 tarball](https://static.crates.io/crates/unicode-normalization/unicode-normalization-0.1.26.crate); [crates.io API: 0.1.26](https://crates.io/api/v1/crates/unicode-normalization/0.1.26)
- docs.rs "latest" resolves to `"version": "0.1.26"` (default platform x86_64-unknown-linux-gnu), and the docs.rs item pages for 0.1.26 all return HTTP 200, so the docs built. — [docs.rs latest](https://docs.rs/crate/unicode-normalization/latest)
- GitHub tag `v0.1.26` points to commit `16c9597b73ec5b6b8ed55f4249a5ac854892544c` ("Release 0.1.26", committed 2026-10-16T23:28:01Z). That commit was also the newest commit on `master` at query time, and the tarball's `.cargo_vcs_info.json` records the same sha1. — [GitHub tags](https://github.com/unicode-rs/unicode-normalization/tags); [commit 16c9597](https://github.com/unicode-rs/unicode-normalization/commit/16c9597b73ec5b6b8ed55f4249a5ac854892544c); [commits on master](https://github.com/unicode-rs/unicode-normalization/commits/master); [0.1.26 tarball](https://static.crates.io/crates/unicode-normalization/unicode-normalization-0.1.26.crate)
- Issue #118 "Upload to crates.io for Unicode 18" was opened by sayrer at 2026-10-16T23:16:48Z ("This seems done on main, just not published."). Manishearth replied "Done!" at 2026-10-16T23:28:46Z and closed it, which matches the crates.io timestamp. — [issue #118](https://github.com/unicode-rs/unicode-normalization/issues/118)
- The repository publishes no GitHub Releases (the API returns an empty list). Tags exist for v0.1.22, v0.1.23, v0.1.24 and v0.1.26, but there is **no v0.1.25 tag**. The 0.1.25 tarball's `.cargo_vcs_info.json` points to `5a69b3bafb625caccdec7871a42bed0d9a6604d1`, the merge commit of PR #115 "Release 0.1.25". — [releases API](https://api.github.com/repos/unicode-rs/unicode-normalization/releases); [tags](https://github.com/unicode-rs/unicode-normalization/tags); [0.1.25 tarball](https://static.crates.io/crates/unicode-normalization/unicode-normalization-0.1.25.crate); [commit 5a69b3b](https://github.com/unicode-rs/unicode-normalization/commit/5a69b3bafb625caccdec7871a42bed0d9a6604d1)
- The project's `Cargo.lock` (lines 206-209) already contains `name = "unicode-normalization"`, `version = "0.1.26"` and `checksum = "75cd3fb03d5288b3ba9a1ee103ac7e9cbb59f0b03d64f8ddfcc04dd42758a85d"`, the same value as the registry. — local file `Cargo.lock`; registry: [crates.io API: 0.1.26](https://crates.io/api/v1/crates/unicode-normalization/0.1.26)

### Inferences
- The version number and the publish date are real, not hallucinated. The `# 2026-10-16` comment on `Cargo.toml` line 20 matches the UTC publish date.
- Because `Cargo.lock` holds the genuine registry checksum, the dependency was resolved against the real crates.io index. Nothing points to "stand-in" APIs.

### Gaps
- The human-facing crates.io page (`https://crates.io/crates/unicode-normalization/0.1.26`) returned HTTP 404 to a non-browser client, because it is a JavaScript single-page app. All crates.io facts above therefore come from the JSON API.

## 2. Which Unicode version do 0.1.26 and the latest version implement, and is it exposed as a public constant?

### Takeaway
0.1.26, which is also the latest version, implements **Unicode 18.0.0**. SPEC.md says Unicode 16.0, which is wrong: 16.0.0 was implemented by 0.1.24. The version is public as **`unicode_normalization::UNICODE_VERSION`**, its type is **`(u8, u8, u8)`**, and its value is **`(18, 0, 0)`**.

### Cited Findings
- docs.rs renders the declaration as follows, without the value. The constant is listed at the crate root. — [docs.rs: constant UNICODE_VERSION](https://docs.rs/unicode-normalization/0.1.26/unicode_normalization/constant.UNICODE_VERSION.html); [docs.rs: crate index](https://docs.rs/unicode-normalization/0.1.26/unicode_normalization/index.html)

```rust
pub const UNICODE_VERSION: (u8, u8, u8);
```

- `lib.rs` line 64 re-exports it at the crate root: `pub use crate::tables::UNICODE_VERSION;`. — [GitHub v0.1.26 lib.rs#L64](https://github.com/unicode-rs/unicode-normalization/blob/v0.1.26/src/lib.rs#L64)
- The value is on line 18 of the generated `src/tables.rs`: `pub const UNICODE_VERSION: (u8, u8, u8) = (18, 0, 0);`. — [docs.rs source: 0.1.26 src/tables.rs](https://docs.rs/crate/unicode-normalization/0.1.26/source/src/tables.rs)
- The generator `scripts/unicode.py` sets `UNICODE_VERSION = "18.0.0"` on line 25 and `UCD_URL = "https://www.unicode.org/Public/%s/ucd/" % UNICODE_VERSION` on line 26. Lines 591-593 write `#[allow(unused)]` followed by `pub const UNICODE_VERSION: (u8, u8, u8) = %s;`. — [GitHub v0.1.26 scripts/unicode.py](https://github.com/unicode-rs/unicode-normalization/blob/v0.1.26/scripts/unicode.py#L25)
- `UNICODE_VERSION` in each published crate (tables.rs line 18):
  - 0.1.22: `(15, 0, 0)` — [0.1.22 tables.rs](https://docs.rs/crate/unicode-normalization/0.1.22/source/src/tables.rs)
  - 0.1.23: `(15, 1, 0)` — [0.1.23 tables.rs](https://docs.rs/crate/unicode-normalization/0.1.23/source/src/tables.rs)
  - 0.1.24: `(16, 0, 0)` — [0.1.24 tables.rs](https://docs.rs/crate/unicode-normalization/0.1.24/source/src/tables.rs)
  - 0.1.25: `(17, 0, 0)` — [0.1.25 tables.rs](https://docs.rs/crate/unicode-normalization/0.1.25/source/src/tables.rs)
  - 0.1.26: `(18, 0, 0)` — [0.1.26 tables.rs](https://docs.rs/crate/unicode-normalization/0.1.26/source/src/tables.rs)
- The Unicode 18 update came from PR #117 "feat: Update to Unicode 18.0.0" by Martin005 (commit `1a63a4819b`, 2026-09-18T12:21:42Z). It was merged at 2026-09-18T16:24:44Z as `222d8d61ed`, followed by a "fmt" commit `b77212b847`. — [PR #117](https://github.com/unicode-rs/unicode-normalization/pull/117); [commit 1a63a48](https://github.com/unicode-rs/unicode-normalization/commit/1a63a4819b); [commits on master](https://github.com/unicode-rs/unicode-normalization/commits/master)
- Between the 0.1.25 and 0.1.26 tarballs, only these files changed:
  - the version string in `scripts/unicode.py`
  - the regenerated `src/tables.rs` (9,801 changed lines in a plain `diff`)
  - the `version` and `license` fields in `Cargo.toml`
  - a new `LICENSE-UNICODE` file

  No other `.rs` file changed. — [0.1.25 tarball](https://static.crates.io/crates/unicode-normalization/unicode-normalization-0.1.25.crate); [0.1.26 tarball](https://static.crates.io/crates/unicode-normalization/unicode-normalization-0.1.26.crate)
- Upstream CI has a `regen` job. It runs `cd scripts && python3 unicode.py`, then `diff src/tables.rs scripts/tables.rs` and `diff tests/data/normalization_tests.rs scripts/normalization_tests.rs`, so the committed tables and tests must match a fresh UCD regeneration. — [GitHub v0.1.26 .github/workflows/rust.yml](https://github.com/unicode-rs/unicode-normalization/blob/v0.1.26/.github/workflows/rust.yml)
- The local `SPEC.md` line 15 reads "...record the Unicode version the pinned `unicode-normalization` crate implements (`unicode-normalization = "=0.1.26"`, Unicode 16.0)." — local file `SPEC.md`

### Inferences
- SPEC.md line 15 is wrong and must say Unicode 18.0.0. This is a documentation defect against the SPEC's own requirement to record the Unicode version. It does not affect compilation.
- `UNICODE_VERSION` is a plain tuple constant, so a test can pin it exactly. If a future crate bump changes the NFC data, CI would then fail loudly instead of digests silently drifting. (§7 gives the code.)
- Peers that canonicalize with older Unicode data, such as other JCS implementations, JS engines or Python `unicodedata`, can disagree with pep-sidecar on characters encoded in Unicode 16 to 18. §6 (issue #105) has a concrete example. The general rule that NFC never changes for previously assigned characters comes from Unicode's normalization stability policy, which was not verified here because only docs.rs, crates.io and GitHub were in scope.

### Gaps
- SPEC.md says the conformance vectors were "recomputed independently in Python". I did not check which Unicode version that Python's `unicodedata` uses, because that is outside the allowed sources. If any vector contains a character newer than that Python's UCD, the cross-check would not be meaningful for that vector.

## 3. MSRV (`rust-version`), edition, and features (`std` default; no_std/alloc behaviour), pinned and latest (same release)

### Takeaway
0.1.26 declares `rust-version = "1.36"` and `edition = "2018"`. Its features are `default = ["std"]` and `std = []`. It has no build script and no target-specific code. Disabling `std` makes the crate `#![no_std]`, but it **still requires `alloc`**. None of this conflicts with the project's MSRV 1.88, its Rust 1.97.0 toolchain, or the x86_64-unknown-linux-gnu and aarch64-apple-darwin targets.

### Cited Findings
- `Cargo.toml.orig` in 0.1.26:
  - line 14: `license = "(MIT OR Apache-2.0) AND Unicode-3.0"`
  - line 30: `rust-version = "1.36"`
  - line 32: `edition = "2018"`
  - lines 36-38: `[dependencies.tinyvec]` with `version = "1"` and `features = ["alloc"]`
  - lines 41-43: `[features]` with `default = ["std"]` and `std = []`

  — [docs.rs source: 0.1.26 Cargo.toml.orig](https://docs.rs/crate/unicode-normalization/0.1.26/source/Cargo.toml.orig); [GitHub v0.1.26 Cargo.toml](https://github.com/unicode-rs/unicode-normalization/blob/v0.1.26/Cargo.toml)
- crates.io agrees: `rust_version: 1.36`, `edition: 2018`, and features `{"default":["std"],"std":[]}`. That feature map has been the same since 0.1.13; 0.1.12 and earlier have `{}`. — [crates.io API: versions](https://crates.io/api/v1/crates/unicode-normalization/versions?per_page=100)
- `rust-version` was first declared in 0.1.24. crates.io shows no `rust_version` for 0.1.23 or earlier, and the diff from the 0.1.23 tarball to the 0.1.24 tarball adds `rust-version = "1.36"`. — [crates.io API: versions](https://crates.io/api/v1/crates/unicode-normalization/versions?per_page=100); [0.1.24 tarball](https://static.crates.io/crates/unicode-normalization/unicode-normalization-0.1.24.crate)
- docs.rs's feature page lists `default` and `std`. — [docs.rs: 0.1.26 features](https://docs.rs/crate/unicode-normalization/0.1.26/features)
- How no_std works: `lib.rs` line 45 has `#![cfg_attr(not(feature = "std"), no_std)]`, and lines 47-48 have `#[cfg(not(feature = "std"))] extern crate alloc;`. The `std` feature has no dependencies (`std = []`), so all it does is turn `no_std` off. — [GitHub v0.1.26 lib.rs#L45-L48](https://github.com/unicode-rs/unicode-normalization/blob/v0.1.26/src/lib.rs#L45-L48)
- The README says: "This crate is completely `no_std` + `alloc` compatible. This can be enabled by disabling the `std` feature, i.e. specifying `default-features = false` for this crate on your `Cargo.toml`." Its "Note about MSRV" section, added in 0.1.25, says: "Dependencies' MSRVs evolve independently of this crate's MSRV ... For instance, to compile on Rust 1.36, `tinyvec` must be `<=1.6.0`". — [GitHub v0.1.26 README.md](https://github.com/unicode-rs/unicode-normalization/blob/v0.1.26/README.md)
- The only dependency is `tinyvec` with requirement `^1`: kind normal, `optional: false`, `default_features: true`, features `alloc`. — [crates.io API: 0.1.26 dependencies](https://crates.io/api/v1/crates/unicode-normalization/0.1.26/dependencies)
- No feature removes the `alloc` requirement, and issue #58 "Support #![no_std] without liballoc" (opened 2020-05-21) is still open. — [issue #58](https://github.com/unicode-rs/unicode-normalization/issues/58)
- tinyvec's latest stable version is 1.13.3 (2026-09-13). Versions 1.11.0 through 1.13.3 declare no `rust_version`, and all use edition 2018. — [crates.io API: tinyvec versions](https://crates.io/api/v1/crates/tinyvec/versions)
- The project lock resolves `tinyvec` 1.13.3 with checksum `fd3ca314f692efd6c868f8408f53fe444634a845f96c028b97d35f6a1f79f0ee` (local `Cargo.lock` lines 188-191).
- The crate has no build script: the normalized `Cargo.toml` in the tarball says `build = false`. A search of `src/` found no `cfg(target_…)` attributes. — [0.1.26 tarball](https://static.crates.io/crates/unicode-normalization/unicode-normalization-0.1.26.crate)
- Unsafe code in the crate:
  - `lib.rs` line 40: `#![deny(missing_docs, unsafe_code)]` — [GitHub v0.1.26 lib.rs#L40](https://github.com/unicode-rs/unicode-normalization/blob/v0.1.26/src/lib.rs#L40)
  - `normalize.rs` re-allows it locally: `#[allow(unsafe_code)]` at lines 75 and 183, and `#[allow(unsafe_code, unused_unsafe)]` on `unsafe fn decompose_hangul` at lines 143-145.
  - The unsafe calls are `char::from_u32_unchecked` in Hangul composition and decomposition (lines 201 and 208), each with a safety comment.

  — [GitHub v0.1.26 normalize.rs](https://github.com/unicode-rs/unicode-normalization/blob/v0.1.26/src/normalize.rs)
- Upstream CI for 0.1.26:
  - environment: `RUSTFLAGS: -D warnings` and `RUSTDOCFLAGS: -D warnings --cfg docsrs`
  - build/test matrix: `os: [ ubuntu-latest, windows-latest ]` × Rust {the MSRV from `package.rust_version`, stable, beta, nightly}
  - the MSRV row runs `cargo update -p tinyvec --precise 1.6.0`
  - clippy and rustfmt run on stable

  — [GitHub v0.1.26 rust.yml](https://github.com/unicode-rs/unicode-normalization/blob/v0.1.26/.github/workflows/rust.yml)

### Inferences
- 1.36 ≤ 1.88 (project MSRV) ≤ 1.97.0 (toolchain), so the crate creates no MSRV conflict. Editions are set per crate, so an edition-2018 dependency works inside an edition-2024 package (general Rust behaviour, not re-verified here).
- The crate is pure Rust with no build script and no target cfgs. `cargo clippy --target aarch64-apple-darwin` therefore treats it like any other dependency.
- `RUSTFLAGS='-D warnings'` should not break on this dependency. Cargo caps lints for registry dependencies (general Cargo behaviour, not verified within the allowed sources), and upstream CI builds with `-D warnings` on stable, beta and nightly anyway.
- pep-sidecar's `unsafe_code = "forbid"` applies only to pep-sidecar itself. The dependency contains a small amount of commented `unsafe` in the Hangul code paths. Record that in a dependency audit; it does not affect compilation.
- 0.1.26 adds `Unicode-3.0` to the license expression (PR #116). There is no `deny.toml` in the repository today, but a license allowlist added later (cargo-deny or cargo-about) must allow `Unicode-3.0`.

### Gaps
- I did not verify that tinyvec 1.13.3 compiles on Rust 1.88 exactly, because tinyvec declares no `rust-version`. This does not matter for the pinned 1.97.0 toolchain.

## 4. Exact signatures of `is_nfc_quick`, `IsNormalized`, `UnicodeNormalization` (and impls) and `Recompositions` (docs.rs 0.1.26, verbatim)

### Takeaway
Every item the call site imports exists at the crate root with the shape the code assumes:
- `is_nfc_quick<I: Iterator<Item = char>>(s: I) -> IsNormalized`.
- `IsNormalized` has three variants (`Yes`, `No`, `Maybe`) and derives only `Debug`, `Eq` and `PartialEq`. It is not `Clone` or `Copy`.
- `UnicodeNormalization<I: Iterator<Item = char>>` has `fn nfc(self) -> Recompositions<I>`. It is implemented for `&'a str` (with `Chars<'a>`), for `char`, and for any `char` iterator, but **not for `String`**.
- `Recompositions<I>` implements `Iterator<Item = char>`.

### Cited Findings
- `is_nfc_quick`, as docs.rs renders it: — [docs.rs: fn is_nfc_quick](https://docs.rs/unicode-normalization/0.1.26/unicode_normalization/fn.is_nfc_quick.html)

```rust
pub fn is_nfc_quick<I: Iterator<Item = char>>(s: I) -> IsNormalized
```

- In the source (`quick_check.rs` lines 71-77) the function also carries `#[inline]` and the doc comment "Quickly check if a string is in NFC, potentially returning `IsNormalized::Maybe` if further checks are necessary. In this case a check like `s.chars().nfc().eq(s.chars())` should suffice." — [GitHub v0.1.26 quick_check.rs#L71-L77](https://github.com/unicode-rs/unicode-normalization/blob/v0.1.26/src/quick_check.rs#L71-L77)
- The quick-check algorithm is in `quick_check.rs` lines 22-69, commented `// https://unicode.org/reports/tr15/#Detecting_Normalization_Forms`:
  - ASCII characters (`ch <= '\x7f'`) reset `last_cc` and are skipped.
  - `if last_cc > cc && cc != 0 { return IsNormalized::No; }`
  - A per-character table lookup that returns `No` makes the function return `No`; one that returns `Maybe` downgrades the result to `Maybe`.
  - `Yes` is returned only when no character produced `No` or `Maybe`.

  — [GitHub v0.1.26 quick_check.rs#L22-L69](https://github.com/unicode-rs/unicode-normalization/blob/v0.1.26/src/quick_check.rs#L22-L69)
- `IsNormalized`, with the trait implementations docs.rs lists for it: — [docs.rs: enum IsNormalized](https://docs.rs/unicode-normalization/0.1.26/unicode_normalization/enum.IsNormalized.html)

```rust
pub enum IsNormalized {
    Yes,
    No,
    Maybe,
}
```

```text
impl Debug for IsNormalized
impl Eq for IsNormalized
impl PartialEq for IsNormalized
impl StructuralPartialEq for IsNormalized
```

- docs.rs also lists the auto traits `Freeze`, `RefUnwindSafe`, `Send`, `Sync`, `Unpin`, `UnsafeUnpin` and `UnwindSafe`, plus the standard blanket impls (`Any`, `Borrow`, `From`, `Into`, `TryFrom`, `TryInto`). — [docs.rs: enum IsNormalized](https://docs.rs/unicode-normalization/0.1.26/unicode_normalization/enum.IsNormalized.html)
- The source declares `#[derive(Debug, Eq, PartialEq)]`. The variant docs are: `Yes`, "The text is definitely normalized."; `No`, "The text is definitely not normalized."; `Maybe`, "The text may be normalized.". There is no `Clone`, `Copy` or `Hash`, and the enum is not `#[non_exhaustive]`. — [GitHub v0.1.26 quick_check.rs#L6-L20](https://github.com/unicode-rs/unicode-normalization/blob/v0.1.26/src/quick_check.rs#L6-L20)
- `UnicodeNormalization` trait, as docs.rs renders it. The `ⓘ` is rustdoc's "notable traits" marker, not part of the signature. — [docs.rs: trait UnicodeNormalization](https://docs.rs/unicode-normalization/0.1.26/unicode_normalization/trait.UnicodeNormalization.html)

```rust
pub trait UnicodeNormalization<I: Iterator<Item = char>> {
    // Required methods
    fn nfd(self) -> Decompositions<I> ⓘ;
    fn nfkd(self) -> Decompositions<I> ⓘ;
    fn nfc(self) -> Recompositions<I> ⓘ;
    fn nfkc(self) -> Recompositions<I> ⓘ;
    fn cjk_compat_variants(self) -> Replacements<I> ⓘ;
    fn stream_safe(self) -> StreamSafe<I> ⓘ;
}
```

- In the source the trait is at `lib.rs` lines 99-136, with `fn nfc(self) -> Recompositions<I>;` on line 110. Its doc text is "An Iterator over the string in Unicode Normalization Form C (canonical decomposition followed by canonical composition)." — [GitHub v0.1.26 lib.rs#L99-L136](https://github.com/unicode-rs/unicode-normalization/blob/v0.1.26/src/lib.rs#L99-L136)
- Implementors listed on docs.rs (all of them): — [docs.rs: trait UnicodeNormalization](https://docs.rs/unicode-normalization/0.1.26/unicode_normalization/trait.UnicodeNormalization.html)

```rust
impl UnicodeNormalization<IntoIter<char>> for char
impl<'a> UnicodeNormalization<Chars<'a>> for &'a str
impl<I: Iterator<Item = char>> UnicodeNormalization<I> for I
```

- In the source:
  - `IntoIter` is `core::option::IntoIter` and `Chars` is `core::str::Chars` (`use core::{option, str::Chars};` on line 65).
  - The `&'a str` impl is at lines 138-168, with `fn nfc(self) -> Recompositions<Chars<'a>> { Recompositions::new_canonical(self.chars()) }` at lines 149-152.
  - The `char` impl starts at line 170 and the blanket impl at line 202.
  - There is **no** impl for `String`, `&String`, `str` or `Cow<str>`.

  — [GitHub v0.1.26 lib.rs#L138-L232](https://github.com/unicode-rs/unicode-normalization/blob/v0.1.26/src/lib.rs#L138-L232)
- `Recompositions` declaration and its trait implementations on docs.rs. docs.rs also lists the blankets `impl<T> ToString for T where T: Display + ?Sized` and `impl<I> UnicodeNormalization<I> for I where I: Iterator<Item = char>,`. — [docs.rs: struct Recompositions](https://docs.rs/unicode-normalization/0.1.26/unicode_normalization/struct.Recompositions.html)

```rust
pub struct Recompositions<I> { /* private fields */ }
```

```rust
impl<I: Iterator<Item = char>> Recompositions<I>
impl<I: Clone> Clone for Recompositions<I>
impl<I: Iterator<Item = char> + Clone> Display for Recompositions<I>
impl<I: Iterator<Item = char> + FusedIterator> FusedIterator for Recompositions<I>
impl<I: Iterator<Item = char>> Iterator for Recompositions<I>
```

- In `recompose.rs`:
  - The `Iterator` impl is `impl<I: Iterator<Item = char>> Iterator for Recompositions<I> { type Item = char; ... }` (lines 67-68).
  - The public constructors are `pub fn new_canonical(iter: I) -> Self` (line 41) and `pub fn new_compatible(iter: I) -> Self` (line 56).
  - The `FusedIterator` impl is on line 160 and the `Display` impl on line 162.

  — [GitHub v0.1.26 recompose.rs](https://github.com/unicode-rs/unicode-normalization/blob/v0.1.26/src/recompose.rs)
- Items at the docs.rs crate root:
  - module: `char`
  - structs: `Decompositions`, `Recompositions`, `Replacements`, `StreamSafe`
  - enum: `IsNormalized`
  - constant: `UNICODE_VERSION`
  - trait: `UnicodeNormalization`
  - functions: `is_nfc`, `is_nfc_quick`, `is_nfc_stream_safe`, `is_nfc_stream_safe_quick`, `is_nfd`, `is_nfd_quick`, `is_nfd_stream_safe`, `is_nfd_stream_safe_quick`, `is_nfkc`, `is_nfkc_quick`, `is_nfkd`, `is_nfkd_quick`

  — [docs.rs: crate index](https://docs.rs/unicode-normalization/0.1.26/unicode_normalization/index.html)
- The re-exports are at `lib.rs` lines 55-64: `pub use crate::quick_check::{ is_nfc, is_nfc_quick, ..., IsNormalized, };` and `pub use crate::recompose::Recompositions;`. — [GitHub v0.1.26 lib.rs#L55-L64](https://github.com/unicode-rs/unicode-normalization/blob/v0.1.26/src/lib.rs#L55-L64)
- The crate's own doc example normalizes a `&str` with `let c = s.nfc().collect::<String>();`. — [GitHub v0.1.26 lib.rs#L15-L28](https://github.com/unicode-rs/unicode-normalization/blob/v0.1.26/src/lib.rs#L15-L28)

### Inferences
- `text.nfc()` with `text: String` resolves through method-call autoderef, applying standard Rust method-resolution rules to the impl set verified above:
  - `String`, `&String` and `&mut String` fail the blanket impl's `I: Iterator<Item = char>` bound.
  - The compiler then derefs to `str` and autorefs to `&str`, which selects `impl<'a> UnicodeNormalization<Chars<'a>> for &'a str`.
  - The result is `Recompositions<Chars<'_>>`, which borrows `text`.
- `.collect()` takes `String` from the function's return type. `String: FromIterator<char>` holds and `Recompositions<Chars>` has `Item = char`, so this compiles. `text.nfc().to_string()` would also work through `Display`, because `Chars: Clone`, but there is no reason to change.
- `matches!(…, IsNormalized::Yes)` compiles. `== IsNormalized::Yes` would compile too, because the enum derives `PartialEq`.
- Only `Yes` is a definitive answer. `No` and `Maybe` both take the full `nfc()` path, so the fast path cannot let non-NFC text through as long as the quick-check tables are correct (see §6).

### Gaps
- The auto-trait list docs.rs shows (for example `UnsafeUnpin`) comes from docs.rs's own rustdoc toolchain, not from a promise in the crate's API. It does not matter for this call site.

## 5. Breaking or notable changes 0.1.22 → 0.1.26 affecting these items

### Takeaway
**Nothing the call site uses changed in a breaking way from 0.1.22 to 0.1.26.** The releases consist of:
- Unicode data bumps: 15.0 → 15.1 → 16.0 → 17.0 → 18.0
- additive API: public iterator constructors and `FusedIterator` impls
- license metadata changes
- the MSRV declaration
- CI changes

There is no CHANGELOG, so the history below was rebuilt from diffs of the published tarballs and from the commit and PR history.

### Cited Findings
- There is no CHANGELOG file at the repository root, which contains `.github`, `.gitignore`, `.travis.yml`, `COPYRIGHT`, `Cargo.toml`, `LICENSE-APACHE`, `LICENSE-MIT`, `LICENSE-UNICODE`, `README.md`, `benches`, `fuzz`, `scripts`, `src` and `tests`. There are no GitHub Releases either. — [GitHub contents API](https://api.github.com/repos/unicode-rs/unicode-normalization/contents/); [releases API](https://api.github.com/repos/unicode-rs/unicode-normalization/releases)
- **0.1.22** (2022-09-16): Unicode 15.0.0 (PR #89, commit `b0610c9791`). — [PR #89](https://github.com/unicode-rs/unicode-normalization/pull/89)
- **0.1.22 → 0.1.23** (2024-02-20):
  - Unicode 15.1.0 (commit `2810fe2c63` "Bump Unicode to version 15.1.0, regenerate tables", PR #91).
  - A new CI `regen` job (commit `af878a3f5c`).
  - The tarball diff touches only version strings, the README, `unicode.py`, CI and 8 lines of `tables.rs`. `lib.rs`, `quick_check.rs` and `recompose.rs` are byte-identical.

  — [PR #91](https://github.com/unicode-rs/unicode-normalization/pull/91); [0.1.22 tarball](https://static.crates.io/crates/unicode-normalization/unicode-normalization-0.1.22.crate); [0.1.23 tarball](https://static.crates.io/crates/unicode-normalization/unicode-normalization-0.1.23.crate)
- **0.1.23 → 0.1.24** (2024-09-17):
  - Unicode 16.0.0 (PR #103, commit `fdfe8e02ea` "Update Unicode to version 16.0.0, bump to 0.1.24").
  - `rust-version = "1.36"` added.
  - `FusedIterator` impls for `Decompositions`, `Recompositions`, `Replacements` and `StreamSafe` (PR #94, commit `c8ab427dd2` "Add missing `FusedIterator` impls").
  - The private free functions `decompose::new_canonical`/`new_compatible` and `recompose::new_canonical`/`new_compatible` became the public inherent constructors `Decompositions::new_canonical`/`new_compatible` and `Recompositions::new_canonical`/`new_compatible` (PR #101, commit `154ebfc06c` "Directly expose constructors for iterators rather than relying on hard-to-discover trait stuff").
  - Safety comments were added and `decompose_hangul` became an `unsafe fn` (PR #100, commit `a97388a047`).
  - Generated tables now use `..=` and are rustfmt-clean (PR #96, commits `42fd2c191a` and `061dc3c934`), and `#[rustfmt::skip]` was removed from `mod tables`.
  - The internal `no_std_prelude` module was removed.
  - The composition-table generator was fixed (commit `99d6e46cfb`, see §6).
  - In `lib.rs`, only the constructor call paths inside the impl bodies changed; trait and impl signatures are identical. `quick_check.rs` gained only doc-comment lines.

  — [PR #103](https://github.com/unicode-rs/unicode-normalization/pull/103); [PR #94](https://github.com/unicode-rs/unicode-normalization/pull/94); [PR #101](https://github.com/unicode-rs/unicode-normalization/pull/101); [PR #100](https://github.com/unicode-rs/unicode-normalization/pull/100); [PR #96](https://github.com/unicode-rs/unicode-normalization/pull/96); [0.1.24 tarball](https://static.crates.io/crates/unicode-normalization/unicode-normalization-0.1.24.crate)
- **0.1.24 → 0.1.25** (2025-10-30):
  - Unicode 17.0.0 (PR #113, commit `01f4bd6383`).
  - The license string changed from `MIT/Apache-2.0` to the SPDX form `MIT OR Apache-2.0` (PR #104, commit `0772fc9104`).
  - `Replacements::new_cjk_compat_variants` and `StreamSafe::new` became public (PR #106, commit `5b31ba1aa8` "Expose all iterator constructors, add hyperlinks to Unicode glossary/technical reports"). `StreamSafe`'s inherent impl changed from `impl<I> StreamSafe<I>` to `impl<I: Iterator<Item = char>> StreamSafe<I>`.
  - A README MSRV note was added and CI was reworked (PR #112, commit `c7a2cc5d5a`).
  - Doc links were fixed.
  - Nothing used by the call site changed.

  — [PR #113](https://github.com/unicode-rs/unicode-normalization/pull/113); [PR #104](https://github.com/unicode-rs/unicode-normalization/pull/104); [PR #106](https://github.com/unicode-rs/unicode-normalization/pull/106); [PR #112](https://github.com/unicode-rs/unicode-normalization/pull/112); [0.1.25 tarball](https://static.crates.io/crates/unicode-normalization/unicode-normalization-0.1.25.crate)
- **0.1.25 → 0.1.26** (2026-10-16):
  - Unicode 18.0.0 (PR #117).
  - The license became `(MIT OR Apache-2.0) AND Unicode-3.0` and a `LICENSE-UNICODE` file was added (PR #116, commit `277de760b3` "Add Unicode-3.0 license for Unicode data").
  - No `.rs` file changed except the regenerated `tables.rs`.

  — [PR #116](https://github.com/unicode-rs/unicode-normalization/pull/116); [PR #117](https://github.com/unicode-rs/unicode-normalization/pull/117); [compare v0.1.24...v0.1.26](https://github.com/unicode-rs/unicode-normalization/compare/v0.1.24...v0.1.26)
- Open, unreleased work: PR #114 "Track position where normalization failed" (open since 2025-10-08) and issue #111 "Version 1.0.0?" (open since 2025-08-02). — [GitHub issues API](https://api.github.com/repos/unicode-rs/unicode-normalization/issues?state=all&per_page=100)

### Inferences
- The call site would compile unchanged against any release from 0.1.22 to 0.1.26. Only the Unicode data differs between these releases, and with it the NFC output for newly encoded characters. That is why the pin must stay exact (`=`) and why the Unicode version must be recorded.

### Gaps
- These diffs compare published tarballs. `Cargo.toml.orig` line 34 excludes `tests/*` from the package, so changes that touched only the repository's tests are not visible here. — [docs.rs source: 0.1.26 Cargo.toml.orig](https://docs.rs/crate/unicode-normalization/0.1.26/source/Cargo.toml.orig)

## 6. Known correctness bugs in the official tracker (NFC composition, `is_nfc_quick`)

### Takeaway
I found **no issue or PR, open or closed, that reports `is_nfc_quick` wrongly returning `Yes` or a composition-exclusion error**. The only open report about NFC output (#105, against ICU4X) was put down to different Unicode versions, and the crate's outputs in that report match its own Unicode 16+ tables. A real composition-table generator bug was fixed in 0.1.24, so it does not affect 0.1.26.

### Cited Findings
- Issue #105 "Weird discrepancy with ICU4X" (aumetra, opened 2024-10-09, still open):
  - NFC of `"\u{11366}\u{113ce}"` gives `"\u{113ce}\u{11366}"` in unicode-normalization, but `icu_normalizer` leaves it unchanged.
  - `"\u{113c2}\u{113b8}"` becomes `"\u{113c7}"` in unicode-normalization, but ICU4X leaves it unchanged.
  - Manishearth commented: "This crate hasn't been updated to Unicode 16.0 yet. Doing so is not super straightforward this time due to some of the newer characters having interesting combinations of properties."
  - The reporter answered: "Good to know this is due to a new standard revision and not due to a bug".

  — [issue #105](https://github.com/unicode-rs/unicode-normalization/issues/105)
- The 0.1.26 tables store each canonical combining class (ccc) as `(code point << 8) | ccc`; the generator expression is `f"0x{int(combining_classes[k]) | (k << 8):07X}"`.
  - `0x11366E6` (tables.rs line 152) means ccc(U+11366) = 230.
  - `0x113CE09` (line 219) means ccc(U+113CE) = 9.
  - `composition_table_astral` contains `('\u{113C2}', '\u{113B8}') => Some('\u{113C7}'),` (line 1248).

  — [docs.rs source: 0.1.26 tables.rs](https://docs.rs/crate/unicode-normalization/0.1.26/source/src/tables.rs); [GitHub v0.1.26 scripts/unicode.py](https://github.com/unicode-rs/unicode-normalization/blob/v0.1.26/scripts/unicode.py)
- Commit `99d6e46cfb` "Fix composition table" (2024-09-17, part of PR #103, shipped in 0.1.24):
  - It changed the generator condition from `if c1 >= 0x10000 and c2 >= 0x10000:` to `if c1 >= 0x10000 or c2 >= 0x10000:`.
  - This added the mixed astral-plus-BMP pairs `('\u{105D2}', '\u{0307}') => Some('\u{105C9}')` and `('\u{105DA}', '\u{0307}') => Some('\u{105E4}')` to `composition_table_astral`.

  — [commit 99d6e46](https://github.com/unicode-rs/unicode-normalization/commit/99d6e46cfb); [PR #103](https://github.com/unicode-rs/unicode-normalization/pull/103)
- Issue #108 "nfd() problem" was closed as user error: the reporter misused `Iterator::reduce`, and the maintainer replied "This crate does not implement `reduce()`, it gets it from the standard library". — [issue #108](https://github.com/unicode-rs/unicode-normalization/issues/108)
- A body-text search of the tracker found nothing that reports a quick-check or composition-exclusion error:
  - `is_nfc_quick`: #58 (no_std without liballoc) and #67 (recomposition-buffer PR).
  - "quick check": #114, #29, #67, #38, #33 and #36.
  - "composition exclusion": only #38 (a test-tarball problem).
  - "is_nfc wrong": no hits.

  — [search: is_nfc_quick](https://api.github.com/search/issues?q=repo%3Aunicode-rs%2Funicode-normalization%20is_nfc_quick); [search: quick check](https://api.github.com/search/issues?q=repo%3Aunicode-rs%2Funicode-normalization%20quick%20check); [search: composition exclusion](https://api.github.com/search/issues?q=repo%3Aunicode-rs%2Funicode-normalization%20composition%20exclusion)
- The other open items are not correctness bugs:
  - #119 "StreamSafe: carry the non-starter count across separate inputs (chunked streams)", opened 2026-10-27; a feature request about the `StreamSafe` API, which pep-sidecar does not use.
  - #99 "collect optimization ?"
  - #57 "10x slower performance over ICU"
  - #29 "Long compilation time"

  — [issue #119](https://github.com/unicode-rs/unicode-normalization/issues/119); [GitHub issues API](https://api.github.com/repos/unicode-rs/unicode-normalization/issues?state=all&per_page=100)

### Inferences
- In #105 the crate behaves exactly as its 0.1.26 tables predict: canonical reordering puts ccc 9 before ccc 230, and U+113C2 + U+113B8 composes to U+113C7. The divergence most likely came from ICU4X running older data at the time. I did not verify this, because ICU4X is outside the allowed sources.
- The maintainer's "hasn't been updated to Unicode 16.0 yet" conflicts with crates.io, which shows 0.1.24 (Unicode 16.0.0) published on 2024-09-17, three weeks before the report.
- The relevant risk for pep-sidecar is Unicode-version skew between peers, not a crate bug. Two correct normalizers on different Unicode versions produce different bytes for newly encoded characters, and therefore different `sha-256:` digests. Recording and testing `(18, 0, 0)` makes that skew visible.
- The 0.1.24 generator fix shows that 0.1.23 and earlier would have missed mixed BMP/astral composition pairs. Such pairs first appear in the Unicode 16.0 data, and the pinned 0.1.26 includes the fix.

### Gaps
- I did not run the Unicode 18.0.0 `NormalizationTest.txt` against 0.1.26 myself; the conformance tests are excluded from the published crate. I relied on upstream CI's `regen` job, which diffs regenerated tables and tests against the committed ones, and on its test jobs.

## 7. Verdict for the `src/jcs.rs` call site and the `=0.1.26` pin

### Takeaway
**Verdict: compiles as-is.** The pin `unicode-normalization = "=0.1.26"` resolves: the version exists, is not yanked, is the newest release, and its checksum is already in `Cargo.lock`. The import `use unicode_normalization::{IsNormalized, UnicodeNormalization as _, is_nfc_quick};` and `fn nfc` match the real 0.1.26 API exactly. **No Rust change is needed.** One documentation fix is required: SPEC.md line 15 says Unicode 16.0, but the pinned crate implements **Unicode 18.0.0**.

### Cited Findings
The table maps each element of the call site to the real API. Sources: [docs.rs: enum IsNormalized](https://docs.rs/unicode-normalization/0.1.26/unicode_normalization/enum.IsNormalized.html); [docs.rs: fn is_nfc_quick](https://docs.rs/unicode-normalization/0.1.26/unicode_normalization/fn.is_nfc_quick.html); [docs.rs: trait UnicodeNormalization](https://docs.rs/unicode-normalization/0.1.26/unicode_normalization/trait.UnicodeNormalization.html); [docs.rs: struct Recompositions](https://docs.rs/unicode-normalization/0.1.26/unicode_normalization/struct.Recompositions.html); [GitHub v0.1.26 recompose.rs#L67-L68](https://github.com/unicode-rs/unicode-normalization/blob/v0.1.26/src/recompose.rs#L67-L68); [crates.io API: 0.1.26](https://crates.io/api/v1/crates/unicode-normalization/0.1.26)

| Call-site element (local `src/jcs.rs` lines 11 and 644-650; `Cargo.toml` line 20) | Real 0.1.26 API | Status |
|---|---|---|
| `use unicode_normalization::IsNormalized` | crate-root `pub enum IsNormalized { Yes, No, Maybe }` | OK |
| `use unicode_normalization::is_nfc_quick` | `pub fn is_nfc_quick<I: Iterator<Item = char>>(s: I) -> IsNormalized` | OK |
| `use unicode_normalization::UnicodeNormalization as _` | crate-root `pub trait UnicodeNormalization<I: Iterator<Item = char>>` | OK |
| `is_nfc_quick(text.chars())` | `Chars<'_>` satisfies `Iterator<Item = char>` | OK |
| `matches!(…, IsNormalized::Yes)` | variant `Yes` exists (the enum is `PartialEq`, but `matches!` doesn't need it) | OK |
| `text.nfc()` on a `String` | resolves to `impl<'a> UnicodeNormalization<Chars<'a>> for &'a str` via autoderef (there is no `String` impl) | OK |
| `.collect()` into the `String` return type | `impl<I: Iterator<Item = char>> Iterator for Recompositions<I>`, `type Item = char` | OK |
| `unicode-normalization = "=0.1.26"` | exists, not yanked, newest; checksum `75cd3fb0…a85d` matches `Cargo.lock` | OK |
| SPEC.md line 15: "Unicode 16.0" | `UNICODE_VERSION = (18, 0, 0)` | **WRONG: fix the doc** |

### Inferences
- **Required doc fix.** In `SPEC.md` line 15, replace the parenthetical `` (`unicode-normalization = "=0.1.26"`, Unicode 16.0). `` with `` (`unicode-normalization = "=0.1.26"`, Unicode 18.0.0, i.e. `unicode_normalization::UNICODE_VERSION == (18, 0, 0)`). ``.
- **Recommended (optional) guard test.** This makes the "record the Unicode version" requirement mechanical. Add it to the existing `#[cfg(test)]` module in `src/jcs.rs`, which under CLAUDE.md F-02 already carries the `#[allow(clippy::unwrap_used, …)]` block:

```rust
#[test]
fn nfc_tables_are_unicode_18_0_0() {
    assert_eq!(unicode_normalization::UNICODE_VERSION, (18, 0, 0));
}
```

- Optional: extend the `Cargo.toml` line 20 comment from `# 2026-10-16` to `# 2026-10-16, Unicode 18.0.0`. The date already in the comment is correct.
- Clippy pedantic should not flag `fn nfc`. `needless_pass_by_value` does not apply because `text` is moved out in the `Yes` branch, and the function uses no indexing, integer arithmetic, `unwrap` or `panic`. This is reasoned, not executed.
- The code is semantically right as well as compiling. Only `IsNormalized::Yes` keeps the input unchanged; `No` and `Maybe` both run the full `nfc()`, following the UAX #15 quick-check rules that the crate's `quick_check` implements (§4).

### Gaps
- This was a research-only task, so I did not run `cargo build` or `cargo clippy`. To confirm empirically, run the project's five-command verification loop in WSL, as CLAUDE.md §2 requires (including `--features lenient-numbers` and `--target aarch64-apple-darwin`).
