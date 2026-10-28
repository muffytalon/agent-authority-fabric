# ryu-js (Boa project): real API and output behaviour compared with pep-sidecar's `=1.0.3` pin and its `ecma_number` call site (as of 2026-10-27)

Local evidence used throughout (reading local files and running the project's own commands, not web searches):
- **PROJECT** = `C:\Users\mitam\OneDrive\Documents\Cryptographic Biscuits\agent-authority-fabric\` (Cargo.toml, Cargo.lock, src\jcs.rs).
- **LOCAL** = the real crates.io package unpacked by Cargo in WSL: `/home/fletchling/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/ryu-js-1.0.3/`. Its `.crate` file's SHA-256 equals the crates.io checksum (see Q1), so its text is the published 1.0.3 source, the same source docs.rs renders.
- **RUN** = commands run in WSL on 2026-10-27 with `CARGO_TARGET_DIR=$HOME/.cargo-target/pep-sidecar RUSTFLAGS='-D warnings'`, `--locked --offline` (no change to the lockfile and no network access). Scripts: `C:\Users\mitam\AppData\Local\Temp\claude\c--Users-mitam-OneDrive-Documents-Cryptographic-Biscuits-agent-authority-fabric\cf2570fd-3856-4ec6-89eb-48c92f577416\scratchpad\run_ryu_tests.sh` and `...\scratchpad\run_ryu_clippy.sh` (same directory).

## Q1. Does 1.0.3 exist, is it yanked, when was it published, what is the latest stable version, and which repository is official?

### Takeaway
ryu-js 1.0.3 is real and not yanked. It was published 2026-07-10T21:05:46Z, and it is also the latest stable version (and the newest of any kind) as of 2026-10-27; no pre-release has ever been published. The official repository is https://github.com/boa-dev/ryu-js. The project's `=1.0.3` pin, its `# 2026-07-10` comment and its Cargo.lock checksum all match crates.io exactly.

### Cited Findings
- crates.io has 8 versions in total (`meta.total = 8`), and none is yanked — [crates.io versions API](https://crates.io/api/v1/crates/ryu-js/versions)

  | Version | Published (UTC, crates.io `created_at`) | Yanked | `rust_version` | Edition | Checksum (SHA-256) | Published by |
  |---|---|---|---|---|---|---|
  | 1.0.3 | 2026-07-10T21:05:46.645363Z | false | 1.71 | 2021 | 04d056b875a9d2e6cb9a61d127afee9ac5999b9f87bcb32079d1318e505be714 | jasonwilliams |
  | 1.0.2 | 2025-02-16T15:30:32.901280Z | false | 1.64 | 2018 | dd29631678d6fb0903b69223673e122c32e9ae559d0960a38d574695ebc0ea15 | jasonwilliams |
  | 1.0.1 | 2024-03-03T18:41:39.100107Z | false | 1.64 | 2018 | ad97d4ce1560a5e27cec89519dc8300d1aa6035b099821261c651486a19e44d5 | jasonwilliams |
  | 1.0.0 | 2023-10-05T18:05:37.096612Z | false | 1.64 | 2018 | 4950d85bc52415f8432144c97c4791bd0c4f7954de32a7270ee9cccd3c22b12b | HalidOdat |
  | 0.2.2 | 2021-12-16T09:22:08.743925Z | false | 1.36 | 2018 | 6518fc26… | HalidOdat |
  | 0.2.1 | 2020-09-11T14:09:25.038042Z | false | null | 2018 | e2686418… | HalidOdat |
  | 0.2.0 | 2020-07-14T21:53:34.501853Z | false | null | 2018 | 1010bb9c… | HalidOdat |
  | 0.1.0 | 2020-07-13T18:25:02.184333Z | false | null | 2018 | 2a53c65c… | HalidOdat |
- 1.0.3 is licensed `Apache-2.0 OR BSL-1.0`, and its `crate_size` is 73922 bytes — [crates.io versions API](https://crates.io/api/v1/crates/ryu-js/versions)
- `crate.max_version`, `max_stable_version`, `newest_version` and `default_version` are all `1.0.3`. `crate.updated_at` is `2026-07-10T21:05:46.645363Z`, the same instant as the 1.0.3 publish. The crate had 47,336,135 downloads at fetch time — [crates.io crate API](https://crates.io/api/v1/crates/ryu-js)
- **Pre-releases:** none. All eight version numbers are plain `X.Y.Z` — [crates.io versions API](https://crates.io/api/v1/crates/ryu-js/versions). The GitHub releases page shows no pre-release labels and marks v1.0.3 "Latest" — [GitHub releases](https://github.com/boa-dev/ryu-js/releases)
- **Official repository:** every version's `repository` is `https://github.com/boa-dev/ryu-js`, `homepage` is null and `documentation` is `https://docs.rs/ryu-js`. The crate description reads "Fast floating point to string conversion, ECMAScript compliant." — [crates.io crate API](https://crates.io/api/v1/crates/ryu-js)
- **Repository details:**
  - The default branch is `main`, the repository is public and no archived banner is shown.
  - Its About text is "Fast floating point to string conversion that complies to the ECMAScript number-to-string algorithm".
  - The README says "Ryū-js is a fork of the ryu crate adjusted to comply to the ECMAScript number-to-string algorithm, also implementing Number.prototype.toFixed() compliant conversion."
  - Source: [GitHub repo](https://github.com/boa-dev/ryu-js)
- docs.rs lists the owners as Razican, HalidOdat and the `github:boa-dev:owners` team — [docs.rs crate root 1.0.3](https://docs.rs/ryu-js/1.0.3/ryu_js/)
- **Date conflicts** between the CHANGELOG and crates.io:
  - The CHANGELOG headings say "1.0.3 (2026-07-05)", "1.0.2 (2024-02-16)" and "1.0.1 (2024-03-02)" — [CHANGELOG 1.0.3](https://docs.rs/crate/ryu-js/1.0.3/source/CHANGELOG.md).
  - crates.io records 2026-07-10, 2025-02-16 and 2024-03-03 for the same versions — [crates.io versions API](https://crates.io/api/v1/crates/ryu-js/versions).
- **Project side:**
  - PROJECT `Cargo.toml` line 17 reads `ryu-js = { version = "=1.0.3", default-features = false }  # 2026-07-10`.
  - PROJECT `Cargo.lock` lines 139–143 record `name = "ryu-js"`, `version = "1.0.3"`, `source = "registry+https://github.com/rust-lang/crates.io-index"` and `checksum = "04d056b875a9d2e6cb9a61d127afee9ac5999b9f87bcb32079d1318e505be714"` (local files).
- **Cached package:** `sha256sum` of the cached `ryu-js-1.0.3.crate` in WSL's `~/.cargo/registry/cache/index.crates.io-1949cf8c6b5b557f/` gives `04d056b875a9d2e6cb9a61d127afee9ac5999b9f87bcb32079d1318e505be714`, the same as the crates.io checksum (local command output, 2026-10-27).

### Inferences
- The exact pin `=1.0.3` resolves, so the failure mode of a nonexistent version does not apply. The `# 2026-07-10` comment is the correct UTC publish date.
- The concern that "a model with no internet access" wrote this does not apply to this dependency. A SHA-256 checksum cannot be guessed, so the Cargo.lock entry, and the identical checksum of the downloaded `.crate`, come from a real resolution against crates.io.
- Because 1.0.3 is also the latest stable version, the facts for "the pinned version" and "the latest stable version" are the same below.
- Treat crates.io timestamps as authoritative. The CHANGELOG dates contain at least one wrong year (1.0.2) and a pre-publish date (1.0.3).

### Gaps
- The GitHub releases page text fetched here shows dates without years, so publish dates rely on crates.io alone (which is authoritative).

## Q2. What are the MSRV (`rust-version`) and edition, which features exist and which are on by default, and what does `default-features = false` turn off?

### Takeaway
ryu-js 1.0.3 declares `rust-version = "1.71"` and edition 2021. It is `#![no_std]` and has no build script. It has two features: `small`, declared explicitly, and `no-panic`, which exists implicitly because the `no-panic 0.1` dependency is optional. Neither is on by default, so `default-features = false` turns off nothing; it is a harmless no-op. The project's `rust-version = "1.88"` and its toolchain 1.97.0 are both well above 1.71.

### Cited Findings
- **`rust_version` by version:** 1.0.3 is `"1.71"`; 1.0.0 to 1.0.2 are `"1.64"`; 0.2.2 is `"1.36"`; 0.1.0 to 0.2.1 are `null`. — [crates.io versions API](https://crates.io/api/v1/crates/ryu-js/versions)
- **Edition by version:** 1.0.3 is `2021`; every earlier version is `2018`. — [crates.io versions API](https://crates.io/api/v1/crates/ryu-js/versions)
- **Published manifest** (LOCAL `Cargo.toml`, the normalized copy):
  - `edition = "2021"` and `rust-version = "1.71"` (lines 13–14).
  - `build = false` and `exclude = ["build.rs", "*.png"]` (lines 21–25).
  - `[features]` / `small = []` (lines 53–54).
  - `[dependencies.no-panic]` with `version = "0.1"` and `optional = true` (lines 106–108).
  - The same content appears in [docs.rs Cargo.toml.orig 1.0.3](https://docs.rs/crate/ryu-js/1.0.3/source/Cargo.toml.orig), which also lists the authors as David Tolnay and boa-dev.
- docs.rs says "This version has **2** feature flags, **0** of them enabled by **default**". `no-panic` maps to `dep:no-panic`, an implicit feature for the optional dependency `no-panic ^0.1`, and `small` "does not enable additional features". — [docs.rs features 1.0.3](https://docs.rs/crate/ryu-js/1.0.3/features)
- The crates.io `features` map is `{"small":[]}` for every version and has no `default` key. — [crates.io versions API](https://crates.io/api/v1/crates/ryu-js/versions)
- **What `small` does:** it uses smaller lookup tables. For f64 it stores only every 26th power of 5 and computes the rest with a multiplication, which makes the table about 10× smaller at some cost in speed. — [docs.rs Cargo.toml.orig 1.0.3](https://docs.rs/crate/ryu-js/1.0.3/source/Cargo.toml.orig)
- **No dependencies for consumers:** the dev-dependencies are `num_cpus 1.8`, `rand 0.10`, `rand_core 0.10`, `rand_xorshift 0.5` and `criterion 0.8` (non-Miri targets only), and consumers do not build them. With default features there are no runtime dependencies. — [docs.rs Cargo.toml.orig 1.0.3](https://docs.rs/crate/ryu-js/1.0.3/source/Cargo.toml.orig)
- **`no_std`:** the crate root has `#![no_std]` (LOCAL `src/lib.rs` line 71). Its crates.io categories are `no-std`, `no-std::no-alloc` and `value-formatting` — [crates.io crate API](https://crates.io/api/v1/crates/ryu-js)
- **Upstream CI** — [CI workflow](https://github.com/boa-dev/ryu-js/blob/main/.github/workflows/ci.yml):
  - The `msrv` job ("Rust 1.71.0") runs `cargo build` and `cargo build --features small`.
  - The `test` job uses the matrix `[nightly, beta, stable, 1.86.0]`.
  - `no-panic` is exercised only on nightly, as `cargo build --tests --features no-panic --release`.
  - All jobs run on `ubuntu-latest`. There are no macOS, Windows or aarch64 runners.
  - Miri covers `x86_64-unknown-linux-gnu`, `powerpc64-unknown-linux-gnu` (64-bit big-endian), `i686-unknown-linux-gnu` and `mips-unknown-linux-gnu` (32-bit big-endian).
  - The clippy job runs `cargo clippy --tests --benches -- -Dclippy::all -Dclippy::pedantic`.
- **No target-specific code:** the only `cfg`/`cfg_attr` conditions in 1.0.3's `src/` are `feature = "no-panic"`, `feature = "small"` and `test`. There are no `target_os`, `target_arch`, `target_pointer_width` or `target_endian` conditions. (Local grep of LOCAL `src/`.)
- **Project feature set:** RUN `cargo tree --locked --offline -i ryu-js -e features` prints `ryu-js v1.0.3 └── pep-sidecar v0.1.0 … └── pep-sidecar feature "default"`. No ryu-js feature is enabled. (Local command output.)

### Inferences
- Today `default-features = false` disables nothing. Keeping it is harmless, and the exact pin already freezes the feature set.
- The `1.86.0` entry in the upstream test matrix is most likely the floor for the dev-dependencies (rand 0.10, criterion 0.8), not the library's MSRV. The library MSRV is 1.71, and that is what the `msrv` job builds. Consumers need only 1.71.
- **Risk for `aarch64-apple-darwin`:**
  - Upstream does not test this target in CI.
  - The crate is pure-Rust `no_std`, has no build script (`build = false`), no runtime dependencies and no target-specific `cfg`s.
  - Miri covers both endiannesses and both 32-bit and 64-bit.
  - Overall the target-specific risk is very low. Q6 confirms a passing clippy run for this target.
- Do not enable the `no-panic` feature. Upstream exercises it only as a `--release` build on nightly, which suggests it depends on optimisation. That behaviour of the `no-panic` crate was not researched here.
- The editions are independent. A crate on edition 2024 (pep-sidecar) can depend on an edition 2021 crate (ryu-js 1.0.3). This is general Cargo behaviour, not researched here, but RUN confirms that it builds.

### Gaps
- I did not check whether `no-panic` was an optional dependency in versions before 1.0.3. The crates.io `features` map leaves out implicit features.

## Q3. What are the exact signatures of `Buffer::new`, `format_finite` and `format`, of the `Float` trait, and of `Buffer`'s trait impls, and how is the returned `&str`'s lifetime tied to `&mut self`?

### Takeaway
Both calls exist exactly as the project uses them: `ryu_js::Buffer::new()`, a plain `pub fn` (not a `const fn`), and `pub fn format_finite<F: Float>(&mut self, f: F) -> &str`. `Float` is sealed and implemented only for `f32` and `f64`. `Buffer` implements `Copy`, `Clone` and `Default`, but not `Debug`. The returned `&str` borrows the buffer: by lifetime elision it is tied to `&mut self`. There are no stand-in APIs: these are the crate's real public items.

### Cited Findings
- **Exports:** the crate exports `pub use crate::buffer::{Buffer, Float, FloatToFixed};` and `pub mod raw { … }` (LOCAL `src/lib.rs` lines 108 and 111). docs.rs lists the module `raw` ("unsafe functions that mirror the C implementation's API"), the struct `Buffer`, and the traits `Float` and `FloatToFixed`, with no functions at the crate root — [docs.rs crate root 1.0.3](https://docs.rs/ryu-js/1.0.3/ryu_js/)
- **Signatures as docs.rs renders them** — [docs.rs `struct Buffer` 1.0.3](https://docs.rs/ryu-js/1.0.3/ryu_js/struct.Buffer.html):
  ```rust
  pub struct Buffer { /* private fields */ }
  ```
  ```rust
  pub fn new() -> Self
  ```
  ```rust
  pub fn format<F: Float>(&mut self, f: F) -> &str
  ```
  ```rust
  pub fn format_finite<F: Float>(&mut self, f: F) -> &str
  ```
  ```rust
  pub fn format_to_fixed<F: FloatToFixed>(&mut self, f: F, fraction_digits: u8) -> &str
  ```
- **Trait implementations on the same page:**
  ```rust
  impl Clone for Buffer
  impl Copy for Buffer
  impl Default for Buffer
  ```
  The auto traits are `Freeze`, `RefUnwindSafe`, `Send`, `Sync`, `Unpin`, `UnsafeUnpin` and `UnwindSafe`. `Debug` is not listed. — [docs.rs `struct Buffer` 1.0.3](https://docs.rs/ryu-js/1.0.3/ryu_js/struct.Buffer.html)
- **The `Float` trait** — [docs.rs `trait Float` 1.0.3](https://docs.rs/ryu-js/1.0.3/ryu_js/trait.Float.html):
  ```rust
  pub trait Float: Sealed { }
  ```
  Implementations on foreign types:
  ```rust
  impl Float for f32
  impl Float for f64
  ```
  The page states it "cannot be implemented for types outside of the `ryu-js` crate."
- **Verbatim source, 1.0.3 `src/buffer/mod.rs`** — [docs.rs source](https://docs.rs/ryu-js/1.0.3/src/ryu_js/buffer/mod.rs.html); the text is identical in LOCAL `src/buffer/mod.rs`, lines 24–34, 78–80 and 122–160:
  ```rust
  #[derive(Copy)]
  pub struct Buffer {
      bytes: [MaybeUninit<u8>; BUFFER_SIZE],
  }

  impl Buffer {
      /// This is a cheap operation; you don't need to worry about reusing buffers
      /// for efficiency.
      #[inline]
      #[cfg_attr(feature = "no-panic", no_panic)]
      pub fn new() -> Self {
          let bytes = [MaybeUninit::<u8>::uninit(); BUFFER_SIZE];

          Buffer { bytes }
      }
  ```
  ```rust
      #[inline]
      #[cfg_attr(feature = "no-panic", no_panic)]
      pub fn format_finite<F: Float>(&mut self, f: F) -> &str {
          unsafe {
              let n = f.write_to_ryu_buffer(self.bytes.as_mut_ptr().cast::<u8>());
              debug_assert!(n <= self.bytes.len());
              let slice = slice::from_raw_parts(self.bytes.as_ptr().cast::<u8>(), n);
              str::from_utf8_unchecked(slice)
          }
      }
  ```
  ```rust
  #[allow(clippy::non_canonical_clone_impl)]
  impl Clone for Buffer {
      #[inline]
      fn clone(&self) -> Self {
          Buffer::new()
      }
  }

  impl Default for Buffer {
      #[inline]
      #[cfg_attr(feature = "no-panic", no_panic)]
      fn default() -> Self {
          Buffer::new()
      }
  }
  ```
  ```rust
  pub trait Float: Sealed {}
  impl Float for f32 {}
  impl Float for f64 {}
  // …
  pub trait FloatToFixed: Sealed {}
  impl FloatToFixed for f64 {}

  pub trait Sealed: Copy {
      fn is_nonfinite(self) -> bool;
      fn format_nonfinite(self) -> &'static str;
  ```
- **Bodies of `format` and `format_to_fixed`:** `format` is `if f.is_nonfinite() { f.format_nonfinite() } else { self.format_finite(f) }`. `format_to_fixed` first does `let fraction_digits = fraction_digits.min(100);` and returns the NaN/Infinity strings for non-finite input. — [docs.rs source buffer/mod.rs](https://docs.rs/ryu-js/1.0.3/src/ryu_js/buffer/mod.rs.html)
- **What `format_finite` calls:** for `f64`, the sealed `write_to_ryu_buffer` calls `raw::format64(self, result)`. — [docs.rs source buffer/mod.rs](https://docs.rs/ryu-js/1.0.3/src/ryu_js/buffer/mod.rs.html)
- **Usage examples:** the doc example on the struct is `let mut buffer = ryu_js::Buffer::new(); let printed = buffer.format_finite(1.234); assert_eq!(printed, "1.234");` (LOCAL `src/buffer/mod.rs` lines 17–23). The README and crate-root example uses `buffer.format(1.234)` and expects `"1.234"`. — [GitHub repo README](https://github.com/boa-dev/ryu-js), [docs.rs crate root 1.0.3](https://docs.rs/ryu-js/1.0.3/ryu_js/)
- **Raw API, for comparison:**
  - The signature is `pub unsafe fn format64(f: f64, result: *mut u8) -> usize`, marked `#[must_use]`.
  - Its doc says "Print f64 to the given buffer and return number of bytes written." and "At most 25 bytes will be written."
  - Source: [docs.rs source pretty/mod.rs](https://docs.rs/ryu-js/1.0.3/src/ryu_js/pretty/mod.rs.html). The attributes and signature are at LOCAL `src/pretty/mod.rs` lines 53–55; the doc text is quoted from docs.rs.

### Inferences
- `Buffer::new` is **not** a `const fn`: neither the docs.rs rendering nor the source has `const`. This does not matter for the call site, which builds a runtime local.
- **Lifetime:** by elision, the signature means `fn format_finite<'a, F: Float>(&'a mut self, f: F) -> &'a str`. The returned slice keeps `buffer` mutably borrowed until it is last used. In the project, `.to_owned()` copies the slice into a `String` in the same statement, so the borrow ends at once. `buffer` must be a `let mut` binding, and it is.
- **Sealing:** `Sealed` is `pub` but lives in the private `buffer` module and is not re-exported, so code outside the crate cannot name it. Only `f32` and `f64` satisfy `Float`. The project passes `value: f64` (its type comes from `let parsed: f64`), which is accepted.
- **Unsafe code:** the `raw` functions are `unsafe`. The project's `unsafe_code = "forbid"` therefore allows only the safe `Buffer` API, and that is exactly what it uses. The `unsafe` blocks inside ryu-js do not trip the project's lint, because lint levels apply per crate.
- **No `Debug`:** a pep-sidecar struct holding a `ryu_js::Buffer` could not `#[derive(Debug)]`, and the project enables `missing_debug_implementations`. The current code holds the buffer only as a function-local, so this does not matter.
- **`Clone`:** cloning a `Buffer` returns a fresh, empty buffer and does not copy the bytes. This does not matter here.

### Gaps
- No material gaps. I did not fetch the separate docs.rs page for `FloatToFixed`; its implementation for `f64` alone comes from the verbatim source above.

## Q4. Behaviour: does `format_finite` produce ECMAScript Number::toString output (RFC 8785 §3.2.2.3), how does it handle -0.0, NaN and infinity, and do the crate's tests confirm the project's expected outputs?

### Takeaway
`format_finite` produces the ECMAScript Number::toString layout. That means:
- integers print without ".0", padded with trailing zeros up to 21 digits;
- other values from 1e-6 up to below 1e21 print in plain decimal form;
- values below 1e-6 print in exponent form, for example "1e-7";
- values at 1e21 and above print in exponent form with an explicit sign, for example "1e+21";
- the digits are Ryū's shortest digits that read back as the same number.

-0.0 prints "0", because the zero check runs before the sign is written. For NaN and ±∞, `format_finite` is documented to print an "unspecified numerical value" and does not panic. `format` prints "NaN", "Infinity" and "-Infinity". The crate's own 1.0.3 tests directly assert "1", "1e-7", "0" (for both 0.0 and -0.0) and "0.1", and they assert close analogues of the project's other expected outputs. The project's two tests pass against the real crate (RUN).

### Cited Findings
- **`format_finite` doc comment (verbatim):** "This function **does not** check for NaN or infinity. If the input number is not a finite float, the printed representation will be some correctly formatted but unspecified numerical value." It continues: "Please check [`is_finite`] yourself before calling this function, or check [`is_nan`] and [`is_infinite`] and handle those cases yourself." — [docs.rs source buffer/mod.rs](https://docs.rs/ryu-js/1.0.3/src/ryu_js/buffer/mod.rs.html), [docs.rs `struct Buffer`](https://docs.rs/ryu-js/1.0.3/ryu_js/struct.Buffer.html)
- **`format` doc comment (verbatim):** "This function formats NaN as the string "NaN", positive infinity as "Infinity", and negative infinity as "-Infinity" to match the [ECMAScript specification][spec]." Here `[spec]` is `https://tc39.es/ecma262/#sec-numeric-types-number-tostring`. — [docs.rs source buffer/mod.rs](https://docs.rs/ryu-js/1.0.3/src/ryu_js/buffer/mod.rs.html)
- **Logic of `raw::format64`**, verbatim excerpt: the bodies are elided with `…`, and the branch conditions and comments are exact (LOCAL `src/pretty/mod.rs` lines 56–122) — [docs.rs source pretty/mod.rs](https://docs.rs/ryu-js/1.0.3/src/ryu_js/pretty/mod.rs.html):
  ```rust
      if ieee_exponent == 0 && ieee_mantissa == 0 {
          *result = b'0';
          return 1;
      }

      let mut index = 0isize;
      if sign {
          *result = b'-';
          index += 1;
      }

      let v = d2d(ieee_mantissa, ieee_exponent);

      let length = d2s::decimal_length17(v.mantissa) as isize;
      let k = v.exponent as isize;
      let kk = length + k; // 10^(kk-1) <= v < 10^kk
      debug_assert!(k >= -324);

      if 0 <= k && kk <= 21 {
          // 1234e7 -> 12340000000.0
          …
      } else if 0 < kk && kk <= 21 {
          // 1234e-2 -> 12.34
          …
      } else if -6 < kk && kk <= 0 {
          // 1234e-6 -> 0.001234
          …
      } else if length == 1 {
          // 1e+30
          *result.offset(index) = b'0' + v.mantissa as u8;
          *result.offset(index + 1) = b'e';
          index as usize + 2 + write_exponent3(kk - 1, result.offset(index + 2))
      } else {
          // 1234e30 -> 1.234e+33
          …
      }
  ```
  The f32 path, `format32`, uses the same zero branch and the same thresholds (LOCAL `src/pretty/mod.rs` lines 170–211).
- **Exponent writer:** `write_exponent3` writes `b'-'` (and negates `k`) for a negative exponent and `b'+'` otherwise, then 1–3 digits with no leading zeros. The `e` itself is written by the caller. — [docs.rs source pretty/exponent.rs](https://docs.rs/ryu-js/1.0.3/src/ryu_js/pretty/exponent.rs.html)
- **Test helper:** in the 1.0.3 test file, the helper is `fn pretty(f: f64) -> String { ryu_js::Buffer::new().format(f).to_owned()`. — [docs.rs tests/d2s_test.rs 1.0.3](https://docs.rs/crate/ryu-js/1.0.3/source/tests/d2s_test.rs)
- **Assertions in that file, verbatim** — [docs.rs tests/d2s_test.rs 1.0.3](https://docs.rs/crate/ryu-js/1.0.3/source/tests/d2s_test.rs):
  - `test_basic`:
    - `assert_eq!(pretty(0.0), "0");`
    - `assert_eq!(pretty(-0.0), "0");`
    - `assert_eq!(pretty(1.0), "1");`
    - `assert_eq!(pretty(-1.0), "-1");`
    - `assert_eq!(pretty(f64::INFINITY), "Infinity");`
    - `assert_eq!(pretty(f64::NEG_INFINITY), "-Infinity");`
    - `assert_eq!(pretty(f64::NAN.copysign(-1.0)), "NaN");`
  - `test_ecma262_compliance`:
    - `assert_eq!(pretty(9.0), "9");`
    - `assert_eq!(pretty(90.0), "90");`
    - `assert_eq!(pretty(90.12), "90.12");`
    - `assert_eq!(pretty(0.1), "0.1");`
    - `assert_eq!(pretty(0.000001), "0.000001");`
    - `assert_eq!(pretty(0.0000001), "1e-7");`
    - `assert_eq!(pretty(0.00000012), "1.2e-7");`
    - `assert_eq!(pretty(3e50), "3e+50");`
    - `assert_eq!(pretty(111111111111111111111.0), "111111111111111110000");`
    - `assert_eq!(pretty(1111111111111111111111.0), "1.1111111111111111e+21");`
    - `assert_eq!(pretty(-0.0), "0");`
    - `assert_eq!(pretty(-0.0000000123), "-1.23e-8");`
    - `assert_eq!(pretty(123456789010111213141516171819.0), "1.234567890101112e+29");`
  - `test_ryu`:
    - `assert_eq!(pretty(1234000000000000.0), "1234000000000000");`
    - `assert_eq!(pretty(1.234e16), "12340000000000000");`
    - `assert_eq!(pretty(1.1e128), "1.1e+128");`
    - `assert_eq!(pretty(1.7976931348623157e308), "1.7976931348623157e+308");`
  - `test_regression`:
    - `assert_eq!(pretty(4.708356024711512e+18), "4708356024711512000");`
    - `assert_eq!(pretty(9.409340012568248e+18), "9409340012568248000");`
  - `test_min_max_shift`:
    - `assert_eq!(pretty(1.8014398509481984e16), "18014398509481984");`
  - `test_random`:
    - `assert_eq!(f, buffer.format_finite(f).parse().unwrap());` (the output reads back as the same number).
  - `test_non_finite`:
    - calls `ryu_js::Buffer::new().format_finite(f);` on non-finite inputs.
- **Test function names** in that file: `test_ryu`, `test_random`, `test_non_finite`, `test_basic`, `test_switch_to_subnormal`, `test_min_and_max`, `test_lots_of_trailing_zeros`, `test_regression`, `test_looks_like_pow5`, `test_output_length`, `test_min_max_shift`, `test_ecma262_compliance` and `max_size_double_to_string`. — [docs.rs tests/d2s_test.rs 1.0.3](https://docs.rs/crate/ryu-js/1.0.3/source/tests/d2s_test.rs)
- **History of the -0 and ECMAScript behaviour:**
  - The 0.2.0 CHANGELOG entry says "Fixed converting from `-0.0` to `0`." and "Optimized `0` and `-0` to string conversion".
  - The 0.1.0 release "introduces ECMAScript compliant `f64` to string conversions".
  - No 1.0.x entry changes this behaviour.
  - Source: [CHANGELOG 1.0.3](https://docs.rs/crate/ryu-js/1.0.3/source/CHANGELOG.md)
- **Correctness proof:** the crate docs say the algorithm comes from the PLDI'18 paper "Ryū: fast float-to-string conversion" by Ulf Adams, which "includes a complete correctness proof". — [docs.rs crate root 1.0.3](https://docs.rs/ryu-js/1.0.3/ryu_js/)
- **The project's call site** (PROJECT `src\jcs.rs` lines 834–849):
  - It parses `text.parse::<f64>()`.
  - It rejects `!parsed.is_finite()` with `NumberNotFinite`.
  - It maps the bit pattern `0x8000_0000_0000_0000` (-0.0) to `0.0`.
  - It then calls `ryu_js::Buffer::new()` and `buffer.format_finite(value).to_owned()` (local file).
- **RUN, lenient-numbers:** `cargo test --locked --offline --features lenient-numbers --lib -- lenient_request_numbers result_profile_numbers` printed `test jcs::tests::lenient_request_numbers ... ok`, `test jcs::tests::result_profile_numbers ... ok` and `2 passed; 0 failed` (local command output).
- **RUN, default features:** `cargo test --locked --offline --lib -- result_profile_numbers` printed `1 passed; 0 failed`, on cargo 1.97.0 (c980f4866 2026-06-30) and rustc 1.97.0 (2d8144b78 2026-07-07) (local command output).

**The project's expected pairs, traced through the real 1.0.3 code.** In the Branch column, `digits` is Ryū's shortest digit string, `length` is the number of digits, `k` is the decimal exponent and `kk = length + k`, as in the `format64` source above.

| Project input | f64 passed to `format_finite` | `format64` branch | Output | Crate evidence | Status |
|---|---|---|---|---|---|
| `"1.0"` | 1.0 | digits `1`, k=0, kk=1: `0 <= k && kk <= 21` | `1` | `pretty(1.0) == "1"` | Direct assertion; RUN passes |
| `"1e2"` | 100.0 | digits `1`, k=2, kk=3: integer branch pads 2 zeros | `100` | `pretty(90.0) == "90"`, `pretty(1234000000000000.0) == "1234000000000000"` | Analogue; RUN passes |
| `"1E-7"` | 1e-7 | digits `1`, k=-7, kk=-6: fails `-6 < kk`, so `length == 1` gives `1` + `e` + `-7` | `1e-7` | `pretty(0.0000001) == "1e-7"` | Direct assertion; RUN passes |
| `"-0.0"` | 0.0 after the project's mapping (raw value -0.0) | zero branch, returned before the sign is written | `0` | `pretty(0.0) == "0"`, `pretty(-0.0) == "0"` | Direct assertion (with or without the mapping); RUN passes |
| `"123.456e2"` | 12345.6 | digits `123456`, k=-1, kk=5: `0 < kk && kk <= 21` | `12345.6` | `pretty(90.12) == "90.12"` | Analogue; RUN passes |
| `"0.1"` | 0.1 | digits `1`, k=-1, kk=0: `-6 < kk && kk <= 0` | `0.1` | `pretty(0.1) == "0.1"` | Direct assertion; RUN passes |
| `"12.5"` | 12.5 | digits `125`, k=-1, kk=2: decimal branch | `12.5` | `pretty(90.12) == "90.12"` | Analogue; RUN passes |
| `"18446744073709551615"` | 18446744073709551616.0 (2^64) | digits `18446744073709552` (17 digits), k=3, kk=20: integer branch pads 3 zeros | `18446744073709552000` | `pretty(4.708356024711512e+18) == "4708356024711512000"`, `pretty(111111111111111111111.0) == "111111111111111110000"` | Analogue; RUN passes |
| `"30000.0"` | 30000.0 | digits `3`, k=4, kk=5: integer branch | `30000` | `pretty(90.0) == "90"` | Analogue; RUN passes |

### Inferences
- The crate's thresholds match the ECMA-262 Number::toString steps, reading Ryū's `kk` as ECMAScript's `n` and `length` as its `k`:
  - k ≤ n ≤ 21: print the digits followed by zeros;
  - 0 < n ≤ 21: put the decimal point inside the digits;
  - −6 < n ≤ 0: print "0." with leading zeros;
  - otherwise: exponent form, with an explicit "+" or "−" sign.

  RFC 8785 §3.2.2.3 requires exactly this serialization. I did not fetch the ECMA-262 or RFC 8785 text, because of the research constraints. The mapping rests on the spec link in the crate's own docs and on its `test_ecma262_compliance` assertions.
- For finite inputs, `format` returns exactly what `format_finite` returns, because `format` delegates to it. The `pretty`-based crate tests therefore cover `format_finite`, the method the project calls.
- The project's -0.0 → 0.0 mapping is redundant with ryu-js, which ignores the sign in its zero branch and asserts `pretty(-0.0) == "0"`, but it is harmless. Keeping it is reasonable defence in depth: the public API docs for `format_finite` say nothing about -0. That behaviour is promised only by the tests, the source and the 0.2.0 CHANGELOG entry.
- The project calls `is_finite` before `format_finite`, so the documented "unspecified numerical value" path for NaN and ±∞ cannot be reached.
- **2^64 tie-break:** several 17-digit strings lie inside 2^64's rounding interval. Ryū picks the closest one, `18446744073709552`, which matches the ECMAScript rule to choose the s closest to the value and gives JavaScript's well-known `"18446744073709552000"`. This is consistent with the passing project test, but no crate test asserts this exact value.
- Accepting `"1E-7"` with a capital E, and rounding `"18446744073709551615"` to 2^64, is Rust's `str::parse::<f64>` behaviour, not ryu-js's. I did not research it; it is shown only indirectly by the passing project tests.

### Gaps
- No ryu-js test literally asserts 100, 12.5, 12345.6, 30000 or 2^64 → "18446744073709552000". Those rows rest on the branch code, the analogous assertions and the passing project tests.
- I did not inspect the `check!` macro (in `tests/macros/`), `tests/exhaustive.rs` or the f32 tests.
- I did not fetch the ECMA-262 or RFC 8785 text (outside the allowed domains).

## Q5. Which breaking or notable changes between 1.0.0 and the latest version matter (MSRV bumps, formatting changes)?

### Takeaway
Within 1.0.x, only two changes are visible to consumers, both in 1.0.3: the MSRV rose from 1.64 to 1.71 (marked breaking), and a panic in `format64_to_fixed` was fixed (this only affects `format_to_fixed`). 1.0.3 also moved from edition 2018 to 2021, which is internal and not mentioned in the changelog. No 1.0.x entry changes the output of `format` or `format_finite`. None of this affects pep-sidecar, whose `rust-version` is 1.88.

### Cited Findings
- **1.0.0** (crates.io 2023-10-05; CHANGELOG title "ECMAScript compliant implementation of `Number.prototype.toFixed()`") — [CHANGELOG 1.0.3](https://docs.rs/crate/ryu-js/1.0.3/source/CHANGELOG.md):
  - Breaking: "Minimum rust version has been bumped from `1.36.0` to `1.64.0`."
  - Feature: "ECMAScript specification compliant `Number.prototype.toFixed()` implementation" (PR #35).
  - Internal: dependabot, an upstream sync, templates, criterion benchmarks, benchmark CI and a merge queue.
- **1.0.1** (crates.io 2024-03-03) is internal only: "Add release workflow" (#45), "Add `#[inline]` to public functions" (#43) and "Sync upstream/master" (#42). — [CHANGELOG 1.0.3](https://docs.rs/crate/ryu-js/1.0.3/source/CHANGELOG.md), [GitHub releases](https://github.com/boa-dev/ryu-js/releases)
- **1.0.2** (crates.io 2025-02-16) is internal only: "Sync `upstream/master`" (#48). — [CHANGELOG 1.0.3](https://docs.rs/crate/ryu-js/1.0.3/source/CHANGELOG.md), [GitHub releases](https://github.com/boa-dev/ryu-js/releases)
- **1.0.3** (crates.io 2026-07-10; CHANGELOG says 2026-07-05) — [CHANGELOG 1.0.3](https://docs.rs/crate/ryu-js/1.0.3/source/CHANGELOG.md), [GitHub releases](https://github.com/boa-dev/ryu-js/releases):
  - Breaking: "Minimum rust version has been bumped from `1.64.0` to `1.71.0`."
  - Bug fix (BUG #56): "Fix panic in `format64_to_fixed` when rounding carries past all integer digits." by @Ansh-699.
  - Internal: "Sync `upstream/main`" (#57) and "Make `Cursor` store unsigned integer len and index" (#63).
  - The BUG #56 link in the notes points to `pull/2`, which does not match the number in the title.
- **Edition change in 1.0.3:** crates.io records edition 2021 for 1.0.3 and 2018 for 1.0.0 to 1.0.2. — [crates.io versions API](https://crates.io/api/v1/crates/ryu-js/versions)
- **Where the API is:** `format_to_fixed` and `FloatToFixed` exist in 1.0.3. — [docs.rs `struct Buffer` 1.0.3](https://docs.rs/ryu-js/1.0.3/ryu_js/struct.Buffer.html)

### Inferences
- Moving within 1.0.x does not change the Number::toString output that pep-sidecar depends on. Every upstream sync (#42, #48, #57) is filed under "Internal Improvements", and the 1.0.3 test file asserts the current ECMAScript behaviour.
- `format_to_fixed` and `FloatToFixed` are most likely the API added for the 1.0.0 `toFixed()` feature. The changelog does not name the API, so this is an inference. pep-sidecar does not use them.
- The 1.0.3 MSRV bump to 1.71 sits well below pep-sidecar's 1.88. It therefore causes no conflict with Cargo's MSRV-aware resolver (Rust 1.84+, enabled by default under edition 2024), and the `=` pin makes the choice of version moot anyway. This is general Cargo behaviour, not researched here.

### Gaps
- I did not compare the upstream-sync PRs #42, #48 and #57 line by line, and did not fetch the GitHub compare view. A behaviour change hidden inside one of them cannot be fully ruled out from the changelog alone. It is ruled out for this project's inputs by the 1.0.3 tests and the passing project tests.

## Q6. Verdict: does the call site compile against the real crate and produce the expected output, and what must change?

### Takeaway
**Verdict: compiles as-is. No change is needed.**
- `ryu-js = { version = "=1.0.3", default-features = false }` names a real, non-yanked version that is also the latest stable one, published 2026-07-10.
- `ryu_js::Buffer::new()` and `Buffer::format_finite::<f64>(…) -> &str` are the crate's real public API.
- The crate's output matches all nine expected pairs.

The local runs confirmed this: the project's two tests pass, and the clippy gates pass under `-D warnings` for both the lenient-numbers host build and `aarch64-apple-darwin`.

### Cited Findings
- **The call site today** (PROJECT `src\jcs.rs` lines 843–849, local file):
  ```rust
  let value = if parsed.to_bits() == NEG_ZERO_BITS {
      0.0
  } else {
      parsed
  };
  let mut buffer = ryu_js::Buffer::new();
  let canonical = buffer.format_finite(value).to_owned();
  ```
  These are the only uses of ryu-js in `src/`. A grep of the project for `ryu` finds only `src\jcs.rs` lines 848–849, plus Cargo.toml, Cargo.lock and WEEK1_PLAN.md (local grep).
- **The API it compiles against:** `pub fn new() -> Self`, `pub fn format_finite<F: Float>(&mut self, f: F) -> &str` and `impl Float for f64`. — [docs.rs `struct Buffer` 1.0.3](https://docs.rs/ryu-js/1.0.3/ryu_js/struct.Buffer.html), [docs.rs `trait Float` 1.0.3](https://docs.rs/ryu-js/1.0.3/ryu_js/trait.Float.html)
- **RUN, tests:** `cargo test --locked --offline --features lenient-numbers --lib -- lenient_request_numbers result_profile_numbers` gave 2 passed and exit code 0. `cargo test --locked --offline --lib -- result_profile_numbers` gave 1 passed and exit code 0. (Local command output.)
- **RUN, clippy:** `cargo clippy --locked --offline --all-targets --features lenient-numbers -- -D warnings` and `cargo clippy --locked --offline --all-targets --target aarch64-apple-darwin -- -D warnings` both finished with exit code 0. The installed rustup targets are `aarch64-apple-darwin` and `x86_64-unknown-linux-gnu`. (Local command output.)

### Inferences
- **No stand-ins:** the project imports the crate's real public paths. `ryu_js::Buffer` is re-exported from `crate::buffer`, and nothing in the repository is a mock module.
- **Lints at the call site:** nothing at the call site trips the project's denied lints.
  - The call does no float arithmetic.
  - It has no `as` casts, indexing or unwraps.
  - Clippy's `float_cmp` is avoided, because -0.0 is detected by `to_bits()`.
  - `unused_qualifications` is not triggered: no `use ryu_js::…` exists, so the full path is required.
- **ryu-js under `-D warnings`:** with `RUSTFLAGS='-D warnings'`, the clippy runs re-checked only `pep-sidecar`, so Cargo reused cached ryu-js artifacts built with the same flags (Cargo includes RUSTFLAGS in a crate's fingerprint). ryu-js 1.0.3 therefore built cleanly under rustc 1.97.0 with these flags for the host and for `aarch64-apple-darwin`. Cargo also caps lint levels for registry dependencies (`--cap-lints`), so a lint that a future rustc adds inside ryu-js could not fail this build anyway. That is general Cargo behaviour, not researched here.
- **Replacement code:** none is required.
- **Optional changes, not required:**
  1. `default-features = false` could be dropped, since ryu-js has no default features; keeping it is equally fine.
  2. The -0.0 → 0.0 mapping could be dropped, since ryu-js already prints `"0"` for -0.0. I recommend **keeping** it, because the `format_finite` API docs do not document that guarantee.

### Gaps
- I did not run the full five-command CLAUDE.md loop (`cargo fmt --check`, default-feature clippy, the full test suite). I ran only the commands that cover this call site, and they all passed.
- `aarch64-apple-darwin` was confirmed by clippy (a type and lint check). No binary was linked or run on macOS, and upstream CI has no macOS runner.
