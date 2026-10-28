# thiserror `=2.0.21`: real API vs. pep-sidecar usage (checked 2026-10-27)

Method: web facts come only from the crates.io API, docs.rs (the rendered docs and the source view of the *published* 2.0.21 crates), and github.com/dtolnay/thiserror. Local facts come from the repo files, cited by path. The fetch tool returns verbatim text in short fragments, so multi-line quotes below are reassembled from consecutive verbatim source lines: `&mdash;` is rendered as "—" and `&ensp;⟶&ensp;` as " ⟶ ". No compiler was run during this research (see the Gaps in sections 4, 6 and 7).

## 1. Does 2.0.21 exist? Is it yanked? When was it published? What is the latest stable (any 3.x or pre-release)?

### Takeaway
2.0.21 is a real crates.io release, published 2026-09-23 by dtolnay and not yanked. As of 2026-10-27 it is the latest stable release and the newest release of any kind. No 3.x and no pre-release has ever been published. The project's date comment is correct, and the Cargo.lock checksums for `thiserror`, `thiserror-impl` and `syn` match crates.io byte for byte.

### Cited Findings
- `2.0.21`: `"created_at": "2026-09-23T20:24:07.771104Z"`, `"yanked": false`, `"yank_message": null`, published_by login `dtolnay`, `"license": "MIT OR Apache-2.0"`, `"crate_size": 29021`. — [crates.io versions API](https://crates.io/api/v1/crates/thiserror/versions)
- Crate metadata: `"max_version": "2.0.21"`, `"max_stable_version": "2.0.21"`, `"newest_version": "2.0.21"`, `"default_version": "2.0.21"`, `"updated_at": "2026-09-23T20:24:07.771104Z"`, `"repository": "https://github.com/dtolnay/thiserror"`. — [crates.io crate API](https://crates.io/api/v1/crates/thiserror)
- The versions listing ends with `"meta":{"total":92,"next_page":null}`. No `num` value contains a hyphen (no pre-releases), and none starts with `3.` (read in two passes, offset 0 and offset 100000). — [crates.io versions API](https://crates.io/api/v1/crates/thiserror/versions)
- On GitHub, release `2.0.21` is marked "Latest" and dated "23 Sep 20:25". Its only note is "Fix parsing of generic unit variants in display expressions (#459)". — [GitHub release 2.0.21](https://github.com/dtolnay/thiserror/releases/tag/2.0.21)
- 2.x `created_at` dates, none yanked: 2.0.0 2024-11-06 · 2.0.1 2024-11-08 · 2.0.2 and 2.0.3 2024-11-10 · 2.0.4 2024-12-03 · 2.0.5 2024-12-07 · 2.0.6 2024-12-08 · 2.0.7 2024-12-13 · 2.0.8 2024-12-18 · 2.0.9 2024-12-21 · 2.0.10 2025-01-08 · 2.0.11 2025-01-10 · 2.0.12 2025-03-03 · 2.0.13 and 2.0.14 2025-08-11 · 2.0.15 2025-08-16 · 2.0.16 2025-08-20 · 2.0.17 2025-09-28 · 2.0.18 2026-01-18 · 2.0.19 2026-07-18 · 2.0.20 2026-08-08 · 2.0.21 2026-09-23. The 1.x line ends at 1.0.69. — [crates.io versions API](https://crates.io/api/v1/crates/thiserror/versions)
- The crates.io checksum for 2.0.21 is `09e52cb86a36cede5cb101bf8908837b3e4c6e5e59fe7fd85c23fb56200d189e`. — [crates.io versions API](https://crates.io/api/v1/crates/thiserror/versions). It is identical to Cargo.lock line 171 (`name = "thiserror"`, `version = "2.0.21"`). — [Cargo.lock](<C:\Users\mitam\OneDrive\Documents\Cryptographic Biscuits\agent-authority-fabric\Cargo.lock>)
- `thiserror-impl` 2.0.21: `"checksum":"fe5197923287db20a58125f0bc85c062f7f2c892de97b18c356f9efb14b28524"`, `"created_at":"2026-09-23T20:24:05.038819Z"`, `"yanked":false`. — [crates.io thiserror-impl 2.0.21](https://crates.io/api/v1/crates/thiserror-impl/2.0.21). It is identical to Cargo.lock line 180. — [Cargo.lock](<C:\Users\mitam\OneDrive\Documents\Cryptographic Biscuits\agent-authority-fabric\Cargo.lock>)
- thiserror 2.0.21 depends on `[dependencies.thiserror-impl] version = "=2.0.21"`. — [docs.rs Cargo.toml 2.0.21](https://docs.rs/crate/thiserror/2.0.21/source/Cargo.toml)
- The project pins `thiserror = "=2.0.21"  # 2026-09-23` (line 19), under the header comment "Versions verified on crates.io 2026-10-24." (line 14). — [Cargo.toml](<C:\Users\mitam\OneDrive\Documents\Cryptographic Biscuits\agent-authority-fabric\Cargo.toml>)

### Inferences
- The exact `=2.0.21` pin resolves: the version exists and is not yanked. The comment date 2026-09-23 matches the crates.io `created_at` (UTC).
- Three post-2025 crates (thiserror, thiserror-impl, syn 3.0.9; see section 2) have lockfile SHA-256 checksums that match crates.io. So the Cargo.lock came from a real Cargo resolution against the registry; it was not invented. For thiserror, the idea that the code was written against a "stand-in" API is not supported. The source uses the real `thiserror::Error` path and contains no mock module.
- Because the pin is also the newest release, there is no newer 2.0.x to evaluate and no 3.x migration to plan.

### Gaps
- I did not fetch the 2.0.1 release notes (page 3 of the GitHub releases list). Section 5 covers 2.0.0 and 2.0.2 to 2.0.21.

## 2. MSRV, edition, features, which `Error` trait the derive implements, and the effect of `default-features = false`

### Takeaway
2.0.21 declares `rust-version = "1.77"`, `edition = "2021"`, and the features `default = ["std"]` and `std = []`. That is compatible with the project's `rust-version = "1.88"` and its 1.97.0 toolchain. The generated impl targets `::thiserror::__private21::Error`, which is a re-export of `core::error::Error`. With the default `std` feature, thiserror aliases `core` to `std`, so the trait is `std::error::Error`, the same trait as `core::error::Error` on Rust 1.81 and later.

### Cited Findings
- Published Cargo.toml: `edition = "2021"`, `rust-version = "1.77"`, `build = "build.rs"`, `[features] default = ["std"]`, `std = []`. It has no `[lints]` section. Its docs.rs metadata builds only `targets = ["x86_64-unknown-linux-gnu"]`. — [docs.rs Cargo.toml 2.0.21](https://docs.rs/crate/thiserror/2.0.21/source/Cargo.toml)
- crates.io agrees: `"rust_version": "1.77"`, `"edition": "2021"`, `"features": {"default":["std"],"std":[]}`. — [crates.io versions API](https://crates.io/api/v1/crates/thiserror/versions)
- MSRV history from crates.io `rust_version`: 2.0.0 to 2.0.17 = 1.61; 2.0.18 = 1.68; 2.0.19 and 2.0.20 = 1.71; 2.0.21 = 1.77. Every 2.x release uses edition 2021. — [crates.io versions API](https://crates.io/api/v1/crates/thiserror/versions)
- `thiserror-impl` 2.0.21: `edition = "2021"`, `rust-version = "1.77"`, `[lib] proc-macro = true`, with dependencies `proc-macro2` `"1.0.74"`, `quote` `"1.0.35"` and `syn` `"3"`. crates.io lists `"features":{}`. — [docs.rs thiserror-impl Cargo.toml](https://docs.rs/crate/thiserror-impl/2.0.21/source/Cargo.toml), [crates.io thiserror-impl 2.0.21](https://crates.io/api/v1/crates/thiserror-impl/2.0.21)
- The 2.0.19 release note reads "Update to syn 3". — [GitHub releases](https://github.com/dtolnay/thiserror/releases)
- `syn` 3.0.9, the version in the lockfile (line 158): `"rust_version": "1.71"`, `"edition": "2021"`, `"created_at": "2026-10-12T15:04:09.212573Z"`, `"yanked": false`, `"checksum": "d78c8dee4c7bf0e14673097256fed6142ce9d3b85a408189d07482442145823b"`, which equals Cargo.lock line 160. — [crates.io syn 3.0.9](https://crates.io/api/v1/crates/syn/3.0.9), [Cargo.lock](<C:\Users\mitam\OneDrive\Documents\Cryptographic Biscuits\agent-authority-fabric\Cargo.lock>)
- `src/lib.rs` contains `#![no_std]`, `pub use thiserror_impl::*;`, `#[cfg(feature = "std")]` `extern crate std;`, `#[cfg(feature = "std")]` `extern crate std as core;`, `mod private;` and `include!(concat!(env!("OUT_DIR"), "/private.rs"));`. — [docs.rs lib.rs 2.0.21](https://docs.rs/crate/thiserror/2.0.21/source/src/lib.rs)
- `src/private.rs` contains `#[doc(hidden)] pub use core::error::Error;` and `#[cfg(all(feature = "std", not(thiserror_no_backtrace_type)))] #[doc(hidden)] pub use std::backtrace::Backtrace;`. It also re-exports `AsDynError`, `AsDisplay` and `Var`, plus `ThiserrorProvide` only under `#[cfg(error_generic_member_access)]`. — [docs.rs private.rs](https://docs.rs/crate/thiserror/2.0.21/source/src/private.rs)
- `build.rs` writes `private.rs`, which holds a `#[doc(hidden)]` module named `__private` plus the patch number (`__private21` for 2.0.21) that re-exports `crate::private::*`. It emits `cargo:rustc-cfg=feature="std"` when the crate lacks the `std` feature and the rustc minor version is below 81; the code comment cites 1.81 as the release that stabilized `core::error::Error`. It emits `thiserror_no_backtrace_type` when the minor version is below 65. It also runs a nightly probe for `error_generic_member_access`; on stable the probe fails and the cfg stays off. — [docs.rs build.rs](https://docs.rs/crate/thiserror/2.0.21/source/build.rs)
- In the generator, the Error impl's trait path is `::thiserror::#private::Error`. — [docs.rs thiserror-impl expand.rs](https://docs.rs/crate/thiserror-impl/2.0.21/source/src/expand.rs)
- The crate docs say: "This library provides a convenient derive macro for the standard library's `std::error::Error` trait." — [docs.rs thiserror 2.0.21](https://docs.rs/thiserror/2.0.21/thiserror/)
- `display.rs` implements `AsDisplay` for `Path` and `PathBuf` only under `#[cfg(feature = "std")]`, and for a `Placeholder` under `#[cfg(not(feature = "std"))]`. — [docs.rs display.rs](https://docs.rs/crate/thiserror/2.0.21/source/src/display.rs)
- 2.0.0 feature: "Support disabling thiserror's standard library dependency by disabling the default "std" Cargo feature" (#373), with the example `thiserror = { version = "2", default-features = false }`. — [GitHub release 2.0.0](https://github.com/dtolnay/thiserror/releases/tag/2.0.0)
- "Using `Backtrace` in errors requires a nightly compiler with Rust version 1.73 or newer." — [docs.rs thiserror 2.0.21](https://docs.rs/thiserror/2.0.21/thiserror/)

### Inferences
- The project uses default features. Inside thiserror, `core` is therefore aliased to `std`, so the derive implements `std::error::Error`. On Rust 1.81 and later that is the same trait as `core::error::Error`, so `?`, `Box<dyn std::error::Error>` and `.source()` chains behave normally.
- `default-features = false` would drop the `std` dependency, the `Backtrace` re-export and the `Path`/`PathBuf` display helpers, and the derive would then implement the real `core::error::Error` (on compilers older than 1.81, build.rs turns the `std` cfg back on). pep-sidecar needs none of this: it uses default features and has no `Backtrace` or `Path` fields.
- Edition 2024 turns on Cargo's rust-version-aware resolver. thiserror and thiserror-impl require 1.77 and syn 3.0.9 requires 1.71, all at or below the package's 1.88, so the resolver sees no MSRV conflict. The library's own edition (2021) does not limit a consumer on edition 2024.
- On stable 1.97 the `error_generic_member_access` probe fails. That is the normal stable path: no `provide()` and no nightly features.

### Gaps
- The release notes do not say why 2.0.21 raised `rust-version` from 1.71 to 1.77.
- I did not check `proc-macro2` 1.0.107, `quote` 1.0.47 or `unicode-ident` 1.0.27 (from the lockfile) against crates.io one by one. The checksums that were checked all matched.

## 3. Attribute syntax supported in 2.x (verbatim rules)

### Takeaway
Every form pep-sidecar uses is documented: `#[error("...")]` on unit, tuple and struct variants; positional `{0}` and named `{field}`; format specs such as `:?` and `:o`; and `#[from]` on a single-field tuple variant (which generates `From` and implies `#[source]`). The derive has four helper attributes (`#[backtrace]`, `#[error]`, `#[from]`, `#[source]`). One field name is special (`source`), and so is one type name (`Backtrace`). Nothing else is.

### Cited Findings
- The derive's signature block: `#[derive(Error)] { // Attributes available to this derive: #[backtrace] #[error] #[from] #[source] }`. — [docs.rs derive.Error](https://docs.rs/thiserror/2.0.21/thiserror/derive.Error.html)
- "Errors may be enums, structs with named fields, tuple structs, or unit structs." — [docs.rs lib.rs 2.0.21](https://docs.rs/crate/thiserror/2.0.21/source/src/lib.rs)
- "A [`Display`] impl is generated for your error if you provide `#[error("...")]` messages on the struct or each variant of your enum, as shown above in the example." — [docs.rs lib.rs 2.0.21](https://docs.rs/crate/thiserror/2.0.21/source/src/lib.rs)
- The first doc example mixes all three variant shapes, including `#[from] io::Error` (indentation normalized):
  ```rust
  use thiserror::Error;
  #[derive(Error, Debug)]
  pub enum DataStoreError {
      #[error("data store disconnected")]
      Disconnect(#[from] io::Error),
      #[error("the data for key `{0}` is not available")]
      Redaction(String),
      #[error("invalid header (expected {expected:?}, found {found:?})")]
      InvalidHeader {
          expected: String,
          found: String,
      },
      #[error("unknown data store error")]
      Unknown,
  }
  ```
  — [docs.rs lib.rs 2.0.21](https://docs.rs/crate/thiserror/2.0.21/source/src/lib.rs)
- "The messages support a shorthand for interpolating fields from the error." — [docs.rs thiserror 2.0.21](https://docs.rs/thiserror/2.0.21/thiserror/)
- The shorthand list, verbatim: `#[error("{var}")]` ⟶ `write!("{}", self.var)` · `#[error("{0}")]` ⟶ `write!("{}", self.0)` · `#[error("{var:?}")]` ⟶ `write!("{:?}", self.var)` · `#[error("{0:?}")]` ⟶ `write!("{:?}", self.0)`. — [docs.rs lib.rs 2.0.21](https://docs.rs/crate/thiserror/2.0.21/source/src/lib.rs)
- "These shorthands can be used together with any additional format args, which may be arbitrary expressions." — [docs.rs thiserror 2.0.21](https://docs.rs/thiserror/2.0.21/thiserror/). Also: "If one of the additional expression arguments needs to refer to a field of the struct or enum, then refer to named fields as `.var` and tuple fields as `.0`." The doc example is `#[error("invalid rdo_lookahead_frames {0} (expected < {max})", max = i32::MAX)]`. — [docs.rs lib.rs 2.0.21](https://docs.rs/crate/thiserror/2.0.21/source/src/lib.rs)
- How the derive maps a format spec to a trait (it reads the last character of the spec): `Some('?') => Trait::Debug`, `Some('o') => Trait::Octal`, `Some('x') => Trait::LowerHex`, `Some('X') => Trait::UpperHex`, `Some('p') => Trait::Pointer`, `Some('b') => Trait::Binary`, `Some('e') => Trait::LowerExp`, `Some('E') => Trait::UpperExp`, `Some(_) => Trait::Display`, `None => { bonus_display = true; ... Trait::Display }`. Digits become `MemberUnraw::Unnamed(Index { index, span })` (a tuple field); identifiers starting with `'a'..='z' | 'A'..='Z' | '_'` become `MemberUnraw::Named(ident)`; `if read.starts_with("r#") { continue; }`. A plain `{x}` (no spec) is emitted as `#binding_value.as_display()`. — [docs.rs thiserror-impl fmt.rs](https://docs.rs/crate/thiserror-impl/2.0.21/source/src/fmt.rs)
- `AsDisplay`: `impl<'a, T> AsDisplay<'a> for &T` `where T: Display + ?Sized + 'a`, with extra `Path`/`PathBuf` impls under `std`. — [docs.rs display.rs](https://docs.rs/crate/thiserror/2.0.21/source/src/display.rs)
- The 2.0.0 notes use an octal spec on a field: `#[error("{thing:o}", thing = "...")]` (bounds are no longer inferred when a named argument shadows the field, #345). — [GitHub release 2.0.0](https://github.com/dtolnay/thiserror/releases/tag/2.0.0)
- Source rule: "The Error trait's [`source()`] method is implemented to return whichever field has a `#[source]` attribute or is named `source`, if any. This is for identifying the underlying lower level error that caused your error." — [docs.rs lib.rs 2.0.21](https://docs.rs/crate/thiserror/2.0.21/source/src/lib.rs)
- "A `From` impl is generated for each variant that contains a `#[from]` attribute." — [docs.rs thiserror 2.0.21](https://docs.rs/thiserror/2.0.21/thiserror/)
- "The variant using `#[from]` must not contain any other fields beyond the source error (and possibly a backtrace — see below). Usually `#[from]` fields are unnamed, but `#[from]` is allowed on a named field too." — [docs.rs lib.rs 2.0.21](https://docs.rs/crate/thiserror/2.0.21/source/src/lib.rs)
- "The `#[from]` attribute always implies that the same field is `#[source]`, so you don't ever need to specify both attributes." — [docs.rs lib.rs 2.0.21](https://docs.rs/crate/thiserror/2.0.21/source/src/lib.rs)
- "Any error type that implements `std::error::Error` or dereferences to `dyn std::error::Error` will work as a source." — [docs.rs lib.rs 2.0.21](https://docs.rs/crate/thiserror/2.0.21/source/src/lib.rs)
- Generated signatures: `fn source(&self) -> ::core::option::Option<&(dyn ::thiserror::#private::Error + 'static)> {` and `fn from(#source_var: #from) -> Self {`, where `source_var` is `source`. — [docs.rs thiserror-impl expand.rs](https://docs.rs/crate/thiserror-impl/2.0.21/source/src/expand.rs)
- `aserror.rs`: `impl<'a, T: Error + 'a> AsDynError<'a> for T {` with `fn as_dyn_error(&self) -> &(dyn Error + 'a)`, plus impls for `dyn Error + 'a`, `dyn Error + Send + 'a`, `dyn Error + Send + Sync + 'a` and `dyn Error + Send + Sync + UnwindSafe + 'a`; also `impl<T: Error> Sealed for T {}`. Here `Error` is `use core::error::Error;`. — [docs.rs aserror.rs](https://docs.rs/crate/thiserror/2.0.21/source/src/aserror.rs)
- Backtrace rule: "The Error trait's [`provide()`] method is implemented to provide whichever field has a type named `Backtrace`, if any, as a [`std::backtrace::Backtrace`]." — [docs.rs lib.rs 2.0.21](https://docs.rs/crate/thiserror/2.0.21/source/src/lib.rs). "The `#[backtrace]` attribute requires a nightly compiler with Rust version 1.73 or newer." — [docs.rs thiserror 2.0.21](https://docs.rs/thiserror/2.0.21/thiserror/)
- Opt-out for the `source` name: "Support using `r#source` as field name to opt out of a field named "source" being treated as an error's" `Error::source()` (#350). — [GitHub release 2.0.0](https://github.com/dtolnay/thiserror/releases/tag/2.0.0)
- "Errors may use `error(transparent)` to forward the source and [`Display`] methods straight through to an underlying error without adding an additional message. This would be appropriate for enums that need an "anything else" variant." — [docs.rs lib.rs 2.0.21](https://docs.rs/crate/thiserror/2.0.21/source/src/lib.rs). The `#[error(fmt = path::to::myfmt)]` form exists from 2.0.0 (#367). — [GitHub release 2.0.0](https://github.com/dtolnay/thiserror/releases/tag/2.0.0). pep-sidecar uses neither.

### Inferences
- `{guard:?}` needs only `GuardId: Debug`. The `?` spec selects Debug, and no Display bound is involved.
- `{reason}` needs `PolicyError: Display` (through `AsDisplay for &T where T: Display`), which PolicyError's own thiserror derive provides. `{offset}` (usize), `{owner}`, `{expected}` and `{actual}` (u32) use Display, which these types implement.
- `{mode:o}` on `mode: u32`: the last character `o` maps to `Trait::Octal`, and the spec stays in the emitted format string. u32 implements Octal, so the field prints in octal without a `0o` prefix (mode 0o750 prints as `750`). Optional cosmetic change, not needed to compile: `{mode:04o}` prints `0750`, which reads naturally beside the literal "0660".
- `#[from]` and `#[source]` field types must satisfy `T: core::error::Error + 'static`, or be a `'static` `dyn Error` trait object. The `'static` comes from the generated `source()` signature, and `T: Error + 'a` from `AsDynError`. `Debug + Display` come with Error's supertraits. JcsError, StoreError and ConfigError (thiserror-derived, no lifetimes), `nix::Errno` and `io::Error` all qualify (see section 4).
- The field names `reason`, `guard`, `offset`, `mode`, `owner`, `expected` and `actual` are not special. The only name rule is `source`, the only type rule is a type named `Backtrace`, and the helper attributes are the four listed above. No pep-sidecar field is named `source` or has a type named `Backtrace`, so no field is silently treated as a source or backtrace.
- `///` doc comments on struct-variant fields are ordinary `#[doc]` attributes, not helper attributes, so they do not affect the derive.

### Gaps
- I did not fetch thiserror-impl's `prop.rs` and `valid.rs`, which contain the exact detection code for the `source` name and the `Backtrace` type. The rules above rest on the crate docs.

## 4. `#[from]` on `Clone + Copy + PartialEq + Eq` enums, and `#[from] nix::Error` / `#[from] io::Error` on a non-Copy enum

### Takeaway
Both work. The derive adds only `Error`, `Display` and `From` impls. It adds no fields, no wrapper and no Drop, so `Clone`, `Copy`, `PartialEq` and `Eq` depend only on the user's own fields, and all of PepError's fields are Copy. `nix::Error` is `Errno`, which implements `Error`, `Display`, `Debug` and `Copy`. `io::Error` is a standard error type, and the crate's own first doc example uses `#[from] io::Error`.

### Cited Findings
- "Thiserror deliberately does not appear in your public API. You get the same thing as if you had written an implementation of [`std::error::Error`] by hand, and switching from handwritten impls to thiserror or vice versa is not a breaking change." — [docs.rs lib.rs 2.0.21](https://docs.rs/crate/thiserror/2.0.21/source/src/lib.rs), [docs.rs thiserror 2.0.21](https://docs.rs/thiserror/2.0.21/thiserror/)
- The generator emits bare `impl` items (Error, Display, From) with no `const _: () = { ... }` wrapper. The From body is built as `quote!({ #from_member: #some_source, #backtrace })` and wrapped as `#ty::#variant #body` for enums. `#backtrace` is added only when a backtrace field exists, and `#some_source` wraps the value in `Some` only when the field is an `Option`. — [docs.rs thiserror-impl expand.rs](https://docs.rs/crate/thiserror-impl/2.0.21/source/src/expand.rs)
- "For variants that use `#[from]` and also contain a `Backtrace` field, a backtrace is captured from within the `From` impl." — [docs.rs thiserror 2.0.21](https://docs.rs/thiserror/2.0.21/thiserror/)
- The doc example's `Disconnect(#[from] io::Error),`. — [docs.rs lib.rs 2.0.21](https://docs.rs/crate/thiserror/2.0.21/source/src/lib.rs)
- `pub type Error = Errno;`, documented as "Nix’s main error type." and badged "Available on **Unix** only." — [docs.rs nix 0.31.3 type.Error](https://docs.rs/nix/0.31.3/nix/type.Error.html)
- `Errno` implements `Clone`, `Copy`, `Debug`, `Display`, `Eq`, `PartialEq` and `Error` (the docs link `Error` to `core::error::Error`). There are also `impl From<Errno> for Error` (io::Error) and `impl TryFrom<Error> for Errno`, and `Send` and `Sync` are auto traits. — [docs.rs nix 0.31.3 Errno](https://docs.rs/nix/0.31.3/nix/errno/enum.Errno.html)
- Local code:
  - `PepError` is `#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]` with `Malformed(#[from] JcsError)`, `Denied { guard: GuardId, reason: PolicyError }`, `Store(#[from] StoreError)`, `InvalidConfig(#[from] ConfigError)` and `const fn to_agent_code(self)` (engine.rs lines 238–281).
  - `GuardId`, `PolicyError`, `ConfigError`, `StoreError` and `JcsError` all derive `Clone, Copy, PartialEq, Eq` (engine.rs lines 68, 91, 193, 224; jcs.rs line 38).
  - `PeerError` is `#[derive(Debug, thiserror::Error)]` with `Sys(#[from] nix::Error)` and `Io(#[from] io::Error)` (peercred.rs lines 44–51).
  - `peercred` is gated by `#[cfg(any(target_os = "linux", target_os = "macos"))] pub mod peercred;` (lib.rs lines 13–14), which matches the target-gated `nix` dependency (Cargo.toml lines 22–23).
  - Sources: [engine.rs](<C:\Users\mitam\OneDrive\Documents\Cryptographic Biscuits\agent-authority-fabric\src\engine.rs>), [jcs.rs](<C:\Users\mitam\OneDrive\Documents\Cryptographic Biscuits\agent-authority-fabric\src\jcs.rs>), [peercred.rs](<C:\Users\mitam\OneDrive\Documents\Cryptographic Biscuits\agent-authority-fabric\src\peercred.rs>), [lib.rs](<C:\Users\mitam\OneDrive\Documents\Cryptographic Biscuits\agent-authority-fabric\src\lib.rs>), [Cargo.toml](<C:\Users\mitam\OneDrive\Documents\Cryptographic Biscuits\agent-authority-fabric\Cargo.toml>)

### Inferences
- PepError gets `impl From<JcsError>`, `From<StoreError>` and `From<ConfigError>`. These are three distinct types, so the impls cannot overlap. The generated `source()` takes `&self` and returns a borrowed `&dyn Error`, and `from()` moves the inner value into the variant. Neither depends on Copy, and Copy holds because every field type is Copy.
- `PepError::Denied` has no `#[source]` or `#[from]` and no field named `source`, so its `source()` is `None`. `reason: PolicyError` is not picked up as a source even though PolicyError implements Error, because thiserror chooses sources only by attribute or by name.
- `const fn to_agent_code(self)` is unaffected: the derive emits no Drop impl and changes no fields.
- PeerError's `From<Errno>` and `From<io::Error>` are distinct, and nix's own `impl From<Errno> for io::Error` does not conflict with either. Applying `?` to a `nix::Result` inside a function that returns `Result<_, PeerError>` produces `PeerError::Sys`. PeerError correctly derives neither Clone nor Copy, because `io::Error` is not Clone.
- The `nix::Error` alias exists only on Unix, but `peercred` compiles only on Linux and macOS, which covers both required targets (x86_64-unknown-linux-gnu and aarch64-apple-darwin).

### Gaps
- No `cargo check` or `cargo clippy` was run. `cargo` exists only inside WSL (CLAUDE.md §2), and my attempt to download the published `.crate` archives was blocked by the permission classifier, so I used the docs.rs source view instead. The verdicts here are inferred from the docs and the generator's source, not from an observed build.

## 5. Breaking changes (1.x → 2.0 and within 2.0.x), and the fully qualified derive path

### Takeaway
None of the 2.0 breaking changes reach pep-sidecar's code: it uses no raw-identifier format arguments, no named arguments that shadow a field, no `{0}` alongside extra positional arguments, and it depends on `thiserror` directly. The 2.0.x patches are bug and lint fixes plus MSRV bumps up to 1.77. `#[derive(thiserror::Error)]` with no `use` resolves to the derive at the crate root, which is supported because the expansion uses absolute `::thiserror::__private21::…` paths.

### Cited Findings
- 2.0.0 (GitHub "06 Nov"; crates.io 2024-11-06T02:52:22Z), breaking changes:
  - "Referencing keyword-named fields by a raw identifier like `{r#type}` inside a format string is no longer accepted" (#347). Example: `#[error("... {type} ...")]  // Before: {r#type}`
  - "Trait bounds are no longer inferred on fields whose value is shadowed by an explicit named argument" (#345). Example: `#[error("{thing:o}", thing = "...")]`
  - "Tuple structs and tuple variants can no longer use numerical `{0}` `{1}` access at the same time as supplying extra" positional arguments (#354). Rejected example: `#[error("ambiguous: {0} {}", $N)]`
  - "Code containing invocations of thiserror's `derive(Error)` must now have a direct dependency on the `thiserror` crate" (#368, #369, #370, #372)
  - Source: [GitHub release 2.0.0](https://github.com/dtolnay/thiserror/releases/tag/2.0.0)
- 2.0.0 features: the `std` feature (#373); `r#source` (#350); "Infinite recursion in a generated Display impl now produces an `unconditional_recursion` warning" (#359), for example `#[error("??? {self}")]`; `#[error(fmt = path::to::myfmt)]` (#367); and transparent variants in enums that have an enum-level message (#366). — [GitHub release 2.0.0](https://github.com/dtolnay/thiserror/releases/tag/2.0.0)
- The rejected positional case produces the error "ambiguous reference to positional arguments by number in a {container}; change this to a named argument". — [docs.rs thiserror-impl fmt.rs](https://docs.rs/crate/thiserror-impl/2.0.21/source/src/fmt.rs)
- 2.0.2 to 2.0.11, verbatim:
  - 2.0.2: "Fix hang on invalid input inside #[error(...)] attribute (#382)"
  - 2.0.3: "Support the same Path field being repeated in both Debug and Display representation in error message (#383)" and "Improve error message when a format trait used in error message is not implemented by some field (#384)"
  - 2.0.4: "Eliminate needless_lifetimes clippy lint in generated `From` impls (#391, thanks @matt-phylum)"
  - 2.0.5: "Prevent deprecation warning on generated impl for deprecated type (#394)"
  - 2.0.6: "Suppress deprecation warning on generated From impls (#396)"
  - 2.0.7: "Work around conflict with #[deny(clippy::allow_attributes)] (#397, thanks @zertosh)"
  - 2.0.8: "Improve support for macro-generated `derive(Error)` call sites (#399)"
  - 2.0.9: "Work around `missing_inline_in_public_items` clippy restriction being triggered in macro-generated code (#404)"
  - 2.0.10: "Support errors containing a generic type parameter's associated type in a field (#408)"
  - 2.0.11: "Add feature gate to tests that use std (#409, #410, thanks @Maytha8)"
  - Source: [GitHub releases page 2](https://github.com/dtolnay/thiserror/releases?page=2)
- 2.0.12 to 2.0.21, verbatim:
  - 2.0.12: "Prevent elidable_lifetime_names pedantic clippy lint in generated impl (#413)"
  - 2.0.13: "Documentation improvements"
  - 2.0.14: "Allow build-script cleanup failure with NFSv3 output directory to be non-fatal (#426)"
  - 2.0.15: "Prevent `Error::provide` API becoming unavailable from a future new compiler lint (#427)"
  - 2.0.16: "Add to "no-std" crates.io category (#429)"
  - 2.0.17: "Use differently named __private module per patch release (#434)"
  - 2.0.18: "Make compatible with project-level `needless_lifetimes = "forbid"` (#443, thanks @LucaCappelletti94)"
  - 2.0.19: "Update to syn 3"
  - 2.0.20: "Suppress redundant_field_names clippy lint in generated code (#454)"
  - 2.0.21: "Fix parsing of generic unit variants in display expressions (#459)"
  - Source: [GitHub releases](https://github.com/dtolnay/thiserror/releases)
- The derive is the item `Error` at the crate root (`thiserror/derive.Error.html`). — [docs.rs derive.Error](https://docs.rs/thiserror/2.0.21/thiserror/derive.Error.html). It is exported by `pub use thiserror_impl::*;`. — [docs.rs lib.rs 2.0.21](https://docs.rs/crate/thiserror/2.0.21/source/src/lib.rs)
- Generated code refers to `::thiserror::#private::Error`, `::thiserror::#private::AsDynError`, `::thiserror::#private::AsDisplay` and `::thiserror::#private::Backtrace`. — [docs.rs thiserror-impl expand.rs](https://docs.rs/crate/thiserror-impl/2.0.21/source/src/expand.rs). In 2.0.21, `#private` is `__private21`. — [docs.rs build.rs](https://docs.rs/crate/thiserror/2.0.21/source/build.rs)
- The project depends on `thiserror` directly, under its own name: `thiserror = "=2.0.21"`. — [Cargo.toml](<C:\Users\mitam\OneDrive\Documents\Cryptographic Biscuits\agent-authority-fabric\Cargo.toml>)

### Inferences
- `#[derive(Debug, …, thiserror::Error)]` is ordinary path-based derive resolution. The derive registers its helper attributes (`#[error]`, `#[from]`) however it is named, so `use thiserror::Error` is not needed. Because the expansion uses absolute `::thiserror::…` paths, the real requirement is a direct, non-renamed dependency called `thiserror`, which the project has.
- Checked against the project's code: no `{r#…}`, no `name = expr` arguments, no extra positional arguments, no `{self}`, no `transparent` and no `fmt =`. Tuple variants use only `{0}`. Nothing needs to change.
- Each patch release has its own `__private` module, and thiserror requires `thiserror-impl = "=2.0.21"`, so Cargo always keeps the two crates on the same patch; the lockfile has both at 2.0.21. The 2.0.21 fix (#459, generic unit variants in display expressions) does not affect pep-sidecar, which has no generics and no expression arguments.
- Upgrading from 1.x would not matter either: every 2.0 breaking change listed above is absent from the project's code.

### Gaps
- I did not fetch the 2.0.1 release notes. For 2.0.0 I have only short excerpts, not the full explanatory text.

## 6. Known issues where 2.0.x derive output triggers warnings under the project's lints

### Takeaway
thiserror 2.0.21's generated impls carry their own `#[allow]`s for `unused_qualifications`, `deprecated`, `unused_variables`, `clippy::used_underscore_binding` and `clippy::redundant_field_names` (plus the lifetime lints when the type has lifetimes). The crate's tests check the output under `deny(unused_qualifications)`, `deny(clippy::allow_attributes)`, `deny(deprecated)` and `forbid(clippy::needless_lifetimes)`. The output contains no casts, `unsafe`, panics, unwraps or `let _ =`. Every clippy issue in generated code reported during 2.0.x was fixed by or before 2.0.21. I found no tracker issue about `trivial_casts`, `rust_2018_idioms`/`elided_lifetimes_in_paths`, or edition 2024.

### Cited Findings
- Attributes the generator emits:
  - Error impl: `#[allow(unused_qualifications)]` and `#[automatically_derived]`; for enums, the `source` and `provide` matches add `#[allow(deprecated)]`.
  - Display impl: `#[allow(unused_qualifications)]` and `#[automatically_derived]`. The enum Display match adds `#[allow(unused_variables, deprecated, clippy::used_underscore_binding)]`. For structs, `fmt` adds `#[allow(clippy::used_underscore_binding)]` and the inner `let` adds `#[allow(unused_variables, deprecated)]`.
  - From impl: `#[allow(deprecated, unused_qualifications, #lint_allows)]` and `#[automatically_derived]`, and the `from` function adds `#[allow(clippy::redundant_field_names)]`. `#lint_allows` expands to `clippy::elidable_lifetime_names, clippy::needless_lifetimes,` only when the type has lifetimes.
  - No `#[expect(` appears.
  - Source: [docs.rs thiserror-impl expand.rs](https://docs.rs/crate/thiserror-impl/2.0.21/source/src/expand.rs)
- The emitted code contains no `unsafe`, `panic!`, `unreachable!`, `.unwrap()` or `let _ =`. The only `as` is the rename `use ::thiserror::#private::AsDynError as _;`, not a cast. There is no `const _` wrapper. The `fmt` signature is `fn fmt(&self, __formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {`, with no `<'_>`. — [docs.rs thiserror-impl expand.rs](https://docs.rs/crate/thiserror-impl/2.0.21/source/src/expand.rs)
- `tests/test_lints.rs`:
  - `test_allow_attributes`: `#![deny(clippy::allow_attributes)]` on `pub struct MyError(#[from] anyhow::Error);`
  - `test_unused_qualifications`: `#![deny(unused_qualifications)]`, with the comment "Expansion of derive(Error) macro can't know whether something like std::error::Error is already imported in the caller's scope so it must suppress unused_qualifications."
  - `test_needless_lifetimes`: `#![deny(clippy::elidable_lifetime_names, clippy::needless_lifetimes)]`
  - `test_forbid_needless_lifetimes`: `#![forbid(clippy::needless_lifetimes)]` on `pub struct MyError(#[from] std::io::Error);`
  - `test_deprecated`: `#![deny(deprecated)]`
  - Source: [docs.rs test_lints.rs](https://docs.rs/crate/thiserror/2.0.21/source/tests/test_lints.rs)
- PR #454, "Suppress redundant_field_names clippy lint": its description says "New clippy lint in nightly-2026-08-08". The warnings it fixed were on `#[from] source` (named) fields in `tests/test_from.rs` and `tests/test_generics.rs`. It was merged on Aug 8, 2026 and cross-references rust-lang/rust-clippy#17525, "redundant_field_names triggered on derived code" (closed). — [GitHub PR #454](https://github.com/dtolnay/thiserror/pull/454)
- Lint fixes in generated code across 2.0.x: #391 needless_lifetimes in From (2.0.4), #394 and #396 deprecation (2.0.5, 2.0.6), #397 allow_attributes (2.0.7), #404 missing_inline_in_public_items (2.0.9), #413 elidable_lifetime_names (2.0.12), #427 provide vs. a future compiler lint (2.0.15), #443 `needless_lifetimes = "forbid"` (2.0.18), #454 redundant_field_names (2.0.20). — [GitHub releases](https://github.com/dtolnay/thiserror/releases), [GitHub releases page 2](https://github.com/dtolnay/thiserror/releases?page=2)
- thiserror's own crate-level `#![allow(clippy::elidable_lifetime_names, clippy::module_name_repetitions, clippy::needless_lifetimes, clippy::return_self_not_must_use, clippy::wildcard_imports)]` applies only to thiserror's source. — [docs.rs lib.rs 2.0.21](https://docs.rs/crate/thiserror/2.0.21/source/src/lib.rs)
- Searches on github.com for thiserror with `unused_qualifications`, with `elided_lifetimes_in_paths`/`rust_2018_idioms`, and with edition-2024 lint warnings found no matching dtolnay/thiserror issue. Unrelated hits included #398 (E0425 when deriving Error for an enum declared inside a macro; a duplicate of #86) and #332 ("Generic unit variants are handled incorrectly inside format args"). — [thiserror #398](https://github.com/dtolnay/thiserror/issues/398), [thiserror #332](https://github.com/dtolnay/thiserror/issues/332)
- Context from outside the thiserror repo (search titles only, not fetched): rust-lang/rust#51903, "println!(), derive(Debug), derive(Clone), and probably many other macros break when using the elided_lifetimes_in_paths lint", and rust-lang/rust PR #52069, "add structured suggestions and fix false-positive for elided-lifetimes-in-paths lint". — [rust#51903](https://github.com/rust-lang/rust/issues/51903), [rust PR #52069](https://github.com/rust-lang/rust/pull/52069)

### Inferences (each project lint against the 2.0.21 expansion)
| Project lint (all `-D warnings`) | Exposure in thiserror output | Expected result |
|---|---|---|
| `unused_qualifications` | Paths like `::core::fmt::Display` and user-spanned types such as `nix::Error` and `io::Error` | Allowed on every generated impl, and covered by a regression test, so no warning |
| `trivial_casts`, `trivial_numeric_casts`, `clippy::as_conversions` | No `as` casts are emitted | Not applicable |
| `missing_docs`, `unreachable_pub`, `missing_debug_implementations` | Only trait impls are emitted, with no new `pub` items; the user enums already derive `Debug` | Not applicable |
| `let_underscore_drop` | No `let _ =` | Not applicable |
| `rust_2018_idioms` (`elided_lifetimes_in_paths`) | `&mut ::core::fmt::Formatter` has a hidden lifetime, but the tokens come from `quote!` with call-site spans in an external derive, where rustc suppresses lints not marked to report in external macros. No thiserror report exists despite very wide use | Expected no warning. **Not observed locally**; this is the only residual risk |
| `unsafe_code = "forbid"` | No `unsafe` and no `allow(unsafe_code)` in the output | No E0453 conflict |
| `clippy::all` + `clippy::pedantic` | Explicit allows cover the lints that fired before (`used_underscore_binding`, `redundant_field_names`, the lifetime lints), and clippy generally skips external-macro output | No warning expected |
| `unwrap_used`, `expect_used`, `panic`, `todo`, `unimplemented`, `indexing_slicing`, `arithmetic_side_effects`, `string_slice`, `unreachable`, `unwrap_in_result`, `float_arithmetic`, `dbg_macro`, `print_*`, `exit`, `mem_forget` | None of these constructs are emitted | Not applicable |

- `RUSTFLAGS='-D warnings'` does not turn warnings inside thiserror's own source into errors, because Cargo caps lints for registry dependencies. Only the expansion inside pep-sidecar's crate is subject to the project's lint levels. This is standard Cargo behavior, not something a thiserror source states.
- The `redundant_field_names` behavior that #454 suppresses appeared in clippy nightly-2026-08-08, which should be newer than the project's 1.97.0 toolchain (inferred from the six-week release train). The pinned 2.0.21 already suppresses it either way. Also, pep-sidecar's `#[from]` fields are tuple fields (`0: source`), not the `source: source` shape that triggered the lint.

### Gaps
- No build output was observed. The remaining risks are `elided_lifetimes_in_paths` (through `rust_2018_idioms`) and any clippy lint added after 1.97, which matters only if the toolchain is upgraded. Running the five-command verification loop in CLAUDE.md §2 would settle this.
- Open issue #446 ("No unused field warnings are produced on enums deriving thiserror::Error") appeared only in a search summary and was not fetched. It concerns warnings that are *missing*, so it cannot break a `-D warnings` build.

## 7. Verdict per usage pattern: compiles as-is, or needs change?

### Takeaway
Nothing needs to change. Every thiserror usage in pep-sidecar compiles as-is against the real thiserror 2.0.21, which is a real, unyanked release and the latest stable. One caveat: success under the full `-D warnings` lint set is inferred from the docs and the generator's source, not seen in a build.

### Cited Findings
- The pin exists, is not yanked, is the latest stable, needs Rust 1.77 or later, and its lockfile checksums match. — [crates.io versions API](https://crates.io/api/v1/crates/thiserror/versions), [crates.io crate API](https://crates.io/api/v1/crates/thiserror), [Cargo.lock](<C:\Users\mitam\OneDrive\Documents\Cryptographic Biscuits\agent-authority-fabric\Cargo.lock>)
- Attribute rules (`#[error]` per variant, `{var}`, `{0}`, `{var:?}`, `#[from]` implying `#[source]`, the source bounds): see the verbatim quotes in section 3. — [docs.rs lib.rs 2.0.21](https://docs.rs/crate/thiserror/2.0.21/source/src/lib.rs), [docs.rs thiserror-impl fmt.rs](https://docs.rs/crate/thiserror-impl/2.0.21/source/src/fmt.rs)
- Lint hygiene of the generated code: see section 6. — [docs.rs thiserror-impl expand.rs](https://docs.rs/crate/thiserror-impl/2.0.21/source/src/expand.rs), [docs.rs test_lints.rs](https://docs.rs/crate/thiserror/2.0.21/source/tests/test_lints.rs)
- `nix::Error` = `Errno`, which implements `Error`, `Display` and `Copy`. — [docs.rs nix 0.31.3 Errno](https://docs.rs/nix/0.31.3/nix/errno/enum.Errno.html)

### Inferences (verdicts)
| # | Usage pattern | Where | Verdict | Basis |
|---|---|---|---|---|
| 1 | `thiserror = "=2.0.21"` with default features | Cargo.toml line 19 | **compiles as-is** | Real, unyanked, latest stable (2026-09-23); MSRV 1.77 ≤ 1.88 ≤ 1.97; the date comment is correct |
| 2 | Fully qualified `#[derive(…, thiserror::Error)]` with no `use` | engine.rs, jcs.rs, peercred.rs | **compiles as-is** | The derive sits at the crate root; the dependency is direct and not renamed (2.0.0 requirement); expansion uses `::thiserror::__private21` |
| 3 | Unit variants with `#[error("literal")]` | PolicyError, ConfigError, StoreError, PepError and PeerError unit variants | **compiles as-is** | `#[error]` applies to "each variant of your enum"; doc example `Unknown` |
| 4 | Struct variants interpolating named fields (`{offset}`, `{owner}`, `{expected}`, `{actual}`) | JcsError, PeerError | **compiles as-is** | `{var}` ⟶ `write!("{}", self.var)`; the fields are not special names |
| 5 | `{guard:?}` with Debug-only `GuardId`, plus `{reason}` | PepError::Denied | **compiles as-is** | `{var:?}` selects Debug; `{reason}` needs `PolicyError: Display`, which its derive supplies |
| 6 | `{mode:o}` octal spec on `u32` | PeerError::AncestorUnsafe, ParentModeTooPermissive, SocketModeMismatch | **compiles as-is** | `Some('o') => Trait::Octal`; u32 implements Octal. Optional cosmetic change only: `{mode:04o}` |
| 7 | `#[from]` single-field tuple variants on a Copy enum with Copy, thiserror-derived inner types | PepError::Malformed, Store, InvalidConfig | **compiles as-is** | Generates `From` and implies `#[source]`; inner types are `Error + 'static`; the derive adds no fields or Drop |
| 8 | `#[from] nix::Error` and `#[from] io::Error` on a non-Copy enum | PeerError::Sys, Io | **compiles as-is** | `Errno` implements Error and Display; `io::Error` appears in the doc example; peercred is gated to Linux and macOS like nix |
| 9 | `///` docs on variant fields alongside thiserror attributes | JcsError, PeerError, PepError::Denied | **compiles as-is** | Doc comments are not helper attributes; the derive has only four |
| 10 | The full lint set under `-D warnings` (rustc + clippy all/pedantic/restriction) | all four files | **compiles as-is (expected)** | Generated impls carry their own allows, and the crate's tests cover several of these lints; only `elided_lifetimes_in_paths` is unverified |

- No replacement code is needed for any pattern. If the CLAUDE.md verification loop ever flags derive-generated code, report it upstream to dtolnay/thiserror and keep the lints as they are; CLAUDE.md §3 forbids weakening lints or adding `#[allow]` without approval.

### Gaps
- No compiler run confirms the verdicts. The five commands in CLAUDE.md §2 (fmt, clippy, test, and clippy+test with `lenient-numbers` on x86_64, then clippy for `aarch64-apple-darwin`) are the definitive check, especially for item 10.
