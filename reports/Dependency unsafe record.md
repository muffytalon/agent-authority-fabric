# Dependency unsafe record

pep-sidecar forbids `unsafe` in its own code (`unsafe_code = "forbid"`), but that lint stops at the crate boundary. This record lists every dependency that uses `unsafe`, what that code does, and whether our build compiles it. It is a map for reviewers, not a soundness audit.

- **As of:** 2026-10-28, `Cargo.lock` at commit `58a3f30` (unchanged since).
- **Build covered:** targets `x86_64-unknown-linux-gnu` and `aarch64-apple-darwin`, with every feature (`lenient-numbers` adds no dependencies). Both targets resolve the same 24 dependencies.
- **Method:** read the sources in Cargo's registry cache, whose checksums Cargo verifies against `Cargo.lock`, skipping tests and benches. For each crate the record notes its crate-level `unsafe_code` attribute and which `unsafe` items the enabled features and the two targets actually compile.
- **Keep it current:** redo this survey whenever a pin in `Cargo.toml` changes. `deny.toml` checks licences, sources and duplicate versions, but not `unsafe`.

## Linked into the sidecar

These crates end up in the binary. File references are to each crate's published source.

| Crate | Reached through | `unsafe` compiled in our build |
|---|---|---|
| base64 0.23.1 | `jcs::sha256_b64url` | **None.** With `simd-unsafe` off (we set `default-features = false`), the crate is `#![forbid(unsafe_code)]` (`src/lib.rs:284`). Its SIMD engines are the only `unsafe` and are not compiled. Turning base64's default features back on would bring them in. |
| sha2 0.11.1 | `jcs` digests | **Yes.** The portable SHA-256 backend reads its round constants with `ptr::read` (`read_volatile` on non-x86) (`src/sha256/soft/unroll.rs:39`). x86_64 also compiles the SHA-NI backend, which loads blocks with `_mm_loadu_si128` intrinsics (`src/sha256/x86_sha.rs`). aarch64 compiles the `aarch64_sha2` backend, which uses `vld1q_*` NEON intrinsics (`src/sha256/aarch64_sha2.rs`). The backend is picked at run time through cpufeatures (`src/sha256.rs:47-67`). The SHA-512 backends compile too, but pep-sidecar never calls SHA-512. |
| cpufeatures 0.3.1 | sha2 | **Yes.** x86_64 runs `cpuid` and `_xgetbv` (`src/x86.rs:41-71`). aarch64-apple-darwin calls `sysctlbyname` through libc (`src/aarch64.rs:141-160`), but only for features Apple does not guarantee. The `sha2` check is the constant `true` on Apple targets. |
| block-buffer 0.12.1 | digest | **Yes.** Unchecked position updates and raw-pointer block reads (`ptr::read`, `slice::from_raw_parts`) in `src/lib.rs`, `src/read.rs` and `src/sealed.rs`. The crate sets `#![allow(clippy::undocumented_unsafe_blocks)]` with a TODO to document these blocks (`src/lib.rs:41`). |
| hybrid-array 0.4.15 | digest, crypto-common (the digest output type) | **Yes.** Pointer casts between `Array<T, U>` and arrays or slices, `MaybeUninit::assume_init`, and `unsafe impl` of `ArraySize`, `Send` and `Sync` (`src/lib.rs`, `src/from_fn.rs`, `src/flatten.rs`, `src/sizes.rs`). |
| digest 0.11.3, crypto-common 0.2.2, typenum 1.20.1 | sha2 | **None.** Each is `#![forbid(unsafe_code)]`. |
| cfg-if 1.0.5 | sha2, nix | **None.** A macro only. |
| ryu-js 1.0.3 | `jcs` result-profile numbers | **Yes.** `Buffer::format_finite` writes through a raw pointer into a `MaybeUninit` buffer and returns `str::from_utf8_unchecked` (`src/buffer/mod.rs:81-110`). The Ryū core uses `get_unchecked` table lookups and `assume_init` (`src/d2s.rs`, `src/d2s_small_table.rs`, `src/pretty/`). There is no crate-level `unsafe_code` lint. |
| unicode-normalization 0.1.26 | `jcs` NFC | **Yes, a little.** The crate is `#![deny(unsafe_code)]` (`src/lib.rs:40`) with local allows for Hangul only: `decompose_hangul` (`src/normalize.rs:90-153`) and `char::from_u32_unchecked` in Hangul composition (`src/normalize.rs:201`, `208`). Each block has a safety comment. |
| tinyvec 1.13.3 | unicode-normalization | **None.** `#![forbid(unsafe_code)]` (`src/lib.rs:2`). |
| thiserror 2.0.21 | the error types | **None**, and the code it generates contains none either. |
| nix 0.31.3 | `peercred` | **Yes:** thin wrappers over libc system calls. Only the items the `socket` and `user` features enable compile, plus a small ungated core (`errno`, and parts of `fcntl`, `sys` and `unistd`). pep-sidecar uses `getsockopt` with `PeerCredentials` (Linux) or `LocalPeerPid` (macOS), plus `getpeereid` (macOS) and `geteuid`. These read results through `MaybeUninit` and the libc call (`src/sys/socket/sockopt.rs`, `src/unistd.rs`). |
| libc 0.2.191 | nix, cpufeatures | **Yes.** FFI declarations: every `extern "C"` function is unsafe to call, and helpers such as the `CMSG_*` macros are `unsafe fn`s. Only the module for the build target compiles (`unix/linux_like/linux/gnu` or `unix/bsd/apple`). |
| memoffset 0.9.1 | nix (`socket`) | **Macros only**, so their `unsafe` expands inside nix. On rustc 1.77 and later, `build.rs` sets `stable_offset_of`, so `offset_of!` forwards to the safe `core::mem::offset_of!`. The `raw_field!` macros still wrap `addr_of!` in `unsafe` (`src/raw_field.rs:136-222`). |
| bitflags 2.13.2 | nix | **None.** `#![cfg_attr(not(test), forbid(unsafe_code))]` (`src/lib.rs:273`). Its only `unsafe impl`s sit behind the `bytemuck` feature, which is off. |

## Compile time only

These run inside rustc while the crate builds (the `thiserror` derive and the build scripts) and are not linked into the binary.

| Crate | `unsafe` |
|---|---|
| thiserror-impl 2.0.21 | **None.** The one match is the keyword string `"unsafe"` in its expression scanner (`src/scan_expr.rs:46`). |
| syn 3.0.9 | **Yes.** Raw-pointer token cursors (`src/buffer.rs`). Most other matches are the parser handling Rust's `unsafe` keyword. |
| proc-macro2 1.0.107 | **Yes, a little.** A `ptr::read` (`src/fallback.rs:107`) and `Literal::from_str_unchecked`. |
| unicode-ident 1.0.27 | **Yes, a little.** Two `get_unchecked` table lookups (`src/lib.rs:278`, `291`). |
| quote 1.0.47, autocfg 1.5.1, cfg_aliases 0.2.2 | **None.** |

## Where review effort pays most

All of the following sit on paths that agent-controlled bytes reach:

- **ryu-js:** canonicalizing every non-integer number in a tool result.
- **unicode-normalization:** NFC on every string and key.
- **sha2, block-buffer and hybrid-array:** every digest and F-07 key.
- **nix and libc:** the peer-credential check at the socket.

The highest-risk switch is base64's `simd-unsafe` feature. It is on by default and is the only thing that would add `unsafe` to base64, so `default-features = false` on base64 must stay.
