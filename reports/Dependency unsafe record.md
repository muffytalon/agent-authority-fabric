# Dependency unsafe record

pep-sidecar forbids `unsafe` in its own code (`unsafe_code = "forbid"`), but that lint stops at the crate boundary. This record lists every dependency that uses `unsafe`, what that code does, and whether our build compiles it. It is a map for reviewers, not a soundness audit.

- **As of:** 2026-11-03, `Cargo.lock` with p256 0.14.0 added (WEEK2_PLAN step 3). The first survey covered the 24 dependencies of `Cargo.lock` at commit `58a3f30` (2026-10-28). This update adds the 23 crates p256 brings in and the features it turns on in three existing ones.
- **Build covered:** targets `x86_64-unknown-linux-gnu` and `aarch64-apple-darwin`, with every feature (`lenient-numbers` adds no dependencies). Both targets resolve the same 47 dependencies, with the same feature sets.
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
| hybrid-array 0.4.15 | digest's block-buffer and crypto-common (the digest output type); since step 3 also crypto-bigint, elliptic-curve, sec1 and wnaf | **Yes.** Pointer casts between `Array<T, U>` and arrays or slices, `MaybeUninit::assume_init`, and `unsafe impl` of `ArraySize`, `Send` and `Sync` (`src/lib.rs`, `src/from_fn.rs`, `src/flatten.rs`, `src/sizes.rs`). p256's tree turns on the `subtle` and `zeroize` features. They add `ConditionallySelectable`, `ConstantTimeEq`, `Zeroize` and `ZeroizeOnDrop` impls with no `unsafe` (`src/lib.rs:1158-1212`). |
| digest 0.11.3, crypto-common 0.2.2, typenum 1.20.1 | sha2; since step 3 also ecdsa, elliptic-curve, hmac and signature | **None.** Each is `#![forbid(unsafe_code)]`. p256's tree adds digest's `mac` and `oid` features and crypto-common's `rand_core` feature, which changes nothing here. |
| cfg-if 1.0.5 | sha2, nix | **None.** A macro only. |
| ryu-js 1.0.3 | `jcs` result-profile numbers | **Yes.** `Buffer::format_finite` writes through a raw pointer into a `MaybeUninit` buffer and returns `str::from_utf8_unchecked` (`src/buffer/mod.rs:81-110`). The Ryū core uses `get_unchecked` table lookups and `assume_init` (`src/d2s.rs`, `src/d2s_small_table.rs`, `src/pretty/`). There is no crate-level `unsafe_code` lint. |
| unicode-normalization 0.1.26 | `jcs` NFC | **Yes, a little.** The crate is `#![deny(unsafe_code)]` (`src/lib.rs:40`) with local allows for Hangul only: `decompose_hangul` (`src/normalize.rs:90-153`) and `char::from_u32_unchecked` in Hangul composition (`src/normalize.rs:201`, `208`). Each block has a safety comment. |
| tinyvec 1.13.3 | unicode-normalization | **None.** `#![forbid(unsafe_code)]` (`src/lib.rs:2`). |
| thiserror 2.0.21 | the error types | **None**, and the code it generates contains none either. |
| nix 0.31.3 | `peercred` | **Yes:** thin wrappers over libc system calls. Only the items the `socket` and `user` features enable compile, plus a small ungated core (`errno`, and parts of `fcntl`, `sys` and `unistd`). pep-sidecar uses `getsockopt` with `PeerCredentials` (Linux) or `LocalPeerPid` (macOS), plus `getpeereid` (macOS) and `geteuid`. These read results through `MaybeUninit` and the libc call (`src/sys/socket/sockopt.rs`, `src/unistd.rs`). |
| libc 0.2.191 | nix, cpufeatures | **Yes.** FFI declarations: every `extern "C"` function is unsafe to call, and helpers such as the `CMSG_*` macros are `unsafe fn`s. Only the module for the build target compiles (`unix/linux_like/linux/gnu` or `unix/bsd/apple`). |
| memoffset 0.9.1 | nix (`socket`) | **Macros only**, so their `unsafe` expands inside nix. On rustc 1.77 and later, `build.rs` sets `stable_offset_of`, so `offset_of!` forwards to the safe `core::mem::offset_of!`. The `raw_field!` macros still wrap `addr_of!` in `unsafe` (`src/raw_field.rs:136-222`). |
| bitflags 2.13.2 | nix | **None.** `#![cfg_attr(not(test), forbid(unsafe_code))]` (`src/lib.rs:273`). Its only `unsafe impl`s sit behind the `bytemuck` feature, which is off. |

## Added by p256 0.14.0 (2026-11-03)

`p256 = { version = "=0.14.0", default-features = false, features = ["ecdsa"] }` adds these 23 crates. They are compiled into the build, but nothing in pep-sidecar calls p256 until `tokens.rs` (step 6), so until then none of their code is reachable. Enabled features of note: p256 `arithmetic`, `ecdsa` and `sha256`; crypto-bigint `hybrid-array`, `rand_core`, `subtle` and `zeroize`; subtle `const-generics` and `i128`. No crate enables `std`, `alloc` or `getrandom`.

| Crate | Reached through | `unsafe` compiled in our build |
|---|---|---|
| p256 0.14.0 | `tokens` (step 6): ES256 for Episode Tokens, Call Proofs and DSSE | **None** in its source, although it sets no crate-level `unsafe_code` lint. |
| ecdsa 0.17.0, rfc6979 0.6.0, hmac 0.13.0 | p256 (signing, RFC 6979 nonces) | **None.** Each sets `unsafe_code = "forbid"` in its `[lints.rust]`. |
| signature 3.0.0, sec1 0.8.1, ff 0.14.0, primefield 0.14.0, wnaf 0.14.1, ctutils 0.4.8 | ecdsa, elliptic-curve, p256 | **None.** Each is `#![forbid(unsafe_code)]`; ctutils gives the reason "`unsafe` should go in `cmov`". |
| group 0.14.0, primeorder 0.14.0, rand_core 0.10.1, cpubits 0.1.1 | elliptic-curve, p256, crypto-bigint | **None** in their sources, although none sets a crate-level `unsafe_code` lint. |
| elliptic-curve 0.14.3 | p256, ecdsa | **Yes, a little.** `#![deny(unsafe_code)]` with four local allows, each an array cast to the inner type of a `repr(transparent)` newtype: `NonZeroScalar` (`src/scalar/nonzero.rs:73`, `83`) and `NonIdentity` (`src/point/non_identity.rs:63`, `73`). Each has a safety comment. |
| crypto-bigint 0.7.10 | elliptic-curve, primefield, rfc6979 (the field and scalar arithmetic) | **Yes.** `unsafe_code = "deny"` in its `[lints.rust]`, with local allows. Most are casts between `repr(transparent)` newtypes: `Limb` and `Word` (`src/limb.rs:121-165`), `Uint` to `Int` (`src/uint.rs:286`), `Odd`, `NonZero` and `UintRef` (`src/odd.rs:130`, `src/non_zero.rs:120`, `src/uint/ref_type.rs`). The others are word-to-byte slice casts (`src/uint/encoding.rs:395-414`) and an `Ordering` transmute from an `i8` in {-1, 0, 1} (`src/uint/ref_type/cmp.rs:85`). `src/uint/boxed/` is behind `alloc`, which is off. |
| cmov 0.5.4 | ctutils, so crypto-bigint | **Yes: the constant-time core.** On x86_64, `src/backends/x86.rs` compiles: `asm!` with `test` plus a `cmov` instruction, under `options(pure, nomem, nostack)`. On aarch64, `src/backends/aarch64.rs` compiles the same with `csel`. The portable `src/backends/soft.rs` compiles on neither target. Also compiled: slice casts between signed and unsigned integers (`cast_slice`, `split_at_unchecked` and `slice_as_chunks_unchecked`, `src/slice.rs`), `NonZero*::new_unchecked` (`src/lib.rs:280`) and an `Ordering` cast from `i8` (`src/lib.rs:326`). The crate sets `#![allow(clippy::undocumented_unsafe_blocks)]` with a TODO to document them (`src/lib.rs:8`). |
| subtle 2.6.1 | crypto-bigint, ctutils, elliptic-curve, ff, group, hybrid-array, primefield, sec1 | **Yes, two blocks.** `black_box` is a `read_volatile` optimization barrier (`src/lib.rs:225`), compiled because the `core_hint_black_box` feature is off. `ConditionallySelectable for Ordering` casts an `i8` back to `Ordering` (`src/lib.rs:564`). There is no crate-level `unsafe_code` lint. |
| zeroize 1.9.1 | crypto-bigint, der, ecdsa, elliptic-curve, hybrid-array, primefield, sec1 | **Yes.** Volatile writes (`ptr::write_volatile` and `volatile_set`, `src/lib.rs:385-465`, `737-763`), an empty `asm!` optimization barrier on both targets (`src/barrier.rs:68`), and `mem::zeroed` for SIMD register types (`src/x86.rs`, `src/aarch64.rs`). The `alloc` impls (`Vec`, `String`, `Box`) are off. `#![allow(clippy::undocumented_unsafe_blocks, reason = "TODO")]` (`src/lib.rs:8`). |
| der 0.8.3 | ecdsa, sec1 (DER signatures, which step 10's DSSE reads) | **Yes, a little.** `#![deny(unsafe_code)]` with four local allows, each a cast to a `repr(transparent)` newtype: `BytesRef` (`src/bytes.rs:29`), `StringRef` (`src/string.rs:26`), `OctetStringRef` (`src/asn1/octet_string.rs:37`) and `SequenceRef` (`src/asn1/sequence.rs:55`). |
| const-oid 0.10.2 | der, digest (`oid`) | **Yes, one block.** `#![deny(unsafe_code)]` with one local allow: `ObjectIdentifierRef::from_bytes_unchecked` casts `&[u8]` to its `repr(transparent)` newtype (`src/lib.rs:320`). |
| base16ct 1.0.0 | elliptic-curve, sec1 | **Yes, a little.** `encode_str` returns `str::from_utf8_unchecked` over the hex digits it has just written (`src/lower.rs:35`, `src/upper.rs:35`). `encode_string`'s `String::from_utf8_unchecked` is behind `alloc`, which is off. There is no crate-level lint. |
| num-traits 0.2.19 | crypto-bigint | **Yes, one macro.** Float-to-integer casts call `to_int_unchecked` after a range check (`src/cast.rs:281-285`). Its build script uses autocfg, already listed below. |

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
- **p256, elliptic-curve, crypto-bigint, cmov and subtle** (from step 6): verifying every Episode Token and Call Proof, whose signatures come from the wire, and signing every Call Proof with the per-boot key. cmov's `asm!` is what keeps the arithmetic constant-time.
- **der** (from step 10): parsing DSSE signatures from the lockfile.

The highest-risk switch is base64's `simd-unsafe` feature. It is on by default and is the only thing that would add `unsafe` to base64, so `default-features = false` on base64 must stay.

p256's default features are the second switch. `std` enables getrandom, and `pem` and `precomputed-tables` add code the sidecar does not need, so `default-features = false` on p256 must stay too. `deny.toml` bans getrandom, and CI fails if it appears on any target.
