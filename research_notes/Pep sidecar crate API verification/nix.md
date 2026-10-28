# nix crate API verification for pep-sidecar: peer credentials, effective uid and errors on Linux and macOS (as of 2026-10-27)

*Method: crates.io API, docs.rs pages and the nix-rust/nix GitHub repository (CHANGELOG on `master`, source at tag `v0.31.3`), all fetched 2026-10-27. Local project facts cite the local files.*

## Q1. Does nix 0.31.3 exist, is it yanked, when was it published, what is the latest stable version, and what are its MSRV and edition?

### Takeaway
nix 0.31.3 is real and not yanked. It was published 2026-05-11T07:01:18Z, and it is still the latest stable and newest version of any kind as of 2026-10-27. Its `rust_version` is 1.69 (at most 1.88) and its edition is 2021. The `=0.31.3` pin resolves, and the `# 2026-05-11` comment in Cargo.toml is accurate.

### Cited Findings
- Project pin: `nix = { version = "=0.31.3", default-features = false, features = ["socket", "user"] } # 2026-05-11`, under `[target.'cfg(any(target_os = "linux", target_os = "macos"))'.dependencies]`. The project has `rust-version = "1.88"` and `edition = "2024"`. — [local Cargo.toml lines 4-5, 22-23](file:///C:/Users/mitam/OneDrive/Documents/Cryptographic%20Biscuits/agent-authority-fabric/Cargo.toml)
- 0.31.3 version record: `num` "0.31.3", `created_at` "2026-05-11T07:01:18.650221Z", `updated_at` "2026-05-11T07:01:18.650221Z", `yanked` false, `yank_message` null, `rust_version` "1.69", `edition` "2021", `license` "MIT", `crate_size` 347476. — [crates.io API /crates/nix/0.31.3](https://crates.io/api/v1/crates/nix/0.31.3)
- Crate record: `max_version` "0.31.3", `max_stable_version` "0.31.3", `newest_version` "0.31.3", `default_version` "0.31.3", `updated_at` "2026-05-11T07:01:18.650221Z", `repository` "https://github.com/nix-rust/nix". — [crates.io API /crates/nix](https://crates.io/api/v1/crates/nix)
- Most recent versions, sorted by date (79 versions in total, `"total":79`). Each has `yanked` false unless marked otherwise. — [crates.io API versions?sort=date](https://crates.io/api/v1/crates/nix/versions?per_page=20&sort=date)

  | version | created_at (UTC) | rust_version | edition |
  |---|---|---|---|
  | 0.31.3 | 2026-05-11T07:01:18Z | 1.69 | 2021 |
  | 0.31.2 | 2026-02-28T02:15:51Z | 1.69 | 2021 |
  | 0.31.1 | 2026-01-23T01:14:19Z | 1.69 | 2021 |
  | 0.31.0 | 2026-01-22T10:44:26Z | 1.69 | 2021 |
  | 0.30.1 | 2025-05-04T04:20:05Z | 1.69 | 2021 |
  | 0.30.0 | 2025-04-29T09:17:38Z | 1.69 | 2021 |
  | 0.29.0 | 2024-05-24T12:23:09Z | 1.69 | 2021 |
  | 0.28.0 | 2024-02-24T04:27:21Z | 1.69 | 2021 |
  | 0.27.0 / 0.27.1 | 2023-08-28 | 1.65 | 2021 |
  | 0.26.3 (**yanked**) | 2023-08-27 | 1.56 | 2018 |
- Pre-releases: nothing was published after 0.31.3, so no newer pre-release exists, because the date-sorted list starts with 0.31.3 ([crates.io versions?sort=date](https://crates.io/api/v1/crates/nix/versions?per_page=20&sort=date)). The only pre-release in the readable part of the crate JSON is `0.5.1-pre` (2016-06-10, yanked). — [crates.io API /crates/nix](https://crates.io/api/v1/crates/nix)
- CHANGELOG release headings: "## [0.31.3] - 2026-05-11", "## [0.31.2] - 2026-02-28", "## [0.31.1] - 2026-01-23", "## [0.31.0] - 2026-01-22", "## [0.30.1] - 2025-05-04", "## [0.30.0] - 2025-04-29", "## [0.29.0] - 2024-05-24". There is no Unreleased section. — [CHANGELOG.md on master (raw of github.com/nix-rust/nix/blob/master/CHANGELOG.md)](https://raw.githubusercontent.com/nix-rust/nix/master/CHANGELOG.md)
- MSRV history: 0.28.0 says "The MSRV is now 1.69", and 0.27.0 says "The MSRV is now 1.65". — [CHANGELOG.md](https://raw.githubusercontent.com/nix-rust/nix/master/CHANGELOG.md)
- The git tag `v0.31.3` exists, because its source files were fetchable, for example [src/sys/socket/sockopt.rs @ v0.31.3](https://raw.githubusercontent.com/nix-rust/nix/v0.31.3/src/sys/socket/sockopt.rs).

### Inferences
- The exact pin resolves, and the version line needs no change. The pinned version equals the latest stable, so every fact below about 0.31.3 also applies to "latest".
- nix's MSRV of 1.69 is far below the project's 1.88, and nix's edition 2021 does not constrain an edition-2024 dependent, because editions are per crate.

### Gaps
- The crate JSON was cut off after 100,000 of 116,064 characters, so older pre-releases could not all be listed. This does not affect "latest".
- I did not check the MSRV of nix's own dependencies (libc ≥ 0.2.181, memoffset, and others). The CHANGELOG (0.23.1) warns that "the MSRV is not guaranteed to work with all versions of all dependencies". — [CHANGELOG.md](https://raw.githubusercontent.com/nix-rust/nix/master/CHANGELOG.md)

## Q2. Which Cargo features gate each item? Are `default-features = false` and `features = ["socket", "user"]` enough? What do the planned items need?

### Takeaway
`["socket", "user"]` covers every current call on both Linux and macOS. `getpeereid` needs **both** `socket` and `user`, which is exactly the set the project enables. The planned `sockopt::PeerPidfd` needs only `socket`, so the features stay unchanged. The planned `nix::fcntl::Flock` needs **`fs`**, which is not enabled now. No current or planned item needs `process` or `net`.

### Cited Findings
- nix 0.31.3 features: `default: []`, `socket: ["memoffset"]`, `user: ["feature"]`, `fs: []`, `process: []`, `net: ["socket"]`, `dir: ["fs"]`, `signal: ["process"]`, plus acct, aio, env, event, fanotify, feature, hostname, inotify, ioctl, kmod, mman, mount, mqueue, personality, poll, pthread, ptrace, quota, reboot, resource, sched, syslog, term, time, ucontext, uio and zerocopy. — [crates.io API /crates/nix/0.31.3](https://crates.io/api/v1/crates/nix/0.31.3)
- Gate of each item in 0.31.3 (feature from the docs.rs banner; platform from the source `cfg`):

  | Item | docs.rs feature banner | Platform `cfg` (source @ v0.31.3) |
  |---|---|---|
  | `sys::socket::getsockopt` | "Available on crate feature `socket` only." ([docs.rs](https://docs.rs/nix/0.31.3/nix/sys/socket/fn.getsockopt.html)) | no platform `cfg` was observed; see Gaps |
  | `sockopt::PeerCredentials` | "Available on crate feature `socket` only." ([docs.rs](https://docs.rs/nix/0.31.3/nix/sys/socket/sockopt/struct.PeerCredentials.html)) | `#[cfg(linux_android)]`, not net-gated ([sockopt.rs](https://raw.githubusercontent.com/nix-rust/nix/v0.31.3/src/sys/socket/sockopt.rs)) |
  | `sys::socket::UnixCredentials` | "Available on crate feature `socket` only." ([docs.rs](https://docs.rs/nix/0.31.3/nix/sys/socket/struct.UnixCredentials.html)) | (Linux build) |
  | `sockopt::LocalPeerPid` | "Available on crate feature `socket` only." ([docs.rs x86_64-apple-darwin](https://docs.rs/nix/0.31.3/x86_64-apple-darwin/nix/sys/socket/sockopt/struct.LocalPeerPid.html)) | `#[cfg(apple_targets)]`, not net-gated ([sockopt.rs](https://raw.githubusercontent.com/nix-rust/nix/v0.31.3/src/sys/socket/sockopt.rs)) |
  | `unistd::getpeereid` | "Available on crate features `socket` and `user` only." ([docs.rs x86_64-apple-darwin](https://docs.rs/nix/0.31.3/x86_64-apple-darwin/nix/unistd/fn.getpeereid.html)) | `feature! { #![all(feature = "socket", feature = "user")]` + `#[cfg(bsd)]` ([unistd.rs](https://raw.githubusercontent.com/nix-rust/nix/v0.31.3/src/unistd.rs)) |
  | `unistd::geteuid` | "Available on crate feature `user` only." ([docs.rs](https://docs.rs/nix/0.31.3/nix/unistd/fn.geteuid.html)) | inside `feature! { #![feature = "user"] ... }`, with no `#[cfg]` on the fn ([unistd.rs](https://raw.githubusercontent.com/nix-rust/nix/v0.31.3/src/unistd.rs)) |
  | `unistd::Uid` / `Gid` (`as_raw`) | `Uid`: "Available on crate feature `user` only." ([docs.rs](https://docs.rs/nix/0.31.3/nix/unistd/struct.Uid.html)) | both inside `feature! { #![feature = "user"] ... }` ([unistd.rs](https://raw.githubusercontent.com/nix-rust/nix/v0.31.3/src/unistd.rs)) |
  | `nix::Error` (alias) | "Available on Unix only." ([docs.rs](https://docs.rs/nix/0.31.3/nix/type.Error.html)) | no feature gate |
  | `nix::errno::Errno` | Linux: "Available on Unix and (`linux_android` or Emscripten or Fuchsia) only." ([docs.rs](https://docs.rs/nix/0.31.3/nix/errno/enum.Errno.html)). macOS: "Available on apple_targets and Unix only." ([docs.rs x86_64-apple-darwin](https://docs.rs/nix/0.31.3/x86_64-apple-darwin/nix/errno/enum.Errno.html)) | no feature gate |
  | `sockopt::PeerPidfd` (planned) | "Available on crate feature `socket` only." ([docs.rs](https://docs.rs/nix/0.31.3/nix/sys/socket/sockopt/struct.PeerPidfd.html)) | `#[cfg(target_os = "linux")]` (Linux only, not Android), not net-gated ([sockopt.rs](https://raw.githubusercontent.com/nix-rust/nix/v0.31.3/src/sys/socket/sockopt.rs)) |
  | `fcntl::Flock` (planned) | "Available on crate feature `fs` only." ([docs.rs](https://docs.rs/nix/0.31.3/nix/fcntl/struct.Flock.html)) | present in the Linux build and the x86_64-apple-darwin build ([Flockable, x86_64-apple-darwin](https://docs.rs/nix/0.31.3/x86_64-apple-darwin/nix/fcntl/trait.Flockable.html)) |
- The cfg aliases in build.rs at v0.31.3 are `apple_targets: { any(ios, macos, watchos, tvos, visionos) }`, `bsd: { any(freebsd, dragonfly, netbsd, openbsd, apple_targets) }`, `linux_android: { any(android, linux) }` and `freebsdlike: { any(dragonfly, freebsd) }`. The base aliases (`macos`, `linux`, and the rest) each map to the `target_os` value of the same name. — [build.rs @ v0.31.3](https://raw.githubusercontent.com/nix-rust/nix/v0.31.3/build.rs)
- CHANGELOG 0.27.0 says "Removed `flock` from `::nix::fcntl` on Solaris". — [CHANGELOG.md](https://raw.githubusercontent.com/nix-rust/nix/master/CHANGELOG.md)

### Inferences
- nix's `default` feature is `[]`, so `default-features = false` is redundant but harmless.
- Enabling `user` also enables nix's `feature` feature, and `socket` pulls in the optional `memoffset` dependency. Neither affects these call sites.
- If `user` were removed, `geteuid` would fail on both OSes and `getpeereid` would fail on macOS. If `socket` were removed, `getsockopt`, every sockopt and `getpeereid` would fail. Both must stay.
- aarch64-apple-darwin has `target_os = "macos"`, so it satisfies `apple_targets` and `bsd`. `LocalPeerPid` and `getpeereid` therefore exist on that target, even though docs.rs only renders x86_64-apple-darwin (see Q4).
- Planned work: add `"fs"` for `Flock`. `PeerPidfd` needs no new feature. `process` is not needed by any listed item.

### Gaps
- I did not read the platform `cfg` attributes of `getsockopt` and `UnixCredentials` (in `src/sys/socket/mod.rs`) or of `Flock` (in `src/fcntl.rs`). Their presence on the Linux docs.rs build, plus CHANGELOG 0.30.0 "Add support for `libc::LOCAL_PEERTOKEN` in `getsockopt`", an Apple-only option, shows that `getsockopt` exists on both OSes. I did not fetch the macOS `getsockopt` page separately.

## Q3. What are the exact signatures in 0.31.3 (= latest) for the Linux call sites and the shared items?

### Takeaway
The Linux path matches the real API exactly. `getsockopt` takes `fd: &F` with `F: AsFd`, which matches the `socket: &F` the project passes. `PeerCredentials` yields `UnixCredentials`, whose `uid()`, `gid()` and `pid()` return `uid_t`, `gid_t` and `pid_t`. `geteuid() -> Uid`, and `Uid::as_raw(self) -> uid_t`.

### Cited Findings
- `getsockopt` (docs.rs, default target x86_64-unknown-linux-gnu; doc text "Get the current value for the requested socket option") — [docs.rs fn.getsockopt](https://docs.rs/nix/0.31.3/nix/sys/socket/fn.getsockopt.html)
  ```rust
  pub fn getsockopt<F: AsFd, O: GetSockOpt>(fd: &F, opt: O) -> Result<O::Val>
  ```
- `sockopt::PeerCredentials` (doc: "Return the credentials of the foreign process connected to this socket."; implements Clone, Copy, Debug, Eq, GetSockOpt, Hash and PartialEq) — [docs.rs struct.PeerCredentials](https://docs.rs/nix/0.31.3/nix/sys/socket/sockopt/struct.PeerCredentials.html)
  ```rust
  pub struct PeerCredentials;
  impl GetSockOpt for PeerCredentials
      type Val = UnixCredentials
      fn get<F: AsFd>(&self, fd: &F) -> Result<UnixCredentials>
  ```
  Source definition — [sockopt.rs @ v0.31.3](https://raw.githubusercontent.com/nix-rust/nix/v0.31.3/src/sys/socket/sockopt.rs)
  ```rust
  #[cfg(linux_android)]
  sockopt_impl!(
      /// Return the credentials of the foreign process connected to this socket.
      PeerCredentials,
      GetOnly,
      libc::SOL_SOCKET,
      libc::SO_PEERCRED,
      super::UnixCredentials
  );
  ```
- `UnixCredentials` (implements Clone, Copy, Debug, Default, Eq, `From<UnixCredentials> for ucred`, `From<ucred> for UnixCredentials` and PartialEq) — [docs.rs struct.UnixCredentials](https://docs.rs/nix/0.31.3/nix/sys/socket/struct.UnixCredentials.html)
  ```rust
  pub struct UnixCredentials(/* private fields */);
  pub fn new() -> Self        // "Creates a new instance with the credentials of the current process"
  pub fn pid(&self) -> pid_t  // "Returns the process identifier"
  pub fn uid(&self) -> uid_t  // "Returns the user identifier"
  pub fn gid(&self) -> gid_t  // "Returns the group identifier"
  ```
- `geteuid` (doc: "Get the effective user ID"; "See also geteuid(2)") — [docs.rs fn.geteuid](https://docs.rs/nix/0.31.3/nix/unistd/fn.geteuid.html)
  ```rust
  pub fn geteuid() -> Uid
  ```
  Source, inside `feature! { #![feature = "user"] ... }` — [unistd.rs @ v0.31.3](https://raw.githubusercontent.com/nix-rust/nix/v0.31.3/src/unistd.rs)
  ```rust
  // POSIX requires that geteuid is always successful, so no need to check return
  // value or errno.
  #[inline]
  pub fn geteuid() -> Uid {
      Uid(unsafe { libc::geteuid() })
  }
  ```
- `Uid` (implements Clone, Copy, Debug, Display, Eq, `From<Uid> for uid_t`, `From<u32> for Uid`, Hash and PartialEq) — [docs.rs struct.Uid](https://docs.rs/nix/0.31.3/nix/unistd/struct.Uid.html)
  ```rust
  pub struct Uid(/* private fields */);
  pub const fn from_raw(uid: uid_t) -> Self
  pub fn current() -> Self
  pub fn effective() -> Self   // "a more Rusty alias for `geteuid`"
  pub const fn is_root(self) -> bool
  pub const fn as_raw(self) -> uid_t
  ```
- `Uid` and `Gid` in the source (inside `feature! { #![feature = "user"] ... }`) — [unistd.rs @ v0.31.3](https://raw.githubusercontent.com/nix-rust/nix/v0.31.3/src/unistd.rs)
  ```rust
  #[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
  pub struct Uid(uid_t);
      /// Get the raw `uid_t` wrapped by `self`.
      pub const fn as_raw(self) -> uid_t {
          self.0
      }
  #[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
  pub struct Gid(gid_t);
      /// Get the raw `gid_t` wrapped by `self`.
      pub const fn as_raw(self) -> gid_t {
          self.0
      }
  ```
- The project's Linux call site is `getsockopt(socket, sockopt::PeerCredentials)?`, where `socket: &F` and `F: AsFd`. It builds `PeerCred { uid: credentials.uid(), gid: credentials.gid(), pid: Some(credentials.pid()) }`, whose fields are `uid: u32, gid: u32, pid: Option<i32>`, and it calls `geteuid().as_raw()`. — [local src/peercred.rs lines 132-159, 219](file:///C:/Users/mitam/OneDrive/Documents/Cryptographic%20Biscuits/agent-authority-fabric/src/peercred.rs)

### Inferences
- `getsockopt(socket, …)` with `socket: &F` binds `fd: &F` directly, so no `.as_fd()` is needed.
- docs.rs renders `From<uid_t> for Uid` as `From<u32> for Uid` on the Linux build, which shows that `uid_t = u32` on x86_64-linux-gnu. That is consistent with `PeerCred.uid: u32` and with comparing `geteuid().as_raw()` to `MetadataExt::uid() -> u32`. `gid_t = u32` and `pid_t = i32` are the standard libc definitions, and the project's test `Some(i32::try_from(std::process::id()).unwrap())` already relies on `pid_t = i32`.
- The `?` conversions work because these functions return nix's `Result<T>`, whose error is `Errno` (= `nix::Error`). `getpeereid`'s body, `Errno::result(ret).map(...)`, which returns `Result<(Uid, Gid)>`, is consistent with that ([unistd.rs](https://raw.githubusercontent.com/nix-rust/nix/v0.31.3/src/unistd.rs)).

### Gaps
- I did not fetch docs.rs pages for `Gid` or for the `nix::Result` alias, nor libc docs for `uid_t`/`gid_t`/`pid_t`. `Gid::as_raw` comes from the tagged source, and the primitive types are inferred.
- I did not fetch the `GetSockOpt` trait definition itself; it is not in `sockopt.rs`. The `get` signature above comes from the impl blocks docs.rs shows.

## Q4. What are the exact macOS (aarch64-apple-darwin) signatures for `getpeereid` and `LocalPeerPid`, and do the macOS call sites match?

### Takeaway
docs.rs does not build nix for aarch64-apple-darwin; those per-target URLs return 404. The x86_64-apple-darwin build, together with the target_os-based `cfg`s, shows that both items exist on all macOS targets. `getpeereid` takes `F: AsFd` **by value**, so the project's `getpeereid(socket.as_fd())` (a `BorrowedFd` by value) is correct. `LocalPeerPid` yields `c_int` (i32).

### Cited Findings
- `https://docs.rs/nix/0.31.3/aarch64-apple-darwin/nix/unistd/fn.getpeereid.html` returned HTTP 404 ([link](https://docs.rs/nix/0.31.3/aarch64-apple-darwin/nix/unistd/fn.getpeereid.html)), and so did the matching `LocalPeerPid` URL ([link](https://docs.rs/nix/0.31.3/aarch64-apple-darwin/nix/sys/socket/sockopt/struct.LocalPeerPid.html)).
- The docs.rs platform dropdown for nix 0.31.3 lists 9 targets: aarch64-apple-ios, aarch64-linux-android, x86_64-apple-darwin, x86_64-unknown-freebsd, x86_64-unknown-fuchsia, x86_64-unknown-illumos, x86_64-unknown-linux-gnu, x86_64-unknown-netbsd and x86_64-unknown-redox. aarch64-apple-darwin is not among them. — [docs.rs getpeereid (x86_64-apple-darwin)](https://docs.rs/nix/0.31.3/x86_64-apple-darwin/nix/unistd/fn.getpeereid.html)
- `getpeereid` (banner "Available on crate features `socket` and `user` only."; doc "Get the effective user ID and group ID associated with a Unix domain socket.") — [docs.rs x86_64-apple-darwin fn.getpeereid](https://docs.rs/nix/0.31.3/x86_64-apple-darwin/nix/unistd/fn.getpeereid.html)
  ```rust
  pub fn getpeereid<F: AsFd>(fd: F) -> Result<(Uid, Gid)>
  ```
  Source, reassembled from the fetch tool's verbatim segments — [unistd.rs @ v0.31.3](https://raw.githubusercontent.com/nix-rust/nix/v0.31.3/src/unistd.rs)
  ```rust
  feature! {
  #![all(feature = "socket", feature = "user")]

  /// Get the effective user ID and group ID associated with a Unix domain socket.
  ///
  /// See also [getpeereid(3)](https://www.freebsd.org/cgi/man.cgi?query=getpeereid)
  #[cfg(bsd)]
  pub fn getpeereid<F: std::os::fd::AsFd>(fd: F) -> Result<(Uid, Gid)> {
      use std::os::fd::AsRawFd;

      let mut uid = 1;
      let mut gid = 1;

      let ret = unsafe { libc::getpeereid(fd.as_fd().as_raw_fd(), &mut uid, &mut gid) };

      Errno::result(ret).map(|_| (Uid(uid), Gid(gid)))
  }
  }
  ```
- `sockopt::LocalPeerPid` (banner "Available on crate feature `socket` only."; doc "Get the PID of the peer process of a connected unix domain socket.") — [docs.rs x86_64-apple-darwin struct.LocalPeerPid](https://docs.rs/nix/0.31.3/x86_64-apple-darwin/nix/sys/socket/sockopt/struct.LocalPeerPid.html)
  ```rust
  pub struct LocalPeerPid;
  impl GetSockOpt for LocalPeerPid
      type Val = i32
      fn get<F: AsFd>(&self, fd: &F) -> Result<c_int>
  ```
  Source — [sockopt.rs @ v0.31.3](https://raw.githubusercontent.com/nix-rust/nix/v0.31.3/src/sys/socket/sockopt.rs)
  ```rust
  #[cfg(apple_targets)]
  sockopt_impl!(
      /// Get the PID of the peer process of a connected unix domain socket.
      LocalPeerPid,
      GetOnly,
      libc::SOL_LOCAL,
      libc::LOCAL_PEERPID,
      libc::c_int
  );
  ```
- Related Apple-only sockopts, defined in the same file (each `#[cfg(apple_targets)]`, `libc::SOL_LOCAL`): `LocalPeerCred` (`libc::LOCAL_PEERCRED`, Val `super::XuCred`) and `LocalPeerToken` (`libc::LOCAL_PEERTOKEN`, Val `super::audit_token_t`). There is also a `#[cfg(freebsdlike)]` `LocalPeerCred` at level `0`. — [sockopt.rs @ v0.31.3](https://raw.githubusercontent.com/nix-rust/nix/v0.31.3/src/sys/socket/sockopt.rs)
- `LocalPeerPid` was "Added ... to `nix::sys::socket::sockopt` for macOS" in 0.27.0. `LOCAL_PEERTOKEN` support was added in 0.30.0 (#2529). — [CHANGELOG.md](https://raw.githubusercontent.com/nix-rust/nix/master/CHANGELOG.md)
- The `cfg` aliases `apple_targets` and `bsd` both include `macos`, where `macos` means `target_os = "macos"`. — [build.rs @ v0.31.3](https://raw.githubusercontent.com/nix-rust/nix/v0.31.3/build.rs)
- The project's macOS call sites are `let (uid, gid) = nix::unistd::getpeereid(socket.as_fd())?;`, `let pid = getsockopt(socket, sockopt::LocalPeerPid)?;`, and then `PeerCred { uid: uid.as_raw(), gid: gid.as_raw(), pid: Some(pid) }`. — [local src/peercred.rs lines 161-170](file:///C:/Users/mitam/OneDrive/Documents/Cryptographic%20Biscuits/agent-authority-fabric/src/peercred.rs)

### Inferences
- `getpeereid<F: AsFd>(fd: F)` accepts any `AsFd` by value, and `std::os::fd::BorrowedFd<'_>` implements `AsFd`, so `getpeereid(socket.as_fd())` compiles. Passing `socket` (a `&F`) would also work through std's `AsFd for &T` impl, but no change is needed.
- `LocalPeerPid`'s `Val` is `libc::c_int`, which docs.rs renders as `i32` on Apple. `Some(pid)` therefore fits `pid: Option<i32>`. `Uid::as_raw()`/`Gid::as_raw()` return `uid_t`/`gid_t`, which are `u32` on Apple in libc (standard definition, not fetched).
- The `cfg`s depend on the OS, not the architecture, so the x86_64-apple-darwin docs.rs pages describe aarch64-apple-darwin exactly.
- nix's build.rs only defines `cfg` aliases and registers custom `cfg`s; it compiles no C code. That supports `cargo clippy --target aarch64-apple-darwin` working from WSL without a macOS SDK, provided the rust-std for that target is installed. This was not tested here.

### Gaps
- The fetch tool could not read which target the docs.rs selector had chosen on the x86_64-apple-darwin `getpeereid` page; it guessed Linux. That guess is ruled out: the URL path is `x86_64-apple-darwin`, and the item is `#[cfg(bsd)]`, so it cannot appear in the Linux build.

## Q5. Is `nix::Error` still an alias for `nix::errno::Errno`, and does `Errno` satisfy `#[from] nix::Error` with thiserror?

### Takeaway
Yes. `pub type Error = Errno;`, and `Errno` implements `Debug`, `Display` and `std::error::Error` on both the Linux and the macOS docs.rs builds. `PeerError::Sys(#[from] nix::Error)` compiles as-is.

### Cited Findings
- Alias (doc: "Nix’s main error type." / "It’s a wrapper around Errno."; banner "Available on Unix only.") — [docs.rs type.Error](https://docs.rs/nix/0.31.3/nix/type.Error.html)
  ```rust
  pub type Error = Errno;
  ```
- `Errno` on the Linux build: the declaration reads `#[non_exhaustive]#[repr(i32)]pub enum Errno {`, and the trait implementations are Clone, Copy, **Debug**, **Display**, Eq, **Error**, `From<Errno> for Error` (std::io::Error), PartialEq, StructuralPartialEq and `TryFrom<Error> for Errno`. Its inherent methods include `pub fn last() -> Self`, `pub const fn from_raw(err: i32) -> Errno`, `pub fn desc(self) -> &'static str` and `pub fn result<S: ErrnoSentinel + PartialEq<S>>(value: S) -> Result<S>`. `from_i32` is marked "Deprecated since 0.28.0". — [docs.rs enum.Errno](https://docs.rs/nix/0.31.3/nix/errno/enum.Errno.html)
- `Errno` on the macOS build: the same `#[non_exhaustive]#[repr(i32)]` declaration, the same trait list (Clone, Copy, Debug, Display, Eq, Error, `From<Errno> for Error`, PartialEq, StructuralPartialEq, `TryFrom<Error> for Errno`), and the banner "Available on apple_targets and Unix only." — [docs.rs x86_64-apple-darwin enum.Errno](https://docs.rs/nix/0.31.3/x86_64-apple-darwin/nix/errno/enum.Errno.html)
- 0.31.0 (#2692): "Define errno EWOULDBLOCK as an alias of EAGAIN to match the AIX libc definition." — [CHANGELOG.md](https://raw.githubusercontent.com/nix-rust/nix/master/CHANGELOG.md)

### Inferences
- `Debug` satisfies `#[derive(Debug)]` on `PeerError`. `Display` satisfies `#[error("system call failed: {0}")]`. `std::error::Error` plus `'static` (a plain enum) satisfies the implied `#[source]` of `#[from]`. `Errno` is `#[non_exhaustive]`, which only matters for exhaustive `match`, and the project does not match on it.

### Gaps
- None for the call sites.

## Q6. Which breaking changes from 0.27 to 0.31.x (CHANGELOG) affect these items?

### Takeaway
The relevant breaks predate 0.30. In 0.28.0, `getpeereid` moved from `RawFd` to `AsFd` and the MSRV rose to 1.69. In 0.27.0 and 0.29.0, most of the API moved to I/O safety. 0.30.0 only added items (`PeerPidfd`, `LocalPeerToken`) and finished the unistd and fcntl I/O-safety work. 0.31.0 to 0.31.3 contain nothing that touches these items: no sockopt renames or removals, no feature renames, and no MSRV change.

### Cited Findings (all from [CHANGELOG.md on master](https://raw.githubusercontent.com/nix-rust/nix/master/CHANGELOG.md))
- 0.27.0 (2023-08-28): "Implemented I/O safety for many, but not all, of Nix's APIs." "Added `LocalPeerPid` to `nix::sys::socket::sockopt` for macOS." "The MSRV is now 1.65".
- 0.28.0 (2024-02-24): "The following APIs now take an implementation of `AsFd` rather than a `RawFd`:", with "`unistd::getpeereid`" in that list. Also "Added newtype `Flock` to automatically unlock a held flock upon drop.", "Added `Flockable` trait to represent valid types for `Flock`." and "The MSRV is now 1.69".
- 0.29.0 (2024-05-24): "Most functions that previously accepted a `AsRawFd` argument now accept an `AsFd` instead." (#2401) and "Added `Flock::relock` for upgrading and downgrading locks." (#2407).
- 0.30.0 (2025-04-29):
  - "Add `PeerPidfd` (`SO_PEERPIDFD`) to `socket::sockopt` for Linux" (#2620)
  - "Add support for `libc::LOCAL_PEERTOKEN` in `getsockopt`." (#2529)
  - "Added `sockopt_impl!` to the public API."
  - "Module unistd now adopts I/O safety."
  - "Public interfaces in `fcntl.rs` and `dir.rs` now use I/O-safe types." (#2434)
  - "Properly exclude NUL characters from `OSString`s returned by `getsockopt`." (#2557)
  - "Added `sockopt::LingerSec` for Apple targets" (#2572)
- 0.31.0 (2026-01-22): "Bumped libc to 0.2.180" (#2724), plus the AIX EWOULDBLOCK alias (#2692).
- 0.31.2 (2026-02-28): "The libc requirement is now `0.2.181`, rather than pinned to 0.2.180." (#2744)
- 0.30.1, 0.31.1 and 0.31.3: no bullet mentions any of the searched terms (sockopt, getsockopt, getpeereid, Uid/Gid, Errno, AsFd, Flock, MSRV, features).
- crates.io `rust_version` is "1.69" for every release from 0.28.0 through 0.31.3. — [crates.io versions](https://crates.io/api/v1/crates/nix/versions?per_page=20&sort=date)

### Inferences
- Code written for 0.27 or earlier, like `getpeereid(fd.as_raw_fd())`, would fail on 0.31.3. The project's `AsFd` style matches the post-0.28 API, so none of these breaks hits the current code.

### Gaps
- The search was keyword-based, so 0.31.0 may contain other breaking changes outside these items.
- I did not pin down the exact release in which `getsockopt` itself moved from `RawFd` to `&F: AsFd`. It is probably part of the 0.27.0 I/O-safety table, but that is unverified. Its 0.31.3 signature is verified (Q3).

## Q7. Planned work: what is the real sockopt for `SO_PEERPIDFD`, and what does `nix::fcntl::Flock` look like?

### Takeaway
The real name is `nix::sys::socket::sockopt::PeerPidfd`. It is Linux-only, gated by the `socket` feature that is already enabled, and its `Val` is `std::os::fd::OwnedFd`; it has existed since 0.30.0, and nix does the `unsafe` internally. `nix::fcntl::Flock<T: Flockable>` needs the `fs` feature. `Flockable` is an `unsafe trait` already implemented for `File` and `OwnedFd`, so the project can use it under `forbid(unsafe_code)`. `Flock::lock` returns its error as `(T, Errno)`, which `?` cannot convert directly.

### Cited Findings
- `PeerPidfd` (banner "Available on crate feature `socket` only."; doc "Return the pidfd of the foreign process connected to this socket.") — [docs.rs struct.PeerPidfd](https://docs.rs/nix/0.31.3/nix/sys/socket/sockopt/struct.PeerPidfd.html)
  ```rust
  pub struct PeerPidfd;
  impl GetSockOpt for PeerPidfd
      type Val = OwnedFd
      fn get<F: AsFd>(&self, fd: &F) -> Result<OwnedFd>
  ```
  Source, with nix's internal OwnedFd getter — [sockopt.rs @ v0.31.3](https://raw.githubusercontent.com/nix-rust/nix/v0.31.3/src/sys/socket/sockopt.rs)
  ```rust
  #[cfg(target_os = "linux")]
  sockopt_impl!(
      /// Return the pidfd of the foreign process connected to this socket.
      PeerPidfd,
      GetOnly,
      libc::SOL_SOCKET,
      libc::SO_PEERPIDFD,
      OwnedFd
  );
  // ...
  #[doc(hidden)]
  #[derive(Clone, Copy, Debug)]
  pub struct GetOwnedFd {
      len: socklen_t,
      val: MaybeUninit<c_int>,
  }
  // in `unsafe fn assume_init(self) -> OwnedFd`:
  unsafe { OwnedFd::from_raw_fd(self.val.assume_init() as RawFd) }
  ```
- PR #2620, "Add sockopt::PeerPidfd (SO_PEERPIDFD) sockopt support to socket::sockopt", was written by swick and merged by SteveLauC on Apr 11, 2025. Its description says: "PIDs are inherently racy, leading to confused deputy problems… The pidfd mechanism solves this by using a FD to refer to a process which the kernel can keep proper track of… implements sockopt::PeerPidfd (SO_PEERPIDFD) returning an OwnedFd representing the process connected to the socket." — [GitHub PR #2620](https://github.com/nix-rust/nix/pull/2620)
- The project's SPEC says the sidecar "Verifies peer identity via `SO_PEERCRED` + `SO_PEERPIDFD` (Linux) or `getpeereid` + `LOCAL_PEERPID` (macOS)." — [local SPEC.md line 6](file:///C:/Users/mitam/OneDrive/Documents/Cryptographic%20Biscuits/agent-authority-fabric/SPEC.md)
- `Flock` (banner "Available on crate feature `fs` only."; method docs "Obtain a/an flock.", "Remove the lock and return the object wrapped within.", "Relock the file. This can upgrade or downgrade the lock type."; the doc examples use `FlockArg::LockExclusive` and `FlockArg::LockShared`) — [docs.rs struct.Flock](https://docs.rs/nix/0.31.3/nix/fcntl/struct.Flock.html)
  ```rust
  pub struct Flock<T: Flockable>(/* private fields */);
  pub fn lock(t: T, args: FlockArg) -> Result<Self, (T, Errno)>
  pub fn unlock(self) -> Result<T, (Self, Errno)>
  pub fn relock(&self, arg: FlockArg) -> Result<()>
  ```
- `Flockable` (banner "Available on crate feature `fs` only."; doc "Represents valid types for flock."; Safety: "Types implementing this must not be `Clone`."; implementations on foreign types: `impl Flockable for File` and `impl Flockable for OwnedFd`) — [docs.rs x86_64-apple-darwin trait.Flockable](https://docs.rs/nix/0.31.3/x86_64-apple-darwin/nix/fcntl/trait.Flockable.html)
  ```rust
  pub unsafe trait Flockable: AsRawFd { }
  ```
- `Flock` was added in 0.28.0 and `Flock::relock` in 0.29.0 (#2407). — [CHANGELOG.md](https://raw.githubusercontent.com/nix-rust/nix/master/CHANGELOG.md)

### Inferences
- Week 2 code for Linux needs no Cargo change and no `unsafe`:
  ```rust
  #[cfg(target_os = "linux")]
  fn os_peer_pidfd<F: AsFd>(socket: &F) -> Result<std::os::fd::OwnedFd, PeerError> {
      getsockopt(socket, sockopt::PeerPidfd).map_err(PeerError::from)
  }
  ```
  It should be gated `#[cfg(target_os = "linux")]`, not `linux_android`, to match nix's `cfg`.
- `Flock` needs `"fs"` added to the nix features (see the verdict). The `std::fs::File` impl lets the project lock a sibling lock file without writing `unsafe`; implementing `Flockable` for its own type would need `unsafe impl`, which `unsafe_code = "forbid"` blocks. Because the error type is a tuple, map it explicitly, for example `.map_err(|(_file, errno)| PeerError::Sys(errno))`.

### Gaps
- Neither nix PR #2620 nor the docs.rs page states the minimum Linux kernel for `SO_PEERPIDFD`. Background knowledge says Linux 6.5, but that is not verified in the allowed sources and needs confirming elsewhere. On older kernels a runtime `ENOPROTOOPT`-style failure is expected but unverified, so the code needs a fail-closed policy for that case.
- The libc constant `libc::SO_PEERPIDFD` is necessarily present in every libc that nix 0.31.3 accepts (≥ 0.2.181, per CHANGELOG 0.31.2), because nix uses it unconditionally on Linux. The exact libc version that introduced it was not checked.
- I did not verify any nix helpers for using a pidfd, such as reading its PID, `pidfd_open` or `pidfd_send_signal`, or their features. Getting `PeerCred.pid` from the pidfd may need code outside nix.
- I did not verify the name of the non-blocking `FlockArg` variant (for example `LockExclusiveNonblock`); only `LockExclusive` and `LockShared` appear in the docs examples. I did not read `Flock`'s own platform `cfg` (see Q2).

## Q8. Verdict per call site: what compiles as-is against nix =0.31.3 on x86_64-unknown-linux-gnu and aarch64-apple-darwin, and what must change?

### Takeaway
Every current nix call site compiles as-is on both targets with `=0.31.3`, `default-features = false` and `["socket", "user"]`. The code uses the real nix API, not stand-ins. The only change needed is for the planned `Flock`: add the `fs` feature. The planned `SO_PEERPIDFD` work needs no Cargo change.

### Cited Findings
- 0.31.3 exists and is not yanked; MSRV 1.69, edition 2021. — [crates.io API /crates/nix/0.31.3](https://crates.io/api/v1/crates/nix/0.31.3)
- `getsockopt<F: AsFd, O: GetSockOpt>(fd: &F, opt: O) -> Result<O::Val>` requires `socket`. — [docs.rs](https://docs.rs/nix/0.31.3/nix/sys/socket/fn.getsockopt.html)
- `PeerCredentials` is `linux_android`, gated by `socket`, with `Val = UnixCredentials`; its `uid()`, `gid()` and `pid()` return `uid_t`, `gid_t` and `pid_t`. — [docs.rs](https://docs.rs/nix/0.31.3/nix/sys/socket/sockopt/struct.PeerCredentials.html), [docs.rs](https://docs.rs/nix/0.31.3/nix/sys/socket/struct.UnixCredentials.html), [sockopt.rs](https://raw.githubusercontent.com/nix-rust/nix/v0.31.3/src/sys/socket/sockopt.rs)
- `getpeereid<F: AsFd>(fd: F)` is `bsd`, gated by `socket` and `user`. `LocalPeerPid` is `apple_targets`, gated by `socket`, with Val `c_int`. — [docs.rs](https://docs.rs/nix/0.31.3/x86_64-apple-darwin/nix/unistd/fn.getpeereid.html), [docs.rs](https://docs.rs/nix/0.31.3/x86_64-apple-darwin/nix/sys/socket/sockopt/struct.LocalPeerPid.html), [unistd.rs](https://raw.githubusercontent.com/nix-rust/nix/v0.31.3/src/unistd.rs)
- `geteuid() -> Uid` is gated by `user`; `Uid::as_raw(self) -> uid_t` and `Gid::as_raw(self) -> gid_t`. — [docs.rs](https://docs.rs/nix/0.31.3/nix/unistd/fn.geteuid.html), [docs.rs](https://docs.rs/nix/0.31.3/nix/unistd/struct.Uid.html)
- `pub type Error = Errno;`, and Errno implements Debug, Display and Error on both builds. — [docs.rs](https://docs.rs/nix/0.31.3/nix/type.Error.html), [docs.rs macOS](https://docs.rs/nix/0.31.3/x86_64-apple-darwin/nix/errno/enum.Errno.html)
- `Flock` is gated by `fs`. — [docs.rs](https://docs.rs/nix/0.31.3/nix/fcntl/struct.Flock.html)

### Inferences
| # | Call site (src/peercred.rs / Cargo.toml) | Linux x86_64-gnu | macOS aarch64 | Verdict |
|---|---|---|---|---|
| 1 | `nix = { version = "=0.31.3", default-features = false, features = ["socket", "user"] }` | resolves | resolves | **compiles as-is** |
| 2 | `use nix::sys::socket::{getsockopt, sockopt};` | `socket` ✓ | `socket` ✓ | **compiles as-is** |
| 3 | `use nix::unistd::geteuid;` + `geteuid().as_raw()` (u32, compared with `MetadataExt::uid()`) | `user` ✓ | `user` ✓ | **compiles as-is** |
| 4 | `Sys(#[from] nix::Error)` with thiserror | ✓ | ✓ | **compiles as-is** |
| 5 | Linux `getsockopt(socket, sockopt::PeerCredentials)?` → `.uid()` / `.gid()` / `Some(.pid())` | `linux_android` ✓, u32/u32/i32 | n/a (cfg'd out) | **compiles as-is** |
| 6 | macOS `nix::unistd::getpeereid(socket.as_fd())?` → `uid.as_raw()` / `gid.as_raw()` | n/a (cfg'd out) | `bsd` ✓, `F: AsFd` by value accepts `BorrowedFd` | **compiles as-is** |
| 7 | macOS `getsockopt(socket, sockopt::LocalPeerPid)?` → `Some(pid)` | n/a | `apple_targets` ✓, `c_int` = i32 | **compiles as-is** |
| 8 | Planned Week 2: `getsockopt(socket, sockopt::PeerPidfd)` → `OwnedFd` under `#[cfg(target_os = "linux")]` | `socket` ✓ | must stay cfg'd out (Linux-only) | **compiles as-is (no Cargo change)** |
| 9 | Planned: `nix::fcntl::Flock` ("behind nix's `fs` feature") | needs `fs` | needs `fs` | **needs change**: replace the Cargo.toml line with the one below |

Exact replacement for row 9, needed only when `Flock` is adopted:
```toml
[target.'cfg(any(target_os = "linux", target_os = "macos"))'.dependencies]
nix = { version = "=0.31.3", default-features = false, features = ["fs", "socket", "user"] } # 2026-05-11
```
Matching usage, which needs no `unsafe` and maps the tuple error:
```rust
let lock = nix::fcntl::Flock::lock(lock_file, nix::fcntl::FlockArg::LockExclusive)
    .map_err(|(_file, errno)| PeerError::Sys(errno))?;
```
- The version, the date comment and the import paths are all real. The "stand-in API" concern does not apply to nix.

### Gaps
- Nothing was compiled; the verdicts come from the documented signatures, `cfg`s and features. The project's 5-command verification loop, including `cargo clippy --all-targets --target aarch64-apple-darwin`, should confirm them.
- The aarch64-apple-darwin facts come from the x86_64-apple-darwin docs.rs build plus target_os-based `cfg`s, because docs.rs does not build that target.
