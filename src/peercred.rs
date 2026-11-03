//! Peer-credential checks and TOCTOU-safe Unix socket binding (F-11, F-12).
//!
//! The parent-directory check is what makes the later path operations race-free: a directory
//! owned by the effective user and not writable by group or others cannot have its entries
//! created, renamed or removed by any other non-root principal between the check and the bind.
//! Others cannot traverse it either, so the gap between `bind` and `chmod` only admits the
//! intended group. Every ancestor of the parent's canonical path is checked as well (owned by
//! root or the effective user, and not writable by group or others unless sticky), so no other
//! user can swap the parent itself, and the socket is bound under that canonical path.
//!
//! On Linux a new socket takes the parent's group only when the parent is setgid (or the
//! process's effective group already is that group), so `/run/pep` should be mode `2750`. The
//! bind fails otherwise, rather than leaving a socket the agent's group cannot open.
//!
//! A second instance is kept out by an exclusive `flock` on `<socket>.lock`, taken before
//! anything at the socket path is unlinked or bound, and held for the listener's lifetime
//! ([`BoundListener`]). With the lock held, any socket already at the path is stale. The
//! kernel releases the lock when the holder dies, so a crashed instance never blocks a restart.
//!
//! [`require_peer`] admits a peer only if both its uid and its gid are the expected ones (Q1).
//! On Linux it also takes the peer's pidfd (`SO_PEERPIDFD`, Linux 6.5 and later) and requires
//! the pidfd's fdinfo `Pid:` to be at least 0.
//! - In Compose the peer sits in a sibling PID namespace. There `SO_PEERCRED` reports pid 0, and
//!   fdinfo shows `Pid: 0` while the peer lives, so the pidfd proves only that the peer is
//!   alive. Identity rests on the uid and gid.
//! - A reaped peer shows `Pid: -1` and is rejected. Recent kernels return a stale pidfd for it,
//!   not an error, so the fdinfo check is what catches it.
//! - Every `getsockopt` error rejects, `ENOPROTOOPT` (a kernel older than 6.5) included.
//!
//! PIDs from `SO_PEERCRED` and `LOCAL_PEERPID` stay advisory. macOS has no pidfd, so there the
//! check is the uid and gid alone.

use std::fs::{self, File, Metadata, OpenOptions, Permissions, TryLockError};
use std::io;
use std::os::fd::AsFd;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::os::unix::fs::{
    FileTypeExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
};
use std::os::unix::net::UnixListener;
use std::path::{Component, Path};

use nix::sys::socket::{getsockopt, sockopt};
use nix::unistd::geteuid;

/// Mode of the bound socket.
pub const SOCKET_MODE: u32 = 0o660;
/// Suffix of the lock file kept next to the socket: `/run/pep/mcp.sock` is guarded by
/// `/run/pep/mcp.sock.lock`.
pub const LOCK_SUFFIX: &str = ".lock";
/// Mode of the lock file. The agent's group can list the socket directory, but cannot open this
/// file, so it cannot take the lock.
pub const LOCK_MODE: u32 = 0o600;
/// Parent-directory permission bits that must be clear: group write and everything for others.
pub const FORBIDDEN_PARENT_BITS: u32 = 0o027;
/// Ancestor permission bits that must be clear unless the ancestor is sticky: group write and
/// other write.
pub const FORBIDDEN_ANCESTOR_BITS: u32 = 0o022;

const STICKY_BIT: u32 = 0o1000;

/// Errors from peer-credential checks and socket binding.
#[derive(Debug, thiserror::Error)]
pub enum PeerError {
    /// A system call failed.
    #[error("system call failed: {0}")]
    Sys(#[from] nix::Error),
    /// A filesystem or socket operation failed.
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
    /// The peer runs as an unexpected user.
    #[error("peer uid {actual} is not the expected uid {expected}")]
    UnexpectedPeerUid {
        /// The required uid.
        expected: u32,
        /// The peer's uid.
        actual: u32,
    },
    /// The peer runs with an unexpected group.
    #[error("peer gid {actual} is not the expected gid {expected}")]
    UnexpectedPeerGid {
        /// The required gid.
        expected: u32,
        /// The peer's gid.
        actual: u32,
    },
    /// The kernel has no `SO_PEERPIDFD` (`ENOPROTOOPT`: Linux older than 6.5).
    #[error("SO_PEERPIDFD is not supported by this kernel")]
    PidfdUnsupported,
    /// The socket has no peer process recorded (`ENODATA`).
    #[error("the socket has no recorded peer process")]
    PidfdNoPeer,
    /// `SO_PEERPIDFD` failed with any other error.
    #[error("SO_PEERPIDFD failed: {0}")]
    PidfdFailed(nix::Error),
    /// The peer process has exited and been reaped (fdinfo `Pid: -1`).
    #[error("the peer process has exited")]
    PeerExited,
    /// The pidfd's fdinfo does not hold exactly one well-formed `Pid:` line.
    #[error("the peer pidfd's fdinfo is malformed")]
    FdinfoMalformed,
    /// The socket path is relative.
    #[error("socket path is not absolute")]
    PathNotAbsolute,
    /// The socket path contains a `..` component.
    #[error("socket path contains a parent-directory component")]
    PathHasParentComponent,
    /// The socket path has no parent directory.
    #[error("socket path has no parent directory")]
    NoParent,
    /// An ancestor of the parent directory would let another user replace the parent.
    #[error("ancestor directory (owner {owner}, mode {mode:o}) is not safe")]
    AncestorUnsafe {
        /// The ancestor's owner.
        owner: u32,
        /// The ancestor's permission bits.
        mode: u32,
    },
    /// The parent directory changed while it was being checked.
    #[error("parent directory changed during the check")]
    ParentChanged,
    /// The parent directory is a symbolic link.
    #[error("parent directory is a symlink")]
    ParentIsSymlink,
    /// The parent is not a directory.
    #[error("parent is not a directory")]
    ParentNotDirectory,
    /// The parent directory is owned by another user.
    #[error("parent directory owner {actual} is not {expected}")]
    ParentOwnerMismatch {
        /// The effective uid.
        expected: u32,
        /// The directory's owner.
        actual: u32,
    },
    /// The parent directory is writable by group or accessible to others.
    #[error("parent directory mode {mode:o} is too permissive")]
    ParentModeTooPermissive {
        /// The directory's permission bits.
        mode: u32,
    },
    /// Something other than a socket exists at the socket path.
    #[error("existing path is not a socket")]
    ExistingNotSocket,
    /// A socket owned by another user exists at the socket path.
    #[error("existing socket owner {actual} is not {expected}")]
    ExistingOwnerMismatch {
        /// The effective uid.
        expected: u32,
        /// The socket's owner.
        actual: u32,
    },
    /// Another process (for example a second PEP instance) holds the socket's lock file.
    #[error("another process holds the socket's lock")]
    LockHeld,
    /// The lock file path is a symbolic link (`O_NOFOLLOW` refused it).
    #[error("the lock file is a symlink")]
    LockIsSymlink,
    /// Something other than a regular file exists at the lock file path.
    #[error("the lock file is not a regular file")]
    LockNotRegularFile,
    /// The lock file is owned by another user.
    #[error("lock file owner {actual} is not {expected}")]
    LockOwnerMismatch {
        /// The effective uid.
        expected: u32,
        /// The lock file's owner.
        actual: u32,
    },
    /// The lock file's mode is not 0600.
    #[error("lock file mode {mode:o} is not 0600")]
    LockModeMismatch {
        /// The lock file's permission bits.
        mode: u32,
    },
    /// The lock file has more than one name (a hard link to it exists).
    #[error("lock file has {nlink} links, not 1")]
    LockLinkCount {
        /// The lock file's link count.
        nlink: u64,
    },
    /// The bound socket does not have mode 0660 or is not ours.
    #[error("bound socket mode {mode:o} is not 0660")]
    SocketModeMismatch {
        /// The socket's permission bits.
        mode: u32,
    },
    /// The bound socket did not get the parent directory's group (make the parent setgid).
    #[error("bound socket group {actual} is not the parent's group {expected}")]
    SocketGroupMismatch {
        /// The parent directory's group.
        expected: u32,
        /// The socket's group.
        actual: u32,
    },
}

/// Credentials of the process at the other end of a Unix socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCred {
    /// Effective user id.
    pub uid: u32,
    /// Effective group id.
    pub gid: u32,
    /// Process id, if the platform reports it (advisory: PIDs can be reused). On Linux it is 0
    /// when the peer is in a PID namespace this process cannot see.
    pub pid: Option<i32>,
}

/// Reads the peer's credentials: `SO_PEERCRED` on Linux, `getpeereid` + `LOCAL_PEERPID` on
/// macOS.
///
/// # Errors
///
/// Returns [`PeerError::Sys`] if the socket option cannot be read.
pub fn peer_cred<F: AsFd>(socket: &F) -> Result<PeerCred, PeerError> {
    os_peer_cred(socket)
}

#[cfg(target_os = "linux")]
fn os_peer_cred<F: AsFd>(socket: &F) -> Result<PeerCred, PeerError> {
    let credentials = getsockopt(socket, sockopt::PeerCredentials)?;
    Ok(PeerCred {
        uid: credentials.uid(),
        gid: credentials.gid(),
        pid: Some(credentials.pid()),
    })
}

#[cfg(target_os = "macos")]
fn os_peer_cred<F: AsFd>(socket: &F) -> Result<PeerCred, PeerError> {
    let (uid, gid) = nix::unistd::getpeereid(socket.as_fd())?;
    let pid = getsockopt(socket, sockopt::LocalPeerPid)?;
    Ok(PeerCred {
        uid: uid.as_raw(),
        gid: gid.as_raw(),
        pid: Some(pid),
    })
}

/// Reads the peer's credentials and requires its uid to be `uid` and its gid to be `gid`. On
/// Linux the peer must also be alive, as its pidfd shows (see the module docs). Every failure
/// rejects the peer.
///
/// # Errors
///
/// - [`PeerError::UnexpectedPeerUid`] or [`PeerError::UnexpectedPeerGid`] for another identity;
/// - on Linux, [`PeerError::PidfdUnsupported`], [`PeerError::PidfdNoPeer`],
///   [`PeerError::PidfdFailed`], [`PeerError::PeerExited`] or [`PeerError::FdinfoMalformed`]
///   when the peer cannot be shown to be alive, or [`PeerError::Io`] if its fdinfo is
///   unreadable;
/// - the errors of [`peer_cred`].
pub fn require_peer<F: AsFd>(socket: &F, uid: u32, gid: u32) -> Result<PeerCred, PeerError> {
    let credentials = peer_cred(socket)?;
    if credentials.uid != uid {
        return Err(PeerError::UnexpectedPeerUid {
            expected: uid,
            actual: credentials.uid,
        });
    }
    if credentials.gid != gid {
        return Err(PeerError::UnexpectedPeerGid {
            expected: gid,
            actual: credentials.gid,
        });
    }
    #[cfg(target_os = "linux")]
    require_peer_alive(socket)?;
    Ok(credentials)
}

/// Requires the peer's pidfd to show a live process. The pidfd is closed on return.
#[cfg(target_os = "linux")]
fn require_peer_alive<F: AsFd>(socket: &F) -> Result<(), PeerError> {
    let pidfd = peer_pidfd(socket)?;
    let fdinfo = fs::read_to_string(fdinfo_path(&pidfd))?;
    pidfd_alive(fdinfo_pid(&fdinfo)?)
}

#[cfg(target_os = "linux")]
fn peer_pidfd<F: AsFd>(socket: &F) -> Result<OwnedFd, PeerError> {
    classify_pidfd(getsockopt(socket, sockopt::PeerPidfd))
}

/// Maps a `SO_PEERPIDFD` failure to its error. Separate from the system call so that tests can
/// inject any errno.
#[cfg(target_os = "linux")]
fn classify_pidfd(result: nix::Result<OwnedFd>) -> Result<OwnedFd, PeerError> {
    result.map_err(|errno| match errno {
        nix::errno::Errno::ENOPROTOOPT => PeerError::PidfdUnsupported,
        nix::errno::Errno::ENODATA => PeerError::PidfdNoPeer,
        other => PeerError::PidfdFailed(other),
    })
}

#[cfg(target_os = "linux")]
fn fdinfo_path(fd: &OwnedFd) -> std::path::PathBuf {
    std::path::PathBuf::from(format!("/proc/self/fdinfo/{}", fd.as_raw_fd()))
}

/// The value of the single `Pid:` line of a pidfd's fdinfo. (`NSpid:` lines do not match.)
#[cfg(target_os = "linux")]
fn fdinfo_pid(fdinfo: &str) -> Result<i32, PeerError> {
    let mut values = fdinfo.lines().filter_map(|line| line.strip_prefix("Pid:"));
    let (Some(value), None) = (values.next(), values.next()) else {
        return Err(PeerError::FdinfoMalformed);
    };
    value.trim().parse().map_err(|_| PeerError::FdinfoMalformed)
}

/// Q1's liveness rule for an fdinfo `Pid:` value:
/// - `-1`: the peer has been reaped, so it is rejected;
/// - `0`: the peer lives in a PID namespace this process cannot see (the Compose case);
/// - a positive value: the peer's pid in this namespace.
///
/// Any other negative value is malformed.
#[cfg(target_os = "linux")]
fn pidfd_alive(pid: i32) -> Result<(), PeerError> {
    match pid {
        -1 => Err(PeerError::PeerExited),
        0.. => Ok(()),
        _ => Err(PeerError::FdinfoMalformed),
    }
}

/// Binds a Unix listener at `path` without TOCTOU races.
///
/// 1. `path` must be absolute and have no `..` component.
/// 2. Its parent must be a real directory (not a symlink) owned by the effective uid, with
///    none of [`FORBIDDEN_PARENT_BITS`] set. Every ancestor of the parent's canonical path must
///    be a directory owned by root or the effective uid, with none of
///    [`FORBIDDEN_ANCESTOR_BITS`] set unless it is sticky.
/// 3. Before anything at `path` is unlinked or bound, it takes an exclusive lock on
///    `<path>.lock` ([`LOCK_SUFFIX`]) in the canonical parent. That file is opened with
///    `O_NOFOLLOW` and checked by fstat: a regular file, mode [`LOCK_MODE`], owned by the
///    effective uid, with one link. If another process holds the lock, this fails with
///    [`PeerError::LockHeld`].
/// 4. An existing file at `path` is unlinked only if it is a socket owned by the effective uid.
///    With the lock held no other instance can be listening on it, so it is stale.
/// 5. The socket is bound under the parent's canonical path, set to [`SOCKET_MODE`], and checked
///    again, including that it carries the parent's group.
///
/// The lock lasts as long as the returned [`BoundListener`], and the kernel releases it if the
/// process dies. `flock` locks belong to the open file description, so a child process forked
/// while the lock is held shares it until the child execs (std opens the file close-on-exec),
/// and a release can lag by that window. The lock file itself is never removed: unlinking it would let two instances
/// lock two different files. `flock` needs a local filesystem (tmpfs, overlayfs or a local
/// volume), so the socket directory must never be on NFS.
///
/// # Errors
///
/// Returns a [`PeerError`] describing the first check that failed, or an I/O error.
pub fn bind_safe_listener(path: &Path) -> Result<BoundListener, PeerError> {
    if !path.is_absolute() {
        return Err(PeerError::PathNotAbsolute);
    }
    if path
        .components()
        .any(|component| component == Component::ParentDir)
    {
        return Err(PeerError::PathHasParentComponent);
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or(PeerError::NoParent)?;
    let name = path.file_name().ok_or(PeerError::NoParent)?;
    let euid = geteuid().as_raw();
    let checked = check_parent(parent, euid)?;
    let real_parent = fs::canonicalize(parent)?;
    check_ancestors(&real_parent, euid)?;
    let real = fs::symlink_metadata(&real_parent)?;
    if (real.dev(), real.ino()) != (checked.dev(), checked.ino()) {
        return Err(PeerError::ParentChanged);
    }
    let socket = real_parent.join(name);
    let mut lock_name = name.to_os_string();
    lock_name.push(LOCK_SUFFIX);
    let lock = take_lock(&real_parent.join(lock_name), euid)?;
    check_existing(&socket, euid)?;
    let listener = UnixListener::bind(&socket)?;
    let finished = fs::set_permissions(&socket, Permissions::from_mode(SOCKET_MODE))
        .map_err(PeerError::from)
        .and_then(|()| verify_bound(&socket, euid, checked.gid()));
    if let Err(error) = finished {
        // Do not leave a socket with the wrong mode or group behind. This call created it, in
        // a directory no other user can write to, so removing it cannot touch anyone else's
        // file.
        drop(listener);
        drop(fs::remove_file(&socket));
        return Err(error);
    }
    Ok(BoundListener {
        listener,
        _lock: lock,
    })
}

/// A listener bound by [`bind_safe_listener`], with the lock that guards its path.
#[derive(Debug)]
pub struct BoundListener {
    /// Declared first, so it is dropped first: the socket closes before the lock is released.
    listener: UnixListener,
    /// Never read. The lock lasts as long as this file stays open.
    _lock: File,
}

impl BoundListener {
    /// The listening socket.
    #[must_use]
    pub const fn listener(&self) -> &UnixListener {
        &self.listener
    }
}

/// Opens the lock file at `path` and takes an exclusive, non-blocking lock on it.
fn take_lock(path: &Path, euid: u32) -> Result<File, PeerError> {
    let file = open_lock_file(path)?;
    check_lock_file(&file.metadata()?, euid)?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => Err(PeerError::LockHeld),
        Err(TryLockError::Error(error)) => Err(PeerError::Io(error)),
    }
}

/// Opens the lock file, creating it if needed.
/// - `O_NOFOLLOW` refuses a symlink at the path.
/// - `O_NONBLOCK` makes the open of a FIFO planted there fail at once instead of blocking.
/// - A file this call creates is set to exactly [`LOCK_MODE`], whatever the umask. An existing
///   file must already have that mode ([`check_lock_file`]).
///
/// std opens every file close-on-exec, so a child process never inherits the lock.
fn open_lock_file(path: &Path) -> Result<File, PeerError> {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .mode(LOCK_MODE)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    match options.clone().create_new(true).open(path) {
        Ok(file) => {
            file.set_permissions(Permissions::from_mode(LOCK_MODE))?;
            Ok(file)
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            options.open(path).map_err(lock_open_error)
        }
        Err(error) => Err(lock_open_error(error)),
    }
}

fn lock_open_error(error: io::Error) -> PeerError {
    if error.raw_os_error() == Some(nix::libc::ELOOP) {
        PeerError::LockIsSymlink
    } else {
        PeerError::Io(error)
    }
}

/// The fstat checks on the open lock file.
fn check_lock_file(metadata: &Metadata, euid: u32) -> Result<(), PeerError> {
    if !metadata.file_type().is_file() {
        return Err(PeerError::LockNotRegularFile);
    }
    if metadata.uid() != euid {
        return Err(PeerError::LockOwnerMismatch {
            expected: euid,
            actual: metadata.uid(),
        });
    }
    let mode = metadata.mode() & 0o7777;
    if mode != LOCK_MODE {
        return Err(PeerError::LockModeMismatch { mode });
    }
    if metadata.nlink() != 1 {
        return Err(PeerError::LockLinkCount {
            nlink: metadata.nlink(),
        });
    }
    Ok(())
}

fn check_parent(parent: &Path, euid: u32) -> Result<Metadata, PeerError> {
    let metadata = fs::symlink_metadata(parent)?;
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(PeerError::ParentIsSymlink);
    }
    if !file_type.is_dir() {
        return Err(PeerError::ParentNotDirectory);
    }
    if metadata.uid() != euid {
        return Err(PeerError::ParentOwnerMismatch {
            expected: euid,
            actual: metadata.uid(),
        });
    }
    let mode = metadata.mode() & 0o7777;
    if mode & FORBIDDEN_PARENT_BITS != 0 {
        return Err(PeerError::ParentModeTooPermissive { mode });
    }
    Ok(metadata)
}

/// Checks every ancestor of the canonical parent path. A sticky directory (like `/tmp`) may be
/// world-writable, because others still cannot rename or remove entries they do not own.
fn check_ancestors(real_parent: &Path, euid: u32) -> Result<(), PeerError> {
    for ancestor in real_parent.ancestors().skip(1) {
        let metadata = fs::symlink_metadata(ancestor)?;
        let owner = metadata.uid();
        let mode = metadata.mode() & 0o7777;
        let trusted_owner = owner == 0 || owner == euid;
        let writable_by_others = mode & FORBIDDEN_ANCESTOR_BITS != 0 && mode & STICKY_BIT == 0;
        if !metadata.file_type().is_dir() || !trusted_owner || writable_by_others {
            return Err(PeerError::AncestorUnsafe { owner, mode });
        }
    }
    Ok(())
}

fn check_existing(path: &Path, euid: u32) -> Result<(), PeerError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(PeerError::Io(error)),
        Ok(metadata) => {
            if !metadata.file_type().is_socket() {
                return Err(PeerError::ExistingNotSocket);
            }
            if metadata.uid() != euid {
                return Err(PeerError::ExistingOwnerMismatch {
                    expected: euid,
                    actual: metadata.uid(),
                });
            }
            // The caller holds the path's lock, so no other instance is listening here and the
            // socket is stale. (This replaces the old connect probe, which could not tell a full
            // backlog from a stale socket on macOS, and raced a second instance.)
            fs::remove_file(path)?;
            Ok(())
        }
    }
}

fn verify_bound(path: &Path, euid: u32, parent_gid: u32) -> Result<(), PeerError> {
    let metadata = fs::symlink_metadata(path)?;
    let mode = metadata.mode() & 0o777;
    if !metadata.file_type().is_socket() || metadata.uid() != euid || mode != SOCKET_MODE {
        return Err(PeerError::SocketModeMismatch { mode });
    }
    if metadata.gid() != parent_gid {
        return Err(PeerError::SocketGroupMismatch {
            expected: parent_gid,
            actual: metadata.gid(),
        });
    }
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use nix::unistd::getegid;
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    /// Set for a helper run of this test binary: the socket the helper uses.
    const HELPER_SOCKET: &str = "PEP_PEERCRED_HELPER_SOCKET";

    /// Re-runs this test binary to execute only the ignored helper test `name`.
    fn helper(name: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.args(["--exact", name, "--ignored", "--test-threads=1", "--quiet"]);
        command
    }

    /// Connects to `path` once a helper process listens there, failing if the helper exits
    /// first or never binds.
    fn connect_when_bound(path: &Path, child: &mut Child) -> UnixStream {
        for _ in 0..400 {
            if let Ok(stream) = UnixStream::connect(path) {
                return stream;
            }
            if let Some(status) = child.try_wait().unwrap() {
                panic!("helper exited before binding: {status}");
            }
            thread::sleep(Duration::from_millis(25));
        }
        drop(child.kill());
        panic!("helper never bound {}", path.display());
    }

    /// Kills and reaps the helper when dropped, so a failing test never leaves it running.
    struct KillOnDrop(Child);

    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            drop(self.0.kill());
            drop(self.0.wait());
        }
    }

    /// The lock file `bind_safe_listener` uses for `socket`.
    fn lock_path(socket: &Path) -> PathBuf {
        let mut name = socket.as_os_str().to_os_string();
        name.push(LOCK_SUFFIX);
        PathBuf::from(name)
    }

    /// Opens `socket`'s lock file the way another instance would, and locks it.
    fn hold_lock(socket: &Path) -> File {
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(LOCK_MODE)
            .open(lock_path(socket))
            .unwrap();
        file.try_lock().unwrap();
        file
    }

    /// Fails unless the helper run succeeded and actually ran its one test. A renamed helper
    /// would otherwise match no test and exit successfully without doing anything.
    fn assert_helper_ran(output: &std::process::Output) {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("test result: ok. 1 passed"),
            "helper failed or ran no test: {}\n{stdout}",
            output.status
        );
    }

    fn is_root() -> bool {
        geteuid().is_root()
    }

    /// Binds `path` right after its lock was released. A process another test spawns at that
    /// moment holds a copy of every open descriptor between its fork and its exec, and `flock`
    /// locks belong to the open file description, so the lock can outlive its release by that
    /// window. Retrying `LockHeld` for a bounded time absorbs it; a lock that really leaked
    /// would never be released, and still fails here.
    fn bind_after_release(path: &Path) -> BoundListener {
        for _ in 0..200 {
            match bind_safe_listener(path) {
                Err(PeerError::LockHeld) => thread::sleep(Duration::from_millis(25)),
                other => return other.unwrap(),
            }
        }
        panic!("the lock on {} was never released", path.display());
    }

    /// A unique directory under the system temp dir, removed on drop.
    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn with_mode(mode: u32) -> Self {
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let path =
                std::env::temp_dir().join(format!("pep-peercred-{}-{n}", std::process::id()));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, Permissions::from_mode(mode)).unwrap();
            Self { path }
        }

        fn socket(&self) -> PathBuf {
            self.path.join("mcp.sock")
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            drop(fs::set_permissions(
                &self.path,
                Permissions::from_mode(0o700),
            ));
            drop(fs::remove_dir_all(&self.path));
        }
    }

    #[test]
    fn bind_roundtrip_peer_cred() {
        let dir = TempDir::with_mode(0o750);
        let path = dir.socket();
        let bound = bind_safe_listener(&path).unwrap();
        let _client = UnixStream::connect(&path).unwrap();
        let (server, _) = bound.listener().accept().unwrap();
        let (uid, gid) = (geteuid().as_raw(), getegid().as_raw());
        let credentials = peer_cred(&server).unwrap();
        assert_eq!((credentials.uid, credentials.gid), (uid, gid));
        assert_eq!(
            credentials.pid,
            Some(i32::try_from(std::process::id()).unwrap())
        );
        assert_eq!(require_peer(&server, uid, gid).unwrap(), credentials);
        assert!(matches!(
            require_peer(&server, uid.wrapping_add(1), gid),
            Err(PeerError::UnexpectedPeerUid { .. })
        ));
    }

    /// C-UID's unit check: a socketpair's peer is this process, so only our own uid and gid pass.
    #[test]
    fn socketpair_self_connect() {
        let (left, _right) = UnixStream::pair().unwrap();
        let (uid, gid) = (geteuid().as_raw(), getegid().as_raw());
        let credentials = require_peer(&left, uid, gid).unwrap();
        assert_eq!((credentials.uid, credentials.gid), (uid, gid));
        assert!(matches!(
            require_peer(&left, uid.wrapping_add(1), gid),
            Err(PeerError::UnexpectedPeerUid { expected, actual })
                if expected == uid.wrapping_add(1) && actual == uid
        ));
        // Uid right, gid wrong: rejected (Q1).
        assert!(matches!(
            require_peer(&left, uid, gid.wrapping_add(1)),
            Err(PeerError::UnexpectedPeerGid { expected, actual })
                if expected == gid.wrapping_add(1) && actual == gid
        ));
    }

    /// The C-PID checks and the kernel-dependent tests. They are Linux-only: macOS has no pidfd.
    #[cfg(target_os = "linux")]
    mod pidfd {
        use super::*;
        use nix::errno::Errno;
        use std::io::Write as _;

        /// `(major, minor, release)` from `/proc/sys/kernel/osrelease`, such as `(6, 18, "6.18.54.1-…")`.
        fn kernel_version() -> (u32, u32, String) {
            let release = fs::read_to_string("/proc/sys/kernel/osrelease").unwrap();
            let release = release.trim().to_owned();
            let mut parts = release.split(['.', '-']);
            let major = parts.next().unwrap().parse().unwrap();
            let minor = parts.next().unwrap().parse().unwrap();
            (major, minor, release)
        }

        fn log(line: &str) {
            writeln!(io::stderr().lock(), "{line}").unwrap();
        }

        /// C-PID: an injected `getsockopt` errno always rejects, and `ENOPROTOOPT` (a kernel
        /// older than 6.5) and `ENODATA` get their own errors.
        #[test]
        fn pidfd_errno_rejects() {
            assert!(matches!(
                classify_pidfd(Err(Errno::ENOPROTOOPT)),
                Err(PeerError::PidfdUnsupported)
            ));
            assert!(matches!(
                classify_pidfd(Err(Errno::ENODATA)),
                Err(PeerError::PidfdNoPeer)
            ));
            for errno in [Errno::EINVAL, Errno::ESRCH, Errno::EBADF, Errno::EMFILE] {
                assert!(matches!(
                    classify_pidfd(Err(errno)),
                    Err(PeerError::PidfdFailed(e)) if e == errno
                ));
            }
        }

        /// C-PID: the fdinfo parser reads exactly one `Pid:` line and ignores `NSpid:`.
        #[test]
        fn fdinfo_pid_parser() {
            let live =
                "pos:\t0\nflags:\t02000002\nmnt_id:\t15\nino:\t1057\nPid:\t1234\nNSpid:\t1234\n";
            assert_eq!(fdinfo_pid(live).unwrap(), 1234);
            assert_eq!(fdinfo_pid("Pid:\t0\nNSpid:\t0\n").unwrap(), 0);
            assert_eq!(fdinfo_pid("Pid:\t-1\nNSpid:\t-1\n").unwrap(), -1);
            for malformed in [
                "",
                "pos:\t0\nNSpid:\t7\n",
                "Pid:\t7\nPid:\t8\n",
                "Pid:\t\n",
                "Pid:\tseven\n",
                "Pid:\t99999999999\n",
            ] {
                assert!(
                    matches!(fdinfo_pid(malformed), Err(PeerError::FdinfoMalformed)),
                    "{malformed:?}"
                );
            }
        }

        /// C-PID: `Pid: -1` rejects, and `Pid: 0` (a peer in a namespace this process cannot
        /// see) is accepted, as Q1 (i) decides.
        #[test]
        fn pidfd_liveness_rule() {
            assert!(matches!(pidfd_alive(-1), Err(PeerError::PeerExited)));
            assert!(pidfd_alive(0).is_ok());
            assert!(pidfd_alive(1).is_ok());
            assert!(pidfd_alive(i32::MAX).is_ok());
            for malformed in [-2, i32::MIN] {
                assert!(matches!(
                    pidfd_alive(malformed),
                    Err(PeerError::FdinfoMalformed)
                ));
            }
        }

        /// The kernel branch: on Linux 6.5 and later the pidfd works and shows this process's
        /// own pid (same namespace); on an older kernel `require_peer` rejects with
        /// `PidfdUnsupported`. The kernel is logged so CI records which branch ran.
        #[test]
        fn require_peer_on_this_kernel() {
            let (major, minor, release) = kernel_version();
            let (left, _right) = UnixStream::pair().unwrap();
            let (uid, gid) = (geteuid().as_raw(), getegid().as_raw());
            if (major, minor) >= (6, 5) {
                log(&format!("kernel {release}: SO_PEERPIDFD expected to work"));
                require_peer(&left, uid, gid).unwrap();
                let pidfd = peer_pidfd(&left).unwrap();
                let fdinfo = fs::read_to_string(fdinfo_path(&pidfd)).unwrap();
                assert_eq!(
                    fdinfo_pid(&fdinfo).unwrap(),
                    i32::try_from(std::process::id()).unwrap()
                );
            } else {
                log(&format!(
                    "kernel {release}: older than 6.5, expecting rejection"
                ));
                assert!(matches!(
                    require_peer(&left, uid, gid),
                    Err(PeerError::PidfdUnsupported)
                ));
            }
        }

        /// C-PID: the pidfd is close-on-exec, and `require_peer` closes it, so no pidfd leaks
        /// into a child process or piles up.
        #[test]
        fn pidfd_cloexec_and_closed() {
            let (left, _right) = UnixStream::pair().unwrap();
            let pidfd = peer_pidfd(&left).unwrap();
            let fdinfo = fs::read_to_string(fdinfo_path(&pidfd)).unwrap();
            let flags = fdinfo
                .lines()
                .find_map(|line| line.strip_prefix("flags:"))
                .map(|value| u32::from_str_radix(value.trim(), 8).unwrap())
                .unwrap();
            let cloexec = u32::try_from(nix::libc::O_CLOEXEC).unwrap();
            assert_ne!(flags & cloexec, 0, "pidfd flags {flags:o} lack O_CLOEXEC");
            drop(pidfd);

            let (uid, gid) = (geteuid().as_raw(), getegid().as_raw());
            let open_fds = || fs::read_dir("/proc/self/fd").unwrap().count();
            let before = open_fds();
            for _ in 0..256 {
                require_peer(&left, uid, gid).unwrap();
            }
            // Other tests open and close descriptors concurrently, so allow some noise; a leak
            // would add 256.
            let after = open_fds();
            assert!(
                after < before + 64,
                "{before} fds before, {after} after 256 checks"
            );
        }

        /// C-PID: a peer that exits and is reaped before the check is rejected. This kernel
        /// (and CI's) returns a stale pidfd showing `Pid: -1`, not an error.
        #[test]
        fn reaped_peer_rejected() {
            let dir = TempDir::with_mode(0o750);
            let path = dir.socket();
            let listener = UnixListener::bind(&path).unwrap();
            // The helper connects and exits; `output` waits for it, which reaps it.
            let output = helper("peercred::tests::pidfd::helper_connect_and_exit")
                .env(HELPER_SOCKET, &path)
                .output()
                .unwrap();
            assert_helper_ran(&output);
            let (server, _) = listener.accept().unwrap();
            let (uid, gid) = (geteuid().as_raw(), getegid().as_raw());
            // The credentials recorded at connect time are still there...
            assert_eq!(peer_cred(&server).unwrap().uid, uid);
            // ...but the peer is gone.
            assert!(matches!(
                require_peer(&server, uid, gid),
                Err(PeerError::PeerExited)
            ));
        }

        #[test]
        #[ignore = "helper process for reaped_peer_rejected; does nothing when run on its own"]
        fn helper_connect_and_exit() {
            if let Some(path) = std::env::var_os(HELPER_SOCKET) {
                drop(UnixStream::connect(path).unwrap());
            }
        }

        /// The Compose case (Q1): the listener is in a new user, PID and mount namespace that
        /// cannot see the peer, so `SO_PEERCRED` reports pid 0 and fdinfo shows `Pid: 0`, and
        /// the live peer is still accepted. The new user namespace maps the peer's uid and gid
        /// to 0, as Appendix A of `WEEK2_PLAN.md` observed.
        #[test]
        #[ignore = "needs unshare(1) with user, PID and mount namespaces (root, or unprivileged user namespaces)"]
        fn cross_namespace_peer_alive_with_pid_zero() {
            let dir = TempDir::with_mode(0o750);
            let path = dir.socket();
            let mut child = Command::new("unshare")
                .args([
                    "--user",
                    "--map-root-user",
                    "--pid",
                    "--fork",
                    "--mount-proc",
                    "--",
                ])
                .arg(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "peercred::tests::pidfd::helper_namespace_listener",
                    "--ignored",
                    "--test-threads=1",
                    "--quiet",
                ])
                .env(HELPER_SOCKET, &path)
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            // Stay connected, and alive, until the helper has checked us.
            let stream = connect_when_bound(&path, &mut child);
            let output = child.wait_with_output().unwrap();
            drop(stream);
            assert_helper_ran(&output);
        }

        #[test]
        #[ignore = "helper process for cross_namespace_peer_alive_with_pid_zero; does nothing when run on its own"]
        fn helper_namespace_listener() {
            let Some(path) = std::env::var_os(HELPER_SOCKET) else {
                return;
            };
            let listener = UnixListener::bind(path).unwrap();
            let (server, _) = listener.accept().unwrap();
            let credentials = require_peer(&server, 0, 0).unwrap();
            assert_eq!(credentials.pid, Some(0));
            let pidfd = peer_pidfd(&server).unwrap();
            let fdinfo = fs::read_to_string(fdinfo_path(&pidfd)).unwrap();
            assert_eq!(fdinfo_pid(&fdinfo).unwrap(), 0);
            // Identity still rests on the uid and gid across namespaces.
            assert!(matches!(
                require_peer(&server, 0, 1),
                Err(PeerError::UnexpectedPeerGid { .. })
            ));
        }
    }

    #[test]
    fn parent_mode_0777_rejected() {
        let dir = TempDir::with_mode(0o777);
        assert!(matches!(
            bind_safe_listener(&dir.socket()),
            Err(PeerError::ParentModeTooPermissive { mode: 0o777 })
        ));
    }

    #[test]
    fn parent_group_writable_rejected() {
        let dir = TempDir::with_mode(0o770);
        assert!(matches!(
            bind_safe_listener(&dir.socket()),
            Err(PeerError::ParentModeTooPermissive { mode: 0o770 })
        ));
    }

    #[test]
    fn parent_symlink_rejected() {
        let dir = TempDir::with_mode(0o750);
        let real = dir.path.join("real");
        fs::create_dir(&real).unwrap();
        fs::set_permissions(&real, Permissions::from_mode(0o750)).unwrap();
        let link = dir.path.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(matches!(
            bind_safe_listener(&link.join("mcp.sock")),
            Err(PeerError::ParentIsSymlink)
        ));
    }

    #[test]
    fn parent_not_directory_rejected() {
        let dir = TempDir::with_mode(0o750);
        let file = dir.path.join("file");
        fs::write(&file, b"x").unwrap();
        assert!(matches!(
            bind_safe_listener(&file.join("mcp.sock")),
            Err(PeerError::ParentNotDirectory)
        ));
    }

    #[test]
    fn regular_file_not_unlinked() {
        let dir = TempDir::with_mode(0o750);
        let path = dir.socket();
        fs::write(&path, b"keep").unwrap();
        assert!(matches!(
            bind_safe_listener(&path),
            Err(PeerError::ExistingNotSocket)
        ));
        assert_eq!(fs::read(&path).unwrap(), b"keep");
    }

    #[test]
    fn stale_socket_replaced() {
        let dir = TempDir::with_mode(0o750);
        let path = dir.socket();
        drop(UnixListener::bind(&path).unwrap());
        assert!(fs::symlink_metadata(&path).unwrap().file_type().is_socket());
        let _listener = bind_safe_listener(&path).unwrap();
    }

    #[test]
    fn socket_mode_0660() {
        let dir = TempDir::with_mode(0o750);
        let path = dir.socket();
        let _listener = bind_safe_listener(&path).unwrap();
        assert_eq!(
            fs::symlink_metadata(&path).unwrap().mode() & 0o777,
            SOCKET_MODE
        );
    }

    #[test]
    fn relative_or_rootless_path_rejected() {
        assert!(matches!(
            bind_safe_listener(Path::new("relative.sock")),
            Err(PeerError::PathNotAbsolute)
        ));
        assert!(matches!(
            bind_safe_listener(Path::new("/")),
            Err(PeerError::NoParent)
        ));
    }

    #[test]
    #[ignore = "needs root: creates a parent directory owned by another uid"]
    fn parent_owner_mismatch_rejected() {
        let dir = TempDir::with_mode(0o750);
        std::os::unix::fs::chown(&dir.path, Some(65_534), None).unwrap();
        assert!(matches!(
            bind_safe_listener(&dir.socket()),
            Err(PeerError::ParentOwnerMismatch { .. })
        ));
    }

    /// C-LOCK: a second instance is blocked while the first holds the lock, and the first's
    /// socket is left alone.
    #[test]
    fn second_instance_blocked() {
        let dir = TempDir::with_mode(0o750);
        let path = dir.socket();
        let first = bind_safe_listener(&path).unwrap();
        assert!(matches!(
            bind_safe_listener(&path),
            Err(PeerError::LockHeld)
        ));
        let _client = UnixStream::connect(&path).unwrap();
        first.listener().accept().unwrap();
    }

    /// C-LOCK: a stale socket is replaced only under the lock. While another process holds the
    /// lock, even a stale socket is left in place.
    #[test]
    fn stale_socket_replaced_only_under_the_lock() {
        let dir = TempDir::with_mode(0o750);
        let path = dir.socket();
        drop(UnixListener::bind(&path).unwrap());
        let held = hold_lock(&path);
        assert!(matches!(
            bind_safe_listener(&path),
            Err(PeerError::LockHeld)
        ));
        assert!(fs::symlink_metadata(&path).unwrap().file_type().is_socket());
        drop(held);
        let bound = bind_after_release(&path);
        let _client = UnixStream::connect(&path).unwrap();
        bound.listener().accept().unwrap();
    }

    /// Dropping the listener releases the lock, so the next instance binds.
    #[test]
    fn lock_released_on_drop() {
        let dir = TempDir::with_mode(0o750);
        let path = dir.socket();
        drop(bind_safe_listener(&path).unwrap());
        let _again = bind_after_release(&path);
    }

    /// C-LOCK: the lock is released when its holder crashes. The helper binds and is then
    /// killed with SIGKILL, so no destructor runs; the kernel releases its lock, and the next
    /// instance replaces the socket it left behind.
    #[test]
    fn lock_released_on_crash() {
        let dir = TempDir::with_mode(0o750);
        let path = dir.socket();
        let mut child = KillOnDrop(
            helper("peercred::tests::helper_hold_listener")
                .env(HELPER_SOCKET, &path)
                .stdout(Stdio::null())
                .spawn()
                .unwrap(),
        );
        // The helper binds only after taking the lock, so a connect means it holds it.
        drop(connect_when_bound(&path, &mut child.0));
        assert!(matches!(
            bind_safe_listener(&path),
            Err(PeerError::LockHeld)
        ));
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        assert!(fs::symlink_metadata(&path).unwrap().file_type().is_socket());
        let bound = bind_safe_listener(&path).unwrap();
        let _client = UnixStream::connect(&path).unwrap();
        bound.listener().accept().unwrap();
    }

    #[test]
    #[ignore = "helper process for lock_released_on_crash; does nothing when run on its own"]
    fn helper_hold_listener() {
        if let Some(path) = std::env::var_os(HELPER_SOCKET) {
            let _bound = bind_safe_listener(Path::new(&path)).unwrap();
            // Hold the lock until killed. Give up after a minute, so a lost helper cannot linger.
            thread::sleep(Duration::from_mins(1));
        }
    }

    /// A lock file this call creates is exactly 0600 whatever the umask. The helper runs under
    /// umask 0277, which would otherwise create it 0400 and fail the mode check.
    #[test]
    fn lock_mode_exact_under_restrictive_umask() {
        let dir = TempDir::with_mode(0o750);
        let output = Command::new("sh")
            .args(["-c", "umask 0277 && exec \"$0\" \"$@\""])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "peercred::tests::helper_bind_under_umask",
                "--ignored",
                "--test-threads=1",
                "--quiet",
            ])
            .env(HELPER_SOCKET, dir.socket())
            .output()
            .unwrap();
        assert_helper_ran(&output);
        let metadata = fs::symlink_metadata(lock_path(&dir.socket())).unwrap();
        assert_eq!(metadata.mode() & 0o7777, LOCK_MODE);
    }

    #[test]
    #[ignore = "helper process for lock_mode_exact_under_restrictive_umask; does nothing when run on its own"]
    fn helper_bind_under_umask() {
        if let Some(path) = std::env::var_os(HELPER_SOCKET) {
            let _bound = bind_safe_listener(Path::new(&path)).unwrap();
        }
    }

    /// C-LOCK: a directory the PEP cannot write fails before anything is created or unlinked.
    /// (Root ignores directory modes, so the check is skipped when the tests run as root.)
    #[test]
    fn read_only_directory_fails() {
        if is_root() {
            return;
        }
        let dir = TempDir::with_mode(0o550);
        let result = bind_safe_listener(&dir.socket());
        assert!(
            matches!(&result, Err(PeerError::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied),
            "{result:?}"
        );
        assert_eq!(fs::read_dir(&dir.path).unwrap().count(), 0);
    }

    /// C-LOCK: a symlink planted at the socket path is refused, as not a socket, and is left
    /// in place along with its target.
    #[test]
    fn symlink_at_socket_path_refused() {
        let dir = TempDir::with_mode(0o750);
        let target = dir.path.join("target");
        fs::write(&target, b"keep").unwrap();
        std::os::unix::fs::symlink(&target, dir.socket()).unwrap();
        assert!(matches!(
            bind_safe_listener(&dir.socket()),
            Err(PeerError::ExistingNotSocket)
        ));
        assert!(
            fs::symlink_metadata(dir.socket())
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read(&target).unwrap(), b"keep");
    }

    /// The lock file is created as a regular file, mode 0600, owned by us, with one link.
    #[test]
    fn lock_file_is_private() {
        let dir = TempDir::with_mode(0o750);
        let _bound = bind_safe_listener(&dir.socket()).unwrap();
        let metadata = fs::symlink_metadata(lock_path(&dir.socket())).unwrap();
        assert!(metadata.file_type().is_file());
        assert_eq!(metadata.mode() & 0o7777, LOCK_MODE);
        assert_eq!(metadata.uid(), geteuid().as_raw());
        assert_eq!(metadata.nlink(), 1);
    }

    /// `O_NOFOLLOW`: a symlink at the lock path is refused, and its target is never created.
    #[test]
    fn symlink_at_lock_path_refused() {
        let dir = TempDir::with_mode(0o750);
        let target = dir.path.join("elsewhere");
        std::os::unix::fs::symlink(&target, lock_path(&dir.socket())).unwrap();
        assert!(matches!(
            bind_safe_listener(&dir.socket()),
            Err(PeerError::LockIsSymlink)
        ));
        assert!(fs::symlink_metadata(&target).is_err());
        assert!(fs::symlink_metadata(dir.socket()).is_err());
    }

    /// An existing lock file must already be 0600; it is never loosened or tightened.
    #[test]
    fn lock_file_with_wrong_mode_refused() {
        let dir = TempDir::with_mode(0o750);
        let lock = lock_path(&dir.socket());
        fs::write(&lock, b"").unwrap();
        fs::set_permissions(&lock, Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            bind_safe_listener(&dir.socket()),
            Err(PeerError::LockModeMismatch { mode: 0o644 })
        ));
        assert_eq!(fs::symlink_metadata(&lock).unwrap().mode() & 0o7777, 0o644);
    }

    /// `nlink` 1: a lock file with a second name is refused.
    #[test]
    fn hard_linked_lock_file_refused() {
        let dir = TempDir::with_mode(0o750);
        let lock = lock_path(&dir.socket());
        drop(hold_lock(&dir.socket()));
        fs::hard_link(&lock, dir.path.join("other-name")).unwrap();
        assert!(matches!(
            bind_safe_listener(&dir.socket()),
            Err(PeerError::LockLinkCount { nlink: 2 })
        ));
    }

    /// `O_NONBLOCK`: a FIFO at the lock path makes the bind fail at once instead of hanging.
    #[test]
    fn fifo_at_lock_path_does_not_block() {
        let dir = TempDir::with_mode(0o750);
        let lock = lock_path(&dir.socket());
        let status = Command::new("mkfifo").arg(&lock).status().unwrap();
        assert!(status.success());
        let (sender, receiver) = mpsc::channel();
        let socket = dir.socket();
        thread::spawn(move || drop(sender.send(bind_safe_listener(&socket).map(drop))));
        let result = receiver
            .recv_timeout(Duration::from_secs(10))
            .expect("bind_safe_listener blocked on a FIFO at the lock path");
        assert!(
            matches!(
                result,
                Err(PeerError::Io(_) | PeerError::LockNotRegularFile)
            ),
            "{result:?}"
        );
    }

    /// The lock file descriptor is close-on-exec, so a child process cannot keep the lock alive
    /// after the PEP dies.
    #[cfg(target_os = "linux")]
    #[test]
    fn lock_fd_is_cloexec() {
        let dir = TempDir::with_mode(0o750);
        let _bound = bind_safe_listener(&dir.socket()).unwrap();
        let lock = fs::canonicalize(lock_path(&dir.socket())).unwrap();
        let fd = fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter_map(Result::ok)
            .find(|entry| fs::read_link(entry.path()).is_ok_and(|target| target == lock))
            .expect("no open descriptor for the lock file")
            .file_name();
        let fdinfo = fs::read_to_string(Path::new("/proc/self/fdinfo").join(fd)).unwrap();
        let flags = fdinfo
            .lines()
            .find_map(|line| line.strip_prefix("flags:"))
            .map(|value| u32::from_str_radix(value.trim(), 8).unwrap())
            .unwrap();
        let cloexec = u32::try_from(nix::libc::O_CLOEXEC).unwrap();
        assert_ne!(flags & cloexec, 0, "lock fd flags {flags:o} lack O_CLOEXEC");
    }

    #[test]
    #[ignore = "needs root: creates a lock file owned by another uid"]
    fn lock_file_owned_by_other_uid_refused() {
        let dir = TempDir::with_mode(0o750);
        let lock = lock_path(&dir.socket());
        drop(hold_lock(&dir.socket()));
        std::os::unix::fs::chown(&lock, Some(65_534), None).unwrap();
        assert!(matches!(
            bind_safe_listener(&dir.socket()),
            Err(PeerError::LockOwnerMismatch { actual: 65_534, .. })
        ));
    }

    #[test]
    fn parent_dir_component_rejected() {
        let dir = TempDir::with_mode(0o750);
        fs::create_dir(dir.path.join("x")).unwrap();
        assert!(matches!(
            bind_safe_listener(&dir.path.join("x/../mcp.sock")),
            Err(PeerError::PathHasParentComponent)
        ));
    }

    #[test]
    fn writable_ancestor_rejected_unless_sticky() {
        let outer = TempDir::with_mode(0o777);
        let inner = outer.path.join("inner");
        fs::create_dir(&inner).unwrap();
        fs::set_permissions(&inner, Permissions::from_mode(0o750)).unwrap();
        assert!(matches!(
            bind_safe_listener(&inner.join("mcp.sock")),
            Err(PeerError::AncestorUnsafe { mode: 0o777, .. })
        ));
        fs::set_permissions(&outer.path, Permissions::from_mode(0o1777)).unwrap();
        let _listener = bind_safe_listener(&inner.join("mcp.sock")).unwrap();
    }

    #[test]
    fn symlinked_ancestor_binds_under_canonical_path() {
        let dir = TempDir::with_mode(0o750);
        let real = dir.path.join("real");
        fs::create_dir(&real).unwrap();
        fs::set_permissions(&real, Permissions::from_mode(0o750)).unwrap();
        let link = dir.path.join("link");
        std::os::unix::fs::symlink(&dir.path, &link).unwrap();
        let bound = bind_safe_listener(&link.join("real/mcp.sock")).unwrap();
        let canonical = fs::canonicalize(&real).unwrap().join("mcp.sock");
        assert_eq!(
            bound.listener().local_addr().unwrap().as_pathname(),
            Some(canonical.as_path())
        );
        assert!(
            fs::symlink_metadata(&canonical)
                .unwrap()
                .file_type()
                .is_socket()
        );
    }

    #[test]
    #[ignore = "needs root: gives the parent directory a group the process is not in"]
    fn socket_group_must_match_parent() {
        let dir = TempDir::with_mode(0o750);
        std::os::unix::fs::chown(&dir.path, None, Some(65_534)).unwrap();
        fs::set_permissions(&dir.path, Permissions::from_mode(0o750)).unwrap();
        assert!(matches!(
            bind_safe_listener(&dir.socket()),
            Err(PeerError::SocketGroupMismatch {
                expected: 65_534,
                ..
            })
        ));
        // The rejected socket is removed, not left behind with the wrong group.
        assert!(fs::symlink_metadata(dir.socket()).is_err());
        fs::set_permissions(&dir.path, Permissions::from_mode(0o2750)).unwrap();
        // The failed bind above took and released the lock.
        let _listener = bind_after_release(&dir.socket());
        assert_eq!(fs::symlink_metadata(dir.socket()).unwrap().gid(), 65_534);
    }
}
