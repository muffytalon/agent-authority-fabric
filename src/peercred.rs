//! Peer-credential checks and TOCTOU-safe Unix socket binding (F-11, F-12).
//!
//! The parent-directory check is what makes the later path operations race-free: a directory
//! owned by the effective user and not writable by group or others cannot have its entries
//! created, renamed or removed by any other non-root principal between the check and the bind.
//! Others cannot traverse it either, so the gap between `bind` and `chmod` only admits the
//! intended group. The remaining assumption is that the parent's ancestors (for example `/run`)
//! are root-owned.
//!
//! The peer PID is advisory until the Week 2 `SO_PEERPIDFD` upgrade.

use std::fs::{self, Permissions};
use std::io;
use std::os::fd::AsFd;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
use std::os::unix::net::UnixListener;
use std::path::Path;

use nix::sys::socket::{getsockopt, sockopt};
use nix::unistd::geteuid;

/// Mode of the bound socket.
pub const SOCKET_MODE: u32 = 0o660;
/// Parent-directory permission bits that must be clear: group write and everything for others.
pub const FORBIDDEN_PARENT_BITS: u32 = 0o027;

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
    /// The socket path is relative.
    #[error("socket path is not absolute")]
    PathNotAbsolute,
    /// The socket path has no parent directory.
    #[error("socket path has no parent directory")]
    NoParent,
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
    /// The bound socket does not have mode 0660 or is not ours.
    #[error("bound socket mode {mode:o} is not 0660")]
    SocketModeMismatch {
        /// The socket's permission bits.
        mode: u32,
    },
}

/// Credentials of the process at the other end of a Unix socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCred {
    /// Effective user id.
    pub uid: u32,
    /// Effective group id.
    pub gid: u32,
    /// Process id, if the platform reports it (advisory: PIDs can be reused).
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

/// Reads the peer's credentials and requires its uid to be `expected`.
///
/// # Errors
///
/// Returns [`PeerError::UnexpectedPeerUid`] for another uid, or the errors of [`peer_cred`].
pub fn require_peer_uid<F: AsFd>(socket: &F, expected: u32) -> Result<PeerCred, PeerError> {
    let credentials = peer_cred(socket)?;
    if credentials.uid == expected {
        Ok(credentials)
    } else {
        Err(PeerError::UnexpectedPeerUid {
            expected,
            actual: credentials.uid,
        })
    }
}

/// Binds a Unix listener at `path` without TOCTOU races.
///
/// 1. `path` must be absolute.
/// 2. Its parent must be a real directory (not a symlink) owned by the effective uid, with
///    none of [`FORBIDDEN_PARENT_BITS`] set.
/// 3. An existing file at `path` is unlinked only if it is a socket owned by the effective uid.
/// 4. The socket is bound, set to [`SOCKET_MODE`], and checked again.
///
/// # Errors
///
/// Returns a [`PeerError`] describing the first check that failed, or an I/O error.
pub fn bind_safe_listener(path: &Path) -> Result<UnixListener, PeerError> {
    if !path.is_absolute() {
        return Err(PeerError::PathNotAbsolute);
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or(PeerError::NoParent)?;
    let euid = geteuid().as_raw();
    check_parent(parent, euid)?;
    check_existing(path, euid)?;
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, Permissions::from_mode(SOCKET_MODE))?;
    verify_bound(path, euid)?;
    Ok(listener)
}

fn check_parent(parent: &Path, euid: u32) -> Result<(), PeerError> {
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
            fs::remove_file(path)?;
            Ok(())
        }
    }
}

fn verify_bound(path: &Path, euid: u32) -> Result<(), PeerError> {
    let metadata = fs::symlink_metadata(path)?;
    let mode = metadata.mode() & 0o777;
    if !metadata.file_type().is_socket() || metadata.uid() != euid || mode != SOCKET_MODE {
        return Err(PeerError::SocketModeMismatch { mode });
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
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

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
        let listener = bind_safe_listener(&path).unwrap();
        let _client = UnixStream::connect(&path).unwrap();
        let (server, _) = listener.accept().unwrap();
        let euid = geteuid().as_raw();
        let credentials = peer_cred(&server).unwrap();
        assert_eq!(credentials.uid, euid);
        assert_eq!(
            credentials.pid,
            Some(i32::try_from(std::process::id()).unwrap())
        );
        assert_eq!(require_peer_uid(&server, euid).unwrap(), credentials);
        assert!(matches!(
            require_peer_uid(&server, euid.wrapping_add(1)),
            Err(PeerError::UnexpectedPeerUid { .. })
        ));
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
}
