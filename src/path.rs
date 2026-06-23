//! Resolving a tracee-relative `(dirfd, path)` to something the supervisor can
//! `stat`, via the kernel's magic symlinks under `/proc/<pid>/`.
//!
//! This is the cluster of logic that broke `fakeroot-ng`: `AT_EMPTY_PATH`,
//! `AT_SYMLINK_NOFOLLOW`, `O_PATH` dirfds, and chroot. We resolve everything
//! relative to the tracee's own `/proc/<pid>/{root,cwd,fd/N}` so the kernel does
//! the hard part correctly.

use crate::error::Result;
use nix::unistd::Pid;
use std::path::{Path, PathBuf};

pub const AT_FDCWD: i32 = libc::AT_FDCWD;

/// The real metadata of a resolved target — what we seed/overlay against.
pub struct RealStat {
    pub dev: u64,
    pub ino: u64,
    pub mode: u32,
    pub nlink: u64,
}

/// Build the `/proc/<pid>/…` path that names the same file the tracee means.
pub fn resolve_path(pid: Pid, dirfd: i32, path: &Path, empty: bool) -> PathBuf {
    let base = format!("/proc/{}", pid.as_raw());
    if empty || path.as_os_str().is_empty() {
        // The target is the dirfd itself (AT_EMPTY_PATH, or an fd-based call).
        return if dirfd == AT_FDCWD {
            PathBuf::from(format!("{base}/cwd"))
        } else {
            PathBuf::from(format!("{base}/fd/{dirfd}"))
        };
    }
    if path.is_absolute() {
        // Honor the tracee's root (chroot-safe).
        return PathBuf::from(format!("{base}/root")).join(path.strip_prefix("/").unwrap_or(path));
    }
    if dirfd == AT_FDCWD {
        PathBuf::from(format!("{base}/cwd")).join(path)
    } else {
        PathBuf::from(format!("{base}/fd/{dirfd}")).join(path)
    }
}

/// Resolve and `stat` a target. Follows symlinks unless `nofollow` (and not an
/// fd/empty target, where we always want the file the fd refers to).
pub fn stat_target(
    pid: Pid,
    dirfd: i32,
    path: &Path,
    nofollow: bool,
    empty: bool,
) -> Result<RealStat> {
    let resolved = resolve_path(pid, dirfd, path, empty);
    let st = if nofollow && !empty {
        nix::sys::stat::lstat(&resolved)?
    } else {
        nix::sys::stat::stat(&resolved)?
    };
    Ok(RealStat {
        dev: st.st_dev as u64,
        ino: st.st_ino as u64,
        mode: st.st_mode as u32,
        nlink: st.st_nlink as u64,
    })
}
