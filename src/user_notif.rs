//! The seccomp `USER_NOTIF` stat pool: a thread pool that services the listener
//! fd and answers the stat family in parallel, bypassing the single-threaded
//! ptrace loop entirely (issue #7).
//!
//! stat arrives as a `SECCOMP_RET_USER_NOTIF` notification — the syscall is
//! *blocked* and the real syscall never runs. We resolve the target the same way
//! the ptrace write-path does (via `/proc/<pid>/…`), do a supervisor-side
//! `stat`/`statx` to obtain the full result struct, overlay faked ownership from
//! the shared table, write the struct back into the tracee, and respond with
//! success. Because the real syscall never executes, we must produce the *whole*
//! struct (not just patch uid/gid) — hence the supervisor-side stat. If we can't
//! resolve/stat (e.g. exotic mount namespace), we fall back to `CONTINUE` so the
//! kernel runs the real syscall rather than failing the caller.

use crate::error::Result;
use crate::handlers::{patch_native, patch_statx};
use crate::mem;
use crate::path;
use crate::table::OwnershipTable;
use nix::unistd::Pid;
use std::ffi::CString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

// seccomp ioctl request codes — libc exposes the structs/constants but not these.
const fn ioc(dir: u32, ty: u32, nr: u32, sz: u32) -> u32 {
    (dir << 30) | (sz << 16) | (ty << 8) | nr
}
const IOC_RW: u32 = 3; // _IOC_READ | _IOC_WRITE
const SECCOMP_IOCTL_NOTIF_RECV: u32 = ioc(
    IOC_RW,
    b'!' as u32,
    0,
    std::mem::size_of::<libc::seccomp_notif>() as u32,
);
const SECCOMP_IOCTL_NOTIF_SEND: u32 = ioc(
    IOC_RW,
    b'!' as u32,
    1,
    std::mem::size_of::<libc::seccomp_notif_resp>() as u32,
);
/// Kept for completeness (TOCTOU check); the stat path doesn't need it yet.
#[allow(dead_code)]
const SECCOMP_IOCTL_NOTIF_ID_VALID: u32 = ioc(2, b'!' as u32, 2, 8); // _IOW('!', 2, __u64)
const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;

/// What to send back for a stat notification.
enum Response {
    /// The syscall never ran; report this return value (0 = success).
    Value(i64),
    /// Couldn't resolve/stat it ourselves — let the kernel run the real syscall.
    Continue,
}

/// A running pool of stat-notification servants. Drop joins the workers.
pub struct NotifPool {
    fd: std::os::fd::RawFd,
    handles: Vec<JoinHandle<()>>,
}

impl NotifPool {
    /// Spawn `n` worker threads all sharing `fd`.
    pub fn spawn(fd: std::os::fd::RawFd, table: &Arc<OwnershipTable>, n: usize) -> Self {
        let handles: Vec<_> = (0..n)
            .map(|_| {
                let table = Arc::clone(table);
                thread::spawn(move || worker(fd, table))
            })
            .collect();
        NotifPool { fd, handles }
    }

    /// Close the listener fd (unblocks `RECV`) and join all workers.
    pub fn join(self) {
        // Closing the fd makes pending RECVs return an error → workers exit.
        unsafe {
            let _ = libc::close(self.fd);
        }
        for h in self.handles {
            let _ = h.join();
        }
    }
}

fn worker(fd: std::os::fd::RawFd, table: Arc<OwnershipTable>) {
    loop {
        let mut req: libc::seccomp_notif = unsafe { std::mem::zeroed() };
        let r = unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV as libc::Ioctl, &mut req) };
        if r != 0 {
            break; // listener closed or fatal error → exit
        }
        let resp = match handle_stat(&req, &table) {
            Response::Value(v) => libc::seccomp_notif_resp {
                id: req.id,
                val: v,
                error: 0,
                flags: 0,
            },
            Response::Continue => libc::seccomp_notif_resp {
                id: req.id,
                val: 0,
                error: 0,
                flags: SECCOMP_USER_NOTIF_FLAG_CONTINUE,
            },
        };
        // Best-effort: if the tracee died between RECV and SEND, the id is stale
        // and SEND fails — there's nothing to do but move on.
        let _ = unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND as libc::Ioctl, &resp) };
    }
}

/// Resolve `dirfd`/`path` the way the tracee sees it (via `/proc/<pid>/…`).
fn resolve(pid: Pid, dirfd: i32, path: &Path, empty: bool) -> PathBuf {
    path::resolve_path(pid, dirfd, path, empty)
}

/// Supervisor-side `stat`/`lstat` of an already-resolved path.
fn do_stat(resolved: &Path, nofollow: bool) -> std::io::Result<libc::stat> {
    let c = CString::new(resolved.as_os_str().as_bytes())?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        if nofollow {
            libc::lstat(c.as_ptr(), &mut st)
        } else {
            libc::stat(c.as_ptr(), &mut st)
        }
    };
    if rc != 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(st)
    }
}

/// Supervisor-side `statx` of an already-resolved path.
fn do_statx(resolved: &Path, nofollow: bool, mask: u32) -> std::io::Result<libc::statx> {
    let c = CString::new(resolved.as_os_str().as_bytes())?;
    let mut stx: libc::statx = unsafe { std::mem::zeroed() };
    let flags = if nofollow {
        libc::AT_SYMLINK_NOFOLLOW
    } else {
        0
    };
    let rc = unsafe { libc::statx(libc::AT_FDCWD, c.as_ptr(), flags, mask, &mut stx) };
    if rc != 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(stx)
    }
}

/// Decide what to do with one stat notification, perform it, and return the
/// response. Never returns `Err`: anything we can't handle becomes `Continue`.
fn handle_stat(req: &libc::seccomp_notif, table: &OwnershipTable) -> Response {
    let pid = Pid::from_raw(req.pid as i32);
    let nr = req.data.nr as i64;
    let arg = |i: usize| req.data.args[i];

    // Native `struct stat` flavours.
    let native = |resolved: &Path, nofollow: bool, buf: u64| -> Response {
        let mut st = match do_stat(resolved, nofollow) {
            Ok(st) => st,
            Err(_) => return Response::Continue,
        };
        let key = (st.st_dev as u64, st.st_ino as u64);
        let node = table.read().get(&key).cloned().unwrap_or_default();
        patch_native(&mut st, &node);
        match mem::write_struct(pid, buf, &st) {
            Ok(()) => Response::Value(0),
            Err(_) => Response::Continue,
        }
    };
    // `struct statx` flavour.
    let statx = |resolved: &Path, nofollow: bool, mask: u32, buf: u64| -> Response {
        let mut stx = match do_statx(resolved, nofollow, mask) {
            Ok(stx) => stx,
            Err(_) => return Response::Continue,
        };
        let dev = libc::makedev(stx.stx_dev_major, stx.stx_dev_minor) as u64;
        let key = (dev, stx.stx_ino);
        let node = table.read().get(&key).cloned().unwrap_or_default();
        patch_statx(&mut stx, &node);
        match mem::write_struct(pid, buf, &stx) {
            Ok(()) => Response::Value(0),
            Err(_) => Response::Continue,
        }
    };
    let readpath = |addr: u64| match mem::read_cstring(pid, addr) {
        Ok(v) => PathBuf::from(std::ffi::OsString::from_vec(v)),
        Err(_) => PathBuf::new(),
    };

    // Dispatch per syscall. (The bare stat/lstat are x86_64-only; the *at/statx
    // forms exist on every arch we support.)
    let r: Response = match nr {
        libc::SYS_fstat => {
            let resolved = resolve(pid, arg(0) as i32, Path::new(""), true);
            native(&resolved, false, arg(1))
        }
        libc::SYS_newfstatat => {
            let dirfd = arg(0) as i32;
            let path = readpath(arg(1));
            let buf = arg(2);
            let flags = arg(3) as i32;
            let nofollow = flags & libc::AT_SYMLINK_NOFOLLOW != 0;
            let empty = flags & libc::AT_EMPTY_PATH != 0;
            let resolved = resolve(pid, dirfd, &path, empty);
            native(&resolved, nofollow, buf)
        }
        libc::SYS_statx => {
            let dirfd = arg(0) as i32;
            let path = readpath(arg(1));
            let flags = arg(2) as i32;
            let mask = arg(3) as u32;
            let buf = arg(4);
            let nofollow = flags & libc::AT_SYMLINK_NOFOLLOW != 0;
            let empty = flags & libc::AT_EMPTY_PATH != 0;
            let resolved = resolve(pid, dirfd, &path, empty);
            statx(&resolved, nofollow, mask, buf)
        }
        _ => {
            #[cfg(target_arch = "x86_64")]
            {
                if nr == libc::SYS_stat {
                    let path = readpath(arg(0));
                    let resolved = resolve(pid, path::AT_FDCWD, &path, false);
                    return native(&resolved, false, arg(1));
                }
                if nr == libc::SYS_lstat {
                    let path = readpath(arg(0));
                    let resolved = resolve(pid, path::AT_FDCWD, &path, false);
                    return native(&resolved, true, arg(1));
                }
            }
            Response::Continue
        }
    };
    r
}

// Keep the `Result` import meaningful for future extensions.
#[allow(dead_code)]
fn _unused() -> Result<()> {
    Ok(())
}
