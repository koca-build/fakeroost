//! Syscall handlers: inspect each trapped syscall at its entry stop and decide
//! how to fake it (overlay stat results, record/skip chown, fake credentials,
//! mknod placeholders, xattrs, and inode-lifecycle cleanup).

use crate::arch::{RegAccess, Regs};
use crate::error::Result;
use crate::mem;
use crate::path::{self, AT_FDCWD};
use crate::table::{FakeNode, OwnershipTable};
use nix::unistd::Pid;
use std::ffi::{CString, OsString};
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};

/// All permission + setuid/setgid/sticky bits (`S_ISUID|S_ISGID|S_ISVTX|0777`).
const ALLPERMS: u32 = 0o7777;

/// Sentinel meaning "leave this id unchanged" in chown(2).
const ID_UNCHANGED: u32 = u32::MAX;

/// What to do with a trapped syscall after inspecting its entry.
pub enum Disposition {
    /// Let it run normally; no exit handling needed.
    Passthrough,
    /// Let it run, then apply the action at its exit stop.
    Step(ExitAction),
    /// Skip the real syscall (it never executes), then apply the action at exit.
    Skip(ExitAction),
}

/// Work to perform at a trapped syscall's exit stop.
pub enum ExitAction {
    /// Overlay faked ownership onto a stat-family result buffer.
    PatchStat { kind: StatKind, buf: u64 },
    /// Force the return value (used after skipping a syscall).
    ForceRet(i64),
    /// If the real syscall failed, pretend it succeeded (used for chmod).
    ZeroOnErr,
    /// Zero the (up to three) `uid_t*`/`gid_t*` out-params, then return 0
    /// (getresuid/getresgid).
    WriteResId { ptrs: [u64; 3] },
    /// Return a faked xattr value into a getxattr buffer (getxattr/lgetxattr/fgetxattr).
    ReturnXattr { buf: u64, size: u64, value: Vec<u8> },
    /// Merge faked xattr names into a real listxattr result.
    MergeXattrList {
        buf: u64,
        size: u64,
        extra: Vec<Vec<u8>>,
    },
    /// After a successful unlink/rmdir/rename-overwrite, drop the table entry if the
    /// inode's last link is gone (so a reused inode doesn't inherit stale ownership).
    UnlinkCommit {
        dev: u64,
        ino: u64,
        nlink_before: u64,
    },
}

/// The handler family a trapped syscall routes to.
///
/// [`REGISTRY`] maps every intercepted syscall to one of these, and *both* the
/// seccomp trap set ([`trapped_syscalls`]) and the entry dispatcher
/// ([`handle_entry`]) are derived from that one table. That makes drift impossible:
/// a syscall can't be trapped without a handler (the tuple demands a `Family`) nor
/// handled without being trapped (the `match` is exhaustive over `Family`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    /// stat/lstat/fstat/newfstatat/statx — overlay ownership onto the result buffer
    /// at the given arg index.
    Stat(StatKind, usize),
    /// getuid/geteuid/getgid/getegid plus every credential *setter* — faked to 0.
    Cred,
    /// getresuid/getresgid — write fake ids into the (up to three) out-params.
    CredRes,
    /// chown/lchown/fchown/fchownat — record the fake owner, skip the real call.
    Chown,
    /// chmod/fchmod/fchmodat — record the fake mode, let the real call run.
    Chmod,
    /// mknod/mknodat — drop a placeholder file, record the intended device node.
    Mknod,
    /// The 12 `*xattr` syscalls — fake xattrs (`security.capability`, ACLs) in the table.
    Xattr,
    /// unlink/rmdir/unlinkat — drop the table entry once the inode's last link is gone.
    Unlink,
    /// rename/renameat/renameat2 — clean up a clobbered destination inode.
    Rename,
}

/// The single source of truth for which syscalls we intercept and how.
///
/// The bare, non-`*at` syscalls (`stat`, `chown`, `chmod`, `rename`, …) are the
/// original kernel interfaces; the `*at` family and `statx` came later. aarch64 was
/// added to Linux after that, so its syscall table only has the `*at` forms — the
/// bare numbers don't exist there. That (and only that) is why those rows are
/// `#[cfg]`-gated to x86_64; it's the one place this arch knowledge lives.
#[rustfmt::skip]
const REGISTRY: &[(i64, Family)] = &[
    // stat family (kept first — by far the most frequently trapped)
    #[cfg(target_arch = "x86_64")] (libc::SYS_stat,  Family::Stat(StatKind::Native, 1)),
    #[cfg(target_arch = "x86_64")] (libc::SYS_lstat, Family::Stat(StatKind::Native, 1)),
    (libc::SYS_fstat,      Family::Stat(StatKind::Native, 1)),
    (libc::SYS_newfstatat, Family::Stat(StatKind::Native, 2)),
    (libc::SYS_statx,      Family::Stat(StatKind::Statx, 4)),
    // chown family
    #[cfg(target_arch = "x86_64")] (libc::SYS_chown,  Family::Chown),
    #[cfg(target_arch = "x86_64")] (libc::SYS_lchown, Family::Chown),
    (libc::SYS_fchown,   Family::Chown),
    (libc::SYS_fchownat, Family::Chown),
    // chmod family
    #[cfg(target_arch = "x86_64")] (libc::SYS_chmod, Family::Chmod),
    (libc::SYS_fchmod,   Family::Chmod),
    (libc::SYS_fchmodat, Family::Chmod),
    // mknod
    #[cfg(target_arch = "x86_64")] (libc::SYS_mknod, Family::Mknod),
    (libc::SYS_mknodat, Family::Mknod),
    // credentials (read) — faked to root
    (libc::SYS_getuid,    Family::Cred),
    (libc::SYS_geteuid,   Family::Cred),
    (libc::SYS_getgid,    Family::Cred),
    (libc::SYS_getegid,   Family::Cred),
    (libc::SYS_getresuid, Family::CredRes),
    (libc::SYS_getresgid, Family::CredRes),
    // credentials (set) — faked to succeed
    (libc::SYS_setuid,    Family::Cred),
    (libc::SYS_setgid,    Family::Cred),
    (libc::SYS_setreuid,  Family::Cred),
    (libc::SYS_setregid,  Family::Cred),
    (libc::SYS_setresuid, Family::Cred),
    (libc::SYS_setresgid, Family::Cred),
    (libc::SYS_setfsuid,  Family::Cred),
    (libc::SYS_setfsgid,  Family::Cred),
    (libc::SYS_setgroups, Family::Cred),
    (libc::SYS_capset,    Family::Cred),
    // inode lifecycle
    #[cfg(target_arch = "x86_64")] (libc::SYS_unlink, Family::Unlink),
    (libc::SYS_unlinkat, Family::Unlink),
    #[cfg(target_arch = "x86_64")] (libc::SYS_rmdir,    Family::Unlink),
    #[cfg(target_arch = "x86_64")] (libc::SYS_rename,   Family::Rename),
    #[cfg(target_arch = "x86_64")] (libc::SYS_renameat, Family::Rename),
    (libc::SYS_renameat2, Family::Rename),
    // xattr
    (libc::SYS_setxattr,     Family::Xattr),
    (libc::SYS_lsetxattr,    Family::Xattr),
    (libc::SYS_fsetxattr,    Family::Xattr),
    (libc::SYS_getxattr,     Family::Xattr),
    (libc::SYS_lgetxattr,    Family::Xattr),
    (libc::SYS_fgetxattr,    Family::Xattr),
    (libc::SYS_listxattr,    Family::Xattr),
    (libc::SYS_llistxattr,   Family::Xattr),
    (libc::SYS_flistxattr,   Family::Xattr),
    (libc::SYS_removexattr,  Family::Xattr),
    (libc::SYS_lremovexattr, Family::Xattr),
    (libc::SYS_fremovexattr, Family::Xattr),
];

/// The syscalls to trap with seccomp `RET_TRACE`, derived from [`REGISTRY`].
pub(crate) fn trapped_syscalls() -> Vec<i64> {
    REGISTRY.iter().map(|&(nr, _)| nr).collect()
}

/// Map a syscall number to its handler family. A linear scan of [`REGISTRY`] —
/// tiny, and dwarfed by the ptrace stop that delivered us here.
fn classify(nr: i64) -> Option<Family> {
    REGISTRY.iter().find(|&&(n, _)| n == nr).map(|&(_, f)| f)
}

/// Inspect a trapped syscall at its entry (seccomp) stop and decide what to do.
/// May record fake ownership in `table`.
pub fn handle_entry(pid: Pid, table: &mut OwnershipTable, regs: &Regs) -> Result<Disposition> {
    let nr = regs.syscall_no();
    let Some(family) = classify(nr) else {
        return Ok(Disposition::Passthrough);
    };
    match family {
        Family::Stat(kind, buf_arg) => Ok(Disposition::Step(ExitAction::PatchStat {
            kind,
            buf: regs.arg(buf_arg),
        })),
        Family::Cred => Ok(Disposition::Skip(ExitAction::ForceRet(0))),
        Family::CredRes => Ok(Disposition::Skip(ExitAction::WriteResId {
            ptrs: [regs.arg(0), regs.arg(1), regs.arg(2)],
        })),
        Family::Chown => handle_chown(pid, table, nr, regs),
        Family::Chmod => handle_chmod(pid, table, nr, regs),
        Family::Mknod => handle_mknod(pid, table, nr, regs),
        Family::Xattr => handle_xattr(pid, table, nr, regs),
        Family::Unlink => handle_unlink(pid, nr, regs),
        Family::Rename => handle_rename(pid, nr, regs),
    }
}

/// unlink/rmdir/unlinkat — let the real removal happen, then (at exit) drop the
/// table entry if the inode's last link is gone.
fn handle_unlink(pid: Pid, nr: i64, regs: &Regs) -> Result<Disposition> {
    #[cfg(target_arch = "x86_64")]
    if nr == libc::SYS_unlink || nr == libc::SYS_rmdir {
        let p = read_path(pid, regs.arg(0))?;
        return Ok(unlink_commit(pid, AT_FDCWD, &p));
    }
    if nr == libc::SYS_unlinkat {
        let dirfd = regs.arg(0) as i32;
        let p = read_path(pid, regs.arg(1))?;
        return Ok(unlink_commit(pid, dirfd, &p));
    }
    Ok(Disposition::Passthrough)
}

fn unlink_commit(pid: Pid, dirfd: i32, path: &Path) -> Disposition {
    // lstat: we're removing this directory entry, not following a final symlink.
    match path::stat_target(pid, dirfd, path, true, false) {
        Ok(rs) => Disposition::Step(ExitAction::UnlinkCommit {
            dev: rs.dev,
            ino: rs.ino,
            nlink_before: rs.nlink,
        }),
        // Doesn't exist (or unreadable): the real syscall will deal with it.
        Err(_) => Disposition::Passthrough,
    }
}

/// rename/renameat/renameat2 — if the destination already exists it will be
/// overwritten, so schedule a table cleanup for the clobbered inode.
fn handle_rename(pid: Pid, nr: i64, regs: &Regs) -> Result<Disposition> {
    let Some((newdirfd, new_arg, flags)) = rename_dest(nr, regs) else {
        return Ok(Disposition::Passthrough);
    };
    // RENAME_EXCHANGE swaps both names; nothing is removed.
    if flags & libc::RENAME_EXCHANGE as i32 != 0 {
        return Ok(Disposition::Passthrough);
    }
    let newp = read_path(pid, regs.arg(new_arg))?;
    Ok(unlink_commit(pid, newdirfd, &newp))
}

/// The `(dest dirfd, dest path arg index, flags)` of a rename-family syscall.
fn rename_dest(nr: i64, regs: &Regs) -> Option<(i32, usize, i32)> {
    #[cfg(target_arch = "x86_64")]
    {
        if nr == libc::SYS_rename {
            return Some((AT_FDCWD, 1, 0));
        }
        if nr == libc::SYS_renameat {
            return Some((regs.arg(2) as i32, 3, 0));
        }
    }
    if nr == libc::SYS_renameat2 {
        return Some((regs.arg(2) as i32, 3, regs.arg(4) as i32));
    }
    None
}

fn read_path(pid: Pid, addr: u64) -> Result<PathBuf> {
    Ok(PathBuf::from(OsString::from_vec(mem::read_cstring(
        pid, addr,
    )?)))
}

/// Record the requested ownership against the resolved inode. New entries seed
/// from the fake-current owner (root, `0:0`), so a partial chown (`-1` for one id)
/// keeps the *fake* current value — matching fakeroot's "unknown is root" model.
fn record_chown(table: &mut OwnershipTable, rs: &path::RealStat, uid: u32, gid: u32) {
    let node = table.entry(rs.dev, rs.ino);
    if uid != ID_UNCHANGED {
        node.uid = uid;
    }
    if gid != ID_UNCHANGED {
        node.gid = gid;
    }
}

/// chown/lchown/fchown/fchownat — record the fake owner, skip the real call.
fn handle_chown(pid: Pid, table: &mut OwnershipTable, nr: i64, regs: &Regs) -> Result<Disposition> {
    let Some((rs, uid, gid)) = chown_target(pid, nr, regs)? else {
        return Ok(Disposition::Passthrough);
    };
    record_chown(table, &rs, uid, gid);
    Ok(Disposition::Skip(ExitAction::ForceRet(0)))
}

/// Resolve a chown-family syscall to `(target inode, uid, gid)`.
fn chown_target(pid: Pid, nr: i64, regs: &Regs) -> Result<Option<(path::RealStat, u32, u32)>> {
    #[cfg(target_arch = "x86_64")]
    if nr == libc::SYS_chown || nr == libc::SYS_lchown {
        let path = read_path(pid, regs.arg(0))?;
        let rs = path::stat_target(pid, AT_FDCWD, &path, nr == libc::SYS_lchown, false)?;
        return Ok(Some((rs, regs.arg(1) as u32, regs.arg(2) as u32)));
    }
    if nr == libc::SYS_fchown {
        let rs = path::stat_target(pid, regs.arg(0) as i32, Path::new(""), false, true)?;
        return Ok(Some((rs, regs.arg(1) as u32, regs.arg(2) as u32)));
    }
    if nr == libc::SYS_fchownat {
        let path = read_path(pid, regs.arg(1))?;
        let flags = regs.arg(4) as i32;
        let nofollow = flags & libc::AT_SYMLINK_NOFOLLOW != 0;
        let empty = flags & libc::AT_EMPTY_PATH != 0;
        let rs = path::stat_target(pid, regs.arg(0) as i32, &path, nofollow, empty)?;
        return Ok(Some((rs, regs.arg(2) as u32, regs.arg(3) as u32)));
    }
    Ok(None)
}

/// chmod/fchmod/fchmodat — record the fake mode but let the real call run so the
/// on-disk permission bits update when the user is allowed to set them.
fn handle_chmod(pid: Pid, table: &mut OwnershipTable, nr: i64, regs: &Regs) -> Result<Disposition> {
    let Some((rs, req_mode)) = chmod_target(pid, nr, regs)? else {
        return Ok(Disposition::Passthrough);
    };
    record_chmod(table, &rs, req_mode);
    Ok(Disposition::Step(ExitAction::ZeroOnErr))
}

/// Resolve a chmod-family syscall to `(target inode, requested mode)`.
fn chmod_target(pid: Pid, nr: i64, regs: &Regs) -> Result<Option<(path::RealStat, u32)>> {
    #[cfg(target_arch = "x86_64")]
    if nr == libc::SYS_chmod {
        let path = read_path(pid, regs.arg(0))?;
        let rs = path::stat_target(pid, AT_FDCWD, &path, false, false)?;
        return Ok(Some((rs, regs.arg(1) as u32)));
    }
    if nr == libc::SYS_fchmod {
        let rs = path::stat_target(pid, regs.arg(0) as i32, Path::new(""), false, true)?;
        return Ok(Some((rs, regs.arg(1) as u32)));
    }
    if nr == libc::SYS_fchmodat {
        let path = read_path(pid, regs.arg(1))?;
        let nofollow = regs.arg(3) as i32 & libc::AT_SYMLINK_NOFOLLOW != 0;
        let rs = path::stat_target(pid, regs.arg(0) as i32, &path, nofollow, false)?;
        return Ok(Some((rs, regs.arg(2) as u32)));
    }
    Ok(None)
}

fn record_chmod(table: &mut OwnershipTable, rs: &path::RealStat, req_mode: u32) {
    let mode = compose_mode(rs.mode, req_mode);
    table.entry(rs.dev, rs.ino).mode = Some(mode);
}

/// mknod/mknodat — we can't create real device nodes unprivileged, so drop a
/// regular placeholder file and record the intended type + rdev so `stat` reports
/// a device node (and archivers store one).
fn handle_mknod(pid: Pid, table: &mut OwnershipTable, nr: i64, regs: &Regs) -> Result<Disposition> {
    #[cfg(target_arch = "x86_64")]
    if nr == libc::SYS_mknod {
        let p = read_path(pid, regs.arg(0))?;
        let resolved = path::resolve_path(pid, AT_FDCWD, &p, false);
        return finish_mknod(table, &resolved, regs.arg(1) as u32, regs.arg(2));
    }
    if nr == libc::SYS_mknodat {
        let dirfd = regs.arg(0) as i32;
        let p = read_path(pid, regs.arg(1))?;
        let resolved = path::resolve_path(pid, dirfd, &p, false);
        return finish_mknod(table, &resolved, regs.arg(2) as u32, regs.arg(3));
    }
    Ok(Disposition::Passthrough)
}

fn finish_mknod(
    table: &mut OwnershipTable,
    resolved: &Path,
    mode: u32,
    dev: u64,
) -> Result<Disposition> {
    use std::os::unix::fs::OpenOptionsExt;
    // Create the placeholder as a normal file (best-effort; ignore EEXIST).
    let _ = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o644)
        .open(resolved);
    let st = nix::sys::stat::stat(resolved)?;
    let node = table.entry(st.st_dev as u64, st.st_ino as u64);
    // A node created while we pretend to be root is root-owned.
    node.uid = 0;
    node.gid = 0;
    node.mode = Some(mode);
    let kind = mode & libc::S_IFMT;
    if kind == libc::S_IFCHR || kind == libc::S_IFBLK {
        node.rdev = Some(dev);
    }
    Ok(Disposition::Skip(ExitAction::ForceRet(0)))
}

fn is_xattr_f_variant(nr: i64) -> bool {
    nr == libc::SYS_fsetxattr
        || nr == libc::SYS_fgetxattr
        || nr == libc::SYS_flistxattr
        || nr == libc::SYS_fremovexattr
}

fn is_xattr_l_variant(nr: i64) -> bool {
    nr == libc::SYS_lsetxattr
        || nr == libc::SYS_lgetxattr
        || nr == libc::SYS_llistxattr
        || nr == libc::SYS_lremovexattr
}

/// Resolve the target inode of an xattr syscall (target is arg0: a path or fd).
fn xattr_target(pid: Pid, nr: i64, regs: &Regs) -> Result<path::RealStat> {
    if is_xattr_f_variant(nr) {
        path::stat_target(pid, regs.arg(0) as i32, Path::new(""), false, true)
    } else {
        let p = read_path(pid, regs.arg(0))?;
        path::stat_target(pid, AT_FDCWD, &p, is_xattr_l_variant(nr), false)
    }
}

/// Fake xattrs in the table. Crucial for `security.capability` and POSIX ACLs,
/// which a non-root process can't really set but packagers need archived.
fn handle_xattr(pid: Pid, table: &mut OwnershipTable, nr: i64, regs: &Regs) -> Result<Disposition> {
    const MAX_XATTR: usize = 64 * 1024;

    // set*xattr(target, name, value, size, flags)
    if nr == libc::SYS_setxattr || nr == libc::SYS_lsetxattr || nr == libc::SYS_fsetxattr {
        let rs = xattr_target(pid, nr, regs)?;
        let name = CString::new(mem::read_cstring(pid, regs.arg(1))?).unwrap_or_default();
        let size = (regs.arg(3) as usize).min(MAX_XATTR);
        let mut value = vec![0u8; size];
        if size > 0 {
            mem::read(pid, regs.arg(2), &mut value)?;
        }
        table.entry(rs.dev, rs.ino).xattrs.insert(name, value);
        return Ok(Disposition::Skip(ExitAction::ForceRet(0)));
    }

    // get*xattr(target, name, value, size)
    if nr == libc::SYS_getxattr || nr == libc::SYS_lgetxattr || nr == libc::SYS_fgetxattr {
        let rs = xattr_target(pid, nr, regs)?;
        let name = CString::new(mem::read_cstring(pid, regs.arg(1))?).unwrap_or_default();
        if let Some(value) = table.get(rs.dev, rs.ino).and_then(|n| n.xattrs.get(&name)) {
            return Ok(Disposition::Skip(ExitAction::ReturnXattr {
                buf: regs.arg(2),
                size: regs.arg(3),
                value: value.clone(),
            }));
        }
        // Not faked — let the real xattr (e.g. user.*) through.
        return Ok(Disposition::Passthrough);
    }

    // list*xattr(target, list, size)
    if nr == libc::SYS_listxattr || nr == libc::SYS_llistxattr || nr == libc::SYS_flistxattr {
        let rs = xattr_target(pid, nr, regs)?;
        let extra: Vec<Vec<u8>> = table
            .get(rs.dev, rs.ino)
            .map(|n| n.xattrs.keys().map(|k| k.as_bytes().to_vec()).collect())
            .unwrap_or_default();
        if extra.is_empty() {
            return Ok(Disposition::Passthrough);
        }
        return Ok(Disposition::Step(ExitAction::MergeXattrList {
            buf: regs.arg(1),
            size: regs.arg(2),
            extra,
        }));
    }

    // remove*xattr(target, name)
    if nr == libc::SYS_removexattr || nr == libc::SYS_lremovexattr || nr == libc::SYS_fremovexattr {
        let rs = xattr_target(pid, nr, regs)?;
        let name = CString::new(mem::read_cstring(pid, regs.arg(1))?).unwrap_or_default();
        table.entry(rs.dev, rs.ino).xattrs.remove(&name);
        return Ok(Disposition::Skip(ExitAction::ForceRet(0)));
    }

    Ok(Disposition::Passthrough)
}

/// Apply an [`ExitAction`] at a syscall-exit stop.
pub fn apply_exit_action(
    pid: Pid,
    table: &mut OwnershipTable,
    action: ExitAction,
    regs: &mut Regs,
) -> Result<()> {
    match action {
        ExitAction::PatchStat { kind, buf } => {
            if regs.ret() == 0 {
                patch_stat_result(pid, table, kind, buf)?;
            }
        }
        ExitAction::ForceRet(v) => {
            regs.set_ret(v);
            regs.store(pid)?;
        }
        ExitAction::ZeroOnErr => {
            if regs.ret() < 0 {
                regs.set_ret(0);
                regs.store(pid)?;
            }
        }
        ExitAction::WriteResId { ptrs } => {
            for p in ptrs {
                if p != 0 {
                    mem::write_struct(pid, p, &0u32)?;
                }
            }
            regs.set_ret(0);
            regs.store(pid)?;
        }
        ExitAction::ReturnXattr { buf, size, value } => {
            let ret = if size == 0 {
                value.len() as i64
            } else if value.len() as u64 <= size {
                mem::write(pid, buf, &value)?;
                value.len() as i64
            } else {
                -(libc::ERANGE as i64)
            };
            regs.set_ret(ret);
            regs.store(pid)?;
        }
        ExitAction::MergeXattrList { buf, size, extra } => {
            // Start from the real names the kernel returned (if any).
            let mut names: Vec<Vec<u8>> = Vec::new();
            let real_ret = regs.ret();
            if real_ret > 0 {
                let mut b = vec![0u8; real_ret as usize];
                mem::read(pid, buf, &mut b)?;
                for n in b.split(|&c| c == 0) {
                    if !n.is_empty() {
                        names.push(n.to_vec());
                    }
                }
            }
            for e in extra {
                if !names.contains(&e) {
                    names.push(e);
                }
            }
            let mut blob = Vec::new();
            for n in &names {
                blob.extend_from_slice(n);
                blob.push(0);
            }
            let ret = if size == 0 {
                blob.len() as i64
            } else if blob.len() as u64 <= size {
                mem::write(pid, buf, &blob)?;
                blob.len() as i64
            } else {
                -(libc::ERANGE as i64)
            };
            regs.set_ret(ret);
            regs.store(pid)?;
        }
        ExitAction::UnlinkCommit {
            dev,
            ino,
            nlink_before,
        } => {
            // Only drop the entry once the inode is truly gone (last link removed
            // / directory removed). Hardlinked files keep their fake ownership.
            if regs.ret() == 0 && nlink_before <= 1 {
                table.remove(dev, ino);
            }
        }
    }
    Ok(())
}

/// Which flavor of stat buffer a syscall fills.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatKind {
    /// Kernel `struct stat` (stat/lstat/fstat/newfstatat).
    Native,
    /// `struct statx`.
    Statx,
}

/// At a stat-family syscall-exit (return value already 0), read the result buffer,
/// and if we have a faked entry for that inode, overlay it and write it back.
pub fn patch_stat_result(pid: Pid, table: &OwnershipTable, kind: StatKind, buf: u64) -> Result<()> {
    // Default fakeroot semantics ("unknown is root"): every untracked file is
    // reported as owned by root, with its real mode/rdev/nlink preserved. Tracked
    // inodes use their stored values. So we always overlay. (`HashMap::new()` in the
    // default doesn't allocate, so this is cheap enough for the hot exit path.)
    let default = FakeNode::default();
    match kind {
        StatKind::Native => {
            let mut st: libc::stat = mem::read_struct(pid, buf)?;
            let node = table
                .get(st.st_dev as u64, st.st_ino as u64)
                .unwrap_or(&default);
            patch_native(&mut st, node);
            mem::write_struct(pid, buf, &st)?;
        }
        StatKind::Statx => {
            let mut stx: libc::statx = mem::read_struct(pid, buf)?;
            let dev = libc::makedev(stx.stx_dev_major, stx.stx_dev_minor) as u64;
            let node = table.get(dev, stx.stx_ino).unwrap_or(&default);
            patch_statx(&mut stx, node);
            mem::write_struct(pid, buf, &stx)?;
        }
    }
    Ok(())
}

/// Overlay faked fields onto a kernel `struct stat`.
pub fn patch_native(st: &mut libc::stat, node: &FakeNode) {
    st.st_uid = node.uid;
    st.st_gid = node.gid;
    if let Some(mode) = node.mode {
        st.st_mode = mode;
    }
    if let Some(rdev) = node.rdev {
        st.st_rdev = rdev as _;
    }
    if let Some(nlink) = node.nlink {
        st.st_nlink = nlink as _;
    }
}

/// Overlay faked fields onto a `struct statx`, setting the corresponding mask bits
/// so the caller trusts them.
pub fn patch_statx(stx: &mut libc::statx, node: &FakeNode) {
    stx.stx_uid = node.uid;
    stx.stx_gid = node.gid;
    stx.stx_mask |= libc::STATX_UID | libc::STATX_GID;
    if let Some(mode) = node.mode {
        stx.stx_mode = mode as u16;
        stx.stx_mask |= libc::STATX_MODE | libc::STATX_TYPE;
    }
    if let Some(rdev) = node.rdev {
        stx.stx_rdev_major = libc::major(rdev as _);
        stx.stx_rdev_minor = libc::minor(rdev as _);
    }
    if let Some(nlink) = node.nlink {
        stx.stx_nlink = nlink as u32;
        stx.stx_mask |= libc::STATX_NLINK;
    }
}

/// Compose a full mode value: keep the real type bits, override the permission
/// bits. Used by chmod/mknod handlers when recording a fake mode.
pub fn compose_mode(real_mode: u32, requested_perms: u32) -> u32 {
    (real_mode & !ALLPERMS) | (requested_perms & ALLPERMS)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zeroed_stat() -> libc::stat {
        unsafe { std::mem::zeroed() }
    }
    fn zeroed_statx() -> libc::statx {
        unsafe { std::mem::zeroed() }
    }

    #[test]
    fn native_overlays_uid_gid_only_by_default() {
        let mut st = zeroed_stat();
        st.st_uid = 1000;
        st.st_gid = 1000;
        st.st_mode = 0o100_644; // regular file, rw-r--r--
        let node = FakeNode {
            uid: 0,
            gid: 0,
            ..Default::default()
        };
        patch_native(&mut st, &node);
        assert_eq!(st.st_uid, 0);
        assert_eq!(st.st_gid, 0);
        assert_eq!(
            st.st_mode, 0o100_644,
            "mode unchanged when node.mode is None"
        );
    }

    #[test]
    fn native_overlays_mode_and_rdev_when_set() {
        let mut st = zeroed_stat();
        let node = FakeNode {
            uid: 200,
            gid: 200,
            mode: Some(libc::S_IFCHR | 0o600),
            rdev: Some(libc::makedev(1, 3) as u64), // /dev/null
            ..Default::default()
        };
        patch_native(&mut st, &node);
        assert_eq!(st.st_uid, 200);
        assert_eq!(st.st_mode, libc::S_IFCHR | 0o600);
        assert_eq!(st.st_rdev as u64, libc::makedev(1, 3) as u64);
    }

    #[test]
    fn statx_sets_mask_bits() {
        let mut stx = zeroed_statx();
        stx.stx_uid = 1000;
        stx.stx_gid = 1000;
        let node = FakeNode {
            uid: 200,
            gid: 200,
            ..Default::default()
        };
        patch_statx(&mut stx, &node);
        assert_eq!(stx.stx_uid, 200);
        assert_eq!(stx.stx_gid, 200);
        assert!(stx.stx_mask & libc::STATX_UID != 0);
        assert!(stx.stx_mask & libc::STATX_GID != 0);
    }

    #[test]
    fn compose_mode_keeps_type_overrides_perms() {
        // regular file 0644 -> chmod 4755 keeps S_IFREG, sets rwsr-xr-x
        let real = libc::S_IFREG | 0o644;
        assert_eq!(compose_mode(real, 0o4755), libc::S_IFREG | 0o4755);
    }

    #[test]
    fn stat_uid_gid_offsets_are_distinct_and_sane() {
        // offset_of! derives the right per-arch offsets from libc's verified structs.
        let uid = std::mem::offset_of!(libc::stat, st_uid);
        let gid = std::mem::offset_of!(libc::stat, st_gid);
        assert_ne!(uid, gid);
        assert!(std::mem::offset_of!(libc::statx, stx_uid) < std::mem::size_of::<libc::statx>());
    }

    #[test]
    fn registry_classifies_known_syscalls() {
        assert_eq!(
            classify(libc::SYS_statx),
            Some(Family::Stat(StatKind::Statx, 4))
        );
        assert_eq!(
            classify(libc::SYS_newfstatat),
            Some(Family::Stat(StatKind::Native, 2))
        );
        assert_eq!(classify(libc::SYS_fchown), Some(Family::Chown));
        assert_eq!(classify(libc::SYS_capset), Some(Family::Cred));
        assert_eq!(classify(libc::SYS_getpid), None);
    }

    #[test]
    fn registry_has_no_duplicate_syscalls() {
        let nums = trapped_syscalls();
        let mut sorted = nums.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), nums.len(), "REGISTRY has duplicate syscalls");
    }
}
