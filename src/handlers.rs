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

/// Inspect a trapped syscall at its entry (seccomp) stop and decide what to do.
/// May record fake ownership in `table`.
pub fn handle_entry(pid: Pid, table: &mut OwnershipTable, regs: &Regs) -> Result<Disposition> {
    let nr = regs.syscall_no();

    if let Some((kind, buf_arg)) = classify_stat(nr) {
        return Ok(Disposition::Step(ExitAction::PatchStat {
            kind,
            buf: regs.arg(buf_arg),
        }));
    }
    if let Some(d) = handle_creds(nr, regs) {
        return Ok(d);
    }
    if let Some(d) = handle_chown(pid, table, nr, regs)? {
        return Ok(d);
    }
    if let Some(d) = handle_chmod(pid, table, nr, regs)? {
        return Ok(d);
    }
    if let Some(d) = handle_mknod(pid, table, nr, regs)? {
        return Ok(d);
    }
    if let Some(d) = handle_xattr(pid, table, nr, regs)? {
        return Ok(d);
    }
    if let Some(d) = handle_unlink(pid, nr, regs)? {
        return Ok(d);
    }
    if let Some(d) = handle_rename(pid, nr, regs)? {
        return Ok(d);
    }
    Ok(Disposition::Passthrough)
}

/// unlink/rmdir/unlinkat — let the real removal happen, then (at exit) drop the
/// table entry if the inode's last link is gone.
fn handle_unlink(pid: Pid, nr: i64, regs: &Regs) -> Result<Option<Disposition>> {
    #[cfg(target_arch = "x86_64")]
    {
        if nr == libc::SYS_unlink || nr == libc::SYS_rmdir {
            let p = read_path(pid, regs.arg(0))?;
            return Ok(Some(unlink_commit(pid, AT_FDCWD, &p)));
        }
    }
    if nr == libc::SYS_unlinkat {
        let dirfd = regs.arg(0) as i32;
        let p = read_path(pid, regs.arg(1))?;
        return Ok(Some(unlink_commit(pid, dirfd, &p)));
    }
    Ok(None)
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
fn handle_rename(pid: Pid, nr: i64, regs: &Regs) -> Result<Option<Disposition>> {
    let newdirfd;
    let new_arg;
    let flags;

    #[cfg(target_arch = "x86_64")]
    {
        if nr == libc::SYS_rename {
            newdirfd = AT_FDCWD;
            new_arg = 1usize;
            flags = 0i32;
        } else if nr == libc::SYS_renameat {
            newdirfd = regs.arg(2) as i32;
            new_arg = 3;
            flags = 0;
        } else if nr == libc::SYS_renameat2 {
            newdirfd = regs.arg(2) as i32;
            new_arg = 3;
            flags = regs.arg(4) as i32;
        } else {
            return Ok(None);
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        if nr == libc::SYS_renameat2 {
            newdirfd = regs.arg(2) as i32;
            new_arg = 3;
            flags = regs.arg(4) as i32;
        } else {
            return Ok(None);
        }
    }

    // RENAME_EXCHANGE swaps both names; nothing is removed.
    if flags & libc::RENAME_EXCHANGE as i32 != 0 {
        return Ok(Some(Disposition::Passthrough));
    }
    let newp = read_path(pid, regs.arg(new_arg))?;
    Ok(Some(unlink_commit(pid, newdirfd, &newp)))
}

/// Fake credential syscalls so the tracee believes it is root.
fn handle_creds(nr: i64, regs: &Regs) -> Option<Disposition> {
    // These all exist on both x86_64 and aarch64.
    match nr {
        n if n == libc::SYS_getuid
            || n == libc::SYS_geteuid
            || n == libc::SYS_getgid
            || n == libc::SYS_getegid =>
        {
            Some(Disposition::Skip(ExitAction::ForceRet(0)))
        }
        n if n == libc::SYS_getresuid || n == libc::SYS_getresgid => {
            Some(Disposition::Skip(ExitAction::WriteResId {
                ptrs: [regs.arg(0), regs.arg(1), regs.arg(2)],
            }))
        }
        n if n == libc::SYS_setuid
            || n == libc::SYS_setgid
            || n == libc::SYS_setreuid
            || n == libc::SYS_setregid
            || n == libc::SYS_setresuid
            || n == libc::SYS_setresgid
            || n == libc::SYS_setfsuid
            || n == libc::SYS_setfsgid
            || n == libc::SYS_setgroups
            || n == libc::SYS_capset =>
        {
            Some(Disposition::Skip(ExitAction::ForceRet(0)))
        }
        _ => None,
    }
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
fn handle_chown(
    pid: Pid,
    table: &mut OwnershipTable,
    nr: i64,
    regs: &Regs,
) -> Result<Option<Disposition>> {
    let rs;
    let (uid, gid);

    #[cfg(target_arch = "x86_64")]
    {
        if nr == libc::SYS_chown || nr == libc::SYS_lchown {
            let path = read_path(pid, regs.arg(0))?;
            let nofollow = nr == libc::SYS_lchown;
            rs = path::stat_target(pid, AT_FDCWD, &path, nofollow, false)?;
            uid = regs.arg(1) as u32;
            gid = regs.arg(2) as u32;
            record_chown(table, &rs, uid, gid);
            return Ok(Some(Disposition::Skip(ExitAction::ForceRet(0))));
        }
    }

    if nr == libc::SYS_fchown {
        let fd = regs.arg(0) as i32;
        rs = path::stat_target(pid, fd, std::path::Path::new(""), false, true)?;
        uid = regs.arg(1) as u32;
        gid = regs.arg(2) as u32;
        record_chown(table, &rs, uid, gid);
        return Ok(Some(Disposition::Skip(ExitAction::ForceRet(0))));
    }
    if nr == libc::SYS_fchownat {
        let dirfd = regs.arg(0) as i32;
        let path = read_path(pid, regs.arg(1))?;
        let flags = regs.arg(4) as i32;
        let nofollow = flags & libc::AT_SYMLINK_NOFOLLOW != 0;
        let empty = flags & libc::AT_EMPTY_PATH != 0;
        rs = path::stat_target(pid, dirfd, &path, nofollow, empty)?;
        uid = regs.arg(2) as u32;
        gid = regs.arg(3) as u32;
        record_chown(table, &rs, uid, gid);
        return Ok(Some(Disposition::Skip(ExitAction::ForceRet(0))));
    }
    Ok(None)
}

/// chmod/fchmod/fchmodat — record the fake mode but let the real call run so the
/// on-disk permission bits update when the user is allowed to set them.
fn handle_chmod(
    pid: Pid,
    table: &mut OwnershipTable,
    nr: i64,
    regs: &Regs,
) -> Result<Option<Disposition>> {
    let rs;
    let req_mode;

    #[cfg(target_arch = "x86_64")]
    {
        if nr == libc::SYS_chmod {
            let path = read_path(pid, regs.arg(0))?;
            rs = path::stat_target(pid, AT_FDCWD, &path, false, false)?;
            req_mode = regs.arg(1) as u32;
            record_chmod(table, &rs, req_mode);
            return Ok(Some(Disposition::Step(ExitAction::ZeroOnErr)));
        }
    }

    if nr == libc::SYS_fchmod {
        let fd = regs.arg(0) as i32;
        rs = path::stat_target(pid, fd, std::path::Path::new(""), false, true)?;
        req_mode = regs.arg(1) as u32;
        record_chmod(table, &rs, req_mode);
        return Ok(Some(Disposition::Step(ExitAction::ZeroOnErr)));
    }
    if nr == libc::SYS_fchmodat {
        let dirfd = regs.arg(0) as i32;
        let path = read_path(pid, regs.arg(1))?;
        let flags = regs.arg(3) as i32;
        let nofollow = flags & libc::AT_SYMLINK_NOFOLLOW != 0;
        rs = path::stat_target(pid, dirfd, &path, nofollow, false)?;
        req_mode = regs.arg(2) as u32;
        record_chmod(table, &rs, req_mode);
        return Ok(Some(Disposition::Step(ExitAction::ZeroOnErr)));
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
fn handle_mknod(
    pid: Pid,
    table: &mut OwnershipTable,
    nr: i64,
    regs: &Regs,
) -> Result<Option<Disposition>> {
    #[cfg(target_arch = "x86_64")]
    {
        if nr == libc::SYS_mknod {
            let p = read_path(pid, regs.arg(0))?;
            let resolved = path::resolve_path(pid, AT_FDCWD, &p, false);
            return finish_mknod(table, &resolved, regs.arg(1) as u32, regs.arg(2));
        }
    }
    if nr == libc::SYS_mknodat {
        let dirfd = regs.arg(0) as i32;
        let p = read_path(pid, regs.arg(1))?;
        let resolved = path::resolve_path(pid, dirfd, &p, false);
        return finish_mknod(table, &resolved, regs.arg(2) as u32, regs.arg(3));
    }
    Ok(None)
}

fn finish_mknod(
    table: &mut OwnershipTable,
    resolved: &Path,
    mode: u32,
    dev: u64,
) -> Result<Option<Disposition>> {
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
    Ok(Some(Disposition::Skip(ExitAction::ForceRet(0))))
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
fn handle_xattr(
    pid: Pid,
    table: &mut OwnershipTable,
    nr: i64,
    regs: &Regs,
) -> Result<Option<Disposition>> {
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
        return Ok(Some(Disposition::Skip(ExitAction::ForceRet(0))));
    }

    // get*xattr(target, name, value, size)
    if nr == libc::SYS_getxattr || nr == libc::SYS_lgetxattr || nr == libc::SYS_fgetxattr {
        let rs = xattr_target(pid, nr, regs)?;
        let name = CString::new(mem::read_cstring(pid, regs.arg(1))?).unwrap_or_default();
        if let Some(value) = table.get(rs.dev, rs.ino).and_then(|n| n.xattrs.get(&name)) {
            return Ok(Some(Disposition::Skip(ExitAction::ReturnXattr {
                buf: regs.arg(2),
                size: regs.arg(3),
                value: value.clone(),
            })));
        }
        // Not faked — let the real xattr (e.g. user.*) through.
        return Ok(Some(Disposition::Passthrough));
    }

    // list*xattr(target, list, size)
    if nr == libc::SYS_listxattr || nr == libc::SYS_llistxattr || nr == libc::SYS_flistxattr {
        let rs = xattr_target(pid, nr, regs)?;
        let extra: Vec<Vec<u8>> = table
            .get(rs.dev, rs.ino)
            .map(|n| n.xattrs.keys().map(|k| k.as_bytes().to_vec()).collect())
            .unwrap_or_default();
        if extra.is_empty() {
            return Ok(Some(Disposition::Passthrough));
        }
        return Ok(Some(Disposition::Step(ExitAction::MergeXattrList {
            buf: regs.arg(1),
            size: regs.arg(2),
            extra,
        })));
    }

    // remove*xattr(target, name)
    if nr == libc::SYS_removexattr || nr == libc::SYS_lremovexattr || nr == libc::SYS_fremovexattr {
        let rs = xattr_target(pid, nr, regs)?;
        let name = CString::new(mem::read_cstring(pid, regs.arg(1))?).unwrap_or_default();
        table.entry(rs.dev, rs.ino).xattrs.remove(&name);
        return Ok(Some(Disposition::Skip(ExitAction::ForceRet(0))));
    }

    Ok(None)
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

/// If `nr` is a stat-family syscall, return `(kind, buffer_arg_index)`.
#[cfg(target_arch = "x86_64")]
pub fn classify_stat(nr: i64) -> Option<(StatKind, usize)> {
    match nr {
        n if n == libc::SYS_stat => Some((StatKind::Native, 1)),
        n if n == libc::SYS_lstat => Some((StatKind::Native, 1)),
        n if n == libc::SYS_fstat => Some((StatKind::Native, 1)),
        n if n == libc::SYS_newfstatat => Some((StatKind::Native, 2)),
        n if n == libc::SYS_statx => Some((StatKind::Statx, 4)),
        _ => None,
    }
}

#[cfg(target_arch = "aarch64")]
pub fn classify_stat(nr: i64) -> Option<(StatKind, usize)> {
    match nr {
        n if n == libc::SYS_fstat => Some((StatKind::Native, 1)),
        n if n == libc::SYS_newfstatat => Some((StatKind::Native, 2)),
        n if n == libc::SYS_statx => Some((StatKind::Statx, 4)),
        _ => None,
    }
}

/// At a stat-family syscall-exit (return value already 0), read the result buffer,
/// and if we have a faked entry for that inode, overlay it and write it back.
pub fn patch_stat_result(pid: Pid, table: &OwnershipTable, kind: StatKind, buf: u64) -> Result<()> {
    // Default fakeroot semantics ("unknown is root"): every untracked file is
    // reported as owned by root, with its real mode/rdev/nlink preserved. Tracked
    // inodes use their stored values. So we always overlay.
    let default = FakeNode::default();
    match kind {
        StatKind::Native => {
            let mut st: libc::stat = mem::read_struct(pid, buf)?;
            let (dev, ino) = native_key(&st);
            let node = table.get(dev, ino).unwrap_or(&default);
            patch_native(&mut st, node);
            mem::write_struct(pid, buf, &st)?;
        }
        StatKind::Statx => {
            let mut stx: libc::statx = mem::read_struct(pid, buf)?;
            let (dev, ino) = statx_key(&stx);
            let node = table.get(dev, ino).unwrap_or(&default);
            patch_statx(&mut stx, node);
            mem::write_struct(pid, buf, &stx)?;
        }
    }
    Ok(())
}

fn native_key(st: &libc::stat) -> (u64, u64) {
    (st.st_dev as u64, st.st_ino as u64)
}

fn statx_key(stx: &libc::statx) -> (u64, u64) {
    let dev = libc::makedev(stx.stx_dev_major, stx.stx_dev_minor);
    (dev as u64, stx.stx_ino)
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
    fn classify_known_stat_calls() {
        assert_eq!(classify_stat(libc::SYS_statx), Some((StatKind::Statx, 4)));
        assert_eq!(
            classify_stat(libc::SYS_newfstatat),
            Some((StatKind::Native, 2))
        );
        assert_eq!(classify_stat(libc::SYS_fstat), Some((StatKind::Native, 1)));
        assert_eq!(classify_stat(libc::SYS_getpid), None);
    }
}
