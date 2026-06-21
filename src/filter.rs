//! Builds the seccomp-BPF filter that narrows ptrace to just the syscalls we care
//! about. Everything not in the trap set runs at full speed (`RET_ALLOW`); the
//! trapped syscalls return `RET_TRACE`, delivering a `PTRACE_EVENT_SECCOMP` to the
//! supervisor. This is what makes the tool cheap *and* able to install itself with
//! no privileges under Docker's default seccomp (only `prctl` is needed).

use crate::error::{Error, Result};
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter};
use std::collections::BTreeMap;

#[cfg(target_arch = "x86_64")]
fn target_arch() -> seccompiler::TargetArch {
    seccompiler::TargetArch::x86_64
}
#[cfg(target_arch = "aarch64")]
fn target_arch() -> seccompiler::TargetArch {
    seccompiler::TargetArch::aarch64
}

/// The syscalls we trap. Built from `libc::SYS_*`, which the `libc` crate already
/// cfg-gates to the build target — and since the tracer runs on the same arch as
/// the tracee, these are exactly the right numbers. Per-arch lists because the
/// legacy path-based calls (`stat`, `chown`, …) simply don't exist on aarch64.
#[cfg(target_arch = "x86_64")]
pub fn trapped_syscalls() -> Vec<i64> {
    vec![
        // stat family
        libc::SYS_stat,
        libc::SYS_lstat,
        libc::SYS_fstat,
        libc::SYS_newfstatat,
        libc::SYS_statx,
        // chown family
        libc::SYS_chown,
        libc::SYS_lchown,
        libc::SYS_fchown,
        libc::SYS_fchownat,
        // chmod family
        libc::SYS_chmod,
        libc::SYS_fchmod,
        libc::SYS_fchmodat,
        // mknod
        libc::SYS_mknod,
        libc::SYS_mknodat,
        // credentials (read)
        libc::SYS_getuid,
        libc::SYS_geteuid,
        libc::SYS_getgid,
        libc::SYS_getegid,
        libc::SYS_getresuid,
        libc::SYS_getresgid,
        // credentials (set) — faked to succeed
        libc::SYS_setuid,
        libc::SYS_setgid,
        libc::SYS_setreuid,
        libc::SYS_setregid,
        libc::SYS_setresuid,
        libc::SYS_setresgid,
        libc::SYS_setfsuid,
        libc::SYS_setfsgid,
        libc::SYS_setgroups,
        libc::SYS_capset,
        // inode lifecycle
        libc::SYS_unlink,
        libc::SYS_unlinkat,
        libc::SYS_rmdir,
        libc::SYS_rename,
        libc::SYS_renameat,
        libc::SYS_renameat2,
        libc::SYS_link,
        libc::SYS_linkat,
        // xattr
        libc::SYS_setxattr,
        libc::SYS_lsetxattr,
        libc::SYS_fsetxattr,
        libc::SYS_getxattr,
        libc::SYS_lgetxattr,
        libc::SYS_fgetxattr,
        libc::SYS_listxattr,
        libc::SYS_llistxattr,
        libc::SYS_flistxattr,
        libc::SYS_removexattr,
        libc::SYS_lremovexattr,
        libc::SYS_fremovexattr,
    ]
}

#[cfg(target_arch = "aarch64")]
pub fn trapped_syscalls() -> Vec<i64> {
    vec![
        // aarch64 has no stat/lstat/chown/lchown/chmod/mknod/unlink/rename/link —
        // only the *at variants and statx. Filled in / verified in M6.
        libc::SYS_fstat,
        libc::SYS_newfstatat,
        libc::SYS_statx,
        libc::SYS_fchown,
        libc::SYS_fchownat,
        libc::SYS_fchmod,
        libc::SYS_fchmodat,
        libc::SYS_mknodat,
        libc::SYS_getuid,
        libc::SYS_geteuid,
        libc::SYS_getgid,
        libc::SYS_getegid,
        libc::SYS_getresuid,
        libc::SYS_getresgid,
        libc::SYS_setuid,
        libc::SYS_setgid,
        libc::SYS_setreuid,
        libc::SYS_setregid,
        libc::SYS_setresuid,
        libc::SYS_setresgid,
        libc::SYS_setfsuid,
        libc::SYS_setfsgid,
        libc::SYS_setgroups,
        libc::SYS_capset,
        libc::SYS_unlinkat,
        // aarch64 has only renameat2 (no rename/renameat) and no rmdir.
        libc::SYS_renameat2,
        libc::SYS_linkat,
        libc::SYS_setxattr,
        libc::SYS_lsetxattr,
        libc::SYS_fsetxattr,
        libc::SYS_getxattr,
        libc::SYS_lgetxattr,
        libc::SYS_fgetxattr,
        libc::SYS_listxattr,
        libc::SYS_llistxattr,
        libc::SYS_flistxattr,
        libc::SYS_removexattr,
        libc::SYS_lremovexattr,
        libc::SYS_fremovexattr,
    ]
}

/// Compile the seccomp filter that traps [`trapped_syscalls`] with `RET_TRACE`
/// and lets everything else through.
pub fn build() -> Result<BpfProgram> {
    let rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = trapped_syscalls()
        .into_iter()
        .map(|nr| (nr, vec![]))
        .collect();

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,    // default: run the syscall normally
        SeccompAction::Trace(0), // trapped: notify the ptracer
        target_arch(),
    )
    .map_err(|e| Error::Other(format!("building seccomp filter: {e}")))?;

    let bpf: BpfProgram = filter
        .try_into()
        .map_err(|e| Error::Other(format!("compiling seccomp filter: {e}")))?;
    Ok(bpf)
}

/// Install the compiled filter on the current process. Sets `NO_NEW_PRIVS` first
/// (required to install a filter without privileges). Must run in the child after
/// `fork` and before `execve`.
///
/// # Safety
/// Async-signal-context after `fork`: this only performs `prctl`/`seccomp`, which
/// is sound here.
pub fn install(bpf: &BpfProgram) -> Result<()> {
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        return Err(nix::errno::Errno::last().into());
    }
    seccompiler::apply_filter(bpf).map_err(|e| Error::Other(format!("applying seccomp: {e}")))?;
    Ok(())
}
