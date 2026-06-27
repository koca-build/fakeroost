//! Builds the seccomp-BPF filter that narrows ptrace to just the syscalls we care
//! about. Everything not in the trap set runs at full speed (`RET_ALLOW`); the
//! trapped syscalls return `RET_TRACE`, delivering a `PTRACE_EVENT_SECCOMP` to the
//! supervisor. This is what makes the tool cheap *and* able to install itself with
//! no privileges under Docker's default seccomp (only `prctl` is needed).

use crate::error::{Error, Result};
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter};
use std::collections::BTreeMap;

fn target_arch() -> seccompiler::TargetArch {
    #[cfg(target_arch = "x86_64")]
    {
        seccompiler::TargetArch::x86_64
    }
    #[cfg(target_arch = "aarch64")]
    {
        seccompiler::TargetArch::aarch64
    }
    #[cfg(target_arch = "riscv64")]
    {
        seccompiler::TargetArch::riscv64
    }
}

/// Compile the seccomp filter that traps the handlers' registry of syscalls with
/// `RET_TRACE` and lets everything else through. The trap set is derived from
/// [`crate::handlers::trapped_syscalls`], so the filter and the dispatcher can't
/// drift apart.
pub fn build() -> Result<BpfProgram> {
    let rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = crate::handlers::trapped_syscalls()
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
