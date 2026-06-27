//! Architecture-specific register access for a stopped tracee.
//!
//! Everything else in the crate is arch-independent: syscall *numbers* come from
//! `libc::SYS_*` (cfg-gated to the build target, and the tracer always runs on the
//! same arch as the tracee), and struct field *offsets* come from
//! `offset_of!(libc::statx, …)`. The only genuinely per-arch code is reading and
//! writing the register file at a ptrace stop — that lives here.
//!
//! Supported architectures: `x86_64` (amd64), `aarch64` (arm64), and `riscv64`.

use crate::error::Result;
use nix::unistd::Pid;

#[cfg(target_arch = "x86_64")]
#[path = "x86_64.rs"]
mod imp;
#[cfg(target_arch = "aarch64")]
#[path = "aarch64.rs"]
mod imp;
#[cfg(target_arch = "riscv64")]
#[path = "riscv64.rs"]
mod imp;

#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "riscv64"
)))]
compile_error!("fakeroost supports only x86_64 (amd64), aarch64 (arm64), and riscv64");

pub use imp::Regs;

/// The register file of a stopped tracee, abstracted across architectures.
///
/// Argument and return-value accessors follow the Linux syscall ABI of the
/// current arch. `syscall_no`/`arg` are meaningful at a syscall-entry (seccomp)
/// stop; `ret` is meaningful at a syscall-exit stop.
pub trait RegAccess: Sized {
    /// Read the register file of a stopped tracee.
    fn fetch(pid: Pid) -> Result<Self>;

    /// Write the (possibly modified) register file back to the tracee.
    fn store(&self, pid: Pid) -> Result<()>;

    /// The syscall number being invoked (entry stop).
    fn syscall_no(&self) -> i64;

    /// Syscall argument `i`, where `i` is in `0..=5`.
    fn arg(&self, i: usize) -> u64;

    /// The syscall return value (exit stop).
    fn ret(&self) -> i64;

    /// Replace the syscall number. Setting it to `-1` makes the kernel skip the
    /// real syscall (it returns `-ENOSYS`, which we then overwrite via `set_ret`).
    fn set_syscall_no(&mut self, no: i64);

    /// Replace the return value (apply at the exit stop, then `store`).
    fn set_ret(&mut self, val: i64);
}
