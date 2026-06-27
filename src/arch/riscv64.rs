//! riscv64 register access.
//!
//! syscall ABI: number in `a7`; args in `a0..a5`; return value in `a0`.
//! General registers are read/written via `PTRACE_GETREGSET`/`SETREGSET` with
//! `NT_PRSTATUS` (riscv64 has no `PTRACE_GETREGS`).
//!
//! Unlike aarch64, the syscall number CAN be changed by writing `a7` directly:
//! the return value lands in `a0`, so `a7` is never clobbered by the kernel,
//! and riscv64 uses the generic `syscall_set_nr` path which re-reads `a7` on
//! restart. No special regset is required.

use super::RegAccess;
use crate::error::Result;
use nix::sys::ptrace;
use nix::unistd::Pid;

pub struct Regs {
    inner: libc::user_regs_struct,
}

impl RegAccess for Regs {
    fn fetch(pid: Pid) -> Result<Self> {
        let inner = ptrace::getregset::<ptrace::regset::NT_PRSTATUS>(pid)?;
        Ok(Regs { inner })
    }

    fn store(&self, pid: Pid) -> Result<()> {
        ptrace::setregset::<ptrace::regset::NT_PRSTATUS>(pid, self.inner)?;
        Ok(())
    }

    fn syscall_no(&self) -> i64 {
        self.inner.a7 as i64
    }

    fn arg(&self, i: usize) -> u64 {
        match i {
            0 => self.inner.a0,
            1 => self.inner.a1,
            2 => self.inner.a2,
            3 => self.inner.a3,
            4 => self.inner.a4,
            5 => self.inner.a5,
            _ => panic!("riscv64 syscall arg index out of range: {i}"),
        }
    }

    fn ret(&self) -> i64 {
        self.inner.a0 as i64
    }

    fn set_syscall_no(&mut self, no: i64) {
        self.inner.a7 = no as u64;
    }

    fn set_ret(&mut self, val: i64) {
        self.inner.a0 = val as u64;
    }
}
