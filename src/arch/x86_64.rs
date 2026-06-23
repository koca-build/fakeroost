//! x86_64 register access.
//!
//! syscall ABI: number in `orig_rax`; args in `rdi, rsi, rdx, r10, r8, r9`;
//! return value in `rax`. (Note: arg 3 is `r10`, not `rcx`, for syscalls.)

use super::RegAccess;
use crate::error::Result;
use nix::sys::ptrace;
use nix::unistd::Pid;

pub struct Regs {
    inner: libc::user_regs_struct,
}

impl RegAccess for Regs {
    fn fetch(pid: Pid) -> Result<Self> {
        Ok(Regs {
            inner: ptrace::getregs(pid)?,
        })
    }

    fn store(&self, pid: Pid) -> Result<()> {
        ptrace::setregs(pid, self.inner)?;
        Ok(())
    }

    fn syscall_no(&self) -> i64 {
        self.inner.orig_rax as i64
    }

    fn arg(&self, i: usize) -> u64 {
        match i {
            0 => self.inner.rdi,
            1 => self.inner.rsi,
            2 => self.inner.rdx,
            3 => self.inner.r10,
            4 => self.inner.r8,
            5 => self.inner.r9,
            _ => panic!("x86_64 syscall arg index out of range: {i}"),
        }
    }

    fn ret(&self) -> i64 {
        self.inner.rax as i64
    }

    fn set_syscall_no(&mut self, no: i64) {
        self.inner.orig_rax = no as u64;
    }

    fn set_ret(&mut self, val: i64) {
        self.inner.rax = val as u64;
    }
}
