//! aarch64 register access.
//!
//! syscall ABI: number in `x8`; args in `x0..x5`; return value in `x0`.
//! General registers are read/written via `PTRACE_GETREGSET`/`SETREGSET` with
//! `NT_PRSTATUS` (aarch64 has no `PTRACE_GETREGS`).
//!
//! Gotcha: on aarch64 the syscall number CANNOT be changed by writing `x8` in the
//! `NT_PRSTATUS` set after entry — it must be set via the `NT_ARM_SYSTEM_CALL`
//! regset. We stash the override and apply it in `store`.

use super::RegAccess;
use crate::error::Result;
use nix::sys::ptrace;
use nix::unistd::Pid;
use std::ffi::c_void;

const NT_ARM_SYSTEM_CALL: libc::c_int = 0x404;

pub struct Regs {
    inner: libc::user_regs_struct,
    /// Pending syscall-number override (applied via NT_ARM_SYSTEM_CALL on `store`).
    sysno_override: Option<i32>,
}

impl RegAccess for Regs {
    fn fetch(pid: Pid) -> Result<Self> {
        let inner = ptrace::getregset::<ptrace::regset::NT_PRSTATUS>(pid)?;
        Ok(Regs {
            inner,
            sysno_override: None,
        })
    }

    fn store(&self, pid: Pid) -> Result<()> {
        ptrace::setregset::<ptrace::regset::NT_PRSTATUS>(pid, self.inner)?;
        if let Some(nr) = self.sysno_override {
            // Changing the syscall number on aarch64 requires NT_ARM_SYSTEM_CALL.
            let mut nr = nr;
            let mut iov = libc::iovec {
                iov_base: (&mut nr as *mut i32).cast::<c_void>(),
                iov_len: std::mem::size_of::<i32>(),
            };
            let rc = unsafe {
                libc::ptrace(
                    libc::PTRACE_SETREGSET,
                    libc::pid_t::from(pid),
                    NT_ARM_SYSTEM_CALL as *mut c_void,
                    (&mut iov as *mut libc::iovec).cast::<c_void>(),
                )
            };
            if rc < 0 {
                return Err(nix::errno::Errno::last().into());
            }
        }
        Ok(())
    }

    fn syscall_no(&self) -> i64 {
        self.inner.regs[8] as i64
    }

    fn arg(&self, i: usize) -> u64 {
        match i {
            0..=5 => self.inner.regs[i],
            _ => panic!("aarch64 syscall arg index out of range: {i}"),
        }
    }

    fn ret(&self) -> i64 {
        self.inner.regs[0] as i64
    }

    fn set_syscall_no(&mut self, no: i64) {
        self.inner.regs[8] = no as u64;
        self.sysno_override = Some(no as i32);
    }

    fn set_ret(&mut self, val: i64) {
        self.inner.regs[0] = val as u64;
    }
}
