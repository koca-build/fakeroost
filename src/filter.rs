//! Builds the seccomp-BPF filter that splits intercepted syscalls between two
//! dispatch paths, fixing issue #7 (the single-threaded ptrace ceiling):
//!
//! - **stat family** (`stat`/`lstat`/`fstat`/`newfstatat`/`statx`) →
//!   `SECCOMP_RET_USER_NOTIF`: the syscall is *not* ptrace-traced; instead a
//!   notification is posted to a listener fd that a **thread pool** services in
//!   parallel. stat is by far the most frequent syscall in a compile, so routing
//!   it off the single ptrace thread is what removes the parallelism ceiling.
//! - **write-path** (`chown`/`chmod`/`mknod`/cred/`unlink`/`rename`/xattr) →
//!   `SECCOMP_RET_TRACE`: handled by the existing ptrace supervisor. These are
//!   rare and need ptrace's skip/step semantics, so they stay on the main thread.
//! - everything else → `SECCOMP_RET_ALLOW` (full speed, never trapped).
//!
//! The syscall→action mapping is derived from the single source of truth,
//! [`crate::handlers::REGISTRY`], so the filter and the handlers can't drift.
//!
//! `seccompiler` 0.5.0 has no `UserNotif` action and uses a single match-action,
//! so this filter's BPF is built raw.

use crate::error::Result;
use crate::handlers::{Family, REGISTRY};

/// seccomp-BPF opcodes (libc exposes the SECCOMP_RET_* constants but not these).
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

/// Offsets within `struct seccomp_data` (it is `{ nr: i32, arch: u32, ip: u64,
/// args: [u64; 6] }`).
const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;

/// The `AUDIT_ARCH_*` value for the current build target (for the arch guard).
const fn audit_arch() -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        62 | 0x8000_0000 | 0x4000_0000 // EM_X86_64 | __AUDIT_ARCH_64BIT | _LE
    }
    #[cfg(target_arch = "aarch64")]
    {
        183 | 0x8000_0000 | 0x4000_0000
    }
    #[cfg(target_arch = "riscv64")]
    {
        243 | 0x8000_0000 | 0x4000_0000
    }
}

fn insn(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

/// Build the hybrid BPF program: arch guard, then per-syscall dispatch (stat →
/// USER_NOTIF, other intercepted → TRACE, default ALLOW).
pub fn build() -> Result<Vec<libc::sock_filter>> {
    // [0] load arch; [1] if it matches skip to [3] (load nr), else [2] kill.
    let head = [
        insn(BPF_LD | BPF_W | BPF_ABS, 0, 0, OFF_ARCH),
        insn(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, audit_arch()),
        insn(BPF_RET | BPF_K, 0, 0, libc::SECCOMP_RET_KILL_PROCESS),
        // [3] load syscall nr.
        insn(BPF_LD | BPF_W | BPF_ABS, 0, 0, OFF_NR),
    ];

    // Per-rule: `JEQ nr, jt=0, jf=1; RET <action>` — on match run the RET, else
    // skip it. Self-contained pairs avoid cross-rule offset arithmetic.
    let mut p: Vec<libc::sock_filter> = Vec::with_capacity(head.len() + 2 * REGISTRY.len() + 1);
    p.extend(head);
    for &(nr, family) in REGISTRY {
        let action = match family {
            Family::Stat(..) => libc::SECCOMP_RET_USER_NOTIF,
            _ => libc::SECCOMP_RET_TRACE, // RET_TRACE | 0 (sifts the syscall number)
        };
        p.push(insn(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, nr as u32));
        p.push(insn(BPF_RET | BPF_K, 0, 0, action));
    }
    // Default: allow.
    p.push(insn(BPF_RET | BPF_K, 0, 0, libc::SECCOMP_RET_ALLOW));
    Ok(p)
}

/// Install `prog` as a seccomp filter **with a new listener** and return the
/// listener fd. Runs in the child right after fork, so it must be async-signal
/// safe (only `prctl` + the `seccomp` syscall). `<0` on failure.
///
/// # Safety
/// Async-signal context after `fork`: only `prctl`/`seccomp` are issued.
pub unsafe fn install_with_listener(prog: &[libc::sock_filter]) -> libc::c_int {
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        return -1;
    }
    let fprog = libc::sock_fprog {
        len: prog.len() as u16,
        filter: prog.as_ptr() as *mut _,
    };
    unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &fprog as *const libc::sock_fprog,
        ) as libc::c_int
    }
}
