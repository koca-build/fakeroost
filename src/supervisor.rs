//! The fakeroot supervisor: forks the target under a hybrid seccomp filter, then
//! runs the ptrace event loop over the whole process tree.
//!
//! ## Hybrid dispatch (issue #7 fix)
//!
//! The single-threaded ptrace ceiling is removed by splitting the intercepted
//! syscalls across two paths:
//!
//! - **stat family** → `SECCOMP_RET_USER_NOTIF`. The filter is installed with
//!   `SECCOMP_FILTER_FLAG_NEW_LISTENER`; the child passes the listener fd to the
//!   parent over a socketpair (`SCM_RIGHTS`), and a [`NotifPool`] of threads
//!   services stat notifications **in parallel**. The real syscall never runs —
//!   each worker resolves the target, stats it supervisor-side, overlays faked
//!   ownership from the shared table, writes the result back, and responds.
//! - **write-path** (`chown`/`chmod`/`mknod`/cred/`unlink`/`rename`/xattr) →
//!   `SECCOMP_RET_TRACE`, handled by this supervisor's `waitpid(-1)` loop. Rare,
//!   and needs ptrace's skip/step semantics, so it stays single-threaded.
//!
//! Control flow per *ptrace-traced* syscall (unchanged):
//! 1. seccomp filter returns `RET_TRACE` → we get a `PTRACE_EVENT_SECCOMP` stop
//!    (this *is* the syscall-entry stop).
//! 2. We inspect/modify args; if we need the result we `PTRACE_SYSCALL` to the
//!    syscall-exit stop and patch there; otherwise we `PTRACE_CONT` and the
//!    syscall runs normally.
//!
//! Note: a tracee's stat calls never appear as ptrace stops — they are consumed
//! by the USER_NOTIF path — so this loop now only sees the write-path.

use crate::arch::{RegAccess, Regs};
use crate::error::{Error, Result};
use crate::filter;
use crate::handlers::{self, Disposition, ExitAction};
use crate::table::OwnershipTable;
use crate::user_notif::NotifPool;
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::{ForkResult, Pid, fork};
use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::os::fd::RawFd;
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;
use std::sync::Arc;

const PTRACE_OPTIONS: ptrace::Options = ptrace::Options::PTRACE_O_TRACESECCOMP
    .union(ptrace::Options::PTRACE_O_TRACEFORK)
    .union(ptrace::Options::PTRACE_O_TRACEVFORK)
    .union(ptrace::Options::PTRACE_O_TRACECLONE)
    .union(ptrace::Options::PTRACE_O_TRACEEXEC)
    .union(ptrace::Options::PTRACE_O_TRACESYSGOOD)
    .union(ptrace::Options::PTRACE_O_EXITKILL);

/// A fully-resolved command to run under fakeroot.
pub struct Spawn {
    /// Program to execute (PATH-searched).
    pub program: CString,
    /// Full argv, including argv[0].
    pub argv: Vec<CString>,
    /// Environment as `KEY=VALUE` entries.
    pub env: Vec<CString>,
}

/// Run `spawn` under fakeroot, blocking until the whole process tree exits.
/// Returns the root process's exit status.
pub fn run(spawn: &Spawn) -> Result<ExitStatus> {
    // Build the filter in the parent (no allocation in the child).
    let prog = filter::build()?;

    // Socketpair used to hand the child's USER_NOTIF listener fd to the parent.
    let pair = socketpair()?;
    let child_sock = pair[0];
    let parent_sock = pair[1];

    match unsafe { fork() }? {
        ForkResult::Child => {
            // Async-signal context: keep to ptrace/prctl/seccomp/sendmsg/exec.
            unsafe { libc::close(parent_sock) };
            let _ = ptrace::traceme();
            let nfd = unsafe { filter::install_with_listener(&prog) };
            if nfd < 0 {
                unsafe { libc::_exit(126) };
            }
            // exec must close our copy of the listener (the parent's dup keeps it alive).
            set_cloexec(nfd);
            if !pass_fd(child_sock, nfd) {
                unsafe { libc::_exit(126) };
            }
            unsafe {
                libc::close(child_sock);
                libc::close(nfd);
            }
            // Stop so the parent can set ptrace options before anything runs.
            unsafe { libc::raise(libc::SIGSTOP) };
            let _ = nix::unistd::execvpe(&spawn.program, &spawn.argv, &spawn.env);
            unsafe { libc::_exit(127) };
        }
        ForkResult::Parent { child } => {
            unsafe { libc::close(child_sock) };
            let nfd = recv_fd(parent_sock).ok_or_else(|| {
                Error::Other("did not receive USER_NOTIF listener fd from child".into())
            })?;
            unsafe { libc::close(parent_sock) };

            let table = Arc::new(OwnershipTable::default());
            let pool = NotifPool::spawn(nfd, &table, notif_worker_count());
            let status = Supervisor::new(child, Arc::clone(&table)).event_loop()?;
            pool.join();
            Ok(status)
        }
    }
}

/// How many USER_NOTIF servant threads to spawn. Benchmarks (issue #7) show the
/// kernel's per-notification wait-queue has severe thundering-herd contention:
/// a single servant already ~6x the old ptrace ceiling (~190k vs ~30k stat/s),
/// and a small pool of ~3 maximizes throughput (~9x). More is strictly worse
/// (pool=128 collapses below baseline). `FAKEROOST_NOTIF_WORKERS` overrides.
fn notif_worker_count() -> usize {
    std::env::var("FAKEROOST_NOTIF_WORKERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3)
        .max(1)
}

struct Supervisor {
    root: Pid,
    /// Tracees whose initial SIGSTOP we've already absorbed.
    initialized: HashSet<Pid>,
    /// Per-tracee action to apply when the stepped syscall reaches its exit stop.
    pending: HashMap<Pid, ExitAction>,
    /// The fake-ownership table, shared with the USER_NOTIF pool.
    table: Arc<OwnershipTable>,
    root_status: Option<ExitStatus>,
}

impl Supervisor {
    fn new(root: Pid, table: Arc<OwnershipTable>) -> Self {
        Supervisor {
            root,
            initialized: HashSet::new(),
            pending: HashMap::new(),
            table,
            root_status: None,
        }
    }

    fn event_loop(mut self) -> Result<ExitStatus> {
        loop {
            let status = match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::__WALL)) {
                Ok(s) => s,
                Err(nix::errno::Errno::ECHILD) => break,
                Err(nix::errno::Errno::EINTR) => continue,
                Err(e) => return Err(e.into()),
            };

            match status {
                WaitStatus::Exited(pid, code) if pid == self.root => {
                    self.root_status = Some(ExitStatus::from_raw((code & 0xff) << 8));
                }
                WaitStatus::Signaled(pid, sig, _core) if pid == self.root => {
                    self.root_status = Some(ExitStatus::from_raw(sig as i32 & 0x7f));
                }
                WaitStatus::PtraceEvent(pid, _sig, event) => self.on_event(pid, event)?,
                WaitStatus::PtraceSyscall(pid) => {
                    // Syscall-exit stop of a trapped syscall we stepped into.
                    self.on_syscall_exit(pid)?;
                    ptrace::cont(pid, None)?;
                }
                WaitStatus::Stopped(pid, sig) => self.on_signal_stop(pid, sig)?,
                _ => {}
            }
        }

        Ok(self.root_status.unwrap_or(ExitStatus::from_raw(0)))
    }

    fn on_event(&mut self, pid: Pid, event: i32) -> Result<()> {
        if event == libc::PTRACE_EVENT_SECCOMP {
            self.on_seccomp(pid)?;
        } else {
            // fork / vfork / clone / exec / exit events: nothing to do yet; the new
            // child (if any) is auto-traced and inherits our options + filter.
            ptrace::cont(pid, None)?;
        }
        Ok(())
    }

    /// A trapped syscall is about to run (entry stop). Dispatch to the handlers,
    /// which decide whether to pass it through, step to its exit, or skip it.
    fn on_seccomp(&mut self, pid: Pid) -> Result<()> {
        let mut regs = Regs::fetch(pid)?;
        match handlers::handle_entry(pid, &self.table, &regs)? {
            Disposition::Passthrough => ptrace::cont(pid, None)?,
            Disposition::Step(action) => {
                self.pending.insert(pid, action);
                ptrace::syscall(pid, None)?;
            }
            Disposition::Skip(action) => {
                regs.set_syscall_no(-1);
                regs.store(pid)?;
                self.pending.insert(pid, action);
                ptrace::syscall(pid, None)?;
            }
        }
        Ok(())
    }

    /// Syscall-exit stop of a trapped syscall we stepped into.
    fn on_syscall_exit(&mut self, pid: Pid) -> Result<()> {
        let Some(action) = self.pending.remove(&pid) else {
            return Ok(());
        };
        let mut regs = Regs::fetch(pid)?;
        handlers::apply_exit_action(pid, &self.table, action, &mut regs)?;
        Ok(())
    }

    fn on_signal_stop(&mut self, pid: Pid, sig: Signal) -> Result<()> {
        // The first stop for any tracee is its initial SIGSTOP (root: the one we
        // raised; children: the post-fork stop). Absorb it; set options on the root.
        if self.initialized.insert(pid) {
            if pid == self.root {
                ptrace::setoptions(pid, PTRACE_OPTIONS)?;
            }
            ptrace::cont(pid, None)?;
            return Ok(());
        }

        match sig {
            // Group-stops / trace artifacts: resume without reinjecting.
            Signal::SIGSTOP
            | Signal::SIGTSTP
            | Signal::SIGTTIN
            | Signal::SIGTTOU
            | Signal::SIGTRAP => {
                ptrace::cont(pid, None)?;
            }
            // Genuine signal-delivery-stop: reinject so the tracee sees its signal.
            other => {
                ptrace::cont(pid, Some(other))?;
            }
        }
        Ok(())
    }
}

// ----- fd plumbing (async-signal-safe in the child) -----

fn socketpair() -> Result<[RawFd; 2]> {
    let mut fds = [0i32; 2];
    let rc = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    };
    if rc != 0 {
        return Err(nix::errno::Errno::last().into());
    }
    Ok(fds)
}

fn set_cloexec(fd: RawFd) {
    unsafe {
        libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
    }
}

/// Send `fd` over `sock` via `SCM_RIGHTS`. Async-signal safe (no allocation).
fn pass_fd(sock: RawFd, fd: RawFd) -> bool {
    unsafe {
        let mut byte: u8 = 0;
        let mut iov = libc::iovec {
            iov_base: &mut byte as *mut _ as *mut _,
            iov_len: 1,
        };
        let mut cbuf = [0u8; 64]; // >= CMSG_SPACE(sizeof(int))
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr() as *mut _;
        msg.msg_controllen = libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as _;
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return false;
        }
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
        std::ptr::copy_nonoverlapping(&fd, libc::CMSG_DATA(cmsg) as *mut RawFd, 1);
        libc::sendmsg(sock, &msg, 0) == 1
    }
}

/// Receive a file descriptor sent via `SCM_RIGHTS` over `sock`.
fn recv_fd(sock: RawFd) -> Option<RawFd> {
    unsafe {
        let mut byte: u8 = 0;
        let mut iov = libc::iovec {
            iov_base: &mut byte as *mut _ as *mut _,
            iov_len: 1,
        };
        let mut cbuf = [0u8; 64];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr() as *mut _;
        msg.msg_controllen = libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as _;
        if libc::recvmsg(sock, &mut msg, 0) != 1 {
            return None;
        }
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return None;
        }
        let mut fd: RawFd = -1;
        std::ptr::copy_nonoverlapping(libc::CMSG_DATA(cmsg) as *const RawFd, &mut fd, 1);
        Some(fd)
    }
}
