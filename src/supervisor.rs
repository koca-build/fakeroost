//! The fakeroot supervisor: forks the target under a seccomp `RET_TRACE` filter,
//! then runs the ptrace event loop over the whole process tree.
//!
//! Control flow per trapped syscall:
//! 1. seccomp filter returns `RET_TRACE` → we get a `PTRACE_EVENT_SECCOMP` stop
//!    (this *is* the syscall-entry stop).
//! 2. We inspect/modify args; if we need the result we `PTRACE_SYSCALL` to the
//!    syscall-exit stop and patch there; otherwise we `PTRACE_CONT` and the
//!    syscall runs normally.

use crate::arch::{RegAccess, Regs};
use crate::error::Result;
use crate::filter;
use crate::handlers::{self, Disposition, ExitAction};
use crate::table::OwnershipTable;
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::{ForkResult, Pid, fork};
use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;

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
    // Compile the filter in the parent (no allocation in the child).
    let bpf = filter::build()?;

    match unsafe { fork() }? {
        ForkResult::Child => {
            // Async-signal context: keep to ptrace/prctl/exec only.
            let _ = ptrace::traceme();
            if filter::install(&bpf).is_err() {
                unsafe { libc::_exit(126) };
            }
            // Stop so the parent can set ptrace options before anything interesting
            // runs. The parent swallows this SIGSTOP.
            unsafe { libc::raise(libc::SIGSTOP) };
            let _ = nix::unistd::execvpe(&spawn.program, &spawn.argv, &spawn.env);
            // execvpe only returns on failure.
            unsafe { libc::_exit(127) };
        }
        ForkResult::Parent { child } => Supervisor::new(child).event_loop(),
    }
}

struct Supervisor {
    root: Pid,
    /// Tracees whose initial SIGSTOP we've already absorbed.
    initialized: HashSet<Pid>,
    /// Per-tracee action to apply when the stepped syscall reaches its exit stop.
    pending: HashMap<Pid, ExitAction>,
    /// The fake-ownership table (in memory only).
    table: OwnershipTable,
    root_status: Option<ExitStatus>,
}

impl Supervisor {
    fn new(root: Pid) -> Self {
        Supervisor {
            root,
            initialized: HashSet::new(),
            pending: HashMap::new(),
            table: OwnershipTable::default(),
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

        // If the tree drained without an explicit code (shouldn't normally happen),
        // assume success.
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
        match handlers::handle_entry(pid, &mut self.table, &regs)? {
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
        handlers::apply_exit_action(pid, &mut self.table, action, &mut regs)?;
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
