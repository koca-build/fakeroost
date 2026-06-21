//! # fakeroot-rs
//!
//! A [`fakeroot`](https://wiki.debian.org/fakeroot)-style fake-root environment
//! built on **ptrace** narrowed by a self-installed **seccomp `RET_TRACE`** filter.
//!
//! Unlike the classic `LD_PRELOAD` fakeroot, this works for **statically linked**
//! binaries (Go, musl, static Rust) because it intercepts at the syscall boundary,
//! not the libc boundary. Unlike the user-namespace approach, it works under
//! **Docker's default seccomp profile** with no extra privileges — installing a
//! seccomp filter via `prctl` and ptracing your own children are both permitted
//! there, whereas `clone(CLONE_NEWUSER)` is not.
//!
//! ## Usage
//!
//! ```no_run
//! use std::process::Command;
//! use fakeroot::FakerootCommandExt;
//!
//! let status = Command::new("tar")
//!     .args(["--numeric-owner", "-cf", "out.tar", "tree/"])
//!     .fakeroot_status()?;
//! assert!(status.success());
//! # Ok::<(), fakeroot::Error>(())
//! ```
//!
//! Inside the closure of the spawned process, `chown`/`chmod`/`mknod`/`stat`/`statx`
//! and the credential syscalls are intercepted so the program believes it is root
//! and sees the fake ownership it set.

// Many `as u64`/`as u32` casts on libc struct fields are redundant on x86_64 but
// required on aarch64 (e.g. `nlink_t` is u32 there). Keep them for portability.
#![allow(clippy::unnecessary_cast)]

mod arch;
mod error;
mod filter;
mod handlers;
mod mem;
mod path;
mod supervisor;
mod table;

pub use error::{Error, Result};
pub use supervisor::Options;

use std::ffi::CString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::process::{Command, ExitStatus};
use supervisor::Spawn;

/// Extension trait adding fake-root execution to [`std::process::Command`].
///
/// Configure the command as usual (`.arg`, `.env`, `.current_dir`, …) and then run
/// it under fakeroot. The supervisor must own the `waitpid` loop for the whole
/// process tree, so these methods do **not** return a [`std::process::Child`];
/// they run the command to completion (or hand back our own supervised handle).
pub trait FakerootCommandExt {
    /// Run the command under fakeroot on the calling thread, blocking until the
    /// whole process tree exits, and return the root process's exit status.
    fn fakeroot_status(&mut self) -> Result<ExitStatus>;

    /// Like [`fakeroot_status`](Self::fakeroot_status), with explicit [`Options`].
    fn fakeroot_status_with(&mut self, opts: Options) -> Result<ExitStatus>;

    /// Run the command under fakeroot on a dedicated supervisor thread, returning a
    /// handle. ptrace requires the tracer to be the thread that forked, so the
    /// supervisor lives entirely on that thread; [`FakerootChild::wait`] retrieves
    /// the exit status.
    fn fakeroot_spawn(&mut self) -> Result<FakerootChild>;
}

impl FakerootCommandExt for Command {
    fn fakeroot_status(&mut self) -> Result<ExitStatus> {
        self.fakeroot_status_with(Options::default())
    }

    fn fakeroot_status_with(&mut self, opts: Options) -> Result<ExitStatus> {
        supervisor::run(&build_spawn(self)?, &opts)
    }

    fn fakeroot_spawn(&mut self) -> Result<FakerootChild> {
        let spawn = build_spawn(self)?;
        let handle = std::thread::spawn(move || supervisor::run(&spawn, &Options::default()));
        Ok(FakerootChild { handle })
    }
}

/// A handle to a command running under fakeroot on its own supervisor thread.
pub struct FakerootChild {
    handle: std::thread::JoinHandle<Result<ExitStatus>>,
}

impl FakerootChild {
    /// Wait for the command (and its whole process tree) to finish.
    pub fn wait(self) -> Result<ExitStatus> {
        self.handle
            .join()
            .map_err(|_| Error::Other("fakeroot supervisor thread panicked".into()))?
    }
}

/// Resolve a [`Command`] into the fully-specified [`Spawn`] the supervisor runs:
/// program, argv, environment (current env with the command's overrides applied),
/// and working directory.
fn build_spawn(cmd: &Command) -> Result<Spawn> {
    let nul = || Error::Other("command component contains a NUL byte".into());

    let program = CString::new(cmd.get_program().as_bytes()).map_err(|_| nul())?;
    let mut argv = vec![program.clone()];
    for a in cmd.get_args() {
        argv.push(CString::new(a.as_bytes()).map_err(|_| nul())?);
    }

    // Start from the current environment and apply the command's overrides.
    // (env_clear is not observable through the std API, so it isn't supported.)
    let mut env: std::collections::BTreeMap<std::ffi::OsString, std::ffi::OsString> =
        std::env::vars_os().collect();
    for (k, v) in cmd.get_envs() {
        match v {
            Some(v) => {
                env.insert(k.to_owned(), v.to_owned());
            }
            None => {
                env.remove(k);
            }
        }
    }
    let env = env
        .into_iter()
        .filter_map(|(k, v)| {
            let mut bytes = k.into_vec();
            bytes.push(b'=');
            bytes.extend_from_slice(v.as_bytes());
            CString::new(bytes).ok()
        })
        .collect();

    let cwd = match cmd.get_current_dir() {
        Some(d) => Some(CString::new(d.as_os_str().as_bytes()).map_err(|_| nul())?),
        None => None,
    };

    Ok(Spawn {
        program,
        argv,
        env,
        cwd,
    })
}
