#![doc = include_str!("../README.md")]
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

use error::{Error, Result};
use std::ffi::{CString, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::process::{Command, ExitStatus};
use supervisor::Spawn;

mod sealed {
    pub trait Sealed {}
    impl Sealed for std::process::Command {}
}

/// Environment variable marking a process that was re-executed to act as the
/// fakeroot supervisor. Set by [`FakerootCommandExt::fakeroot`], consumed by
/// [`init`]. Internal — don't set or rely on it yourself.
const SUPERVISE_VAR: &str = "__FAKEROOST_SUPERVISE";

/// Adds `fakeroot`-like execution to [`std::process::Command`].
pub trait FakerootCommandExt: sealed::Sealed {
    /// Rewrite this command so that running it executes the same program under
    /// fakeroot, returning it as a plain [`std::process::Command`].
    ///
    /// The returned command re-executes the current program (see [`init`]) with
    /// the original program, arguments, environment overrides and working directory
    /// preserved. Run it however you like — `status()`, `output()`, `spawn()`, with
    /// any stdio configuration — it behaves like a normal `Command`, just run under
    /// fakeroot.
    ///
    /// Configure stdio (`.stdout`, pipes, …) on the **returned** command, not before:
    /// `Command` exposes no way to read back its stdio, so any redirection set prior
    /// to this call cannot be carried over.
    fn fakeroot(&self) -> Command;
}

impl FakerootCommandExt for Command {
    fn fakeroot(&self) -> Command {
        // Re-exec ourselves via the kernel's magic symlink (resolved at exec time,
        // so it needs no fallible `current_exe` lookup and survives a moved binary).
        let mut cmd = Command::new("/proc/self/exe");
        cmd.env(SUPERVISE_VAR, "1");
        cmd.arg(self.get_program());
        cmd.args(self.get_args());
        for (key, val) in self.get_envs() {
            match val {
                Some(val) => cmd.env(key, val),
                None => cmd.env_remove(key),
            };
        }
        if let Some(dir) = self.get_current_dir() {
            cmd.current_dir(dir);
        }
        cmd
    }
}

/// Become the fakeroot supervisor if this process was launched as one — call this
/// **once, as the first thing in `main`**.
///
/// ptrace requires the tracer to be a separate process from the traced one, so a
/// command built by [`FakerootCommandExt::fakeroot`] doesn't run your target
/// directly: it re-executes *your own program* in a supervisor mode. `init` is what
/// detects that mode. On a normal launch it returns immediately and your program
/// continues as usual; on a fakeroot re-exec it runs the supervisor over the
/// requested command — owning the whole `waitpid` loop — and exits with that
/// command's status code, never returning.
///
/// Re-executing your own binary (rather than a separate helper) means there is
/// nothing extra to ship or locate at runtime. The price is this one line: if it is
/// missing, or runs after other startup logic, a [`fakeroot()`](FakerootCommandExt::fakeroot)
/// command re-runs that logic instead of the intended target.
pub fn init() {
    if std::env::var_os(SUPERVISE_VAR).is_none() {
        return;
    }
    // We were re-executed as a supervisor: argv[1..] is the target command, and our
    // environment/working directory are already what the child should inherit.
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let code = match supervise(&args) {
        Ok(status) => status.code().unwrap_or(1),
        Err(e) => {
            eprintln!("fakeroost: {e}");
            1
        }
    };
    std::process::exit(code);
}

/// Build a [`Spawn`] for `args` (`[program, args…]`) from the current environment
/// and run it under the supervisor.
fn supervise(args: &[OsString]) -> Result<ExitStatus> {
    let to_cstring = |s: &OsString| {
        CString::new(s.as_bytes())
            .map_err(|_| Error::Other("command component contains a NUL byte".into()))
    };
    let argv: Vec<CString> = args.iter().map(to_cstring).collect::<Result<_>>()?;
    let program = argv
        .first()
        .cloned()
        .ok_or_else(|| Error::Other("no program given to fakeroot supervisor".into()))?;

    // Inherit the current environment (the `.fakeroot()` command already applied any
    // overrides to us), minus our own supervise marker.
    let env = std::env::vars_os()
        .filter(|(k, _)| k != SUPERVISE_VAR)
        .filter_map(|(k, v)| {
            let mut bytes = k.into_vec();
            bytes.push(b'=');
            bytes.extend_from_slice(v.as_bytes());
            CString::new(bytes).ok()
        })
        .collect();

    supervisor::run(&Spawn { program, argv, env })
}
