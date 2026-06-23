//! Tiny CLI shim over the `fakeroot` library.
//!
//! Runs a single command under fakeroot and propagates its exit code. This is
//! deliberately minimal — the full `fakeroot`-compatible CLI (login shell,
//! `-s/-i/-u/-b`, environment compatibility) is a separate effort.

use fakeroot::FakerootCommandExt;
use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    // If we were re-executed as a supervisor, this runs the command and exits;
    // otherwise it returns and we dispatch the CLI invocation below.
    fakeroot::init();

    let mut args = std::env::args_os().skip(1);
    let Some(program) = args.next() else {
        eprintln!("usage: fakeroot-rs <program> [args...]");
        return ExitCode::from(2);
    };
    let rest: Vec<_> = args.collect();

    match Command::new(program).args(rest).fakeroot().status() {
        Ok(status) => ExitCode::from(status.code().unwrap_or(1) as u8),
        Err(e) => {
            eprintln!("fakeroot-rs: {e}");
            ExitCode::from(1)
        }
    }
}
