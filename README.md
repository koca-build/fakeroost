# fakeroot-rs

A [`fakeroot`](https://wiki.debian.org/fakeroot)-style fake-root environment for
Linux, built on **ptrace** narrowed by a self-installed **seccomp `RET_TRACE`**
filter. It lets an unprivileged process believe it is root and see whatever file
ownership it sets — without ever changing anything on disk.

It exists to fix two things the classic fakeroot can't do in modern setups:

- **Static binaries.** Classic fakeroot is an `LD_PRELOAD` shim, so it's invisible
  to statically-linked programs (Go, musl, static Rust) and to anything that issues
  raw syscalls. fakeroot-rs intercepts at the **syscall boundary**, so linking
  doesn't matter.
- **Locked-down Docker / CI.** It needs **no extra privileges** and works under
  Docker's **default seccomp profile**: installing a seccomp filter via `prctl` and
  ptracing your own children are both permitted there, whereas the user-namespace
  approach (`clone(CLONE_NEWUSER)`) is blocked.

## How it works

```
syscall ──> [seccomp filter]
              ├─ read/write/mmap/...      → ALLOW (full speed; tracer never wakes)
              └─ chown/stat/statx/...     → TRACE → ptrace supervisor
                                                     ├─ records fake ownership
                                                     └─ patches results / return values
```

A small seccomp-BPF filter traps only the ~40 ownership-related syscalls and lets
everything else run at native speed. The supervisor keeps an **in-memory**
`(dev, ino) → ownership` table (nothing is persisted) and, by default, reports any
untracked file as root-owned — matching fakeroot's "unknown is root" behavior, so
files created during a build are packaged as `root:root` without explicit chowns.
It handles `stat`/`statx`, `AT_EMPTY_PATH`/`AT_SYMLINK_NOFOLLOW`, device nodes
(`mknod`), extended attributes including `security.capability`, and drops table
entries when an inode's last link goes away so reused inodes start clean.

## Library

```rust
use std::process::Command;
use fakeroot::FakerootCommandExt;

fn main() -> std::io::Result<()> {
    // Call once, first thing in main(). See note below.
    fakeroot::init();

    // Inside fakeroot the process believes it is root:
    let out = Command::new("whoami").fakeroot().output()?;
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "root");
    Ok(())
}
```

`FakerootCommandExt::fakeroot()` returns a plain `std::process::Command` that runs
the same program under fakeroot — so stdio, pipes, `status()`/`output()`/`spawn()`
and `Child` all work exactly as with any `Command`, and it drops into any API that
already accepts a `Command`:

```rust
let mut child = Command::new("make")
    .arg("install")
    .fakeroot()
    .stdout(Stdio::piped())
    .spawn()?;            // real Child: stream stdout, kill(), wait(), …
```

### Why `init()`?

ptrace needs the tracer to be a separate process, so a `.fakeroot()` command runs
your target by **re-executing your own program** in a supervisor mode rather than
shipping a second binary. `fakeroot::init()` is the one line that detects that mode:
it's a no-op on a normal launch, but on a fakeroot re-exec it runs the supervisor and
exits without returning. Keep it at the very top of `main()`. Full details:
[`fakeroot::init` on docs.rs](https://docs.rs/fakeroot-rs).

## CLI

```sh
fakeroot-rs <program> [args...]      # run a command in a fake-root environment
```

This is intentionally minimal. A full `fakeroot`-compatible CLI (login shell,
`-s`/`-i`/`-u`/`-b`, environment compatibility) is a separate effort.

## Supported platforms

- **Linux only.** Requires unprivileged ptrace of own children (default in most
  environments, including default-seccomp Docker).
- **Architectures:** `x86_64` (amd64) and `aarch64` (arm64).

## Limitations

- No state save/load across runs (`fakeroot -s`/`-i`); the table lives only for the
  duration of one run.
- `Command::env_clear` isn't reflected (it isn't observable through the std API).

## License

MIT
