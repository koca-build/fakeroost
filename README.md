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

// Build a tarball whose contents are owned by root, as an unprivileged user:
let status = Command::new("tar")
    .args(["--numeric-owner", "-cf", "out.tar", "tree/"])
    .fakeroot_status()?;
assert!(status.success());
# Ok::<(), fakeroot::Error>(())
```

`FakerootCommandExt` adds to `std::process::Command`:

- `fakeroot_status()` / `fakeroot_status_with(Options)` — run to completion, return
  the exit status (blocks on the calling thread).
- `fakeroot_spawn()` — run on a dedicated supervisor thread, returning a
  `FakerootChild` you `wait()` on.

## CLI

```sh
fakeroot-rs <program> [args...]      # run a command in a fake-root environment
RUST_LOG=debug fakeroot-rs ...       # trace intercepted syscalls
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
