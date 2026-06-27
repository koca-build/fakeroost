# fakeroost

`fakeroost` runs a command in a `fakeroot`-like environment: the program believes it is
root and sees whatever file ownership it sets (via `chown`, `mknod`, …), while
nothing on disk actually changes.

Two things set it apart from the classic
[`fakeroot`](https://wiki.debian.org/FakeRoot):

- **Works with static binaries (musl, Go, static Rust).** Classic fakeroot is an
  `LD_PRELOAD` shim, invisible to statically-linked programs and to anything issuing
  raw syscalls. fakeroost intercepts at the syscall boundary, so linking doesn't
  matter.
- **Works in Docker / CI with no extra privileges.** It runs under Docker's default
  seccomp profile, where a user-namespace approach would be blocked.

## Library

```rust no_run
use std::process::Command;
use fakeroost::FakerootCommandExt;

fn main() -> std::io::Result<()> {
    // Call once, first thing in main(). See note below.
    fakeroost::init();

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

```rust ignore
let mut child = Command::new("make")
    .arg("install")
    .fakeroot()
    .stdout(Stdio::piped())
    .spawn()?;            // real Child: stream stdout, kill(), wait(), …
```

### Why `init()`?

ptrace needs the tracer to be a separate process, so a `.fakeroot()` command runs
your target by **re-executing your own program** in a supervisor mode rather than
shipping a second binary. `fakeroost::init()` is the one line that detects that mode:
it's a no-op on a normal launch, but on a fakeroot re-exec it runs the supervisor and
exits without returning. Keep it at the very top of `main()`. Full details:
[`fakeroost::init` on docs.rs](https://docs.rs/fakeroost).

## CLI

```sh
fakeroost <program> [args...]      # run a command in a `fakeroot`-like environment
```

This is intentionally minimal. A full `fakeroot`-compatible CLI (login shell,
`-s`/`-i`/`-u`/`-b`, environment compatibility) is a separate effort.

## Supported platforms

- **Linux only.** Requires unprivileged ptrace of own children (default in most
  environments, including default-seccomp Docker).
- **Architectures:** `x86_64` (amd64), `aarch64` (arm64), and `riscv64`.

## Limitations

- No state save/load across runs (`fakeroot -s`/`-i`); the table lives only for the
  duration of one run.
- `Command::env_clear()` is unsupported — `.fakeroot()` can't tell whether you called
  it, because the
  [`Command::get_env_clear`](https://doc.rust-lang.org/std/process/struct.Command.html#method.get_env_clear)
  getter is still unstable. Avoid calling it on a `.fakeroot()` command; we can support
  it once that method stabilizes. (`env()` and `env_remove()` work fine.)

## License

MIT
