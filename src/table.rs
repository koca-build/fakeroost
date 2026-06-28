//! The fake-ownership table: what we *pretend* is true about each file.
//!
//! This is a plain in-memory map that lives only for the duration of a
//! supervised run — **nothing is ever written to disk**. We never actually change
//! file ownership on the filesystem (we can't, unprivileged); instead we record
//! the intended values here and overlay them onto every `stat`/`statx` result the
//! tracee reads. Keyed by `(dev, ino)` like upstream fakeroot.
//!
//! (Persisting this table across runs — fakeroot's `-s`/`-i` — is intentionally
//! out of scope for v1.)
//!
//! Access is shared across the supervisor's threads: the ptrace loop (write-path
//! handlers) and the USER_NOTIF stat pool both read it. The pattern is
//! read-heavy (every stat overlay) and write-rare (chown/chmod/mknod), so an
//! `RwLock` backs it — concurrent readers never block, even while a guard is held
//! across the slow `process_vm`/`/proc/pid/mem` transfers.

use std::collections::HashMap;
use std::ffi::CString;
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

/// What we report for one inode. Fields left `None` fall through to the file's real
/// values, so an inode the program only `chown`ed keeps its real mode/rdev.
#[derive(Clone, Debug, Default)]
pub struct FakeNode {
    pub uid: u32,
    pub gid: u32,
    /// Full mode to report (type + permission bits). Set by `chmod`/`mknod`.
    pub mode: Option<u32>,
    /// Device id to report for device nodes. Set by `mknod`.
    pub rdev: Option<u64>,
    /// Overridden hard-link count, when faked.
    pub nlink: Option<u64>,
    /// Faked extended attributes (e.g. `security.capability`).
    pub xattrs: HashMap<CString, Vec<u8>>,
}

/// The in-memory `(dev, ino) -> FakeNode` table, shared via an `RwLock`.
/// Discarded when the run ends.
#[derive(Default)]
pub struct OwnershipTable {
    map: RwLock<HashMap<(u64, u64), FakeNode>>,
}

impl OwnershipTable {
    /// Shared read access to the whole table.
    pub fn read(&self) -> RwLockReadGuard<'_, HashMap<(u64, u64), FakeNode>> {
        self.map.read().expect("ownership table lock poisoned")
    }

    /// Exclusive write access to the whole table (write-rare handlers).
    pub fn write(&self) -> RwLockWriteGuard<'_, HashMap<(u64, u64), FakeNode>> {
        self.map.write().expect("ownership table lock poisoned")
    }
}
