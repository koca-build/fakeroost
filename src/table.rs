//! The fake-ownership table: what we *pretend* is true about each file.
//!
//! This is a plain in-memory `HashMap` that lives only for the duration of a
//! supervised run — **nothing is ever written to disk**. We never actually change
//! file ownership on the filesystem (we can't, unprivileged); instead we record
//! the intended values here and overlay them onto every `stat`/`statx` result the
//! tracee reads. Keyed by `(dev, ino)` like upstream fakeroot.
//!
//! (Persisting this table across runs — fakeroot's `-s`/`-i` — is intentionally
//! out of scope for v1.)

use std::collections::HashMap;
use std::ffi::CString;

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
    /// Overridden hard-link count. Set by `link`/`unlink` tracking (M5).
    pub nlink: Option<u64>,
    /// Faked extended attributes (e.g. `security.capability`). (M4)
    pub xattrs: HashMap<CString, Vec<u8>>,
}

/// The in-memory `(dev, ino) -> FakeNode` table. Owned by the single supervisor
/// thread, so it needs no locking. Discarded when the run ends.
#[derive(Default)]
pub struct OwnershipTable {
    map: HashMap<(u64, u64), FakeNode>,
}

impl OwnershipTable {
    pub fn get(&self, dev: u64, ino: u64) -> Option<&FakeNode> {
        self.map.get(&(dev, ino))
    }

    /// Get a mutable entry, inserting a default (uid/gid = 0, i.e. root) if absent.
    pub fn entry(&mut self, dev: u64, ino: u64) -> &mut FakeNode {
        self.map.entry((dev, ino)).or_default()
    }

    pub fn remove(&mut self, dev: u64, ino: u64) -> Option<FakeNode> {
        self.map.remove(&(dev, ino))
    }
}
