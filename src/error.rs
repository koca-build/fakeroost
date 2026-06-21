//! Error type for the library.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    /// A syscall made by the supervisor itself failed.
    #[error("syscall failed: {0}")]
    Errno(#[from] nix::errno::Errno),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// The tracee or supervisor is running on an architecture we don't support.
    #[error("unsupported architecture")]
    UnsupportedArch,

    /// A feature that is planned but not yet wired up.
    #[error("not yet implemented: {0}")]
    Unimplemented(&'static str),

    #[error("{0}")]
    Other(String),
}
