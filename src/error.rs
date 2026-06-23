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

    #[error("{0}")]
    Other(String),
}
