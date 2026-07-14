//! Deterministic, streaming, pure-Rust ext4 image builder — plus a
//! verification-grade reader.
//!
//! See `DESIGN.md` in the repository for the on-disk layout decisions, the
//! determinism contract, and the metadata-before-data emission argument.
//!
//! Layer map (bottom-up):
//! - [`csum`] / [`dirhash`] — ext4's crc32c conventions and the half_md4
//!   directory hash. Zero-allocation, append-style folds over borrowed
//!   slices; verified against byte vectors extracted from real `mke2fs`
//!   images.
//! - [`spec`] — on-disk structures with byte-exact `decode`/`encode` into
//!   caller-provided buffers.
//! - [`reader`] — walks and verifies complete filesystems (the
//!   differential oracle against `mke2fs`, and the round-trip check for
//!   the writer).

pub mod build;
pub mod csum;
pub mod dirhash;
pub mod layout;
pub mod reader;
pub mod sink;
pub mod spec;

pub use build::{Features, FsBuilder, InodeCount, InodeHandle, Layout, Meta, Options, ROOT};
pub use sink::RegionSink;

mod le;

/// Errors produced by this crate.
#[derive(Debug)]
pub enum Error {
    /// Underlying I/O failure from a source or sink.
    Io(std::io::Error),
    /// The bytes being read do not form a valid structure.
    Corrupt {
        /// What was being decoded.
        what: &'static str,
        /// Why it was rejected.
        why: String,
    },
    /// Structurally valid, but uses a feature this crate does not handle.
    Unsupported(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "i/o error: {e}"),
            Error::Corrupt { what, why } => write!(f, "corrupt {what}: {why}"),
            Error::Unsupported(what) => write!(f, "unsupported: {what}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

/// Crate-wide result type.
pub type Result<T> = std::result::Result<T, Error>;

pub(crate) fn corrupt(what: &'static str, why: impl Into<String>) -> Error {
    Error::Corrupt {
        what,
        why: why.into(),
    }
}
