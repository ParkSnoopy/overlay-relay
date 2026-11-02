//! Error type shared by the hub. Messages are fixed strings or I/O and JSON
//! descriptions; they never include credentials, tokens, payloads or names.

use std::{error::Error as StdError, fmt, io};

/// Result alias used across the crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Failures reported by the hub.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// An I/O operation failed.
    Io(io::Error),
    /// JSON encoding or decoding failed.
    Json(serde_json::Error),
    /// A frame or datagram record violated the wire bounds.
    Protocol(&'static str),
    /// The peers table is malformed, duplicated or oversized.
    Peers(&'static str),
    /// The persisted address assignments cannot be parsed.
    CorruptAssignments,
    /// The overlay address space has no free address for a new account.
    AddressExhausted,
    /// The hub configuration cannot run.
    Config(&'static str),
    /// A bounded read or write did not finish in time.
    Timeout,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "overlay i/o failed: {error}"),
            Self::Json(error) => write!(formatter, "overlay json is invalid: {error}"),
            Self::Protocol(message) | Self::Peers(message) | Self::Config(message) => {
                formatter.write_str(message)
            }
            Self::CorruptAssignments => {
                formatter.write_str("overlay address assignments are corrupt")
            }
            Self::AddressExhausted => formatter.write_str("overlay address space is exhausted"),
            Self::Timeout => formatter.write_str("overlay operation timed out"),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Json(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}
