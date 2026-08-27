//! Stable digests used by parsed protocol identifiers and retained content.

use sha2::{Digest, Sha256};

/// Returns a lowercase SHA-256 hex digest for text.
#[must_use]
pub fn sha256_hex(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

/// Returns a lowercase SHA-256 hex digest for arbitrary bytes.
#[must_use]
pub fn sha256_bytes_hex(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}
