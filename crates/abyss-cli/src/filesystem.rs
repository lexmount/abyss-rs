//! POSIX persistence primitives for CLI-owned files.

use std::{fs, io, path::Path};

use crate::platform::platform_adapter;

/// Applies the active platform's file-creation policy.
///
/// Supported targets apply the requested POSIX `mode`.
pub fn configure_file_creation(options: &mut fs::OpenOptions, mode: u32) {
    platform_adapter().configure_file_creation(options, mode);
}

/// Applies the active platform's policy to an existing CLI-owned path.
///
/// Supported targets apply the requested POSIX `mode`.
pub fn protect(path: &Path, mode: u32) -> io::Result<()> {
    platform_adapter().protect_private_path(path, mode)
}

/// Atomically replaces `destination` with `source`.
pub fn replace(source: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(source, destination)
}
