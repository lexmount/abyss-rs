//! Fallback implementation of local `SQLite` path protection.

use std::{io, path::Path};

use super::StoragePathSecurity;

/// No-op path adapter for targets without a supported permission API.
pub(super) struct FallbackPathSecurity;

impl StoragePathSecurity for FallbackPathSecurity {
    fn protect_file(&self, _path: &Path) -> io::Result<()> {
        Ok(())
    }

    fn protect_directory(&self, _path: &Path) -> io::Result<()> {
        Ok(())
    }
}
