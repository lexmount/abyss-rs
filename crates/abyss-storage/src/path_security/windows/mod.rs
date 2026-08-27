//! Windows implementation of local `SQLite` path protection.

use std::{io, path::Path};

use super::super::StoragePathSecurity;

/// Windows application-data ACL adapter for `SQLite` paths.
pub(super) struct WindowsPathSecurity;

impl StoragePathSecurity for WindowsPathSecurity {
    fn protect_file(&self, _path: &Path) -> io::Result<()> {
        // Windows application-data ACLs are established by the installer and
        // inherited by files created below the application data root.
        Ok(())
    }

    fn protect_directory(&self, _path: &Path) -> io::Result<()> {
        // See `protect_file`: ACL ownership belongs to the Windows installer
        // and service boundary rather than the portable storage crate.
        Ok(())
    }
}
