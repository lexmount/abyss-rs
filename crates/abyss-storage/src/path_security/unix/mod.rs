//! Unix implementation of local `SQLite` path protection.

use std::{fs, io, os::unix::fs::PermissionsExt, path::Path};

use super::super::StoragePathSecurity;

/// Unix owner-only permissions adapter for `SQLite` paths.
pub(super) struct UnixPathSecurity;

impl StoragePathSecurity for UnixPathSecurity {
    fn protect_file(&self, path: &Path) -> io::Result<()> {
        let mut permissions = fs::metadata(path)?.permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(path, permissions)
    }

    fn protect_directory(&self, path: &Path) -> io::Result<()> {
        let mut permissions = fs::metadata(path)?.permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(path, permissions)
    }
}
