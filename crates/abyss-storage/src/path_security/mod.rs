//! Platform-neutral access to local `SQLite` path protection.
//!
//! The storage layer only depends on [`StoragePathSecurity`]. Platform details
//! live in the conditionally compiled sibling modules and are exposed through
//! a trait object, matching the platform adapter pattern used elsewhere in the
//! workspace.

use std::{io, path::Path};

#[cfg(not(any(unix, windows)))]
mod fallback;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

/// Protects a database file and its containing directory for one platform.
pub trait StoragePathSecurity: Send + Sync {
    /// Applies the platform's private-file protection to `path`.
    fn protect_file(&self, path: &Path) -> io::Result<()>;

    /// Applies the platform's private-directory protection to `path`.
    fn protect_directory(&self, path: &Path) -> io::Result<()>;
}

/// Builds the path-security adapter for the current target.
pub fn platform() -> Box<dyn StoragePathSecurity> {
    Box::new(implementation::PlatformPathSecurity)
}

#[cfg(unix)]
mod implementation {
    pub(super) use super::unix::UnixPathSecurity as PlatformPathSecurity;
}

#[cfg(windows)]
mod implementation {
    pub(super) use super::windows::WindowsPathSecurity as PlatformPathSecurity;
}

#[cfg(not(any(unix, windows)))]
mod implementation {
    pub(super) use super::fallback::FallbackPathSecurity as PlatformPathSecurity;
}
