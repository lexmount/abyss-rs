//! Fallback process-context provider for targets without cwd lookup support.

use std::path::PathBuf;

use super::cache::WorkingDirectoryProvider;

pub(super) struct UnavailableWorkingDirectoryProvider;

impl WorkingDirectoryProvider for UnavailableWorkingDirectoryProvider {
    fn lookup(&self, _pid: u32) -> Option<PathBuf> {
        None
    }
}
