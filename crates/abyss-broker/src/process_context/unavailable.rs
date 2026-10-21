//! Fallback process-context provider for targets without native process-context lookup.

use std::path::PathBuf;

use super::cache::ProcessContextProvider;

pub(super) struct UnavailableProcessContextProvider;

impl ProcessContextProvider for UnavailableProcessContextProvider {
    fn lookup(&self, _pid: u32) -> Option<PathBuf> {
        None
    }
}
