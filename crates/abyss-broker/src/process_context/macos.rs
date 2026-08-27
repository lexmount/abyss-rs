//! macOS process working-directory provider backed by the safe sys adapter.

use std::path::PathBuf;

use super::cache::WorkingDirectoryProvider;

pub(super) struct MacOsWorkingDirectoryProvider;

impl WorkingDirectoryProvider for MacOsWorkingDirectoryProvider {
    fn lookup(&self, pid: u32) -> Option<PathBuf> {
        match crate::sys::process_working_directory(pid) {
            Ok(working_directory) => working_directory,
            Err(error) => {
                tracing::debug!(
                    pid,
                    %error,
                    "macOS process working-directory lookup was unavailable"
                );
                None
            }
        }
    }
}
