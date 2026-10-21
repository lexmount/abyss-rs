//! macOS process-context provider backed by the safe sys adapter.

use std::path::PathBuf;

use super::cache::ProcessContextProvider;

pub(super) struct MacOsProcessContextProvider;

impl ProcessContextProvider for MacOsProcessContextProvider {
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

    fn entry_point(&self, pid: u32, pid_version: Option<u32>) -> Option<String> {
        let arguments = crate::sys::process_arguments(pid, pid_version).ok()??;
        super::entry_point::RuntimeEntryPoint::resolve(
            &arguments.executable,
            &arguments
                .argv
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        )
    }
}
