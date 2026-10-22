//! Platform boundary for reading a process's executable and tokenized startup arguments.
//!
//! Providers must preserve argument boundaries and exclude environment variables.
//! These transient values are not diagnostics or policy metadata.

use std::io;

/// Native executable identity and decoded argv, including argv[0].
pub struct ProcessArguments {
    pub executable: String,
    pub argv: Vec<String>,
}

/// Reads only process arguments; it does not identify runtimes or resolve scripts.
pub trait ProcessArgumentsProvider: Send + Sync {
    /// A provider must reject undecodable input rather than changing its contents.
    /// Platforms exposing a command-line string must preserve quoting semantics
    /// when converting it to argv; splitting on whitespace is insufficient.
    fn read(&self, pid: u32) -> io::Result<ProcessArguments>;
}

/// Selects the native reader without exposing platform types to the pipeline.
pub fn process_arguments_provider() -> Box<dyn ProcessArgumentsProvider> {
    #[cfg(target_os = "macos")]
    {
        Box::new(super::macos::MacOsProcessArgumentsProvider)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Box::new(UnavailableProcessArgumentsProvider)
    }
}

#[cfg(not(target_os = "macos"))]
struct UnavailableProcessArgumentsProvider;

#[cfg(not(target_os = "macos"))]
impl ProcessArgumentsProvider for UnavailableProcessArgumentsProvider {
    fn read(&self, _pid: u32) -> io::Result<ProcessArguments> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native process argument lookup is not implemented on this platform",
        ))
    }
}

#[cfg(all(test, not(target_os = "macos")))]
mod tests {
    use super::process_arguments_provider;

    #[test]
    fn unavailable_platform_reports_no_arguments() {
        let error = process_arguments_provider()
            .read(std::process::id())
            .err()
            .unwrap();
        assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
    }
}
