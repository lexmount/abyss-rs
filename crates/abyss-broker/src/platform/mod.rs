//! Compile-time operating-system boundary for broker integration.
//!
//! Broker business modules depend only on the object-safe `PlatformAdapter`
//! contract. Concrete filesystem paths stay in the Linux, macOS, and Windows
//! implementations selected for the current target.

use std::path::PathBuf;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
compile_error!("abyss-broker supports only Linux, macOS, and Windows");

/// Operating-system integration required by the cross-platform broker.
pub trait PlatformAdapter: Send + Sync {
    /// Returns the root directory for broker-owned state.
    fn abyss_home(&self) -> PathBuf;

    /// Returns platform-owned support log files in addition to common broker logs.
    fn platform_support_log_files(&self) -> Vec<PlatformSupportLogFile> {
        Vec::new()
    }
}

/// One platform-specific broker log file exposed in support bundles.
pub struct PlatformSupportLogFile {
    /// Stable file name used in the support bundle response.
    pub name: &'static str,
    /// Absolute path to the platform-owned log file.
    pub path: PathBuf,
}

/// Builds the adapter selected for the current target.
#[cfg(target_os = "linux")]
#[must_use]
pub fn platform_adapter() -> Box<dyn PlatformAdapter> {
    Box::new(linux::LinuxPlatformAdapter)
}

/// Builds the adapter selected for the current target.
#[cfg(target_os = "macos")]
#[must_use]
pub fn platform_adapter() -> Box<dyn PlatformAdapter> {
    Box::new(macos::MacOsPlatformAdapter)
}

/// Builds the adapter selected for the current target.
#[cfg(target_os = "windows")]
#[must_use]
pub fn platform_adapter() -> Box<dyn PlatformAdapter> {
    Box::new(windows::WindowsPlatformAdapter)
}
