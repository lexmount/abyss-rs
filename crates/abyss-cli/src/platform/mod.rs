//! Compile-time operating-system boundary for endpoint CLI integration.
//!
//! Callers depend only on the object-safe `PlatformAdapter` contract. The
//! concrete Linux and macOS implementations remain private and only
//! the implementation for the current target is compiled.

use std::{
    fs, io,
    path::{Path, PathBuf},
};

use abyss_mitm::CaMaterialPersistence;

use crate::{broker::BrokerEndpoint, error::CliError, paths::CliPaths};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("abyss CLI supports only Linux and macOS");

/// Operating-system integration required by the cross-platform CLI.
pub trait PlatformAdapter: Send + Sync {
    /// Returns the platform policy used to persist CLI-owned CA material.
    fn ca_material_persistence(&self) -> &dyn CaMaterialPersistence;

    /// Resolves the CLI-owned state root.
    fn state_root(&self) -> Result<PathBuf, CliError>;

    /// Resolves the current user's home directory.
    fn user_home(&self) -> Result<PathBuf, CliError>;

    /// Configures creation of a CLI-owned file.
    ///
    /// Linux and macOS apply the requested POSIX mode.
    fn configure_file_creation(&self, options: &mut fs::OpenOptions, mode: u32);

    /// Applies the platform's policy to an existing CLI-owned path.
    ///
    /// Linux and macOS apply the requested POSIX mode.
    fn protect_private_path(&self, path: &Path, mode: u32) -> io::Result<()>;

    /// Installs the generated CA with the platform's CLI trust scope.
    fn install_ca_trust(&self, ca_dir: &Path) -> Result<(), CliError>;

    /// Performs the hidden CA installation operation.
    fn install_ca_at(&self, ca_dir: &Path) -> Result<(), CliError>;

    /// Starts or restarts the platform-managed explicit broker.
    fn start_broker(
        &self,
        paths: &CliPaths,
        user: Option<&str>,
        restart: bool,
    ) -> Result<BrokerEndpoint, CliError>;

    /// Discovers the endpoint published by the current CLI-owned broker.
    fn broker_endpoint(&self, paths: &CliPaths) -> Result<Option<BrokerEndpoint>, CliError> {
        BrokerEndpoint::discover(paths)
    }

    /// Stops the platform-managed explicit broker.
    fn stop_broker(&self, paths: &CliPaths, user: Option<&str>) -> Result<(), CliError>;

    /// Renders shell statements for the explicit proxy endpoint.
    fn proxy_environment(&self, proxy_url: &str) -> String;

    /// Returns proxy variables injected into child processes.
    fn proxy_environment_variables(&self, proxy_url: &str) -> Vec<(String, String)>;

    /// Returns platform-specific support metadata.
    fn system_information(&self) -> String;
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

#[cfg(test)]
mod tests {
    use super::{PlatformAdapter, platform_adapter};

    #[test]
    fn factory_returns_the_current_platform_as_a_trait_object() {
        let adapter: Box<dyn PlatformAdapter> = platform_adapter();

        assert!(
            adapter
                .system_information()
                .starts_with(&format!("platform={}\n", std::env::consts::OS))
        );
    }
}
