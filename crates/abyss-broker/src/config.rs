//! Static startup configuration owned by `abyss-broker`.
//!
//! The startup file deliberately excludes MITM and Harness usage policy. Those
//! policies are runtime state managed through the broker REST API. This module
//! owns only developer diagnostics, CA location, and proxy selection.

use std::{
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    ingress::{ProxyPlan, explicit::ExplicitIngressEndpoint},
    platform::PlatformAdapter,
};

const BROKER_CONFIG_SCHEMA_VERSION: u32 = 1;
const DEFAULT_EXPLICIT_PROXY_ENDPOINT: &str = "127.0.0.1:0";
const BROKER_CONFIG_FILE_NAME: &str = "broker-config.toml";
#[cfg(target_os = "windows")]
const DEFAULT_WINDOWS_WFP_ENDPOINT: &str = "127.0.0.1:0";
#[cfg(target_os = "macos")]
const DEFAULT_FLOW_SOCKET: &str = "/var/run/abyss/flow.sock";

/// Static broker configuration loaded once during startup.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerConfig {
    /// Developer diagnostics and local reliability controls.
    #[serde(default)]
    pub devtools: DevtoolsConfig,
    /// Externally provisioned MITM CA location.
    #[serde(default)]
    pub ca: CaConfig,
    /// Proxy mode and endpoint settings.
    #[serde(default)]
    pub proxy: ProxyConfig,
}

/// Developer diagnostics configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DevtoolsConfig {
    /// Maximum normal log verbosity.
    #[serde(default)]
    pub log_level: LogLevel,
    /// Whether the separate performance trace is written.
    #[serde(default)]
    pub performance_trace: bool,
    /// Directory containing broker log files.
    #[serde(default)]
    pub log_location: Option<PathBuf>,
}

/// Supported normal log levels.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    /// Emit trace and more severe records.
    Trace,
    /// Emit debug and more severe records.
    Debug,
    /// Emit informational and more severe records.
    #[default]
    Info,
    /// Emit warnings and errors only.
    Warn,
    /// Emit errors only.
    Error,
}

/// Externally provisioned MITM CA configuration.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaConfig {
    /// Directory containing the CA certificate and private key material.
    #[serde(default)]
    pub path: Option<PathBuf>,
}

/// Static proxy settings.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyConfig {
    /// Selected proxy ingress implementation.
    #[serde(default)]
    pub mode: ProxyIngressMode,
    /// Optional loopback endpoint for explicit-proxy ingress.
    #[serde(default)]
    pub listen_addr: Option<SocketAddr>,
    /// Unix socket used by the macOS Network Extension bridge.
    #[serde(default)]
    pub socket_path: Option<PathBuf>,
}

/// Artifact-level proxy ingress choices.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum ProxyIngressMode {
    /// Local HTTP explicit proxy listener.
    Explicit,
    /// macOS Network Extension framed-flow bridge.
    MacosNetworkExtension,
    /// Windows WFP redirected TCP bridge.
    WindowsWfp,
}

/// Errors returned while loading or validating broker config.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BrokerConfigError {
    /// Config file could not be opened.
    #[error("failed to open broker config `{path}`: {source}")]
    File {
        /// Config path that failed.
        path: PathBuf,
        /// Source I/O error.
        #[source]
        source: io::Error,
    },
    /// Config TOML could not be parsed.
    #[error("failed to parse broker config `{path}`: {source}")]
    Toml {
        /// Config path that failed.
        path: PathBuf,
        /// Source TOML error.
        #[source]
        source: toml::de::Error,
    },
    /// A static configuration value was invalid.
    #[error("invalid broker config: {message}")]
    Invalid {
        /// Human-readable validation failure.
        message: String,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BrokerConfigFile {
    schema_version: u32,
    #[serde(default)]
    devtools: DevtoolsConfig,
    #[serde(default)]
    ca: CaConfig,
    #[serde(default)]
    proxy: ProxyConfig,
}

impl Default for DevtoolsConfig {
    fn default() -> Self {
        Self {
            log_level: LogLevel::Info,
            performance_trace: false,
            log_location: None,
        }
    }
}

impl Default for ProxyIngressMode {
    fn default() -> Self {
        Self::platform_default()
    }
}

impl ProxyIngressMode {
    /// Returns the built-in ingress choice for the current artifact.
    #[must_use]
    pub const fn platform_default() -> Self {
        #[cfg(target_os = "macos")]
        {
            Self::MacosNetworkExtension
        }
        #[cfg(target_os = "windows")]
        {
            Self::WindowsWfp
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            Self::Explicit
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Explicit => "explicit",
            Self::MacosNetworkExtension => "macos_network_extension",
            Self::WindowsWfp => "windows_wfp",
        }
    }
}

impl BrokerConfig {
    /// Loads an explicit file, the platform-local default file, or built-ins.
    ///
    /// An explicitly supplied path must exist. When no path is supplied, a
    /// missing platform-local file is the signal to use built-in defaults.
    ///
    /// # Errors
    ///
    /// Returns an error when a selected file cannot be read or validated.
    pub async fn load(
        explicit_path: Option<&Path>,
        platform: &dyn PlatformAdapter,
    ) -> Result<Self, BrokerConfigError> {
        let path = explicit_path.map_or_else(|| Self::default_path(platform), Path::to_path_buf);
        match Self::from_path(&path).await {
            Ok(config) => Ok(config),
            Err(BrokerConfigError::File { source, .. })
                if explicit_path.is_none() && source.kind() == io::ErrorKind::NotFound =>
            {
                Ok(Self::default())
            }
            Err(error) => Err(error),
        }
    }

    /// Returns the platform-local fallback configuration file.
    #[must_use]
    pub fn default_path(platform: &dyn PlatformAdapter) -> PathBuf {
        platform.abyss_home().join(BROKER_CONFIG_FILE_NAME)
    }

    /// Loads one TOML startup file.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read, parsed, or validated.
    pub async fn from_path<P>(path: P) -> Result<Self, BrokerConfigError>
    where
        P: AsRef<Path>,
    {
        let path = path.as_ref();
        let contents =
            tokio::fs::read_to_string(path)
                .await
                .map_err(|source| BrokerConfigError::File {
                    path: path.to_path_buf(),
                    source,
                })?;
        let config = toml::from_str::<BrokerConfigFile>(&contents).map_err(|source| {
            BrokerConfigError::Toml {
                path: path.to_path_buf(),
                source,
            }
        })?;
        if config.schema_version != BROKER_CONFIG_SCHEMA_VERSION {
            return Err(BrokerConfigError::Invalid {
                message: format!(
                    "unsupported schema_version {}; expected {BROKER_CONFIG_SCHEMA_VERSION}",
                    config.schema_version
                ),
            });
        }
        let mut config = Self {
            devtools: config.devtools,
            ca: config.ca,
            proxy: config.proxy,
        };
        config.validate()?;
        config.resolve_relative_paths(path.parent().unwrap_or_else(|| Path::new(".")));
        Ok(config)
    }

    /// Resolves the configured CA directory or the platform-local default.
    #[must_use]
    pub fn ca_path(&self, platform: &dyn PlatformAdapter) -> PathBuf {
        self.ca
            .path
            .clone()
            .unwrap_or_else(|| platform.abyss_home().join("ca"))
    }

    fn validate(&self) -> Result<(), BrokerConfigError> {
        if self
            .ca
            .path
            .as_ref()
            .is_some_and(|path| path.as_os_str().is_empty())
        {
            return Err(BrokerConfigError::Invalid {
                message: "ca.path must not be empty".to_owned(),
            });
        }
        if self
            .devtools
            .log_location
            .as_ref()
            .is_some_and(|path| path.as_os_str().is_empty())
        {
            return Err(BrokerConfigError::Invalid {
                message: "devtools.log_location must not be empty".to_owned(),
            });
        }
        if self
            .proxy
            .socket_path
            .as_ref()
            .is_some_and(|path| path.as_os_str().is_empty())
        {
            return Err(BrokerConfigError::Invalid {
                message: "proxy.socket_path must not be empty".to_owned(),
            });
        }
        if let Some(address) = self.proxy.listen_addr {
            validate_loopback_address(address, "proxy.listen_addr")?;
        }
        self.proxy.validate_shape()?;
        Ok(())
    }

    fn resolve_relative_paths(&mut self, base: &Path) {
        resolve_relative_path(&mut self.ca.path, base);
        resolve_relative_path(&mut self.devtools.log_location, base);
        resolve_relative_path(&mut self.proxy.socket_path, base);
    }
}

impl ProxyConfig {
    /// Resolves this static configuration into a target-supported proxy plan.
    ///
    /// # Errors
    ///
    /// Returns an error when the selected mode is unavailable in this artifact
    /// or its endpoint is invalid.
    pub fn plan(&self) -> Result<ProxyPlan, BrokerConfigError> {
        match self.mode {
            ProxyIngressMode::Explicit => {
                let address = self.listen_addr.unwrap_or_else(|| {
                    DEFAULT_EXPLICIT_PROXY_ENDPOINT
                        .parse()
                        .expect("built-in explicit endpoint should parse")
                });
                validate_loopback_address(address, "proxy.listen_addr")?;
                Ok(ProxyPlan::explicit(ExplicitIngressEndpoint::new(address)))
            }
            ProxyIngressMode::MacosNetworkExtension => {
                #[cfg(target_os = "macos")]
                {
                    let socket = self
                        .socket_path
                        .clone()
                        .unwrap_or_else(|| PathBuf::from(DEFAULT_FLOW_SOCKET));
                    Ok(ProxyPlan::transparent(
                        crate::ingress::platform::TransparentIngressEndpoint::framed_unix(socket),
                    ))
                }
                #[cfg(not(target_os = "macos"))]
                {
                    Err(self.unavailable_mode())
                }
            }
            ProxyIngressMode::WindowsWfp => {
                #[cfg(target_os = "windows")]
                {
                    let address = self.listen_addr.unwrap_or_else(|| {
                        DEFAULT_WINDOWS_WFP_ENDPOINT
                            .parse()
                            .expect("built-in Windows WFP endpoint should parse")
                    });
                    validate_loopback_address(address, "proxy.listen_addr")?;
                    Ok(ProxyPlan::transparent(
                        crate::ingress::platform::TransparentIngressEndpoint::redirected_tcp(
                            address,
                        ),
                    ))
                }
                #[cfg(not(target_os = "windows"))]
                {
                    Err(self.unavailable_mode())
                }
            }
        }
    }

    fn unavailable_mode(&self) -> BrokerConfigError {
        BrokerConfigError::Invalid {
            message: format!(
                "proxy mode `{}` is unavailable in the {} broker artifact",
                self.mode.name(),
                std::env::consts::OS
            ),
        }
    }

    fn validate_shape(&self) -> Result<(), BrokerConfigError> {
        match self.mode {
            ProxyIngressMode::Explicit => {
                if self.socket_path.is_some() {
                    return Err(BrokerConfigError::Invalid {
                        message: "explicit proxy must not configure proxy.socket_path".to_owned(),
                    });
                }
            }
            ProxyIngressMode::MacosNetworkExtension => {
                if self.listen_addr.is_some() {
                    return Err(BrokerConfigError::Invalid {
                        message:
                            "macOS Network Extension proxy must not configure proxy.listen_addr"
                                .to_owned(),
                    });
                }
            }
            ProxyIngressMode::WindowsWfp => {
                if self.listen_addr.is_some() || self.socket_path.is_some() {
                    return Err(BrokerConfigError::Invalid {
                        message: "Windows WFP proxy always uses a dynamic loopback port and must not configure an endpoint"
                            .to_owned(),
                    });
                }
            }
        }
        Ok(())
    }
}

fn validate_loopback_address(
    address: SocketAddr,
    label: &str,
) -> Result<SocketAddr, BrokerConfigError> {
    if !address.ip().is_loopback() {
        return Err(BrokerConfigError::Invalid {
            message: format!("{label} must use a loopback address"),
        });
    }
    Ok(address)
}

fn resolve_relative_path(path: &mut Option<PathBuf>, base: &Path) {
    let Some(value) = path else {
        return;
    };
    if value.is_relative() {
        *value = base.join(&*value);
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{
        BROKER_CONFIG_FILE_NAME, BrokerConfig, BrokerConfigError, LogLevel, ProxyIngressMode,
    };
    use crate::platform::PlatformAdapter;

    struct TestPlatformAdapter {
        home: PathBuf,
    }

    impl TestPlatformAdapter {
        const fn at(home: PathBuf) -> Self {
            Self { home }
        }
    }

    impl PlatformAdapter for TestPlatformAdapter {
        fn abyss_home(&self) -> PathBuf {
            self.home.clone()
        }
    }

    #[tokio::test]
    async fn startup_file_loads_only_static_configuration() {
        let ca_path = std::env::temp_dir().join("abyss-ca");
        let ca_path_literal =
            toml::Value::String(ca_path.to_string_lossy().into_owned()).to_string();
        let contents = format!(
            r#"schema_version = 1

[devtools]
log_level = "debug"
performance_trace = true
log_location = "/tmp/abyss-logs"

[ca]
path = {ca_path_literal}

[proxy]
mode = "explicit"
listen_addr = "127.0.0.1:28999"
"#
        );
        let config = load_temp_config(&contents)
            .await
            .expect("static config should load");

        assert_eq!(config.devtools.log_level, LogLevel::Debug);
        assert!(config.devtools.performance_trace);
        assert_eq!(config.ca.path, Some(ca_path));
        assert_eq!(config.proxy.mode, ProxyIngressMode::Explicit);
    }

    #[tokio::test]
    async fn relative_paths_resolve_from_the_startup_file_directory() {
        let config = load_temp_config(
            r#"schema_version = 1

[devtools]
log_location = "logs"

[ca]
path = "ca"

[proxy]
mode = "macos_network_extension"
socket_path = "run/flow.sock"
"#,
        )
        .await
        .expect("relative paths should load");

        assert_eq!(
            config.devtools.log_location,
            Some(std::env::temp_dir().join("logs"))
        );
        assert_eq!(config.ca.path, Some(std::env::temp_dir().join("ca")));
        assert_eq!(
            config.proxy.socket_path,
            Some(std::env::temp_dir().join("run/flow.sock"))
        );
    }

    #[tokio::test]
    async fn startup_file_rejects_rest_managed_policy_sections() {
        for section in ["mitm", "hooks"] {
            let contents = format!("schema_version = 1\n[{section}]\n");
            let error = load_temp_config(&contents)
                .await
                .expect_err("REST policy must not load from startup config");
            assert!(matches!(error, BrokerConfigError::Toml { .. }));
        }
    }

    #[tokio::test]
    async fn retired_ingress_section_is_rejected() {
        let error = load_temp_config("schema_version = 1\n[ingress]\nmode = \"explicit\"\n")
            .await
            .expect_err("the retired ingress section must not remain a config alias");

        assert!(matches!(error, BrokerConfigError::Toml { .. }));
    }

    #[tokio::test]
    async fn absent_default_file_uses_built_in_defaults() {
        let root = std::env::temp_dir().join(format!(
            "abyss-broker-missing-config-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let platform = TestPlatformAdapter::at(root.clone());
        let config = BrokerConfig::load(None, &platform)
            .await
            .expect("missing local config should use defaults");

        assert_eq!(config.devtools.log_level, LogLevel::Info);
        assert_eq!(config.ca_path(&platform), root.join("ca"));
    }

    #[tokio::test]
    async fn present_platform_local_file_is_loaded_without_cli_path() {
        let root = std::env::temp_dir().join(format!(
            "abyss-broker-default-config-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        tokio::fs::create_dir_all(&root)
            .await
            .expect("default config root should create");
        tokio::fs::write(root.join("config.json"), b"retired startup schema")
            .await
            .expect("retired config should write");
        tokio::fs::write(
            root.join(BROKER_CONFIG_FILE_NAME),
            b"schema_version = 1\n[devtools]\nlog_level = \"warn\"\n[proxy]\nmode = \"explicit\"\n",
        )
        .await
        .expect("default config should write");
        let platform = TestPlatformAdapter::at(root.clone());

        let config = BrokerConfig::load(None, &platform)
            .await
            .expect("current platform-local config should load instead of the retired file");

        assert_eq!(config.devtools.log_level, LogLevel::Warn);
        tokio::fs::remove_dir_all(root)
            .await
            .expect("default config root should clean up");
    }

    #[tokio::test]
    async fn retired_platform_local_file_is_ignored_without_cli_path() {
        let root = std::env::temp_dir().join(format!(
            "abyss-broker-retired-config-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        tokio::fs::create_dir_all(&root)
            .await
            .expect("default config root should create");
        tokio::fs::write(
            root.join("config.json"),
            br#"{"devtools":{"log_level":"warn"},"proxy":{"mode":"explicit"}}"#,
        )
        .await
        .expect("retired config should write");
        let platform = TestPlatformAdapter::at(root.clone());

        let config = BrokerConfig::load(None, &platform)
            .await
            .expect("retired config should not affect current defaults");

        assert_eq!(config.devtools.log_level, LogLevel::Info);
        tokio::fs::remove_dir_all(root)
            .await
            .expect("default config root should clean up");
    }

    #[tokio::test]
    async fn explicit_missing_file_is_an_error() {
        let path = std::env::temp_dir().join(format!(
            "abyss-broker-explicit-missing-{}-{}.toml",
            std::process::id(),
            rand::random::<u64>()
        ));
        let platform = TestPlatformAdapter::at(PathBuf::from("/unused"));
        let error = BrokerConfig::load(Some(&path), &platform)
            .await
            .expect_err("explicit config must exist");

        assert!(matches!(error, BrokerConfigError::File { .. }));
    }

    #[tokio::test]
    async fn retired_audit_destination_is_rejected() {
        let error = load_temp_config(
            "schema_version = 1\n[audit]\nurl = \"https://example.test/events\"\n",
        )
        .await
        .expect_err("the broker must not accept a delivery destination");
        assert!(matches!(error, BrokerConfigError::Toml { .. }));
    }

    #[tokio::test]
    async fn adapter_fields_are_rejected_by_the_broker() {
        let error = load_temp_config(
            "schema_version = 1\ndefault_action = \"pass\"\nrules = []\n[proxy]\nmode = \"explicit\"\n",
        )
        .await
        .expect_err("adapter fields must not enter broker config");

        assert!(matches!(error, BrokerConfigError::Toml { .. }));
    }

    #[tokio::test]
    async fn retired_wrapper_redirect_field_is_rejected() {
        let error = load_temp_config(
            "schema_version = 1\ncore_redirect_endpoint = \"127.0.0.1:19090\"\n[proxy]\nmode = \"windows_wfp\"\n",
        )
        .await
        .expect_err("retired wrapper redirect field must be rejected");

        assert!(matches!(error, BrokerConfigError::Toml { .. }));
    }

    #[tokio::test]
    async fn unknown_top_level_field_is_rejected() {
        let error = load_temp_config(
            "schema_version = 1\n[audti]\nurl = \"https://audit.example.test/v1/events\"\n[proxy]\nmode = \"explicit\"\n",
        )
        .await
        .expect_err("misspelled startup fields must not silently use defaults");

        assert!(matches!(error, BrokerConfigError::Toml { .. }));
    }

    #[test]
    fn explicit_mode_uses_an_ephemeral_loopback_listener_when_omitted() {
        let config = super::ProxyConfig {
            mode: ProxyIngressMode::Explicit,
            ..super::ProxyConfig::default()
        };

        let plan = config
            .plan()
            .expect("explicit proxy should be available on every broker artifact");

        assert_eq!(plan.endpoint_label(), "127.0.0.1:0");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_wfp_mode_uses_an_ephemeral_builtin_listener_when_omitted() {
        let config = super::ProxyConfig {
            mode: ProxyIngressMode::WindowsWfp,
            ..super::ProxyConfig::default()
        };

        let plan = config
            .plan()
            .expect("built-in Windows WFP proxy config should be startable");

        assert_eq!(plan.endpoint_label(), "127.0.0.1:0");
    }

    async fn load_temp_config(contents: &str) -> Result<BrokerConfig, BrokerConfigError> {
        let path = std::env::temp_dir().join(format!(
            "abyss-broker-config-test-{}-{}.toml",
            std::process::id(),
            rand::random::<u64>()
        ));
        tokio::fs::write(&path, contents)
            .await
            .expect("temp config should write");
        let config = BrokerConfig::from_path(&path).await;
        tokio::fs::remove_file(path)
            .await
            .expect("temp config should be removed");
        config
    }
}
