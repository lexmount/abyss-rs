//! Persisted endpoint CLI startup configuration and runtime policy.
//!
//! The broker startup file contains only process-lifetime settings. Dynamic
//! MITM and hook policy lives in `runtime-policy.toml`, which the broker loads
//! at startup and rewrites after authenticated REST updates.

use std::{
    fs,
    io::Write as _,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    path::{Path, PathBuf},
};

use abyss_agent_hook::HooksConfig;
use abyss_mitm::{TlsDecryptionAction, TlsDecryptionPolicy, TlsDecryptionRule};
use serde::{Deserialize, Serialize};

use crate::{error::CliError, filesystem};

const CONFIG_SCHEMA_VERSION: u32 = 1;
const PACKAGED_BROKER_CONFIG: &str = include_str!("../defaults/broker-config.toml");
const PACKAGED_RUNTIME_POLICY: &str = include_str!("../defaults/runtime-policy.toml");

/// Static broker configuration owned by the endpoint CLI.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalConfig {
    schema_version: u32,
    /// File-managed broker diagnostics settings.
    #[serde(default)]
    pub devtools: LocalDevtoolsConfig,
    /// Existing CA material consumed by the broker.
    #[serde(default)]
    pub ca: LocalCaConfig,
    /// Explicit proxy settings consumed by the broker.
    #[serde(default)]
    pub proxy: LocalProxyConfig,
}

/// Supported broker log filters.
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalLogLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
}

/// Static developer and support settings.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalDevtoolsConfig {
    /// Maximum broker log verbosity.
    #[serde(default)]
    pub log_level: LocalLogLevel,
    /// Whether performance trace output is enabled.
    #[serde(default)]
    pub performance_trace: bool,
    /// Log directory, relative to the startup config when not absolute.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_location: Option<PathBuf>,
}

impl Default for LocalDevtoolsConfig {
    fn default() -> Self {
        Self {
            log_level: LocalLogLevel::Info,
            performance_trace: false,
            log_location: Some(PathBuf::from("logs")),
        }
    }
}

/// Existing broker CA directory.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalCaConfig {
    /// CA directory, relative to the startup config when not absolute.
    #[serde(default = "default_ca_path")]
    pub path: PathBuf,
}

impl Default for LocalCaConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("ca"),
        }
    }
}

/// Cross-platform proxy modes accepted by the shared startup schema.
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalProxyMode {
    #[default]
    Explicit,
    MacosNetworkExtension,
    WindowsWfp,
}

/// Explicit proxy settings persisted in the broker startup file.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalProxyConfig {
    /// Explicit mode is the only mode controlled by the CLI.
    #[serde(default)]
    pub mode: LocalProxyMode,
    /// Loopback address used by the broker, or port zero for automatic choice.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_addr: Option<SocketAddr>,
    /// Reserved platform flow socket for non-explicit modes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socket_path: Option<PathBuf>,
}

impl Default for LocalProxyConfig {
    fn default() -> Self {
        Self {
            mode: LocalProxyMode::Explicit,
            listen_addr: None,
            socket_path: None,
        }
    }
}

/// Dynamic broker policy persisted separately from startup settings.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalRuntimePolicy {
    schema_version: u32,
    /// TLS policy used by the explicit ingress.
    #[serde(default)]
    pub mitm: LocalMitmConfig,
    /// Dynamic Harness usage policy.
    #[serde(default)]
    pub hooks: HooksConfig,
}

/// Product defaults for broker-owned MITM behavior.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalMitmConfig {
    /// Domain- and process-based TLS decryption policy.
    #[serde(default)]
    pub tls_decryption: TlsDecryptionPolicy,
}

impl Default for LocalMitmConfig {
    fn default() -> Self {
        Self {
            tls_decryption: packaged_default_tls_decryption_policy(),
        }
    }
}

impl Default for LocalConfig {
    fn default() -> Self {
        Self {
            schema_version: CONFIG_SCHEMA_VERSION,
            devtools: LocalDevtoolsConfig::default(),
            ca: LocalCaConfig::default(),
            proxy: LocalProxyConfig::default(),
        }
    }
}

impl Default for LocalRuntimePolicy {
    fn default() -> Self {
        Self {
            schema_version: CONFIG_SCHEMA_VERSION,
            mitm: LocalMitmConfig::default(),
            hooks: HooksConfig::default(),
        }
    }
}

impl LocalConfig {
    /// Reads a static configuration file using current defaults when absent.
    pub fn load(path: &Path) -> Result<Self, CliError> {
        let config: Self = load_toml_or_packaged(path, PACKAGED_BROKER_CONFIG)?;
        config.validate_schema("broker")?;
        Ok(config)
    }

    /// Resolves the broker CA directory exactly as the shared startup loader does.
    pub(crate) fn ca_path(&self, config_path: &Path) -> Result<PathBuf, CliError> {
        if self.ca.path.as_os_str().is_empty() {
            return Err(CliError::InvalidConfiguration(
                "ca.path must not be empty".to_owned(),
            ));
        }
        if self.ca.path.is_absolute() {
            return Ok(self.ca.path.clone());
        }
        Ok(config_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(&self.ca.path))
    }

    /// Selects an explicitly requested proxy port and reports whether it changed.
    pub(crate) fn set_explicit_proxy_port(&mut self, requested_port: u16) -> bool {
        let desired = loopback_proxy_listen_addr(requested_port);
        if self.proxy.listen_addr == Some(desired) {
            return false;
        }
        self.proxy.listen_addr = Some(desired);
        true
    }

    /// Rejects transparent proxy modes at the CLI boundary.
    pub(crate) fn require_explicit_mode(&self) -> Result<(), CliError> {
        if matches!(&self.proxy.mode, LocalProxyMode::Explicit) {
            return Ok(());
        }
        Err(CliError::InvalidConfiguration(
            "the Abyss CLI supports only proxy.mode=explicit".to_owned(),
        ))
    }

    /// Writes the static configuration atomically using the platform file policy.
    pub fn write(&self, path: &Path) -> Result<(), CliError> {
        write_state_toml(self, path)
    }

    fn validate_schema(&self, label: &str) -> Result<(), CliError> {
        if self.schema_version == CONFIG_SCHEMA_VERSION {
            return Ok(());
        }
        Err(CliError::InvalidConfiguration(format!(
            "unsupported {label} schema_version {}; expected {CONFIG_SCHEMA_VERSION}",
            self.schema_version
        )))
    }
}

impl LocalRuntimePolicy {
    /// Reads runtime policy using current product defaults when absent.
    pub fn load(path: &Path) -> Result<Self, CliError> {
        let policy: Self = load_toml_or_packaged(path, PACKAGED_RUNTIME_POLICY)?;
        policy.validate_schema()?;
        Ok(policy)
    }

    /// Writes the runtime policy atomically using the platform file policy.
    pub fn write(&self, path: &Path) -> Result<(), CliError> {
        write_state_toml(self, path)
    }

    fn validate_schema(&self) -> Result<(), CliError> {
        if self.schema_version == CONFIG_SCHEMA_VERSION {
            return Ok(());
        }
        Err(CliError::InvalidConfiguration(format!(
            "unsupported runtime policy schema_version {}; expected {CONFIG_SCHEMA_VERSION}",
            self.schema_version
        )))
    }
}

fn packaged_default_tls_decryption_policy() -> TlsDecryptionPolicy {
    TlsDecryptionPolicy {
        default_action: TlsDecryptionAction::Passthrough,
        missing_sni_action: Some(TlsDecryptionAction::Passthrough),
        rules: vec![
            tls_rule(
                "passthrough-openai-support-services",
                TlsDecryptionAction::Passthrough,
                true,
                &["ab.chatgpt.com"],
            ),
            tls_rule(
                "decrypt-openai-codex",
                TlsDecryptionAction::Intercept,
                true,
                &["openai.com", "*.openai.com", "chatgpt.com", "*.chatgpt.com"],
            ),
            tls_rule(
                "decrypt-anthropic-claude-code",
                TlsDecryptionAction::Intercept,
                true,
                &[
                    "anthropic.com",
                    "*.anthropic.com",
                    "claude.ai",
                    "*.claude.ai",
                ],
            ),
        ],
    }
}

fn tls_rule(
    id: &str,
    action: TlsDecryptionAction,
    enabled: bool,
    destination_hosts: &[&str],
) -> TlsDecryptionRule {
    TlsDecryptionRule {
        id: id.to_owned(),
        enabled,
        action,
        process_names: Vec::new(),
        application_ids: Vec::new(),
        destination_hosts: destination_hosts
            .iter()
            .map(|host| (*host).to_owned())
            .collect(),
    }
}

fn load_toml_or_packaged<T>(path: &Path, packaged: &str) -> Result<T, CliError>
where
    T: for<'de> Deserialize<'de>,
{
    match fs::read_to_string(path) {
        Ok(contents) => toml::from_str(&contents).map_err(CliError::TomlDecode),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            toml::from_str(packaged).map_err(CliError::TomlDecode)
        }
        Err(source) => Err(CliError::filesystem("read configuration", path, source)),
    }
}

fn write_state_toml<T>(value: &T, path: &Path) -> Result<(), CliError>
where
    T: Serialize,
{
    let contents = toml::to_string_pretty(value).map_err(CliError::TomlEncode)?;
    write_state_bytes(contents.as_bytes(), path)
}

/// Writes a CLI-owned configuration file atomically with owner-only permissions.
pub fn write_state_bytes(contents: &[u8], path: &Path) -> Result<(), CliError> {
    let parent = path.parent().ok_or_else(|| {
        CliError::InvalidConfiguration("configuration path must have a parent directory".to_owned())
    })?;
    fs::create_dir_all(parent)
        .map_err(|source| CliError::filesystem("create configuration directory", parent, source))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("configuration");
    let temporary = parent.join(format!(".{file_name}.tmp-{}", std::process::id()));
    let result = (|| {
        let mut options = fs::OpenOptions::new();
        options.create_new(true).write(true);
        filesystem::configure_file_creation(&mut options, 0o600);
        let mut file = options.open(&temporary).map_err(|source| {
            CliError::filesystem("create temporary configuration", &temporary, source)
        })?;
        file.write_all(contents).map_err(|source| {
            CliError::filesystem("write temporary configuration", &temporary, source)
        })?;
        if !contents.ends_with(b"\n") {
            file.write_all(b"\n").map_err(|source| {
                CliError::filesystem("terminate temporary configuration", &temporary, source)
            })?;
        }
        file.sync_all().map_err(|source| {
            CliError::filesystem("sync temporary configuration", &temporary, source)
        })?;
        filesystem::replace(&temporary, path)
            .map_err(|source| CliError::filesystem("replace configuration", path, source))
    })();
    if result.is_err() {
        drop(fs::remove_file(&temporary));
    }
    result
}

fn default_ca_path() -> PathBuf {
    PathBuf::from("ca")
}

const fn loopback_proxy_listen_addr(port: u16) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;

    use super::{LocalConfig, LocalProxyMode, LocalRuntimePolicy};
    use abyss_agent_hook::BuiltInHarness;

    fn test_directory() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock should be after the Unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("abyss-cli-config-{}-{nonce}", std::process::id()))
    }

    #[test]
    fn writes_static_config_with_platform_file_policy() {
        let directory = test_directory();
        let path = directory.join("broker-config.toml");
        let config = LocalConfig::default();

        config.write(&path).expect("configuration should write");
        LocalConfig::load(&path).expect("configuration should load");
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&path)
                .expect("configuration metadata should read")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        drop(fs::remove_dir_all(directory));
    }

    #[test]
    fn rejects_unknown_static_sections() {
        let error = toml::from_str::<LocalConfig>(
            "schema_version = 1\n[devtools]\n[ca]\npath = \"ca\"\n[proxy]\nmode = \"explicit\"\n[audti]\n",
        )
        .expect_err("unknown startup fields must fail closed");

        assert!(error.to_string().contains("audti"));
    }

    #[test]
    fn rejects_the_retired_ingress_section() {
        let error =
            toml::from_str::<LocalConfig>("schema_version = 1\n[ingress]\nmode = \"explicit\"\n")
                .expect_err("the retired ingress section must not remain a config alias");

        assert!(error.to_string().contains("ingress"));
    }

    #[test]
    fn rejects_fields_outside_the_current_static_schema() {
        for (field, contents) in [
            ("mitm", "schema_version = 1\n[mitm]\n"),
            ("hooks", "schema_version = 1\n[hooks]\n"),
            (
                "explicit",
                "schema_version = 1\n[proxy.explicit]\nlisten_addr = \"127.0.0.1:30123\"\n",
            ),
        ] {
            let error = toml::from_str::<LocalConfig>(contents)
                .expect_err("fields outside the current startup schema must not be accepted");
            assert!(
                error.to_string().contains(field),
                "unexpected error for {field}: {error}"
            );
        }
    }

    #[test]
    fn rejects_unknown_runtime_policy_sections() {
        let error = toml::from_str::<LocalRuntimePolicy>("schema_version = 1\n[hook]\n")
            .expect_err("unknown runtime policy fields must fail closed");

        assert!(error.to_string().contains("hook"));
    }

    #[test]
    fn ca_path_matches_broker_relative_and_absolute_resolution() {
        let directory = test_directory();
        let config_path = directory.join("broker-config.toml");
        let mut config = LocalConfig::default();

        assert_eq!(
            config
                .ca_path(&config_path)
                .expect("relative CA path should resolve"),
            directory.join("ca")
        );

        let absolute = directory.join("managed-ca");
        config.ca.path = absolute.clone();
        assert_eq!(
            config
                .ca_path(&config_path)
                .expect("absolute CA path should remain unchanged"),
            absolute
        );
    }

    #[test]
    fn empty_ca_path_is_rejected_before_ca_provisioning() {
        let directory = test_directory();
        let config_path = directory.join("broker-config.toml");
        let mut config = LocalConfig::default();
        config.ca.path = PathBuf::new();

        let error = config
            .ca_path(&config_path)
            .expect_err("empty CA path should be rejected");
        assert!(error.to_string().contains("ca.path must not be empty"));
    }

    #[test]
    fn empty_ca_object_uses_packaged_default_path() {
        let config = toml::from_str::<LocalConfig>("schema_version = 1\n[ca]\n")
            .expect("an omitted ca.path should use the packaged default");

        assert_eq!(config.ca.path, PathBuf::from("ca"));
    }

    #[test]
    fn open_defaults_are_valid_for_the_explicit_cli() {
        let config = toml::from_str::<LocalConfig>(super::PACKAGED_BROKER_CONFIG)
            .expect("open CLI broker default should parse");
        let policy = toml::from_str::<LocalRuntimePolicy>(super::PACKAGED_RUNTIME_POLICY)
            .expect("open CLI runtime policy default should parse");

        config
            .require_explicit_mode()
            .expect("the open CLI default must use explicit proxy mode");
        assert!(matches!(config.proxy.mode, LocalProxyMode::Explicit));
        assert_eq!(config.proxy.listen_addr, None);
        assert_eq!(config.devtools.log_location, Some(PathBuf::from("logs")));
        assert_eq!(config.ca.path, PathBuf::from("ca"));

        policy
            .mitm
            .tls_decryption
            .validate()
            .expect("the production CLI TLS policy must be valid");
        assert!(policy.hooks.harness_usage.enabled);
        assert!(
            policy
                .hooks
                .harness_usage
                .config
                .enabled_for_harness(BuiltInHarness::Codex.id())
        );
        assert!(
            policy
                .hooks
                .harness_usage
                .config
                .enabled_for_harness(BuiltInHarness::ClaudeCode.id())
        );
    }

    #[test]
    fn explicit_listener_omits_the_dynamic_default_and_accepts_custom_port() {
        let mut config = LocalConfig::default();

        assert_eq!(config.proxy.listen_addr, None);
        assert!(config.set_explicit_proxy_port(30123));
        assert_eq!(
            config.proxy.listen_addr,
            Some(
                "127.0.0.1:30123"
                    .parse()
                    .expect("custom address should parse")
            )
        );
        assert!(!config.set_explicit_proxy_port(30123));
    }
}
