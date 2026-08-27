//! Claude Code configuration for the explicit proxy.
//!
//! Claude Code is a user process, so explicit-proxy setup must be
//! persisted in its user-scoped `~/.claude/settings.json`. This module owns
//! only the Abyss-managed CA environment entry and preserves the rest of the
//! user's settings document. Explicit proxy variables are injected for a
//! launched command or shell, not persisted in Claude Code settings.

use std::{
    collections::BTreeMap,
    fs,
    io::Write as _,
    path::{Path, PathBuf},
};

use chrono::Utc;
use serde_json::{Map, Value, json};

use crate::{error::CliError, filesystem, local_config::LocalConfig, paths::CliPaths, platform};

const ROOT_CERTIFICATE_FILE_NAME: &str = "abyss-root-ca.pem";
const SETTINGS_FILE_NAME: &str = "settings.json";
const MANAGED_BUNDLE_FILE_NAME: &str = "abyss-ca-bundle.pem";
const STATE_FILE_NAME: &str = "abyss-ca-state.json";
const NODE_EXTRA_CA_CERTS: &str = "NODE_EXTRA_CA_CERTS";

/// Result of configuring Claude Code's user settings.
#[derive(Debug)]
pub struct ClaudeCodeConfiguration {
    settings_path: PathBuf,
    bundle_path: PathBuf,
}

impl ClaudeCodeConfiguration {
    /// Returns the settings file that was updated.
    #[must_use]
    pub fn settings_path(&self) -> &Path {
        &self.settings_path
    }

    /// Returns the managed CA bundle used by `NODE_EXTRA_CA_CERTS`.
    #[must_use]
    pub fn bundle_path(&self) -> &Path {
        &self.bundle_path
    }
}

/// Configures Claude Code for the explicit proxy and Abyss CA.
pub struct ClaudeCodeConfigurator {
    claude_directory: PathBuf,
    settings_path: PathBuf,
    managed_bundle_path: PathBuf,
    state_path: PathBuf,
    root_certificate_path: PathBuf,
}

impl ClaudeCodeConfigurator {
    /// Builds a configurator for the current endpoint user.
    pub fn from_paths(paths: &CliPaths) -> Result<Self, CliError> {
        let home = platform::platform_adapter().user_home()?;
        Self::from_home_and_config(&home, &paths.config_file())
    }

    fn from_home_and_config(home: &Path, config_path: &Path) -> Result<Self, CliError> {
        let config = LocalConfig::load(config_path)?;
        let ca_directory = config.ca_path(config_path)?;
        Ok(Self::at(home, &ca_directory))
    }

    /// Builds a configurator at explicit paths for isolated tests.
    fn at(home: &Path, ca_directory: &Path) -> Self {
        let claude_directory = home.join(".claude");
        Self {
            settings_path: claude_directory.join(SETTINGS_FILE_NAME),
            managed_bundle_path: claude_directory.join(MANAGED_BUNDLE_FILE_NAME),
            state_path: claude_directory.join(STATE_FILE_NAME),
            claude_directory,
            root_certificate_path: ca_directory.join(ROOT_CERTIFICATE_FILE_NAME),
        }
    }

    /// Writes the Abyss-managed environment into Claude Code settings.
    pub fn configure(&self) -> Result<ClaudeCodeConfiguration, CliError> {
        let root_certificate = self.read_root_certificate()?;
        let mut settings = self.read_settings()?;
        let environment = self.environment_object(&mut settings)?;
        let previous_environment = Self::previous_environment(environment);
        let previous_ca_bundle = previous_environment
            .get(NODE_EXTRA_CA_CERTS)
            .and_then(Value::as_str);
        let bundle = self.merged_bundle(previous_ca_bundle, &root_certificate)?;

        fs::create_dir_all(&self.claude_directory).map_err(|source| {
            CliError::filesystem(
                "create Claude Code configuration directory",
                &self.claude_directory,
                source,
            )
        })?;
        write_text_atomic(&self.managed_bundle_path, &bundle, 0o644)?;

        environment.insert(
            NODE_EXTRA_CA_CERTS.to_owned(),
            Value::String(self.managed_bundle_path.to_string_lossy().into_owned()),
        );

        let backup_path = self.backup_settings()?;
        write_json_atomic(&self.settings_path, &Value::Object(settings), 0o600)?;
        let state = json!({
            "configured_at": Utc::now().to_rfc3339(),
            "settings_path": self.settings_path,
            "managed_bundle_path": self.managed_bundle_path,
            "previous_environment": previous_environment,
            "backup_path": backup_path,
        });
        write_json_atomic(&self.state_path, &state, 0o600)?;

        Ok(ClaudeCodeConfiguration {
            settings_path: self.settings_path.clone(),
            bundle_path: self.managed_bundle_path.clone(),
        })
    }

    fn read_root_certificate(&self) -> Result<String, CliError> {
        fs::read_to_string(&self.root_certificate_path).map_err(|source| {
            if source.kind() == std::io::ErrorKind::NotFound {
                CliError::InvalidConfiguration(format!(
                    "Abyss root certificate was not found at {}",
                    self.root_certificate_path.display()
                ))
            } else {
                CliError::filesystem(
                    "read Abyss root certificate",
                    &self.root_certificate_path,
                    source,
                )
            }
        })
    }

    fn read_settings(&self) -> Result<Map<String, Value>, CliError> {
        let contents = match fs::read_to_string(&self.settings_path) {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(source) => {
                return Err(CliError::filesystem(
                    "read Claude Code settings",
                    &self.settings_path,
                    source,
                ));
            }
        };
        if contents.trim().is_empty() {
            return Ok(Map::new());
        }
        let value: Value = serde_json::from_str(&contents).map_err(|source| {
            CliError::InvalidConfiguration(format!(
                "Claude Code settings are not valid JSON at {}: {source}",
                self.settings_path.display()
            ))
        })?;
        value.as_object().cloned().ok_or_else(|| {
            CliError::InvalidConfiguration(format!(
                "Claude Code settings must be a JSON object at {}",
                self.settings_path.display()
            ))
        })
    }

    fn environment_object<'a>(
        &self,
        settings: &'a mut Map<String, Value>,
    ) -> Result<&'a mut Map<String, Value>, CliError> {
        if !settings.contains_key("env") {
            settings.insert("env".to_owned(), Value::Object(Map::new()));
        }
        match settings.get_mut("env") {
            Some(Value::Object(environment)) => Ok(environment),
            _ => Err(CliError::InvalidConfiguration(format!(
                "Claude Code settings env field must be a JSON object at {}",
                self.settings_path.display()
            ))),
        }
    }

    fn previous_environment(environment: &Map<String, Value>) -> BTreeMap<String, Value> {
        environment
            .get(NODE_EXTRA_CA_CERTS)
            .cloned()
            .map(|value| BTreeMap::from([(NODE_EXTRA_CA_CERTS.to_owned(), value)]))
            .unwrap_or_default()
    }

    fn merged_bundle(
        &self,
        previous_path: Option<&str>,
        root_certificate: &str,
    ) -> Result<String, CliError> {
        let Some(previous_path) = previous_path
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            return Ok(normalized_pem(root_certificate));
        };
        let previous_path = PathBuf::from(previous_path);
        if !previous_path.is_absolute() {
            return Err(CliError::InvalidConfiguration(format!(
                "Claude Code NODE_EXTRA_CA_CERTS path must be absolute: {}",
                previous_path.display()
            )));
        }
        let previous_contents =
            if previous_path == self.managed_bundle_path && !previous_path.exists() {
                String::new()
            } else {
                fs::read_to_string(&previous_path).map_err(|source| {
                    CliError::filesystem(
                        "read existing Claude Code CA bundle",
                        &previous_path,
                        source,
                    )
                })?
            };
        if contains_certificate(&previous_contents, root_certificate) {
            return Ok(normalized_pem(&previous_contents));
        }
        Ok(format!(
            "{}\n{}",
            normalized_pem(&previous_contents),
            normalized_pem(root_certificate)
        ))
    }

    fn backup_settings(&self) -> Result<Option<PathBuf>, CliError> {
        if !self.settings_path.exists() {
            return Ok(None);
        }
        let timestamp = Utc::now().format("%Y%m%d-%H%M%S");
        let backup_path = self.claude_directory.join(format!(
            "settings.json.abyss-backup-{timestamp}-{}",
            std::process::id()
        ));
        fs::copy(&self.settings_path, &backup_path).map_err(|source| {
            CliError::filesystem("backup Claude Code settings", &backup_path, source)
        })?;
        Ok(Some(backup_path))
    }
}

fn normalized_pem(content: &str) -> String {
    canonical_pem(content).trim().to_owned() + "\n"
}

fn canonical_pem(content: &str) -> String {
    content.replace("\r\n", "\n").replace('\r', "\n")
}

fn contains_certificate(content: &str, certificate: &str) -> bool {
    canonical_pem(content).contains(normalized_pem(certificate).trim())
}

fn write_json_atomic(path: &Path, value: &Value, mode: u32) -> Result<(), CliError> {
    let contents = serde_json::to_vec_pretty(value).map_err(CliError::Json)?;
    write_text_atomic(
        path,
        &format!("{}\n", String::from_utf8_lossy(&contents)),
        mode,
    )
}

fn write_text_atomic(path: &Path, contents: &str, mode: u32) -> Result<(), CliError> {
    let parent = path.parent().ok_or_else(|| {
        CliError::InvalidConfiguration(format!("path has no parent directory: {}", path.display()))
    })?;
    fs::create_dir_all(parent)
        .map_err(|source| CliError::filesystem("create configuration directory", parent, source))?;
    let temporary = parent.join(format!(
        ".{}.tmp-{}",
        path.file_name().unwrap_or_default().to_string_lossy(),
        std::process::id()
    ));
    let result = (|| {
        let mut options = fs::OpenOptions::new();
        options.create_new(true).write(true);
        filesystem::configure_file_creation(&mut options, mode);
        let mut file = options.open(&temporary).map_err(|source| {
            CliError::filesystem("create temporary Claude Code file", &temporary, source)
        })?;
        file.write_all(contents.as_bytes()).map_err(|source| {
            CliError::filesystem("write temporary Claude Code file", &temporary, source)
        })?;
        file.sync_all().map_err(|source| {
            CliError::filesystem("sync temporary Claude Code file", &temporary, source)
        })?;
        filesystem::replace(&temporary, path)
            .map_err(|source| CliError::filesystem("replace Claude Code file", path, source))
    })();
    if result.is_err() {
        drop(fs::remove_file(&temporary));
    }
    result
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;

    use serde_json::Value;

    use super::ClaudeCodeConfigurator;

    static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(0);

    fn test_paths() -> (PathBuf, ClaudeCodeConfigurator) {
        let test_id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "abyss-cli-claude-code-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock should be after Unix epoch")
                .as_nanos(),
            test_id
        ));
        let ca_directory = root.join("abyss/ca");
        fs::create_dir_all(&ca_directory).expect("CA directory should be created");
        fs::write(
            ca_directory.join("abyss-root-ca.pem"),
            "-----BEGIN CERTIFICATE-----\nabyss-root\n-----END CERTIFICATE-----\n",
        )
        .expect("root certificate should be written");
        let configurator = ClaudeCodeConfigurator::at(&root, &ca_directory);
        (root, configurator)
    }

    #[test]
    fn configure_writes_node_ca_environment() {
        let (root, configurator) = test_paths();
        let result = configurator
            .configure()
            .expect("Claude Code settings should configure");
        let settings: Value = serde_json::from_str(
            &fs::read_to_string(result.settings_path()).expect("settings should read"),
        )
        .expect("settings should be valid JSON");
        let environment = settings
            .get("env")
            .and_then(Value::as_object)
            .expect("env should be an object");
        assert_eq!(
            environment["NODE_EXTRA_CA_CERTS"],
            result.bundle_path().to_string_lossy().as_ref()
        );
        assert!(result.bundle_path().exists());
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(result.settings_path())
                .expect("settings metadata should read")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        drop(fs::remove_dir_all(root));
    }

    #[test]
    fn configured_ca_path_selects_the_claude_code_root_certificate() {
        let (root, _) = test_paths();
        let config_directory = root.join("abyss");
        let custom_ca_directory = root.join("managed-ca");
        fs::create_dir_all(&custom_ca_directory).expect("custom CA directory should be created");
        fs::write(
            custom_ca_directory.join("abyss-root-ca.pem"),
            "-----BEGIN CERTIFICATE-----\nmanaged-root\n-----END CERTIFICATE-----\n",
        )
        .expect("custom root certificate should be written");
        fs::write(
            config_directory.join("broker-config.toml"),
            "schema_version = 1\n[ca]\npath = \"../managed-ca\"\n",
        )
        .expect("broker configuration should be written");

        let configurator = ClaudeCodeConfigurator::from_home_and_config(
            &root,
            &config_directory.join("broker-config.toml"),
        )
        .expect("configured CA path should resolve");
        let result = configurator
            .configure()
            .expect("Claude Code settings should configure from the selected CA");
        let bundle = fs::read_to_string(result.bundle_path()).expect("bundle should read");

        assert!(bundle.contains("managed-root"));
        assert!(!bundle.contains("abyss-root"));
        drop(fs::remove_dir_all(root));
    }

    #[test]
    fn configure_preserves_settings_and_is_idempotent() {
        let (root, configurator) = test_paths();
        let settings_path = root.join(".claude/settings.json");
        fs::create_dir_all(
            settings_path
                .parent()
                .expect("settings parent should exist"),
        )
        .expect("settings parent should be created");
        fs::write(
            &settings_path,
            r#"{"theme":"dark","env":{"CUSTOM":"value","HTTPS_PROXY":"http://user-proxy:8080"}}"#,
        )
        .expect("settings should be written");

        let first = configurator
            .configure()
            .expect("first configuration should succeed");
        let first_bundle = fs::read_to_string(first.bundle_path()).expect("bundle should read");
        configurator
            .configure()
            .expect("second configuration should succeed");
        let second_bundle = fs::read_to_string(first.bundle_path()).expect("bundle should read");
        let settings: Value = serde_json::from_str(
            &fs::read_to_string(first.settings_path()).expect("settings should read"),
        )
        .expect("settings should be valid JSON");
        assert_eq!(settings["theme"], "dark");
        assert_eq!(settings["env"]["CUSTOM"], "value");
        assert_eq!(settings["env"]["HTTPS_PROXY"], "http://user-proxy:8080");
        assert_eq!(first_bundle, second_bundle);
        assert!(
            root.join(".claude")
                .read_dir()
                .expect("directory should read")
                .any(|entry| {
                    entry
                        .expect("entry should read")
                        .file_name()
                        .to_string_lossy()
                        .starts_with("settings.json.abyss-backup-")
                })
        );
        drop(fs::remove_dir_all(root));
    }

    #[test]
    fn configure_rejects_non_object_env() {
        let (root, configurator) = test_paths();
        let settings_path = root.join(".claude/settings.json");
        fs::create_dir_all(
            settings_path
                .parent()
                .expect("settings parent should exist"),
        )
        .expect("settings parent should be created");
        fs::write(&settings_path, r#"{"env":[]}"#).expect("settings should be written");
        let error = configurator
            .configure()
            .expect_err("invalid env should be rejected");
        assert!(
            error
                .to_string()
                .contains("env field must be a JSON object")
        );
        drop(fs::remove_dir_all(root));
    }
}
