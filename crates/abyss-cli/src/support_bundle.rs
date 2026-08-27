//! Endpoint support-bundle collection and ZIP packaging.
//!
//! Broker and CLI logs are materialized as separate redacted files alongside
//! diagnostics, effective configuration, system information, a collection
//! error list, and a manifest. Platform-adapter logs remain outside this
//! CLI-owned bundle.

use std::{
    fs,
    io::{self, Write as _},
    path::{Path, PathBuf},
    sync::OnceLock,
};

use abyss_terminal_auth::CredentialStore;
use chrono::{DateTime, Datelike as _, Timelike as _, Utc};
use regex::Regex;
use serde::Serialize;
use serde_json::{Value, json};

use crate::{
    broker::{BrokerClient, BrokerConnection, ProxyStatusResponse},
    error::CliError,
    filesystem,
    local_config::LocalConfig,
    paths::CliPaths,
    platform,
};

const MAX_BYTES_PER_BROKER_FILE: u64 = 10 * 1024 * 1024;
const MAX_BYTES_PER_CLI_FILE: u64 = 5 * 1024 * 1024;

/// Collects the CLI-owned support bundle.
pub struct SupportBundleCollector {
    paths: CliPaths,
    broker: Option<BrokerConnection>,
    broker_discovery_error: Option<String>,
}

impl SupportBundleCollector {
    /// Creates a collector from the broker discovery outcome.
    ///
    /// Discovery failures are retained as collection errors instead of
    /// preventing local logs and configuration from being packaged.
    #[must_use]
    pub fn new(paths: CliPaths, discovery: Result<Option<BrokerConnection>, CliError>) -> Self {
        let (broker, broker_discovery_error) = match discovery {
            Ok(Some(broker)) => (Some(broker), None),
            Ok(None) => (
                None,
                Some(format!(
                    "broker startup identity was not found at {}",
                    paths.broker_startup_info_file().display()
                )),
            ),
            Err(error) => (None, Some(error.to_string())),
        };
        Self {
            paths,
            broker,
            broker_discovery_error,
        }
    }

    /// Collects component-owned data and writes an endpoint support ZIP.
    ///
    /// The output uses the active platform's POSIX file policy. Individual
    /// broker or diagnostics failures are recorded in `collection-errors.json`
    /// so a partial bundle remains usable.
    pub fn collect(&self, output: Option<PathBuf>) -> Result<PathBuf, CliError> {
        let collected_at = Utc::now();
        let bundle_name = format!("AbyssLogs-{}", collected_at.format("%Y%m%d-%H%M%S"));
        let output =
            output.unwrap_or_else(|| self.paths.logs_dir().join(format!("{bundle_name}.zip")));
        let work_root = std::env::temp_dir().join(format!(
            "abyss-support-{}-{}",
            bundle_name,
            std::process::id()
        ));
        if work_root.exists() {
            fs::remove_dir_all(&work_root).map_err(|source| {
                CliError::filesystem(
                    "remove previous support bundle workspace",
                    &work_root,
                    source,
                )
            })?;
        }
        fs::create_dir_all(&work_root).map_err(|source| {
            CliError::filesystem("create support bundle workspace", &work_root, source)
        })?;
        filesystem::protect(&work_root, 0o700).map_err(|source| {
            CliError::filesystem("protect support bundle workspace", &work_root, source)
        })?;

        let result = self.collect_into(&work_root, &bundle_name, collected_at);
        let archive_result = result.and_then(|()| {
            ZipArchive::from_directory(&work_root, &bundle_name)?.write_to(&output)?;
            filesystem::protect(&output, 0o600).map_err(|source| {
                CliError::filesystem("protect support bundle", &output, source)
            })?;
            Ok(output.clone())
        });
        drop(fs::remove_dir_all(&work_root));
        archive_result
    }

    fn collect_into(
        &self,
        work_root: &Path,
        bundle_name: &str,
        collected_at: DateTime<Utc>,
    ) -> Result<(), CliError> {
        let mut files = Vec::new();
        let mut errors = Vec::new();
        if let Some(error) = &self.broker_discovery_error {
            push_error(
                &mut errors,
                "broker-discovery",
                Some("startup-info.json"),
                error,
            );
        }
        let public = self
            .broker
            .as_ref()
            .map(BrokerConnection::public_client)
            .transpose()?;
        let proxy = public
            .as_ref()
            .and_then(|public| match public.proxy_status() {
                Ok(value) => Some(value),
                Err(error) => {
                    push_error(&mut errors, "diagnostics", Some("proxy"), error.to_string());
                    None
                }
            });
        let broker = match (&public, &self.broker) {
            (Some(public), Some(connection)) if public.health().is_ok() => {
                match connection.authenticated_client() {
                    Ok(broker) => Some(broker),
                    Err(error) => {
                        push_error(&mut errors, "broker", None, error.to_string());
                        None
                    }
                }
            }
            (_, Some(_)) => {
                push_error(&mut errors, "broker", None, "broker health check failed");
                None
            }
            (_, None) => None,
        };

        self.collect_cli_logs(work_root, &mut files, &mut errors)?;
        Self::collect_broker_logs(work_root, broker.as_ref(), &mut files, &mut errors)?;

        let diagnostics = self.collect_diagnostics(
            work_root,
            broker.as_ref(),
            proxy.as_ref(),
            collected_at,
            &mut files,
            &mut errors,
        )?;
        self.collect_runtime_config(
            work_root,
            broker.as_ref(),
            &diagnostics,
            collected_at,
            &mut files,
            &mut errors,
        )?;
        self.write_system_info(work_root, collected_at, &mut files)?;

        let errors_value = serde_json::to_value(&errors).map_err(CliError::Json)?;
        Self::write_json_file(
            work_root,
            "collection-errors.json",
            &errors_value,
            "system",
            &mut files,
        )?;
        let manifest = SupportBundleManifest {
            schema_version: 1_u8,
            bundle_name: bundle_name.to_owned(),
            platform: std::env::consts::OS,
            collected_at: collected_at.to_rfc3339(),
            partial: !errors.is_empty(),
            files,
        };
        let mut manifest_files = Vec::new();
        Self::write_json_file(
            work_root,
            "manifest.json",
            &serde_json::to_value(manifest).map_err(CliError::Json)?,
            "system",
            &mut manifest_files,
        )?;
        Ok(())
    }

    fn collect_cli_logs(
        &self,
        work_root: &Path,
        files: &mut Vec<SupportBundleFileRecord>,
        errors: &mut Vec<SupportBundleCollectionError>,
    ) -> Result<(), CliError> {
        let mut copied = false;
        for name in ["cli.log", "cli.1.log"] {
            let source = self.paths.logs_dir().join(name);
            match read_bounded_text(&source, MAX_BYTES_PER_CLI_FILE) {
                Ok(content) => {
                    let relative_path = Path::new("cli").join(name);
                    Self::write_text_file(
                        work_root,
                        &relative_path,
                        &redact_text(&content),
                        "cli",
                        files,
                    )?;
                    copied = true;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => push_error(errors, "cli", Some(name), error.to_string()),
            }
        }
        if !copied {
            push_error(errors, "cli", None, "No retrievable log file was found.");
        }
        Ok(())
    }

    fn collect_broker_logs(
        work_root: &Path,
        broker: Option<&BrokerClient>,
        files: &mut Vec<SupportBundleFileRecord>,
        errors: &mut Vec<SupportBundleCollectionError>,
    ) -> Result<(), CliError> {
        let Some(broker) = broker else {
            return Ok(());
        };
        let response = match broker.broker_logs(MAX_BYTES_PER_BROKER_FILE) {
            Ok(response) => response,
            Err(error) => {
                push_error(errors, "broker", None, error.to_string());
                return Ok(());
            }
        };
        for file in response.files {
            let relative_path = Path::new("broker").join(safe_file_name(&file.name));
            Self::write_text_file(
                work_root,
                &relative_path,
                &redact_text(&file.content),
                "broker",
                files,
            )?;
        }
        for error in response.errors {
            push_error(errors, "broker", Some(&error.name), &error.error);
        }
        Ok(())
    }

    fn collect_diagnostics(
        &self,
        work_root: &Path,
        broker: Option<&BrokerClient>,
        proxy: Option<&ProxyStatusResponse>,
        collected_at: DateTime<Utc>,
        files: &mut Vec<SupportBundleFileRecord>,
        errors: &mut Vec<SupportBundleCollectionError>,
    ) -> Result<Value, CliError> {
        let broker_state = broker.map_or_else(
            || json!({"available": false}),
            |broker| match broker.diagnostics() {
                Ok(value) => json!({
                    "base_url": self.broker_base_url(),
                    "available": true,
                    "diagnostics": value,
                }),
                Err(error) => {
                    let message = error.to_string();
                    push_error(errors, "diagnostics", Some("state.json"), &message);
                    json!({
                        "base_url": self.broker_base_url(),
                        "available": false,
                        "error": message,
                    })
                }
            },
        );
        let state = json!({
            "schema_version": 1_u8,
            "collected_at": collected_at.to_rfc3339(),
            "platform": std::env::consts::OS,
            "host_app": {
                "package_name": "abyss-cli",
                "package_version": env!("CARGO_PKG_VERSION"),
                "state_root": self.paths.root(),
            },
            "auth": {"status": auth_status(&self.paths)},
            "proxy": proxy,
            "spool": spool_summary(&self.paths),
            "broker": broker_state,
            "network_extension": {"supported": false},
        });
        Self::write_json_file(
            work_root,
            "diagnostics/state.json",
            &state,
            "diagnostics",
            files,
        )?;
        Ok(state)
    }

    fn collect_runtime_config(
        &self,
        work_root: &Path,
        broker: Option<&BrokerClient>,
        diagnostics: &Value,
        collected_at: DateTime<Utc>,
        files: &mut Vec<SupportBundleFileRecord>,
        errors: &mut Vec<SupportBundleCollectionError>,
    ) -> Result<(), CliError> {
        let persisted = match LocalConfig::load(&self.paths.config_file()) {
            Ok(config) => serde_json::to_value(config).map_err(CliError::Json)?,
            Err(error) => {
                push_error(
                    errors,
                    "runtime-config",
                    Some("runtime-config.redacted.json"),
                    error.to_string(),
                );
                Value::Null
            }
        };
        let broker_config = broker.map_or_else(
            || json!({"available": false}),
            |broker| {
                let mitm = match broker.mitm_config() {
                    Ok(config) => match serde_json::to_value(config) {
                        Ok(value) => value,
                        Err(error) => {
                            let message = error.to_string();
                            push_error(errors, "runtime-config", Some("broker.mitm"), &message);
                            json!({"error": message})
                        }
                    },
                    Err(error) => {
                        let message = error.to_string();
                        push_error(errors, "runtime-config", Some("broker.mitm"), &message);
                        json!({"error": message})
                    }
                };
                let hooks = match broker.hooks_config() {
                    Ok(config) => match serde_json::to_value(config) {
                        Ok(value) => value,
                        Err(error) => {
                            let message = error.to_string();
                            push_error(errors, "runtime-config", Some("broker.hooks"), &message);
                            json!({"error": message})
                        }
                    },
                    Err(error) => {
                        let message = error.to_string();
                        push_error(errors, "runtime-config", Some("broker.hooks"), &message);
                        json!({"error": message})
                    }
                };
                json!({"available": true, "mitm": mitm, "hooks": hooks})
            },
        );
        let runtime_config = json!({
            "schema_version": 1_u8,
            "collected_at": collected_at.to_rfc3339(),
            "platform": std::env::consts::OS,
            "host_app": {
                "package_name": "abyss-cli",
                "package_version": env!("CARGO_PKG_VERSION"),
                "state_root": self.paths.root(),
                "config_path": self.paths.config_file(),
            },
            "broker": {
                "base_url": self.broker_base_url(),
                "runtime": broker_config,
                "diagnostics_available": diagnostics
                    .pointer("/broker/available")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            },
            "persisted_config": persisted,
            "network_extension": {"supported": false},
            "errors": errors,
        });
        Self::write_json_file(
            work_root,
            "config/runtime-config.redacted.json",
            &runtime_config,
            "runtime-config",
            files,
        )
    }

    fn write_system_info(
        &self,
        work_root: &Path,
        collected_at: DateTime<Utc>,
        files: &mut Vec<SupportBundleFileRecord>,
    ) -> Result<(), CliError> {
        let text = format!(
            "{}architecture={}\ncli_version={}\nbroker_api={}\nconfig_path={}\nstate_root={}\nhttp_proxy_set={}\nhttps_proxy_set={}\nnode_extra_ca_certs_set={}\nssl_cert_file_set={}\ncollected_at={}\n",
            platform::platform_adapter().system_information(),
            std::env::consts::ARCH,
            env!("CARGO_PKG_VERSION"),
            self.broker_base_url()
                .unwrap_or_else(|| "unavailable".to_owned()),
            self.paths.config_file().display(),
            self.paths.root().display(),
            env_present("HTTP_PROXY", "http_proxy"),
            env_present("HTTPS_PROXY", "https_proxy"),
            env_present("NODE_EXTRA_CA_CERTS", "node_extra_ca_certs"),
            env_present("SSL_CERT_FILE", "ssl_cert_file"),
            collected_at.to_rfc3339(),
        );
        Self::write_text_file(
            work_root,
            Path::new("system-info.txt"),
            &text,
            "system",
            files,
        )
    }

    fn broker_base_url(&self) -> Option<String> {
        self.broker
            .as_ref()
            .map(|broker| format!("http://{}", broker.api_addr()))
    }

    fn write_text_file(
        work_root: &Path,
        relative_path: &Path,
        content: &str,
        source: &str,
        files: &mut Vec<SupportBundleFileRecord>,
    ) -> Result<(), CliError> {
        let path = work_root.join(relative_path);
        let parent = path.parent().ok_or_else(|| {
            CliError::InvalidConfiguration("support file has no parent".to_owned())
        })?;
        fs::create_dir_all(parent).map_err(|source_error| {
            CliError::filesystem("create support bundle directory", parent, source_error)
        })?;
        let mut options = fs::OpenOptions::new();
        options.create_new(true).write(true);
        filesystem::configure_file_creation(&mut options, 0o600);
        let mut file = options.open(&path).map_err(|source_error| {
            CliError::filesystem("create support bundle file", &path, source_error)
        })?;
        file.write_all(content.as_bytes()).map_err(|source_error| {
            CliError::filesystem("write support bundle file", &path, source_error)
        })?;
        files.push(file_record(source, relative_path, byte_len(content.len())));
        Ok(())
    }

    fn write_json_file(
        work_root: &Path,
        relative_path: &str,
        value: &Value,
        source: &str,
        files: &mut Vec<SupportBundleFileRecord>,
    ) -> Result<(), CliError> {
        let redacted = redact_json(value.clone());
        let content = serde_json::to_vec_pretty(&redacted).map_err(CliError::Json)?;
        let path = work_root.join(relative_path);
        let parent = path.parent().ok_or_else(|| {
            CliError::InvalidConfiguration("support file has no parent".to_owned())
        })?;
        fs::create_dir_all(parent).map_err(|source_error| {
            CliError::filesystem("create support bundle directory", parent, source_error)
        })?;
        let mut options = fs::OpenOptions::new();
        options.create_new(true).write(true);
        filesystem::configure_file_creation(&mut options, 0o600);
        let mut file = options.open(&path).map_err(|source_error| {
            CliError::filesystem("create support bundle file", &path, source_error)
        })?;
        file.write_all(&content).map_err(|source_error| {
            CliError::filesystem("write support bundle file", &path, source_error)
        })?;
        files.push(file_record(
            source,
            Path::new(relative_path),
            byte_len(content.len()),
        ));
        Ok(())
    }
}

#[derive(Debug, Serialize)]
struct SupportBundleFileRecord {
    source: String,
    path: String,
    size_bytes: u64,
}

#[derive(Debug, Serialize)]
struct SupportBundleCollectionError {
    source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    file: Option<String>,
    error: String,
}

#[derive(Debug, Serialize)]
struct SupportBundleManifest {
    schema_version: u8,
    bundle_name: String,
    platform: &'static str,
    collected_at: String,
    partial: bool,
    files: Vec<SupportBundleFileRecord>,
}

fn file_record(source: &str, path: &Path, size_bytes: u64) -> SupportBundleFileRecord {
    SupportBundleFileRecord {
        source: source.to_owned(),
        path: path.to_string_lossy().replace('\\', "/"),
        size_bytes,
    }
}

fn byte_len(length: usize) -> u64 {
    u64::try_from(length).unwrap_or(u64::MAX)
}

fn push_error(
    errors: &mut Vec<SupportBundleCollectionError>,
    source: &str,
    file: Option<&str>,
    error: impl Into<String>,
) {
    errors.push(SupportBundleCollectionError {
        source: source.to_owned(),
        file: file.map(str::to_owned),
        error: error.into(),
    });
}

fn auth_status(paths: &CliPaths) -> &'static str {
    let store = crate::credential::CliCredentialStore::from_paths(paths);
    let Ok(store) = store else {
        return "logged_out";
    };
    let Ok(credential) = store.read() else {
        return "logged_out";
    };
    if credential.expires_at <= Utc::now() {
        "expired"
    } else {
        "valid"
    }
}

pub fn spool_summary(paths: &CliPaths) -> Value {
    let path = paths.root().join("delivery").join("failed-events.jsonl");
    let Ok(metadata) = fs::metadata(&path) else {
        return json!({"events": 0, "bytes": 0});
    };
    let events = fs::read_to_string(&path).map_or(0, |content| content.lines().count());
    json!({"events": events, "bytes": metadata.len()})
}

fn read_bounded_text(path: &Path, max_bytes: u64) -> io::Result<String> {
    let bytes = fs::read(path)?;
    let max_bytes = usize::try_from(max_bytes).unwrap_or(usize::MAX);
    let start = bytes.len().saturating_sub(max_bytes);
    Ok(String::from_utf8_lossy(&bytes[start..]).into_owned())
}

fn env_present(primary: &str, fallback: &str) -> bool {
    std::env::var_os(primary).is_some() || std::env::var_os(fallback).is_some()
}

fn safe_file_name(value: &str) -> String {
    let name = Path::new(value)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("broker.log");
    if name.is_empty() {
        "broker.log".to_owned()
    } else {
        name.to_owned()
    }
}

fn redaction_patterns() -> &'static [(Regex, &'static str)] {
    static PATTERNS: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        vec![
            (
                Regex::new(r"(?i)(Authorization\s*:\s*Bearer\s+)[^\s]+")
                    .expect("authorization redaction pattern should compile"),
                "$1<redacted>",
            ),
            (
                Regex::new(r"(?i)(Cookie\s*:\s*)[^\n\r]+")
                    .expect("cookie redaction pattern should compile"),
                "$1<redacted>",
            ),
            (
                Regex::new(r"(?i)(Set-Cookie\s*:\s*)[^\n\r]+")
                    .expect("set-cookie redaction pattern should compile"),
                "$1<redacted>",
            ),
            (
                Regex::new(r"(?i)(access_token=)[^&\s]+")
                    .expect("access token redaction pattern should compile"),
                "$1<redacted>",
            ),
            (
                Regex::new(r"(?i)(refresh_token=)[^&\s]+")
                    .expect("refresh token redaction pattern should compile"),
                "$1<redacted>",
            ),
            (
                Regex::new(r"(?i)(id_token=)[^&\s]+")
                    .expect("id token redaction pattern should compile"),
                "$1<redacted>",
            ),
            (
                Regex::new(r"(?i)(client_secret=)[^&\s]+")
                    .expect("client secret redaction pattern should compile"),
                "$1<redacted>",
            ),
            (
                Regex::new(r"(?i)(password=)[^&\s]+")
                    .expect("password redaction pattern should compile"),
                "$1<redacted>",
            ),
        ]
    })
}

fn redact_text(input: &str) -> String {
    redaction_patterns()
        .iter()
        .fold(input.to_owned(), |value, (pattern, replacement)| {
            pattern.replace_all(&value, *replacement).into_owned()
        })
}

fn redact_json(value: Value) -> Value {
    redact_json_value(value)
}

fn redact_json_value(value: Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .into_iter()
                .map(|(key, value)| {
                    let value = if is_sensitive_key(&key) {
                        Value::String("<redacted>".to_owned())
                    } else {
                        redact_json_value(value)
                    };
                    (key, value)
                })
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.into_iter().map(redact_json_value).collect()),
        Value::String(value) => Value::String(redact_text(&value)),
        value => value,
    }
}

fn is_sensitive_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase();
    [
        "api_key",
        "apikey",
        "authorization",
        "client_secret",
        "cookie",
        "id_token",
        "password",
        "refresh_token",
        "secret",
        "token",
    ]
    .iter()
    .any(|fragment| normalized.contains(fragment))
}

struct ZipArchive {
    entries: Vec<(String, Vec<u8>)>,
}

impl ZipArchive {
    fn from_directory(root: &Path, base_name: &str) -> io::Result<Self> {
        let mut entries = Vec::new();
        collect_files(root, Path::new(""), base_name, &mut entries)?;
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(Self { entries })
    }

    #[expect(
        clippy::too_many_lines,
        reason = "ZIP record encoding remains together to keep the archive format auditable"
    )]
    fn write_to(&self, destination: &Path) -> Result<(), CliError> {
        let parent = destination
            .parent()
            .filter(|path| !path.as_os_str().is_empty());
        if let Some(parent) = parent {
            fs::create_dir_all(parent).map_err(|source| {
                CliError::filesystem("create support bundle directory", parent, source)
            })?;
        }
        let temporary = destination.with_extension(format!("tmp-{}", std::process::id()));
        let result = (|| -> io::Result<()> {
            let mut archive = Vec::new();
            let mut central_directory = Vec::new();
            let timestamp = dos_timestamp(Utc::now());
            for (path, content) in &self.entries {
                let name = path.as_bytes();
                let size = u32::try_from(content.len()).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "support file exceeds ZIP limit",
                    )
                })?;
                let name_length = u16::try_from(name.len()).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "support path exceeds ZIP limit",
                    )
                })?;
                let offset = u32::try_from(archive.len()).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "support archive exceeds ZIP limit",
                    )
                })?;
                let checksum = crc32(content);
                append_u32(&mut archive, 0x0403_4B50);
                append_u16(&mut archive, 20);
                append_u16(&mut archive, 0);
                append_u16(&mut archive, 0);
                append_u16(&mut archive, timestamp.0);
                append_u16(&mut archive, timestamp.1);
                append_u32(&mut archive, checksum);
                append_u32(&mut archive, size);
                append_u32(&mut archive, size);
                append_u16(&mut archive, name_length);
                append_u16(&mut archive, 0);
                archive.extend_from_slice(name);
                archive.extend_from_slice(content);
                central_directory.push((path, checksum, size, offset, name_length));
            }
            let central_offset = u32::try_from(archive.len()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "support archive exceeds ZIP limit",
                )
            })?;
            for (path, checksum, size, offset, name_length) in &central_directory {
                append_u32(&mut archive, 0x0201_4B50);
                append_u16(&mut archive, 20);
                append_u16(&mut archive, 20);
                append_u16(&mut archive, 0);
                append_u16(&mut archive, 0);
                append_u16(&mut archive, timestamp.0);
                append_u16(&mut archive, timestamp.1);
                append_u32(&mut archive, *checksum);
                append_u32(&mut archive, *size);
                append_u32(&mut archive, *size);
                append_u16(&mut archive, *name_length);
                append_u16(&mut archive, 0);
                append_u16(&mut archive, 0);
                append_u16(&mut archive, 0);
                append_u16(&mut archive, 0);
                append_u32(&mut archive, 0);
                append_u32(&mut archive, *offset);
                archive.extend_from_slice(path.as_bytes());
            }
            let central_size = u32::try_from(archive.len())
                .ok()
                .and_then(|length| length.checked_sub(central_offset))
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "support archive exceeds ZIP limit",
                    )
                })?;
            let entry_count = u16::try_from(central_directory.len()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "too many support files")
            })?;
            append_u32(&mut archive, 0x0605_4B50);
            append_u16(&mut archive, 0);
            append_u16(&mut archive, 0);
            append_u16(&mut archive, entry_count);
            append_u16(&mut archive, entry_count);
            append_u32(&mut archive, central_size);
            append_u32(&mut archive, central_offset);
            append_u16(&mut archive, 0);
            let mut options = fs::OpenOptions::new();
            options.create_new(true).write(true);
            filesystem::configure_file_creation(&mut options, 0o600);
            let mut file = options.open(&temporary)?;
            file.write_all(&archive)?;
            file.sync_all()?;
            filesystem::replace(&temporary, destination)
        })();
        if result.is_err() {
            drop(fs::remove_file(&temporary));
        }
        result.map_err(|source| CliError::filesystem("write support bundle", destination, source))
    }
}

fn collect_files(
    root: &Path,
    relative: &Path,
    base_name: &str,
    entries: &mut Vec<(String, Vec<u8>)>,
) -> io::Result<()> {
    let directory = root.join(relative);
    let mut children = fs::read_dir(directory)?.collect::<Result<Vec<_>, io::Error>>()?;
    children.sort_by_key(std::fs::DirEntry::file_name);
    for child in children {
        let child_relative = relative.join(child.file_name());
        let file_type = child.file_type()?;
        if file_type.is_dir() {
            collect_files(root, &child_relative, base_name, entries)?;
        } else if !file_type.is_symlink() {
            let archive_path = format!(
                "{base_name}/{}",
                child_relative.to_string_lossy().replace('\\', "/")
            );
            entries.push((archive_path, fs::read(child.path())?));
        }
    }
    Ok(())
}

fn append_u16(buffer: &mut Vec<u8>, value: u16) {
    buffer.extend_from_slice(&value.to_le_bytes());
}

fn append_u32(buffer: &mut Vec<u8>, value: u32) {
    buffer.extend_from_slice(&value.to_le_bytes());
}

fn dos_timestamp(timestamp: DateTime<Utc>) -> (u16, u16) {
    let year = u16::try_from(
        timestamp
            .year()
            .saturating_sub(1980_i32)
            .clamp(0_i32, 127_i32),
    )
    .unwrap_or(0_u16);
    let hour = u16::try_from(timestamp.hour()).unwrap_or(0_u16);
    let minute = u16::try_from(timestamp.minute()).unwrap_or(0_u16);
    let second = u16::try_from(timestamp.second()).unwrap_or(0_u16);
    let month = u16::try_from(timestamp.month()).unwrap_or(0_u16);
    let day = u16::try_from(timestamp.day()).unwrap_or(0_u16);
    let time = (hour << 11_u16) | (minute << 5_u16) | (second >> 1_u16);
    let date = (year << 9_u16) | (month << 5_u16) | day;
    (time, date)
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFF_u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0_u8..8_u8 {
            crc = if crc & 1_u32 == 1_u32 {
                0xEDB8_8320_u32 ^ (crc >> 1_u32)
            } else {
                crc >> 1_u32
            };
        }
    }
    crc ^ 0xFFFF_FFFF_u32
}

#[cfg(test)]
mod tests {
    use super::{ZipArchive, redact_json, redact_text};

    #[test]
    fn redacts_text_credentials() {
        let value =
            redact_text("Authorization: Bearer abc Cookie: abyss_session=secret password=hidden");
        assert!(!value.contains("abc"));
        assert!(!value.contains("secret"));
        assert!(!value.contains("hidden"));
        assert!(value.contains("<redacted>"));
    }

    #[test]
    fn redacts_sensitive_json_keys() {
        let value = redact_json(serde_json::json!({
            "token": "secret",
            "nested": {"authorization_header": "Bearer secret"},
            "safe": "value"
        }));
        assert_eq!(value["token"], "<redacted>");
        assert_eq!(value["nested"]["authorization_header"], "<redacted>");
        assert_eq!(value["safe"], "value");
    }

    #[test]
    fn zip_writer_includes_base_directory_and_stored_files() {
        let root =
            std::env::temp_dir().join(format!("abyss-support-zip-test-{}", std::process::id()));
        std::fs::create_dir_all(root.join("broker")).expect("test directory should create");
        std::fs::write(root.join("broker/abyss-broker.log"), "log").expect("test log should write");
        let archive =
            ZipArchive::from_directory(&root, "AbyssLogs-test").expect("archive should build");
        let destination = root.with_extension("zip");
        archive
            .write_to(&destination)
            .expect("archive should write");
        let bytes = std::fs::read(&destination).expect("archive should read");
        assert!(bytes.starts_with(b"PK\x03\x04"));
        assert!(
            bytes
                .windows(b"broker/abyss-broker.log".len())
                .any(|window| { window == b"broker/abyss-broker.log" })
        );
        drop(std::fs::remove_file(destination));
        drop(std::fs::remove_dir_all(root));
    }
}
