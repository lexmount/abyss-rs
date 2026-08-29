//! Private filesystem state and generated configuration for local deployment.

use std::{
    fs,
    io::{self, Write as _},
    net::{Ipv4Addr, SocketAddrV4},
    path::{Path, PathBuf},
};

use rand::TryRngCore as _;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest as _, Sha256};

use crate::{error::CliError, filesystem, paths::CliPaths};

pub(super) const BACKEND_VERSION: &str = "1.0.0";
pub(super) const DASHBOARD_PACKAGE: &str = "@lexmount.com/abyss-dashboard@0.1.0";
pub(super) const DASHBOARD_VERSION: &str = "0.1.0";
const STATE_SCHEMA_VERSION: u32 = 1;
const PRODUCT_PLUGIN_ID: &str = "lexmount.abyss.local";

#[derive(Clone)]
pub(super) struct LocalPaths {
    root: PathBuf,
}

impl LocalPaths {
    pub(super) fn from_cli(paths: &CliPaths) -> Self {
        Self {
            root: paths.local_deployment_dir(),
        }
    }

    pub(super) fn root(&self) -> &Path {
        &self.root
    }

    pub(super) fn runtime_dir(&self) -> PathBuf {
        self.root.join("runtime")
    }

    pub(super) fn data_dir(&self) -> PathBuf {
        self.root.join("data")
    }

    pub(super) fn run_dir(&self) -> PathBuf {
        self.root.join("run")
    }

    pub(super) fn logs_dir(&self) -> PathBuf {
        self.root.join("logs")
    }

    pub(super) fn database_file(&self) -> PathBuf {
        self.data_dir().join("abyss.sqlite")
    }

    pub(super) fn token_file(&self) -> PathBuf {
        self.root.join("backend.token")
    }

    pub(super) fn authorization_file(&self) -> PathBuf {
        self.root.join("backend.authorization")
    }

    pub(super) fn state_file(&self) -> PathBuf {
        self.root.join("deployment.json")
    }

    pub(super) fn operation_lock_file(&self) -> PathBuf {
        self.run_dir().join("deployment.lock")
    }

    pub(super) fn backend_pid_file(&self) -> PathBuf {
        self.run_dir().join("backend.json")
    }

    pub(super) fn backend_lock_file(&self) -> PathBuf {
        self.run_dir().join("backend.lock")
    }

    pub(super) fn backend_log_file(&self) -> PathBuf {
        self.logs_dir().join("backend.log")
    }

    pub(super) fn dashboard_pid_file(&self) -> PathBuf {
        self.run_dir().join("dashboard.json")
    }

    pub(super) fn dashboard_lock_file(&self) -> PathBuf {
        self.run_dir().join("dashboard.lock")
    }

    pub(super) fn dashboard_log_file(&self) -> PathBuf {
        self.logs_dir().join("dashboard.log")
    }

    pub(super) fn backend_runtime_dir(&self) -> PathBuf {
        self.runtime_dir().join("backend").join(BACKEND_VERSION)
    }

    pub(super) fn dashboard_runtime_dir(&self) -> PathBuf {
        self.runtime_dir().join("dashboard").join(DASHBOARD_VERSION)
    }

    pub(super) fn ensure_directories(&self) -> Result<(), CliError> {
        for path in [
            self.root(),
            &self.runtime_dir(),
            &self.data_dir(),
            &self.run_dir(),
            &self.logs_dir(),
        ] {
            ensure_private_directory(path)?;
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DeploymentState {
    schema_version: u32,
    pub(super) backend_port: u16,
    pub(super) dashboard_port: u16,
    backend_version: String,
    dashboard_package: String,
}

impl DeploymentState {
    pub(super) fn new(backend_port: u16, dashboard_port: u16) -> Self {
        Self {
            schema_version: STATE_SCHEMA_VERSION,
            backend_port,
            dashboard_port,
            backend_version: BACKEND_VERSION.to_owned(),
            dashboard_package: DASHBOARD_PACKAGE.to_owned(),
        }
    }

    pub(super) fn load(paths: &LocalPaths) -> Result<Option<Self>, CliError> {
        let Some(contents) = read_optional_regular_file(&paths.state_file(), "deployment state")?
        else {
            return Ok(None);
        };
        let state = serde_json::from_slice::<Self>(&contents)?;
        if state.schema_version != STATE_SCHEMA_VERSION {
            return Err(CliError::InvalidConfiguration(format!(
                "unsupported local deployment schema_version {}; expected {STATE_SCHEMA_VERSION}",
                state.schema_version
            )));
        }
        if state.backend_port == state.dashboard_port {
            return Err(CliError::InvalidConfiguration(
                "local backend and dashboard ports must differ".to_owned(),
            ));
        }
        Ok(Some(state))
    }

    pub(super) fn uses_current_artifacts(&self) -> bool {
        self.backend_version == BACKEND_VERSION && self.dashboard_package == DASHBOARD_PACKAGE
    }

    pub(super) fn write(&self, paths: &LocalPaths) -> Result<(), CliError> {
        let mut contents = serde_json::to_vec_pretty(self)?;
        contents.push(b'\n');
        atomic_write(&paths.state_file(), &contents, 0o600, "deployment state")
    }

    pub(super) fn backend_url(&self) -> String {
        format!(
            "http://{}",
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, self.backend_port)
        )
    }

    pub(super) fn dashboard_url(&self) -> String {
        format!(
            "http://{}",
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, self.dashboard_port)
        )
    }
}

pub(super) struct LocalCredentials {
    pub(super) token_sha256: String,
}

impl LocalCredentials {
    pub(super) fn ensure(paths: &LocalPaths) -> Result<Self, CliError> {
        let token_path = paths.token_file();
        let token = if let Some(contents) =
            read_optional_regular_file(&token_path, "backend token")?
        {
            validate_token(&contents)?
        } else {
            let mut bytes = [0_u8; 32];
            rand::rngs::OsRng.try_fill_bytes(&mut bytes).map_err(|error| {
                CliError::InvalidConfiguration(format!(
                    "operating-system randomness failed while creating the local backend token: {error}"
                ))
            })?;
            let token = hex::encode(bytes);
            atomic_write(&token_path, token.as_bytes(), 0o600, "backend token")?;
            token
        };
        filesystem::protect(&token_path, 0o600)
            .map_err(|source| CliError::filesystem("protect backend token", &token_path, source))?;
        let authorization = format!("Bearer {token}\n");
        atomic_write(
            &paths.authorization_file(),
            authorization.as_bytes(),
            0o600,
            "backend authorization header",
        )?;
        Ok(Self {
            token_sha256: hex::encode(Sha256::digest(token.as_bytes())),
        })
    }
}

pub(super) fn validate_product_config_ownership(paths: &CliPaths) -> Result<(), CliError> {
    let path = paths.product_config_file();
    let Some(contents) = read_optional_regular_file(&path, "product configuration")? else {
        return Ok(());
    };
    let value = serde_json::from_slice::<serde_json::Value>(&contents)?;
    if value
        .pointer("/delivery_worker/plugin_id")
        .and_then(|id| id.as_str())
        != Some(PRODUCT_PLUGIN_ID)
    {
        return Err(CliError::InvalidConfiguration(format!(
            "{} belongs to another deployment; set ABYSS_HOME to a separate directory",
            path.display()
        )));
    }
    Ok(())
}

pub(super) fn write_product_config(
    cli_paths: &CliPaths,
    local_paths: &LocalPaths,
    state: &DeploymentState,
) -> Result<(), CliError> {
    let value = json!({
        "schema_version": 1_u32,
        "product": {
            "kind": "cli",
            "dashboard": {"url": state.dashboard_url()}
        },
        "delivery_worker": {
            "plugin_id": PRODUCT_PLUGIN_ID,
            "delivery": {
                "endpoint": format!("{}/v1/agent-usage/events", state.backend_url()),
                "spool_enabled": true,
                "spool_path": "local/delivery/failed-events.jsonl"
            },
            "authentication": {
                "mode": "authorization_header_file",
                "path": "local/backend.authorization"
            }
        }
    });
    let mut contents = serde_json::to_vec_pretty(&value)?;
    contents.push(b'\n');
    atomic_write(
        &cli_paths.product_config_file(),
        &contents,
        0o600,
        "product configuration",
    )?;
    filesystem::protect(local_paths.root(), 0o700).map_err(|source| {
        CliError::filesystem(
            "protect local deployment directory",
            local_paths.root(),
            source,
        )
    })
}

pub(super) fn atomic_write(
    path: &Path,
    contents: &[u8],
    mode: u32,
    label: &'static str,
) -> Result<(), CliError> {
    let parent = path.parent().ok_or_else(|| {
        CliError::InvalidConfiguration(format!("{label} path has no parent directory"))
    })?;
    ensure_private_directory(parent)?;
    reject_symlink(path, label)?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            CliError::InvalidConfiguration(format!("{label} path has no UTF-8 file name"))
        })?;
    let temporary = parent.join(format!(".{file_name}.tmp-{}", std::process::id()));
    let result = (|| {
        let mut options = fs::OpenOptions::new();
        options.create_new(true).write(true);
        filesystem::configure_file_creation(&mut options, mode);
        let mut file = options.open(&temporary).map_err(|source| {
            CliError::filesystem("create temporary local deployment file", &temporary, source)
        })?;
        file.write_all(contents).map_err(|source| {
            CliError::filesystem("write temporary local deployment file", &temporary, source)
        })?;
        file.sync_all().map_err(|source| {
            CliError::filesystem("sync temporary local deployment file", &temporary, source)
        })?;
        drop(file);
        filesystem::protect(&temporary, mode).map_err(|source| {
            CliError::filesystem(
                "protect temporary local deployment file",
                &temporary,
                source,
            )
        })?;
        filesystem::replace(&temporary, path)
            .map_err(|source| CliError::filesystem("replace local deployment file", path, source))
    })();
    if result.is_err() {
        drop(fs::remove_file(&temporary));
    }
    result
}

pub(super) fn ensure_private_directory(path: &Path) -> Result<(), CliError> {
    fs::create_dir_all(path).map_err(|source| {
        CliError::filesystem("create local deployment directory", path, source)
    })?;
    reject_symlink(path, "local deployment directory")?;
    if !path.is_dir() {
        return Err(CliError::InvalidConfiguration(format!(
            "local deployment path is not a directory: {}",
            path.display()
        )));
    }
    filesystem::protect(path, 0o700)
        .map_err(|source| CliError::filesystem("protect local deployment directory", path, source))
}

fn validate_token(contents: &[u8]) -> Result<String, CliError> {
    let token = std::str::from_utf8(contents)
        .map_err(|_| CliError::InvalidConfiguration("local backend token is not UTF-8".to_owned()))?
        .trim_end_matches(['\r', '\n']);
    if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(CliError::InvalidConfiguration(
            "local backend token must contain exactly 64 hexadecimal characters".to_owned(),
        ));
    }
    Ok(token.to_owned())
}

fn read_optional_regular_file(
    path: &Path,
    label: &'static str,
) -> Result<Option<Vec<u8>>, CliError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(CliError::InvalidConfiguration(format!(
                "{label} must be a regular non-symlink file: {}",
                path.display()
            )))
        }
        Ok(_) => fs::read(path)
            .map(Some)
            .map_err(|source| CliError::filesystem("read local deployment file", path, source)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(CliError::filesystem(
            "inspect local deployment file",
            path,
            source,
        )),
    }
}

fn reject_symlink(path: &Path, label: &'static str) -> Result<(), CliError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(CliError::InvalidConfiguration(
            format!("{label} must not be a symbolic link: {}", path.display()),
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(CliError::filesystem(
            "inspect local deployment path",
            path,
            source,
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, time::SystemTime};

    use super::{DeploymentState, LocalCredentials, LocalPaths, validate_token};

    fn test_paths(label: &str) -> LocalPaths {
        let nonce = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("test clock should follow Unix epoch")
            .as_nanos();
        LocalPaths {
            root: std::env::temp_dir().join(format!(
                "abyss-deploy-local-config-{label}-{}-{nonce}",
                std::process::id()
            )),
        }
    }

    #[test]
    fn credentials_are_stable_and_private() {
        let paths = test_paths("credentials");
        paths
            .ensure_directories()
            .expect("directories should create");
        let first = LocalCredentials::ensure(&paths).expect("credentials should create");
        let token = fs::read(paths.token_file()).expect("token should read");
        let second = LocalCredentials::ensure(&paths).expect("credentials should be reused");

        assert_eq!(first.token_sha256, second.token_sha256);
        assert_eq!(
            validate_token(&token).expect("token should validate").len(),
            64
        );
        assert!(
            fs::read_to_string(paths.authorization_file())
                .expect("authorization should read")
                .starts_with("Bearer ")
        );
        drop(fs::remove_dir_all(paths.root()));
    }

    #[test]
    fn deployment_state_rejects_equal_ports() {
        let paths = test_paths("state");
        paths
            .ensure_directories()
            .expect("directories should create");
        let invalid = br#"{
            "schema_version": 1,
            "backend_port": 41234,
            "dashboard_port": 41234,
            "backend_version": "1.0.0",
            "dashboard_package": "@lexmount.com/abyss-dashboard@0.1.0"
        }"#;
        super::atomic_write(&paths.state_file(), invalid, 0o600, "test state")
            .expect("state should write");

        let error = DeploymentState::load(&paths).expect_err("equal ports must fail");
        assert!(error.to_string().contains("ports must differ"));
        drop(fs::remove_dir_all(paths.root()));
    }

    #[test]
    fn current_state_round_trips() {
        let paths = test_paths("round-trip");
        paths
            .ensure_directories()
            .expect("directories should create");
        DeploymentState::new(41001, 41002)
            .write(&paths)
            .expect("state should write");

        let loaded = DeploymentState::load(&paths)
            .expect("state should load")
            .expect("state should exist");
        assert!(loaded.uses_current_artifacts());
        assert_eq!(loaded.backend_port, 41001);
        assert_eq!(loaded.dashboard_port, 41002);
        drop(fs::remove_dir_all(paths.root()));
    }
}
