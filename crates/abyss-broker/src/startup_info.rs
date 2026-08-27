//! Startup handoff file for dynamically addressed broker processes.
//!
//! Production launchd/SCM deployments can use fixed API and token paths. This
//! module supports CLI- and host-launched runs where the broker binds port `0`
//! and reports the concrete REST endpoint to its lifecycle controller.

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

use serde::Serialize;
use tokio::{fs, io::AsyncWriteExt as _};

use crate::error::BrokerError;

/// Machine-readable startup information written after the REST listener binds.
pub struct StartupInfo {
    api_addr: SocketAddr,
    auth_token_file: PathBuf,
    plugin_endpoint: String,
    pid: u32,
}

#[derive(Serialize)]
struct StartupInfoFile<'a> {
    api_addr: String,
    auth_token_file: &'a str,
    plugin_endpoint: &'a str,
    pid: u32,
}

impl StartupInfo {
    /// Creates startup information for the currently running broker process.
    #[must_use]
    pub fn new(api_addr: SocketAddr, auth_token_file: PathBuf, plugin_endpoint: String) -> Self {
        Self {
            api_addr,
            auth_token_file,
            plugin_endpoint,
            pid: std::process::id(),
        }
    }

    /// Writes the startup information JSON atomically to `path`.
    ///
    /// # Errors
    ///
    /// Returns an error when parent directory creation, JSON serialization, file
    /// writing, syncing, or replacement fails.
    pub async fn write_to(&self, path: &Path) -> Result<(), BrokerError> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).await.map_err(|source| {
                BrokerError::io("create broker startup info directory", source)
            })?;
        }

        let auth_token_file = self.auth_token_file.to_string_lossy();
        let payload = StartupInfoFile {
            api_addr: self.api_addr.to_string(),
            auth_token_file: &auth_token_file,
            plugin_endpoint: &self.plugin_endpoint,
            pid: self.pid,
        };
        let body = serde_json::to_vec_pretty(&payload)
            .map_err(|source| BrokerError::StartupInfo { source })?;
        let temporary_path = temporary_path_for(path);

        let write_result = match write_file(&temporary_path, &body).await {
            Ok(()) => fs::rename(&temporary_path, path)
                .await
                .map_err(|source| BrokerError::io("replace broker startup info file", source)),
            Err(error) => Err(error),
        };
        if write_result.is_err() {
            drop(fs::remove_file(&temporary_path).await);
        }
        write_result
    }
}

fn temporary_path_for(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("startup-info.json");
    path.with_file_name(format!(".{file_name}.{}.tmp", std::process::id()))
}

async fn write_file(path: &Path, body: &[u8]) -> Result<(), BrokerError> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .await
        .map_err(|source| BrokerError::io("create broker startup info file", source))?;
    file.write_all(body)
        .await
        .map_err(|source| BrokerError::io("write broker startup info file", source))?;
    file.write_all(b"\n")
        .await
        .map_err(|source| BrokerError::io("finish broker startup info file", source))?;
    file.sync_all()
        .await
        .map_err(|source| BrokerError::io("sync broker startup info file", source))
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use serde::Deserialize;

    use super::{StartupInfo, temporary_path_for};

    #[derive(Deserialize)]
    struct StartupInfoFixture {
        api_addr: String,
        auth_token_file: String,
        plugin_endpoint: String,
        pid: u32,
    }

    #[tokio::test]
    async fn writes_startup_info_json_with_bound_addr_and_token_path() {
        let directory = std::env::temp_dir().join(format!(
            "abyss-startup-info-test-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let path = directory.join("startup.json");
        let api_addr: SocketAddr = "127.0.0.1:18190"
            .parse()
            .expect("test socket address should parse");
        let auth_token_file = directory.join("broker.token");
        tokio::fs::create_dir_all(&directory)
            .await
            .expect("startup info test directory should create");
        tokio::fs::write(&path, b"stale startup info")
            .await
            .expect("stale startup info should write");
        StartupInfo::new(
            api_addr,
            auth_token_file.clone(),
            "/tmp/abyss/runtime/broker-plugin-v1.sock".to_owned(),
        )
        .write_to(&path)
        .await
        .expect("startup info should write");

        let bytes = tokio::fs::read(&path)
            .await
            .expect("startup info file should be readable");
        let parsed: StartupInfoFixture =
            serde_json::from_slice(&bytes).expect("startup info should parse");
        assert_eq!(parsed.api_addr, "127.0.0.1:18190");
        assert_eq!(parsed.auth_token_file, auth_token_file.to_string_lossy());
        assert_eq!(
            parsed.plugin_endpoint,
            "/tmp/abyss/runtime/broker-plugin-v1.sock"
        );
        assert_eq!(parsed.pid, std::process::id());
        assert!(
            !tokio::fs::try_exists(temporary_path_for(&path))
                .await
                .expect("temporary startup info path should be queryable"),
            "atomic replacement must not leave its temporary file behind"
        );
        tokio::fs::remove_dir_all(directory)
            .await
            .expect("startup info test directory should be removed");
    }

    #[tokio::test]
    async fn removes_temporary_file_when_startup_info_replacement_fails() {
        let directory = std::env::temp_dir().join(format!(
            "abyss-startup-info-failure-test-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let path = directory.join("startup.json");
        tokio::fs::create_dir_all(&path)
            .await
            .expect("conflicting startup info directory should create");
        let temporary_path = temporary_path_for(&path);
        let auth_token_file = directory.join("broker.token");

        let result = StartupInfo::new(
            "127.0.0.1:18190"
                .parse()
                .expect("test socket address should parse"),
            auth_token_file,
            "/tmp/abyss/runtime/broker-plugin-v1.sock".to_owned(),
        )
        .write_to(&path)
        .await;

        assert!(result.is_err(), "replacement over a directory must fail");
        assert!(
            !tokio::fs::try_exists(temporary_path)
                .await
                .expect("temporary startup info path should be queryable"),
            "failed replacement must remove its temporary file"
        );
        tokio::fs::remove_dir_all(directory)
            .await
            .expect("startup info failure test directory should be removed");
    }
}
