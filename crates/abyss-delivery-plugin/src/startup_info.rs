//! Product lifecycle readiness record for the official delivery worker.
//!
//! Standalone plugins do not need this file. CLI and Host launchers may request
//! it to distinguish a spawned process from one that completed the broker
//! plugin handshake.

use std::{
    fs,
    io::Write as _,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

use crate::DeliveryPluginError;

const BROKER_STARTUP_INFO_ENV: &str = "ABYSS_BROKER_STARTUP_INFO";

/// Removes a readiness record when the worker that published it exits.
pub struct WorkerStartupInfoGuard {
    path: PathBuf,
    info: WorkerStartupInfo,
}

#[derive(Deserialize, Serialize)]
struct WorkerStartupInfo {
    worker_pid: u32,
    broker_pid: u32,
    control_endpoint: String,
    control_token_file: PathBuf,
}

#[derive(Deserialize)]
struct BrokerStartupInfo {
    pid: u32,
}

impl WorkerStartupInfoGuard {
    /// Resolves the broker identity and publishes product lifecycle readiness.
    ///
    /// An explicit process id is used by lifecycle controllers that already
    /// own the broker process. System process managers can instead provide the
    /// broker startup-info path through `ABYSS_BROKER_STARTUP_INFO`.
    ///
    /// # Errors
    ///
    /// Returns an error when neither identity source exists or when the broker
    /// startup record cannot be read or decoded.
    pub fn publish_for_broker(
        path: &Path,
        broker_pid: Option<u32>,
        control_endpoint: &str,
        control_token_file: &Path,
        group_readable: bool,
    ) -> Result<Self, DeliveryPluginError> {
        let broker_pid = match broker_pid {
            Some(broker_pid) => broker_pid,
            None => Self::read_broker_pid_from_environment()?,
        };
        Self::publish(
            path,
            broker_pid,
            control_endpoint,
            control_token_file,
            group_readable,
        )
    }

    /// Atomically publishes readiness after the plugin handshake succeeds.
    ///
    /// # Errors
    ///
    /// Returns an error when the readiness directory or file cannot be safely
    /// created, written, synchronized, or replaced.
    pub fn publish(
        path: &Path,
        broker_pid: u32,
        control_endpoint: &str,
        control_token_file: &Path,
        group_readable: bool,
    ) -> Result<Self, DeliveryPluginError> {
        let parent = path.parent().ok_or_else(|| {
            Self::io_error(
                "resolve parent for",
                path,
                std::io::Error::other("startup info path has no parent"),
            )
        })?;
        #[cfg(unix)]
        let parent_existed = parent.exists();
        fs::create_dir_all(parent)
            .map_err(|source| Self::io_error("create directory for", parent, source))?;
        #[cfg(unix)]
        if !parent_existed {
            Self::protect_directory(parent)?;
        }

        let info = WorkerStartupInfo {
            worker_pid: std::process::id(),
            broker_pid,
            control_endpoint: control_endpoint.to_owned(),
            control_token_file: control_token_file.to_owned(),
        };
        let body = serde_json::to_vec_pretty(&info).map_err(|source| {
            Self::io_error(
                "encode",
                path,
                std::io::Error::new(std::io::ErrorKind::InvalidData, source),
            )
        })?;
        let temporary = Self::temporary_path(path);
        let result = Self::write_and_replace(path, &temporary, &body, group_readable);
        if result.is_err() {
            drop(fs::remove_file(&temporary));
        }
        result?;
        Ok(Self {
            path: path.to_owned(),
            info,
        })
    }

    fn write_and_replace(
        path: &Path,
        temporary: &Path,
        body: &[u8],
        group_readable: bool,
    ) -> Result<(), DeliveryPluginError> {
        #[cfg(not(unix))]
        let _ = group_readable;
        let mut options = fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        options.mode(if group_readable { 0o640 } else { 0o600 });
        let mut file = options
            .open(temporary)
            .map_err(|source| Self::io_error("create temporary", temporary, source))?;
        file.write_all(body)
            .map_err(|source| Self::io_error("write temporary", temporary, source))?;
        file.write_all(b"\n")
            .map_err(|source| Self::io_error("finish temporary", temporary, source))?;
        file.sync_all()
            .map_err(|source| Self::io_error("sync temporary", temporary, source))?;
        drop(file);
        fs::rename(temporary, path).map_err(|source| Self::io_error("replace", path, source))?;
        #[cfg(unix)]
        Self::protect_file(path, group_readable)?;
        Ok(())
    }

    fn temporary_path(path: &Path) -> PathBuf {
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("delivery-worker-startup.json");
        path.with_file_name(format!(".{file_name}.{}.tmp", std::process::id()))
    }

    fn read_broker_pid_from_environment() -> Result<u32, DeliveryPluginError> {
        let path = std::env::var_os(BROKER_STARTUP_INFO_ENV)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .ok_or(DeliveryPluginError::MissingBrokerIdentity)?;
        Self::read_broker_pid(&path)
    }

    fn read_broker_pid(path: &Path) -> Result<u32, DeliveryPluginError> {
        let body = fs::read(path)
            .map_err(|source| Self::io_error("read broker identity from", path, source))?;
        let info = serde_json::from_slice::<BrokerStartupInfo>(&body).map_err(|source| {
            DeliveryPluginError::DecodeBrokerStartupInfo {
                path: path.to_owned(),
                source,
            }
        })?;
        Ok(info.pid)
    }

    #[cfg(unix)]
    fn protect_directory(path: &Path) -> Result<(), DeliveryPluginError> {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|source| Self::io_error("protect directory for", path, source))
    }

    #[cfg(unix)]
    fn protect_file(path: &Path, group_readable: bool) -> Result<(), DeliveryPluginError> {
        fs::set_permissions(
            path,
            fs::Permissions::from_mode(if group_readable { 0o640 } else { 0o600 }),
        )
        .map_err(|source| Self::io_error("protect", path, source))
    }

    fn io_error(
        operation: &'static str,
        path: impl Into<PathBuf>,
        source: std::io::Error,
    ) -> DeliveryPluginError {
        DeliveryPluginError::StartupInfo {
            operation,
            path: path.into(),
            source,
        }
    }
}

impl Drop for WorkerStartupInfoGuard {
    fn drop(&mut self) {
        let Ok(body) = fs::read(&self.path) else {
            return;
        };
        let Ok(current) = serde_json::from_slice::<WorkerStartupInfo>(&body) else {
            return;
        };
        if current.worker_pid == self.info.worker_pid && current.broker_pid == self.info.broker_pid
        {
            drop(fs::remove_file(&self.path));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
    };

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;
    use tempfile::tempdir;

    use super::{WorkerStartupInfo, WorkerStartupInfoGuard};

    #[test]
    fn publishes_matching_worker_and_broker_identity_then_cleans_up() {
        let directory = tempdir().expect("temporary directory should exist");
        let path = directory.path().join("runtime/worker.json");

        let guard = WorkerStartupInfoGuard::publish(
            &path,
            41,
            "http://127.0.0.1:49152",
            Path::new("/runtime/delivery-control.token"),
            false,
        )
        .expect("worker startup info should publish");
        let info: WorkerStartupInfo =
            serde_json::from_slice(&fs::read(&path).expect("worker startup info should read"))
                .expect("worker startup info should decode");

        assert_eq!(info.worker_pid, std::process::id());
        assert_eq!(info.broker_pid, 41);
        assert_eq!(info.control_endpoint, "http://127.0.0.1:49152");
        assert_eq!(
            info.control_token_file,
            Path::new("/runtime/delivery-control.token")
        );
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&path)
                .expect("startup info metadata should read")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        drop(guard);
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn preserves_permissions_of_a_product_owned_runtime_directory() {
        let directory = tempdir().expect("temporary directory should exist");
        let runtime = directory.path().join("run");
        fs::create_dir(&runtime).expect("runtime directory should exist");
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o750))
            .expect("runtime permissions should be configurable");

        let guard = WorkerStartupInfoGuard::publish(
            &runtime.join("worker.json"),
            41,
            "http://127.0.0.1:49152",
            Path::new("/runtime/delivery-control.token"),
            false,
        )
        .expect("worker startup info should publish");

        assert_eq!(
            fs::metadata(&runtime)
                .expect("runtime metadata should read")
                .permissions()
                .mode()
                & 0o777,
            0o750
        );
        drop(guard);
    }

    #[test]
    fn old_worker_does_not_remove_a_replacement_readiness_record() {
        let directory = tempdir().expect("temporary directory should exist");
        let path = directory.path().join("worker.json");
        let guard = WorkerStartupInfoGuard::publish(
            &path,
            41,
            "http://127.0.0.1:49152",
            Path::new("/runtime/delivery-control.token"),
            false,
        )
        .expect("worker startup info should publish");
        fs::write(
            &path,
            serde_json::to_vec(&WorkerStartupInfo {
                worker_pid: std::process::id(),
                broker_pid: 42,
                control_endpoint: "http://127.0.0.1:49153".to_owned(),
                control_token_file: PathBuf::from("/runtime/replacement.token"),
            })
            .expect("replacement startup info should encode"),
        )
        .expect("replacement startup info should write");

        drop(guard);

        assert!(path.exists());
    }

    #[test]
    fn resolves_broker_identity_from_the_broker_startup_record() {
        let directory = tempdir().expect("temporary directory should exist");
        let broker_path = directory.path().join("broker-startup.json");
        fs::write(&broker_path, r#"{"pid":731,"plugin_endpoint":"test"}"#)
            .expect("broker startup info should write");

        assert_eq!(
            WorkerStartupInfoGuard::read_broker_pid(&broker_path)
                .expect("broker process identity should decode"),
            731
        );
    }
}
