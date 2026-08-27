//! CLI ownership of the fixed official delivery worker process.
//!
//! The broker exposes only its generic plugin stream. This module selects,
//! launches, and reuses the worker compiled into the CLI product without
//! exposing plugin management through the public command line.

mod lock;

use std::{
    fs, io,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

#[cfg(unix)]
use std::os::unix::process::CommandExt as _;

use abyss_delivery_plugin::{DeliveryAuthenticationMode, DeliveryAuthenticationState};
use serde::Deserialize;
use serde_json::json;

use self::lock::{WorkerLifetimeLock, WorkerStartLock};
use crate::{broker::BrokerEndpoint, error::CliError, filesystem, paths::CliPaths};

const STARTUP_TIMEOUT: Duration = Duration::from_secs(5);
const STARTUP_POLL_INTERVAL: Duration = Duration::from_millis(100);
const DELIVERY_PLUGIN_PATH_ENV: &str = "ABYSS_DELIVERY_PLUGIN";
const DELIVERY_PLUGIN_LOG_FILE_NAME: &str = "abyss-delivery-plugin.cli.log";

/// Ensures the CLI's compile-time-selected official worker is connected.
pub struct DeliveryWorker;

/// Authenticated connection to the CLI-owned delivery worker control API.
#[derive(Debug)]
pub struct DeliveryConnection {
    client: reqwest::blocking::Client,
    endpoint: reqwest::Url,
    authorization: String,
}

#[derive(Deserialize)]
struct WorkerStartupInfo {
    worker_pid: u32,
    broker_pid: u32,
    control_endpoint: String,
    control_token_file: PathBuf,
}

#[derive(Deserialize)]
struct DeliveryStatusResponse {
    authentication_mode: DeliveryAuthenticationMode,
}

#[derive(Deserialize)]
struct CredentialUpdateResponse {
    authentication_state: DeliveryAuthenticationState,
}

impl DeliveryWorker {
    /// Reuses the worker connected to `broker` or launches the packaged worker.
    pub fn ensure_running(
        paths: &CliPaths,
        broker: &BrokerEndpoint,
    ) -> Result<DeliveryConnection, CliError> {
        let executable = Self::executable_path()?;
        Self::ensure_running_with_executable(paths, broker, &executable)
    }

    fn ensure_running_with_executable(
        paths: &CliPaths,
        broker: &BrokerEndpoint,
        executable: &Path,
    ) -> Result<DeliveryConnection, CliError> {
        let _start_lock = WorkerStartLock::acquire(paths, STARTUP_TIMEOUT)?;
        let started_at = Instant::now();
        loop {
            if let Some(lifetime_lock) = WorkerLifetimeLock::try_acquire(paths)? {
                Self::remove_stale_startup_info(paths)?;
                return Self::launch(paths, broker, executable, lifetime_lock);
            }
            if let Some(info) = Self::read_startup_info(paths)?
                && info.broker_pid == broker.pid()
                && info.worker_pid != 0
            {
                return DeliveryConnection::from_startup_info(paths, &info);
            }
            if started_at.elapsed() >= STARTUP_TIMEOUT {
                return Err(CliError::InvalidConfiguration(format!(
                    "the delivery worker for the previous broker did not exit before starting broker process {}",
                    broker.pid()
                )));
            }
            thread::sleep(STARTUP_POLL_INTERVAL);
        }
    }

    fn launch(
        paths: &CliPaths,
        broker: &BrokerEndpoint,
        executable: &Path,
        lifetime_lock: WorkerLifetimeLock,
    ) -> Result<DeliveryConnection, CliError> {
        let log_path = paths.logs_dir().join(DELIVERY_PLUGIN_LOG_FILE_NAME);
        let (stdout, stderr) = Self::open_log(&log_path)?;
        let mut command = Command::new(executable);
        command
            .arg("--config")
            .arg(paths.product_config_file())
            .arg("--startup-info-file")
            .arg(paths.delivery_worker_startup_info_file())
            .arg("--broker-pid")
            .arg(broker.pid().to_string())
            .arg("--control-token-file")
            .arg(paths.delivery_control_token_file())
            .env("ABYSS_HOME", paths.root())
            .env(
                "ABYSS_BROKER_STARTUP_INFO",
                paths.broker_startup_info_file(),
            )
            .stdin(lifetime_lock.into_stdio())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        #[cfg(unix)]
        command.process_group(0);
        let mut child = command.spawn().map_err(|source| {
            CliError::filesystem("start abyss-delivery-plugin", executable, source)
        })?;
        Self::wait_until_ready(paths, broker.pid(), &log_path, &mut child)
    }

    fn executable_path() -> Result<PathBuf, CliError> {
        if let Some(path) = std::env::var_os(DELIVERY_PLUGIN_PATH_ENV) {
            return Ok(PathBuf::from(path));
        }
        let current_exe = std::env::current_exe()
            .map_err(|source| CliError::filesystem("resolve abyss executable", "abyss", source))?;
        Ok(current_exe.with_file_name(format!(
            "abyss-delivery-plugin{}",
            std::env::consts::EXE_SUFFIX
        )))
    }

    fn open_log(path: &Path) -> Result<(fs::File, fs::File), CliError> {
        let parent = path.parent().ok_or_else(|| {
            CliError::InvalidConfiguration(
                "delivery worker log path has no parent directory".to_owned(),
            )
        })?;
        fs::create_dir_all(parent).map_err(|source| {
            CliError::filesystem("create delivery worker log directory", parent, source)
        })?;
        filesystem::protect(parent, 0o700).map_err(|source| {
            CliError::filesystem("protect delivery worker log directory", parent, source)
        })?;
        let mut options = fs::OpenOptions::new();
        options.create(true).append(true);
        filesystem::configure_file_creation(&mut options, 0o600);
        let stdout = options.open(path).map_err(|source| {
            CliError::filesystem("open delivery worker process log", path, source)
        })?;
        filesystem::protect(path, 0o600).map_err(|source| {
            CliError::filesystem("protect delivery worker process log", path, source)
        })?;
        let stderr = stdout.try_clone().map_err(|source| {
            CliError::filesystem("clone delivery worker process log", path, source)
        })?;
        Ok((stdout, stderr))
    }

    fn wait_until_ready(
        paths: &CliPaths,
        broker_pid: u32,
        log_path: &Path,
        child: &mut Child,
    ) -> Result<DeliveryConnection, CliError> {
        let started_at = Instant::now();
        while started_at.elapsed() < STARTUP_TIMEOUT {
            match Self::read_startup_info(paths) {
                Ok(Some(info))
                    if info.worker_pid == child.id() && info.broker_pid == broker_pid =>
                {
                    return DeliveryConnection::from_startup_info(paths, &info);
                }
                Ok(_) => {}
                Err(error) => {
                    Self::terminate_failed_start(paths, child)?;
                    return Err(error);
                }
            }
            if let Some(status) = child.try_wait().map_err(|source| {
                CliError::filesystem(
                    "poll abyss-delivery-plugin startup",
                    "abyss-delivery-plugin",
                    source,
                )
            })? {
                Self::remove_stale_startup_info(paths)?;
                return Err(CliError::InvalidConfiguration(format!(
                    "abyss-delivery-plugin exited before connecting to the broker: {status}; see {}",
                    log_path.display()
                )));
            }
            thread::sleep(STARTUP_POLL_INTERVAL);
        }
        Self::terminate_failed_start(paths, child)?;
        Err(CliError::InvalidConfiguration(format!(
            "abyss-delivery-plugin did not connect to the broker before the timeout; see {}",
            log_path.display()
        )))
    }

    fn terminate_failed_start(paths: &CliPaths, child: &mut Child) -> Result<(), CliError> {
        match child.kill() {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::InvalidInput => {}
            Err(source) => {
                return Err(CliError::filesystem(
                    "terminate failed abyss-delivery-plugin startup",
                    "abyss-delivery-plugin",
                    source,
                ));
            }
        }
        child.wait().map_err(|source| {
            CliError::filesystem(
                "reap failed abyss-delivery-plugin startup",
                "abyss-delivery-plugin",
                source,
            )
        })?;
        Self::remove_stale_startup_info(paths)
    }

    fn read_startup_info(paths: &CliPaths) -> Result<Option<WorkerStartupInfo>, CliError> {
        let path = paths.delivery_worker_startup_info_file();
        let body = match fs::read(&path) {
            Ok(body) => body,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(CliError::filesystem(
                    "read delivery worker startup info",
                    path,
                    source,
                ));
            }
        };
        serde_json::from_slice(&body).map(Some).map_err(|error| {
            CliError::InvalidConfiguration(format!(
                "delivery worker startup info is invalid at {}: {error}",
                path.display()
            ))
        })
    }

    fn remove_stale_startup_info(paths: &CliPaths) -> Result<(), CliError> {
        let path = paths.delivery_worker_startup_info_file();
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(CliError::filesystem(
                "remove stale delivery worker startup info",
                path,
                source,
            )),
        }
    }

    /// Returns a control connection when a worker readiness record exists.
    pub fn discover(paths: &CliPaths) -> Result<Option<DeliveryConnection>, CliError> {
        Self::read_startup_info(paths)?
            .map(|info| DeliveryConnection::from_startup_info(paths, &info))
            .transpose()
    }
}

impl DeliveryConnection {
    /// Installs or refreshes the CLI SSO credential when managed mode is enabled.
    pub fn set_bearer_if_managed(&self, token: &str, audience: &str) -> Result<(), CliError> {
        if !matches!(
            self.status()?.authentication_mode,
            DeliveryAuthenticationMode::ManagedBearer
        ) {
            return Ok(());
        }
        let response = self
            .request(reqwest::Method::PUT, "/v1/delivery/auth")
            .json(&json!({"bearer_token": token, "audience": audience}))
            .send()
            .map_err(CliError::DeliveryRequest)?;
        let response = Self::success_response("set delivery credential", response)?;
        let update = response
            .json::<CredentialUpdateResponse>()
            .map_err(CliError::DeliveryRequest)?;
        Self::require_active_credential(&update)
    }

    /// Clears the CLI SSO credential when managed mode is enabled.
    pub fn clear_bearer_if_managed(&self) -> Result<(), CliError> {
        if !matches!(
            self.status()?.authentication_mode,
            DeliveryAuthenticationMode::ManagedBearer
        ) {
            return Ok(());
        }
        let response = self
            .request(reqwest::Method::DELETE, "/v1/delivery/auth")
            .send()
            .map_err(CliError::DeliveryRequest)?;
        Self::require_success("clear delivery credential", response)
    }

    fn from_startup_info(paths: &CliPaths, info: &WorkerStartupInfo) -> Result<Self, CliError> {
        if info.control_token_file != paths.delivery_control_token_file() {
            return Err(CliError::InvalidConfiguration(format!(
                "delivery worker advertised an unexpected control token path: {}",
                info.control_token_file.display()
            )));
        }
        let endpoint = reqwest::Url::parse(&info.control_endpoint).map_err(|error| {
            CliError::InvalidConfiguration(format!(
                "delivery worker advertised an invalid control endpoint: {error}"
            ))
        })?;
        if endpoint.scheme() != "http" || endpoint.host_str() != Some("127.0.0.1") {
            return Err(CliError::InvalidConfiguration(
                "delivery worker control endpoint must use IPv4 loopback HTTP".to_owned(),
            ));
        }
        let token = fs::read_to_string(&info.control_token_file).map_err(|source| {
            CliError::filesystem(
                "read delivery worker control token",
                &info.control_token_file,
                source,
            )
        })?;
        let token = token.trim();
        if token.is_empty() {
            return Err(CliError::InvalidConfiguration(
                "delivery worker control token is empty".to_owned(),
            ));
        }
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(CliError::DeliveryRequest)?;
        Ok(Self {
            client,
            endpoint,
            authorization: format!("Bearer {token}"),
        })
    }

    fn status(&self) -> Result<DeliveryStatusResponse, CliError> {
        let response = self
            .request(reqwest::Method::GET, "/v1/delivery/status")
            .send()
            .map_err(CliError::DeliveryRequest)?;
        let response = Self::success_response("read delivery status", response)?;
        response.json().map_err(CliError::DeliveryRequest)
    }

    const fn require_active_credential(update: &CredentialUpdateResponse) -> Result<(), CliError> {
        if matches!(
            update.authentication_state,
            DeliveryAuthenticationState::Configured
        ) {
            return Ok(());
        }
        Err(CliError::DeliveryCredentialRejected)
    }

    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::blocking::RequestBuilder {
        let endpoint = self
            .endpoint
            .join(path)
            .expect("fixed delivery control path should be valid");
        self.client
            .request(method, endpoint)
            .header(reqwest::header::AUTHORIZATION, &self.authorization)
            .header(reqwest::header::ACCEPT, "application/json")
    }

    fn require_success(
        operation: &'static str,
        response: reqwest::blocking::Response,
    ) -> Result<(), CliError> {
        let _ = Self::success_response(operation, response)?;
        Ok(())
    }

    fn success_response(
        operation: &'static str,
        response: reqwest::blocking::Response,
    ) -> Result<reqwest::blocking::Response, CliError> {
        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }
        let body = response
            .text()
            .unwrap_or_else(|_| "response body unavailable".to_owned());
        Err(CliError::DeliveryStatus {
            operation,
            status,
            body: body.chars().take(512).collect(),
        })
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::{
        fs,
        os::unix::fs::PermissionsExt as _,
        path::{Path, PathBuf},
        thread,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };

    use super::{
        CredentialUpdateResponse, DeliveryConnection, DeliveryWorker, WorkerStartupInfo,
        lock::WorkerLifetimeLock,
    };
    use crate::{broker::BrokerEndpoint, paths::CliPaths};

    #[test]
    fn launches_once_and_reuses_worker_ready_for_the_current_broker() {
        let paths = test_paths("reuse");
        let broker = write_broker_startup_info(&paths, 73);
        let worker = write_worker_script(paths.root(), worker_script());
        fs::write(paths.product_config_file(), product_config())
            .expect("delivery configuration should write");

        DeliveryWorker::ensure_running_with_executable(&paths, &broker, &worker)
            .expect("first delivery worker startup should succeed");
        let first = read_worker_startup_info(&paths);
        DeliveryWorker::ensure_running_with_executable(&paths, &broker, &worker)
            .expect("ready delivery worker should be reused");
        let second = read_worker_startup_info(&paths);

        assert_eq!(first.worker_pid, second.worker_pid);
        assert_eq!(first.broker_pid, 73);
        fs::write(paths.root().join("worker.stop"), b"").expect("worker stop marker should write");
        wait_for_worker_exit(&paths);
        fs::remove_dir_all(paths.root()).expect("test root should be removed");
    }

    #[test]
    fn reports_a_worker_that_exits_before_publishing_handshake_readiness() {
        let paths = test_paths("early-exit");
        let broker = write_broker_startup_info(&paths, 74);
        let worker = write_worker_script(paths.root(), "#!/bin/sh\nexit 23\n");
        fs::write(paths.product_config_file(), product_config())
            .expect("delivery configuration should write");

        let error = DeliveryWorker::ensure_running_with_executable(&paths, &broker, &worker)
            .expect_err("an early worker exit should fail bootstrap");

        assert!(error.to_string().contains("exited before connecting"));
        assert!(!paths.delivery_worker_startup_info_file().exists());
        fs::remove_dir_all(paths.root()).expect("test root should be removed");
    }

    #[test]
    fn rejects_a_credential_invalidated_during_spool_replay() {
        let response = serde_json::from_str::<CredentialUpdateResponse>(
            r#"{"authentication_state":"auth_required"}"#,
        )
        .expect("credential update response should decode");

        let error = DeliveryConnection::require_active_credential(&response)
            .expect_err("an invalidated credential should fail synchronization");

        assert!(error.to_string().contains("rejected the credential"));
    }

    const fn worker_script() -> &'static str {
        r#"#!/bin/sh
set -eu
startup_info=""
broker_pid=""
control_token=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --startup-info-file) startup_info=$2; shift 2 ;;
    --broker-pid) broker_pid=$2; shift 2 ;;
    --control-token-file) control_token=$2; shift 2 ;;
    *) shift ;;
  esac
done
printf '%s' 'test-control-token' >"$control_token"
printf '{"worker_pid":%s,"broker_pid":%s,"control_endpoint":"http://127.0.0.1:49152","control_token_file":"%s"}\n' "$$" "$broker_pid" "$control_token" >"$startup_info"
while [ ! -e "$ABYSS_HOME/worker.stop" ]; do
  sleep 0.05
done
rm -f "$startup_info" "$control_token"
"#
    }

    const fn product_config() -> &'static [u8] {
        br#"{
            "schema_version": 1,
            "product": {
                "kind": "cli",
                "control_plane": {"url": "https://example.test/api"}
            },
            "delivery_worker": {}
        }"#
    }

    fn write_worker_script(root: &Path, contents: &str) -> PathBuf {
        let path = root.join("fake-delivery-worker");
        fs::create_dir_all(root).expect("test root should create");
        fs::write(&path, contents).expect("fake delivery worker should write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("fake delivery worker should be executable");
        path
    }

    fn write_broker_startup_info(paths: &CliPaths, pid: u32) -> BrokerEndpoint {
        let startup_info = paths.broker_startup_info_file();
        fs::create_dir_all(
            startup_info
                .parent()
                .expect("broker startup info should have a parent"),
        )
        .expect("runtime directory should create");
        fs::write(
            &startup_info,
            serde_json::to_vec(&serde_json::json!({
                "api_addr": "127.0.0.1:18190",
                "auth_token_file": paths.broker_token_file(),
                "plugin_endpoint": paths.root().join("runtime/plugin.sock"),
                "pid": pid,
            }))
            .expect("broker startup info should encode"),
        )
        .expect("broker startup info should write");
        BrokerEndpoint::discover(paths)
            .expect("broker startup info should be valid")
            .expect("broker startup info should exist")
    }

    fn read_worker_startup_info(paths: &CliPaths) -> WorkerStartupInfo {
        serde_json::from_slice(
            &fs::read(paths.delivery_worker_startup_info_file())
                .expect("worker startup info should read"),
        )
        .expect("worker startup info should decode")
    }

    fn wait_for_worker_exit(paths: &CliPaths) {
        let started_at = Instant::now();
        while started_at.elapsed() < Duration::from_secs(5) {
            if WorkerLifetimeLock::try_acquire(paths)
                .expect("worker lifetime lock should be inspected")
                .is_some()
            {
                assert!(
                    !paths.delivery_worker_startup_info_file().exists(),
                    "worker startup identity should be removed when the worker exits"
                );
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
        panic!("fake delivery worker did not exit before the timeout");
    }

    fn test_paths(label: &str) -> CliPaths {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock should follow Unix epoch")
            .as_nanos();
        CliPaths::at(std::env::temp_dir().join(format!(
            "abyss-cli-delivery-worker-{label}-{}-{nonce}",
            std::process::id()
        )))
    }
}
