//! macOS CLI-owned explicit broker process lifecycle.
//!
//! This controller owns the macOS process boundary, including detached process
//! group setup, CLI broker ownership validation, serialized startup, readiness
//! polling, graceful shutdown, and stale runtime-file cleanup.

mod lifecycle;

use std::{
    fs, io,
    os::unix::process::CommandExt as _,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::Duration,
};

use crate::{
    broker::{BrokerClient, BrokerEndpoint},
    error::CliError,
    filesystem,
    paths::CliPaths,
};

use self::lifecycle::BrokerLifecycleLock;

const STARTUP_TIMEOUT: Duration = Duration::from_secs(5);
const STARTUP_POLL_INTERVAL: Duration = Duration::from_millis(100);
const DYNAMIC_BROKER_API_ENDPOINT: &str = "127.0.0.1:0";
const BROKER_PATH_ENV: &str = "ABYSS_BROKER";
const BROKER_PROCESS_LOG_FILE_NAME: &str = "abyss-broker.cli.log";

/// Controls the explicit broker process owned by the macOS CLI.
pub(super) struct BrokerController;

impl BrokerController {
    /// Starts or reuses the CLI-owned explicit broker process.
    pub(super) fn start(paths: &CliPaths, restart: bool) -> Result<BrokerEndpoint, CliError> {
        let _start_lock = BrokerStartLock::acquire(paths)?;
        match resolve_broker_lifecycle(paths)? {
            BrokerLifecycleState::Existing { endpoint, broker } => {
                if !restart {
                    return Ok(endpoint);
                }
                broker.shutdown()?;
                let lifecycle_lock = wait_until_stopped(paths, &endpoint)?;
                cleanup_failed_start(paths)?;
                launch_broker(paths, lifecycle_lock)
            }
            BrokerLifecycleState::Vacant(lifecycle_lock) => launch_broker(paths, lifecycle_lock),
        }
    }

    /// Stops only a broker authenticated by the CLI-owned token.
    pub(super) fn stop(paths: &CliPaths) -> Result<(), CliError> {
        let _start_lock = BrokerStartLock::acquire(paths)?;
        match resolve_broker_lifecycle(paths)? {
            BrokerLifecycleState::Existing { endpoint, broker } => {
                broker.shutdown()?;
                let _lifecycle_lock = wait_until_stopped(paths, &endpoint)?;
                cleanup_failed_start(paths)
            }
            BrokerLifecycleState::Vacant(_lifecycle_lock) => cleanup_failed_start(paths),
        }
    }
}

fn broker_command(
    paths: &CliPaths,
    broker_path: &Path,
    stdin: Stdio,
    stdout: Stdio,
    stderr: Stdio,
) -> Command {
    let mut command = Command::new(broker_path);
    command
        .arg("--api")
        .arg(DYNAMIC_BROKER_API_ENDPOINT)
        .arg("--config")
        .arg(paths.config_file())
        .arg("--auth-token-file")
        .arg(paths.broker_token_file())
        .arg("--startup-info-file")
        .arg(paths.broker_startup_info_file())
        .env("ABYSS_HOME", paths.root())
        .stdin(stdin)
        .stdout(stdout)
        .stderr(stderr)
        .process_group(0);
    command
}

fn broker_path() -> Result<PathBuf, CliError> {
    if let Some(path) = std::env::var_os(BROKER_PATH_ENV) {
        return Ok(PathBuf::from(path));
    }
    let current_exe = std::env::current_exe()
        .map_err(|source| CliError::filesystem("resolve abyss executable", "abyss", source))?;
    Ok(current_exe.with_file_name(format!("abyss-broker{}", std::env::consts::EXE_SUFFIX)))
}

fn require_healthy_owned_broker(endpoint: &BrokerEndpoint) -> Result<BrokerClient, CliError> {
    endpoint.public_client()?.health()?;
    endpoint.require_owned_explicit()
}

enum BrokerLifecycleState {
    Existing {
        endpoint: BrokerEndpoint,
        broker: BrokerClient,
    },
    Vacant(BrokerLifecycleLock),
}

fn resolve_broker_lifecycle(paths: &CliPaths) -> Result<BrokerLifecycleState, CliError> {
    resolve_broker_lifecycle_with_timeout(paths, STARTUP_TIMEOUT)
}

fn resolve_broker_lifecycle_with_timeout(
    paths: &CliPaths,
    startup_timeout: Duration,
) -> Result<BrokerLifecycleState, CliError> {
    match BrokerEndpoint::discover(paths) {
        Ok(Some(endpoint)) => {
            return resolve_published_endpoint(paths, endpoint, startup_timeout);
        }
        Ok(None) => {}
        Err(_error) => {
            let Some(lifecycle_lock) = BrokerLifecycleLock::try_acquire(paths)? else {
                return wait_for_inflight_broker(paths, startup_timeout);
            };
            cleanup_failed_start(paths)?;
            return Ok(BrokerLifecycleState::Vacant(lifecycle_lock));
        }
    }
    let Some(lifecycle_lock) = BrokerLifecycleLock::try_acquire(paths)? else {
        return wait_for_inflight_broker(paths, startup_timeout);
    };
    Ok(BrokerLifecycleState::Vacant(lifecycle_lock))
}

fn resolve_published_endpoint(
    paths: &CliPaths,
    endpoint: BrokerEndpoint,
    startup_timeout: Duration,
) -> Result<BrokerLifecycleState, CliError> {
    if let Ok(broker) = require_healthy_owned_broker(&endpoint) {
        return Ok(BrokerLifecycleState::Existing { endpoint, broker });
    }
    let Some(lifecycle_lock) = BrokerLifecycleLock::try_acquire(paths)? else {
        return wait_for_inflight_broker(paths, startup_timeout);
    };
    cleanup_failed_start(paths)?;
    Ok(BrokerLifecycleState::Vacant(lifecycle_lock))
}

fn wait_for_inflight_broker(
    paths: &CliPaths,
    timeout: Duration,
) -> Result<BrokerLifecycleState, CliError> {
    let started_at = std::time::Instant::now();
    let mut last_error = None;
    while started_at.elapsed() < timeout {
        match BrokerEndpoint::discover(paths) {
            Ok(Some(endpoint)) => match require_healthy_owned_broker(&endpoint) {
                Ok(broker) => {
                    return Ok(BrokerLifecycleState::Existing { endpoint, broker });
                }
                Err(error) => last_error = Some(error),
            },
            Ok(None) => {}
            Err(error) => last_error = Some(error),
        }
        if let Some(lifecycle_lock) = BrokerLifecycleLock::try_acquire(paths)? {
            cleanup_failed_start(paths)?;
            return Ok(BrokerLifecycleState::Vacant(lifecycle_lock));
        }
        thread::sleep(STARTUP_POLL_INTERVAL);
    }
    if let Some(lifecycle_lock) = BrokerLifecycleLock::try_acquire(paths)? {
        cleanup_failed_start(paths)?;
        return Ok(BrokerLifecycleState::Vacant(lifecycle_lock));
    }
    Err(last_error.unwrap_or_else(|| {
        CliError::InvalidConfiguration(
            "abyss-broker startup is in progress but did not publish a usable endpoint before the timeout"
                .to_owned(),
        )
    }))
}

fn launch_broker(
    paths: &CliPaths,
    lifecycle_lock: BrokerLifecycleLock,
) -> Result<BrokerEndpoint, CliError> {
    cleanup_failed_start(paths)?;
    let broker_path = broker_path()?;
    let log_path = broker_process_log_path(paths);
    let log_parent = log_path.parent().ok_or_else(|| {
        CliError::InvalidConfiguration("broker log path has no parent directory".to_owned())
    })?;
    fs::create_dir_all(log_parent).map_err(|source| {
        CliError::filesystem("create broker log directory", log_parent, source)
    })?;
    filesystem::protect(log_parent, 0o700).map_err(|source| {
        CliError::filesystem("protect broker log directory", log_parent, source)
    })?;
    let mut log_options = fs::OpenOptions::new();
    log_options.create(true).append(true);
    filesystem::configure_file_creation(&mut log_options, 0o600);
    let stdout = log_options
        .open(&log_path)
        .map_err(|source| CliError::filesystem("open broker process log", &log_path, source))?;
    filesystem::protect(&log_path, 0o600)
        .map_err(|source| CliError::filesystem("protect broker process log", &log_path, source))?;
    let stderr = stdout
        .try_clone()
        .map_err(|source| CliError::filesystem("clone broker process log", &log_path, source))?;

    let stdin = lifecycle_lock.into_stdio();
    let mut command = broker_command(
        paths,
        &broker_path,
        stdin,
        Stdio::from(stdout),
        Stdio::from(stderr),
    );
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(source) => {
            let error = CliError::filesystem("start abyss-broker", &broker_path, source);
            cleanup_failed_start(paths)?;
            return Err(error);
        }
    };
    drop(command);

    wait_until_ready(paths, &mut child)
}

fn broker_process_log_path(paths: &CliPaths) -> PathBuf {
    paths.logs_dir().join(BROKER_PROCESS_LOG_FILE_NAME)
}

fn wait_until_ready(paths: &CliPaths, child: &mut Child) -> Result<BrokerEndpoint, CliError> {
    let started_at = std::time::Instant::now();
    while started_at.elapsed() < STARTUP_TIMEOUT {
        match BrokerEndpoint::discover(paths) {
            Ok(Some(endpoint)) => {
                if endpoint.pid() != child.id() {
                    let error = CliError::InvalidConfiguration(format!(
                        "broker startup identity process {} does not match launched process {}",
                        endpoint.pid(),
                        child.id()
                    ));
                    terminate_failed_start(paths, child)?;
                    return Err(error);
                }
                if require_healthy_owned_broker(&endpoint).is_ok() {
                    return Ok(endpoint);
                }
            }
            Ok(None) => {}
            Err(error) => {
                terminate_failed_start(paths, child)?;
                return Err(error);
            }
        }
        if let Some(status) = child.try_wait().map_err(|source| {
            CliError::filesystem("poll abyss-broker startup", "abyss-broker", source)
        })? {
            cleanup_failed_start(paths)?;
            return Err(CliError::InvalidConfiguration(format!(
                "abyss-broker exited before becoming ready: {status}"
            )));
        }
        thread::sleep(STARTUP_POLL_INTERVAL);
    }
    terminate_failed_start(paths, child)?;
    Err(CliError::InvalidConfiguration(
        "abyss-broker did not become healthy in explicit proxy mode".to_owned(),
    ))
}

fn wait_until_stopped(
    paths: &CliPaths,
    endpoint: &BrokerEndpoint,
) -> Result<BrokerLifecycleLock, CliError> {
    let broker = endpoint.public_client()?;
    let started_at = std::time::Instant::now();
    while started_at.elapsed() < STARTUP_TIMEOUT {
        if broker.health().is_err()
            && !endpoint.auth_token_file().exists()
            && let Some(lifecycle_lock) = BrokerLifecycleLock::try_acquire(paths)?
        {
            return Ok(lifecycle_lock);
        }
        thread::sleep(STARTUP_POLL_INTERVAL);
    }
    Err(CliError::InvalidConfiguration(
        "abyss-broker did not stop before the timeout".to_owned(),
    ))
}

fn terminate_failed_start(paths: &CliPaths, child: &mut Child) -> Result<(), CliError> {
    let status = child.try_wait().map_err(|source| {
        CliError::filesystem("poll timed-out abyss-broker", "abyss-broker", source)
    })?;
    if status.is_none() {
        child.kill().map_err(|source| {
            CliError::filesystem("terminate timed-out abyss-broker", "abyss-broker", source)
        })?;
        child.wait().map_err(|source| {
            CliError::filesystem("reap timed-out abyss-broker", "abyss-broker", source)
        })?;
    }
    cleanup_failed_start(paths)
}

fn cleanup_failed_start(paths: &CliPaths) -> Result<(), CliError> {
    remove_stale_runtime_file(&paths.broker_token_file())?;
    remove_stale_runtime_file(&paths.broker_startup_info_file())
}

fn remove_stale_runtime_file(path: &Path) -> Result<(), CliError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(CliError::filesystem(
            "remove stale broker runtime file",
            path,
            source,
        )),
    }
}

struct BrokerStartLock {
    file: fs::File,
}

impl BrokerStartLock {
    fn acquire(paths: &CliPaths) -> Result<Self, CliError> {
        let path = paths.broker_start_lock_file();
        let parent = path.parent().ok_or_else(|| {
            CliError::InvalidConfiguration("broker start lock has no parent".to_owned())
        })?;
        fs::create_dir_all(parent).map_err(|source| {
            CliError::filesystem("create broker runtime directory", parent, source)
        })?;
        let mut options = fs::OpenOptions::new();
        options.create(true).read(true).write(true).truncate(false);
        filesystem::configure_file_creation(&mut options, 0o600);
        let file = options
            .open(&path)
            .map_err(|source| CliError::filesystem("open broker start lock", &path, source))?;
        filesystem::protect(&path, 0o600)
            .map_err(|source| CliError::filesystem("protect broker start lock", &path, source))?;
        match file.try_lock() {
            Ok(()) => Ok(Self { file }),
            Err(fs::TryLockError::WouldBlock) => Err(CliError::InvalidConfiguration(
                "another Abyss CLI process is starting the explicit proxy".to_owned(),
            )),
            Err(fs::TryLockError::Error(source)) => Err(CliError::filesystem(
                "lock broker start lock",
                &path,
                source,
            )),
        }
    }
}

impl Drop for BrokerStartLock {
    fn drop(&mut self) {
        drop(self.file.unlock());
    }
}

#[cfg(test)]
mod tests {
    use std::{
        ffi::{OsStr, OsString},
        fs,
        path::PathBuf,
        process::Stdio,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use super::{
        BrokerController, BrokerLifecycleLock, BrokerLifecycleState, BrokerStartLock,
        broker_command, resolve_broker_lifecycle_with_timeout,
    };
    use crate::paths::CliPaths;

    #[test]
    fn broker_launch_uses_only_cli_explicit_runtime_paths() {
        let paths = CliPaths::at(PathBuf::from("/Users/example/Abyss CLI"));
        let broker_path = PathBuf::from("/Applications/Abyss.app/Contents/MacOS/abyss-broker");
        let command = broker_command(
            &paths,
            &broker_path,
            Stdio::null(),
            Stdio::null(),
            Stdio::null(),
        );
        let args = command
            .get_args()
            .map(OsStr::to_os_string)
            .collect::<Vec<_>>();

        assert_eq!(
            args,
            vec![
                OsString::from("--api"),
                OsString::from("127.0.0.1:0"),
                OsString::from("--config"),
                paths.config_file().into_os_string(),
                OsString::from("--auth-token-file"),
                paths.broker_token_file().into_os_string(),
                OsString::from("--startup-info-file"),
                paths.broker_startup_info_file().into_os_string(),
            ]
        );
        assert_eq!(
            command
                .get_envs()
                .find(|(name, _value)| name == &OsStr::new("ABYSS_HOME"))
                .and_then(|(_name, value)| value),
            Some(paths.root().as_os_str())
        );
        let rendered = args
            .iter()
            .map(|value| value.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(!rendered.contains("macos_network_extension"));
        assert!(!rendered.contains("windows_wfp"));
        assert!(!rendered.contains("flow.sock"));
        assert!(!rendered.contains("lifecycle-lock-file"));
    }

    #[test]
    fn stop_without_a_startup_identity_cleans_an_orphan_token() {
        let root = test_root("missing-stop");
        let paths = CliPaths::at(root.clone());
        let token_file = paths.broker_token_file();
        fs::create_dir_all(
            token_file
                .parent()
                .expect("broker token path should have a parent"),
        )
        .expect("runtime directory should be created");
        fs::write(&token_file, "test-token").expect("broker token should be written");

        BrokerController::stop(&paths).expect("an absent broker should already be stopped");

        assert!(!token_file.exists());
        drop(fs::remove_dir_all(root));
    }

    #[test]
    fn broker_start_lock_rejects_concurrent_owner_and_recovers_after_drop() {
        let root = test_root("start-lock");
        let paths = CliPaths::at(root.clone());

        let first = BrokerStartLock::acquire(&paths).expect("first start lock should succeed");
        let Err(error) = BrokerStartLock::acquire(&paths) else {
            panic!("a concurrent start lock must be rejected");
        };
        assert!(error.to_string().contains("another Abyss CLI process"));
        drop(first);
        let second = BrokerStartLock::acquire(&paths)
            .expect("the lock should be available after the first owner exits");
        drop(second);
        drop(fs::remove_dir_all(root));
    }

    #[test]
    fn lifecycle_preserves_inflight_state_while_broker_lock_is_held() {
        let root = test_root("locked-inflight");
        let paths = CliPaths::at(root.clone());
        let lifecycle_lock = BrokerLifecycleLock::try_acquire(&paths)
            .expect("lifecycle lock should open")
            .expect("lifecycle lock should be free");
        fs::write(paths.broker_token_file(), b"test-token")
            .expect("broker token should be written");

        let Err(error) = resolve_broker_lifecycle_with_timeout(&paths, Duration::from_millis(25))
        else {
            panic!("an in-flight startup without published identity must time out");
        };

        assert!(error.to_string().contains("startup is in progress"));
        assert!(paths.broker_token_file().is_file());
        drop(lifecycle_lock);
        drop(fs::remove_dir_all(root));
    }

    #[test]
    fn lifecycle_recovers_malformed_identity_only_while_holding_broker_lock() {
        let root = test_root("malformed-free");
        let paths = CliPaths::at(root.clone());
        let available_lock = BrokerLifecycleLock::try_acquire(&paths)
            .expect("lifecycle lock should open")
            .expect("lifecycle lock should be free");
        drop(available_lock);
        fs::write(paths.broker_startup_info_file(), b"{malformed")
            .expect("malformed startup identity should be written");
        fs::write(paths.broker_token_file(), b"stale-token")
            .expect("stale broker token should be written");

        let state = resolve_broker_lifecycle_with_timeout(&paths, Duration::ZERO)
            .expect("malformed identity should recover while the lifecycle lock is free");
        let BrokerLifecycleState::Vacant(lifecycle_lock) = state else {
            panic!("recovered malformed identity must return a held vacant lock");
        };

        assert!(!paths.broker_startup_info_file().exists());
        assert!(!paths.broker_token_file().exists());
        assert!(
            BrokerLifecycleLock::try_acquire(&paths)
                .expect("contender lock probe should succeed")
                .is_none(),
            "malformed identity cleanup must retain lifecycle ownership"
        );
        drop(lifecycle_lock);
        drop(fs::remove_dir_all(root));
    }

    #[test]
    fn lifecycle_preserves_malformed_identity_while_broker_lock_is_held() {
        let root = test_root("malformed-occupied");
        let paths = CliPaths::at(root.clone());
        let lifecycle_lock = BrokerLifecycleLock::try_acquire(&paths)
            .expect("lifecycle lock should open")
            .expect("lifecycle lock should be free");
        fs::write(paths.broker_startup_info_file(), b"{malformed")
            .expect("malformed startup identity should be written");
        fs::write(paths.broker_token_file(), b"live-token")
            .expect("broker token should be written");

        let Err(_error) = resolve_broker_lifecycle_with_timeout(&paths, Duration::from_millis(25))
        else {
            panic!("malformed in-flight identity must fail closed");
        };

        assert!(paths.broker_startup_info_file().is_file());
        assert!(paths.broker_token_file().is_file());
        drop(lifecycle_lock);
        drop(fs::remove_dir_all(root));
    }

    #[test]
    fn lifecycle_recovers_inflight_state_after_lock_owner_exits() {
        let root = test_root("inflight-owner-exit");
        let paths = CliPaths::at(root.clone());
        let lifecycle_lock = BrokerLifecycleLock::try_acquire(&paths)
            .expect("lifecycle lock should open")
            .expect("lifecycle lock should be free");
        fs::write(paths.broker_startup_info_file(), b"{malformed")
            .expect("malformed startup identity should be written");
        fs::write(paths.broker_token_file(), b"stale-token")
            .expect("stale broker token should be written");
        let owner = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(25));
            drop(lifecycle_lock);
        });

        let state = resolve_broker_lifecycle_with_timeout(&paths, Duration::from_secs(1))
            .expect("exited in-flight owner should be recovered");
        let BrokerLifecycleState::Vacant(lifecycle_lock) = state else {
            panic!("an exited in-flight owner must return a held vacant lock");
        };

        owner.join().expect("lock owner should exit");
        assert!(!paths.broker_startup_info_file().exists());
        assert!(!paths.broker_token_file().exists());
        assert!(
            BrokerLifecycleLock::try_acquire(&paths)
                .expect("contender lock probe should succeed")
                .is_none(),
            "in-flight cleanup must retain lifecycle ownership"
        );
        drop(lifecycle_lock);
        drop(fs::remove_dir_all(root));
    }

    fn test_root(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock should be after the Unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "abyss-cli-macos-{label}-{}-{nonce}",
            std::process::id()
        ))
    }
}
