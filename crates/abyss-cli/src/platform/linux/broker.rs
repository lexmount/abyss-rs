//! Linux lifecycle for the explicit broker and its systemd service.

use std::{
    fs,
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    thread,
    time::{Duration, Instant},
};

use crate::{
    broker::{BrokerClient, BrokerEndpoint},
    error::CliError,
    paths::CliPaths,
};

use super::privileged_command;

const STARTUP_TIMEOUT: Duration = Duration::from_secs(5);
const STARTUP_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Owns Linux broker lifecycle operations for `LinuxPlatformAdapter`.
pub(super) struct BrokerController;

impl BrokerController {
    /// Enables and starts or restarts the user-scoped systemd unit.
    pub(super) fn start(
        paths: &CliPaths,
        user: Option<&str>,
        restart: bool,
    ) -> Result<BrokerEndpoint, CliError> {
        let _lifecycle_lock = BrokerLifecycleLock::acquire(paths)?;
        // Reusing the authenticated endpoint must not require sudo on every run.
        // An alternate service user or port change still takes the systemd path.
        if !restart
            && user.is_none()
            && let Some(endpoint) = BrokerEndpoint::discover(paths)?
            && endpoint.require_owned_explicit().is_ok()
        {
            return Ok(endpoint);
        }
        service_control("enable", user)?;
        service_control(if restart { "restart" } else { "start" }, user)?;
        wait_until_ready(paths)
    }

    /// Gracefully stops a running broker, falling back to its systemd unit.
    pub(super) fn stop(paths: &CliPaths, user: Option<&str>) -> Result<(), CliError> {
        let _lifecycle_lock = BrokerLifecycleLock::acquire(paths)?;
        if graceful_shutdown(paths).is_ok() {
            return Ok(());
        }
        service_control("stop", user)
    }
}

fn graceful_shutdown(paths: &CliPaths) -> Result<(), CliError> {
    let endpoint = BrokerEndpoint::discover(paths)?.ok_or_else(|| {
        CliError::InvalidConfiguration("abyss-broker has no published endpoint".to_owned())
    })?;
    let public = endpoint.public_client()?;
    let broker = endpoint.require_owned_explicit()?;
    broker.shutdown()?;
    wait_until_stopped(paths, &public)
}

fn wait_until_ready(paths: &CliPaths) -> Result<BrokerEndpoint, CliError> {
    let started_at = Instant::now();
    let mut last_error = None;
    while started_at.elapsed() < STARTUP_TIMEOUT {
        match BrokerEndpoint::discover(paths) {
            Ok(Some(endpoint)) => match endpoint.require_owned_explicit() {
                Ok(_broker) => return Ok(endpoint),
                Err(error) => {
                    last_error = Some(CliError::InvalidConfiguration(format!(
                        "broker process {} did not pass endpoint ownership validation: {error}",
                        endpoint.pid()
                    )));
                }
            },
            Ok(None) => {}
            Err(error) => last_error = Some(error),
        }
        thread::sleep(STARTUP_POLL_INTERVAL);
    }
    let details = last_error.map_or_else(String::new, |error| format!(": {error}"));
    Err(CliError::InvalidConfiguration(format!(
        "abyss-broker did not publish a healthy owned explicit endpoint before the timeout{details}"
    )))
}

fn wait_until_stopped(paths: &CliPaths, old_broker: &BrokerClient) -> Result<(), CliError> {
    let started_at = Instant::now();
    while started_at.elapsed() < STARTUP_TIMEOUT {
        let endpoint_is_unpublished = matches!(BrokerEndpoint::discover(paths), Ok(None));
        if endpoint_is_unpublished
            && !paths.broker_token_file().exists()
            && old_broker.health().is_err()
        {
            return Ok(());
        }
        thread::sleep(STARTUP_POLL_INTERVAL);
    }
    Err(CliError::InvalidConfiguration(
        "abyss-broker did not stop before the timeout".to_owned(),
    ))
}

fn service_control(operation: &str, user: Option<&str>) -> Result<(), CliError> {
    let unit = service_unit(user)?;
    let output = privileged_command("systemctl", [operation, &unit])
        .output()
        .map_err(|source| CliError::filesystem("run systemctl", "systemctl", source))?;
    if output.status.success() {
        return Ok(());
    }
    Err(CliError::Command {
        program: format!("systemctl {operation} {unit}"),
        status: output.status,
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
    })
}

fn service_unit(user: Option<&str>) -> Result<String, CliError> {
    let user = user
        .map(str::trim)
        .filter(|user| !user.is_empty())
        .map(str::to_owned)
        .or_else(|| {
            std::env::var("USER")
                .ok()
                .filter(|user| !user.trim().is_empty())
        })
        .ok_or_else(|| {
            CliError::InvalidConfiguration("service user is missing; pass --user".to_owned())
        })?;
    if user
        .bytes()
        .any(|byte| byte.is_ascii_whitespace() || byte == b'/')
    {
        return Err(CliError::InvalidConfiguration(
            "service user contains invalid characters".to_owned(),
        ));
    }
    Ok(format!("abyss-broker@{user}.service"))
}

struct BrokerLifecycleLock {
    file: fs::File,
}

impl BrokerLifecycleLock {
    fn acquire(paths: &CliPaths) -> Result<Self, CliError> {
        let path = paths.broker_start_lock_file();
        let parent = path.parent().ok_or_else(|| {
            CliError::InvalidConfiguration("broker lifecycle lock has no parent".to_owned())
        })?;
        fs::create_dir_all(parent).map_err(|source| {
            CliError::filesystem("create broker runtime directory", parent, source)
        })?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(|source| {
            CliError::filesystem("protect broker runtime directory", parent, source)
        })?;
        match fs::set_permissions(&path, fs::Permissions::from_mode(0o600)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(CliError::filesystem(
                    "protect broker lifecycle lock",
                    &path,
                    source,
                ));
            }
        }
        let file = fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .open(&path)
            .map_err(|source| CliError::filesystem("open broker lifecycle lock", &path, source))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).map_err(|source| {
            CliError::filesystem("protect broker lifecycle lock", &path, source)
        })?;
        match file.try_lock() {
            Ok(()) => Ok(Self { file }),
            Err(fs::TryLockError::WouldBlock) => Err(CliError::InvalidConfiguration(
                "another Abyss CLI process is changing the explicit proxy lifecycle".to_owned(),
            )),
            Err(fs::TryLockError::Error(source)) => Err(CliError::filesystem(
                "lock broker lifecycle lock",
                &path,
                source,
            )),
        }
    }
}

impl Drop for BrokerLifecycleLock {
    fn drop(&mut self) {
        drop(self.file.unlock());
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::{BufRead as _, BufReader, Write as _},
        net::TcpListener,
        os::unix::fs::PermissionsExt as _,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::{BrokerController, BrokerLifecycleLock, service_unit};
    use crate::paths::CliPaths;

    #[test]
    fn service_unit_is_user_scoped() {
        assert_eq!(
            service_unit(Some("lexmount")).expect("unit should build"),
            "abyss-broker@lexmount.service"
        );
    }

    #[test]
    fn service_unit_rejects_path_like_user() {
        assert!(service_unit(Some("../root")).is_err());
    }

    #[test]
    fn healthy_owned_explicit_broker_is_reused_without_service_operations() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock should be valid")
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("abyss-linux-reuse-{}-{nonce}", std::process::id()));
        let paths = CliPaths::at(root.clone());
        fs::create_dir_all(root.join("runtime")).expect("runtime should create");
        fs::write(paths.broker_token_file(), "reuse-token").expect("token should write");
        let listener = TcpListener::bind("127.0.0.1:0").expect("broker should bind");
        let address = listener.local_addr().expect("broker address should read");
        fs::write(
            paths.broker_startup_info_file(),
            serde_json::json!({
                "api_addr": address,
                "auth_token_file": paths.broker_token_file(),
                "pid": 42,
            })
            .to_string(),
        )
        .expect("startup identity should write");
        let server = std::thread::spawn(move || {
            for (route, body) in [
                (
                    "/v1/proxy/status",
                    r#"{"lifecycle":"running","process_id":42,"mode":"explicit","ingresses":[],"listen_addr":"127.0.0.1:18191"}"#,
                ),
                ("/v1/support/diagnostics", "{}"),
            ] {
                let (mut stream, _) = listener.accept().expect("request should arrive");
                let mut reader = BufReader::new(stream.try_clone().expect("stream should clone"));
                let mut request = String::new();
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).expect("request should read");
                    if line == "\r\n" {
                        break;
                    }
                    request.push_str(&line);
                }
                assert!(request.starts_with(&format!("GET {route} HTTP/1.1")));
                if route == "/v1/support/diagnostics" {
                    assert!(
                        request
                            .to_ascii_lowercase()
                            .contains("authorization: bearer reuse-token")
                    );
                }
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).expect("response should write");
            }
        });

        let endpoint = BrokerController::start(&paths, None, false)
            .expect("healthy broker reuse must not invoke sudo or systemctl");

        assert_eq!(endpoint.api_addr(), address);
        assert_eq!(endpoint.pid(), 42);
        server.join().expect("broker server should finish");
        fs::remove_dir_all(root).expect("fixture should remove");
    }

    #[test]
    fn lifecycle_lock_rejects_concurrent_owner_repairs_mode_and_recovers_after_drop() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock should be after the Unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "abyss-cli-linux-lifecycle-lock-{}-{nonce}",
            std::process::id()
        ));
        let paths = CliPaths::at(root.clone());
        let lock_path = paths.broker_start_lock_file();

        let first =
            BrokerLifecycleLock::acquire(&paths).expect("first lifecycle lock should succeed");
        assert!(
            lock_path
                .parent()
                .expect("lifecycle lock should have a parent")
                .is_dir(),
            "acquiring the lock should create the runtime directory"
        );
        assert_eq!(
            fs::metadata(
                lock_path
                    .parent()
                    .expect("lifecycle lock should have a parent")
            )
            .expect("runtime directory metadata should be readable")
            .permissions()
            .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&lock_path)
                .expect("lifecycle lock metadata should be readable")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let Err(error) = BrokerLifecycleLock::acquire(&paths) else {
            panic!("a concurrent lifecycle lock must be rejected");
        };
        assert!(error.to_string().contains("another Abyss CLI process"));

        drop(first);
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o000))
            .expect("test lifecycle lock mode should be changed");
        let second = BrokerLifecycleLock::acquire(&paths)
            .expect("the lifecycle lock should recover after its owner exits");
        assert_eq!(
            fs::metadata(&lock_path)
                .expect("reopened lifecycle lock metadata should be readable")
                .permissions()
                .mode()
                & 0o777,
            0o600,
            "acquiring an existing lock should repair its mode"
        );
        drop(second);
        fs::remove_dir_all(root).expect("test lifecycle directory should be removed");
    }
}
