//! Owned child-process lifecycle for the local backend and dashboard.

use std::{
    ffi::{OsStr, OsString},
    fs, io,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use nix::{
    sys::signal::{Signal, kill},
    unistd::Pid,
};
use serde::{Deserialize, Serialize};

#[cfg(unix)]
use std::os::unix::process::CommandExt as _;

use super::config::{LocalPaths, atomic_write, ensure_private_directory};
use crate::{error::CliError, filesystem};

const OPERATION_LOCK_TIMEOUT: Duration = Duration::from_secs(10);
const SERVICE_START_TIMEOUT: Duration = Duration::from_secs(10);
const SERVICE_STOP_TIMEOUT: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(100);

pub(super) struct DeploymentOperationLock {
    file: fs::File,
}

pub(super) struct ServiceCommand {
    program: OsString,
    arguments: Vec<OsString>,
    environment: Vec<(OsString, OsString)>,
    marker: PathBuf,
}

pub(super) struct ManagedService {
    name: &'static str,
    pid_file: PathBuf,
    lock_file: PathBuf,
    log_file: PathBuf,
}

pub(super) enum ServiceStatus {
    Running { pid: u32 },
    Stopped,
    Unhealthy { pid: Option<u32>, reason: String },
}

pub(super) enum StartDisposition {
    Existing,
    Started,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProcessRecord {
    pid: u32,
    marker: PathBuf,
}

impl DeploymentOperationLock {
    pub(super) fn acquire(paths: &LocalPaths) -> Result<Self, CliError> {
        let path = paths.operation_lock_file();
        let file = open_lock_file(&path, "deployment operation")?;
        let started_at = Instant::now();
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(Self { file }),
                Err(fs::TryLockError::WouldBlock)
                    if started_at.elapsed() < OPERATION_LOCK_TIMEOUT =>
                {
                    thread::sleep(POLL_INTERVAL);
                }
                Err(fs::TryLockError::WouldBlock) => {
                    return Err(CliError::InvalidConfiguration(
                        "another `abyss deploy-local` operation did not finish before the timeout"
                            .to_owned(),
                    ));
                }
                Err(fs::TryLockError::Error(source)) => {
                    return Err(CliError::filesystem(
                        "lock local deployment operation",
                        &path,
                        source,
                    ));
                }
            }
        }
    }
}

impl Drop for DeploymentOperationLock {
    fn drop(&mut self) {
        drop(self.file.unlock());
    }
}

impl ServiceCommand {
    pub(super) fn new(program: impl Into<OsString>, marker: PathBuf) -> Self {
        Self {
            program: program.into(),
            arguments: Vec::new(),
            environment: Vec::new(),
            marker,
        }
    }

    pub(super) fn argument(&mut self, value: impl Into<OsString>) -> &mut Self {
        self.arguments.push(value.into());
        self
    }

    pub(super) fn environment(
        &mut self,
        key: impl Into<OsString>,
        value: impl Into<OsString>,
    ) -> &mut Self {
        self.environment.push((key.into(), value.into()));
        self
    }
}

impl ManagedService {
    pub(super) fn backend(paths: &LocalPaths) -> Self {
        Self {
            name: "backend",
            pid_file: paths.backend_pid_file(),
            lock_file: paths.backend_lock_file(),
            log_file: paths.backend_log_file(),
        }
    }

    pub(super) fn dashboard(paths: &LocalPaths) -> Self {
        Self {
            name: "dashboard",
            pid_file: paths.dashboard_pid_file(),
            lock_file: paths.dashboard_lock_file(),
            log_file: paths.dashboard_log_file(),
        }
    }

    pub(super) fn start(
        &self,
        command: &ServiceCommand,
        health_client: &reqwest::blocking::Client,
        health_url: &str,
    ) -> Result<StartDisposition, CliError> {
        let lifetime = open_lock_file(&self.lock_file, self.name)?;
        match lifetime.try_lock() {
            Ok(()) => {}
            Err(fs::TryLockError::WouldBlock) => {
                return match self.status(health_client, health_url)? {
                    ServiceStatus::Running { .. } => Ok(StartDisposition::Existing),
                    ServiceStatus::Stopped => Err(CliError::InvalidConfiguration(format!(
                        "{} lifetime ownership disappeared during startup",
                        self.name
                    ))),
                    ServiceStatus::Unhealthy { reason, .. } => Err(CliError::InvalidConfiguration(
                        format!("{} process is owned but unhealthy: {reason}", self.name),
                    )),
                };
            }
            Err(fs::TryLockError::Error(source)) => {
                return Err(CliError::filesystem(
                    "lock local service lifetime",
                    &self.lock_file,
                    source,
                ));
            }
        }
        drop(fs::remove_file(&self.pid_file));
        let (stdout, stderr) = self.open_log()?;
        let mut process = Command::new(&command.program);
        process
            .args(&command.arguments)
            .envs(command.environment.iter().cloned())
            .stdin(Stdio::from(lifetime))
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        #[cfg(unix)]
        process.process_group(0);
        let mut child = process.spawn().map_err(|source| {
            CliError::filesystem("start local managed service", &command.marker, source)
        })?;
        let record = ProcessRecord {
            pid: child.id(),
            marker: command.marker.clone(),
        };
        if let Err(error) = write_process_record(&self.pid_file, &record) {
            terminate_child(&mut child);
            return Err(error);
        }
        if let Err(error) = self.wait_until_ready(&mut child, health_client, health_url) {
            terminate_child(&mut child);
            drop(fs::remove_file(&self.pid_file));
            return Err(error);
        }
        Ok(StartDisposition::Started)
    }

    pub(super) fn status(
        &self,
        health_client: &reqwest::blocking::Client,
        health_url: &str,
    ) -> Result<ServiceStatus, CliError> {
        if !self.lock_file.exists() {
            return Ok(ServiceStatus::Stopped);
        }
        let lifetime = open_lock_file(&self.lock_file, self.name)?;
        match lifetime.try_lock() {
            Ok(()) => {
                lifetime.unlock().map_err(|source| {
                    CliError::filesystem("unlock stopped local service", &self.lock_file, source)
                })?;
                drop(fs::remove_file(&self.pid_file));
                Ok(ServiceStatus::Stopped)
            }
            Err(fs::TryLockError::WouldBlock) => {
                let Some(record) = read_process_record(&self.pid_file)? else {
                    return Ok(ServiceStatus::Unhealthy {
                        pid: None,
                        reason: format!("{} process record is missing", self.name),
                    });
                };
                if !process_matches(&record)? {
                    return Ok(ServiceStatus::Unhealthy {
                        pid: Some(record.pid),
                        reason: "process identity does not match its ownership record".to_owned(),
                    });
                }
                if !http_ready(health_client, health_url) {
                    return Ok(ServiceStatus::Unhealthy {
                        pid: Some(record.pid),
                        reason: format!("health check failed at {health_url}"),
                    });
                }
                Ok(ServiceStatus::Running { pid: record.pid })
            }
            Err(fs::TryLockError::Error(source)) => Err(CliError::filesystem(
                "inspect local service lifetime",
                &self.lock_file,
                source,
            )),
        }
    }

    pub(super) fn stop(&self) -> Result<bool, CliError> {
        if !self.lock_file.exists() {
            drop(fs::remove_file(&self.pid_file));
            return Ok(false);
        }
        let lifetime = open_lock_file(&self.lock_file, self.name)?;
        match lifetime.try_lock() {
            Ok(()) => {
                lifetime.unlock().map_err(|source| {
                    CliError::filesystem("unlock stopped local service", &self.lock_file, source)
                })?;
                drop(fs::remove_file(&self.pid_file));
                return Ok(false);
            }
            Err(fs::TryLockError::WouldBlock) => {}
            Err(fs::TryLockError::Error(source)) => {
                return Err(CliError::filesystem(
                    "inspect local service lifetime",
                    &self.lock_file,
                    source,
                ));
            }
        }
        let record = read_process_record(&self.pid_file)?.ok_or_else(|| {
            CliError::InvalidConfiguration(format!(
                "refusing to stop owned {} process without an identity record",
                self.name
            ))
        })?;
        require_process_match(&record, self.name)?;
        signal_process(record.pid, Signal::SIGTERM, self.name)?;
        if wait_for_unlock(&lifetime, SERVICE_STOP_TIMEOUT)? {
            drop(fs::remove_file(&self.pid_file));
            return Ok(true);
        }
        require_process_match(&record, self.name)?;
        signal_process(record.pid, Signal::SIGKILL, self.name)?;
        if !wait_for_unlock(&lifetime, SERVICE_STOP_TIMEOUT)? {
            return Err(CliError::InvalidConfiguration(format!(
                "{} process {} did not stop after SIGKILL",
                self.name, record.pid
            )));
        }
        drop(fs::remove_file(&self.pid_file));
        Ok(true)
    }

    fn open_log(&self) -> Result<(fs::File, fs::File), CliError> {
        let parent = self.log_file.parent().ok_or_else(|| {
            CliError::InvalidConfiguration(format!("{} log path has no parent", self.name))
        })?;
        ensure_private_directory(parent)?;
        let mut options = fs::OpenOptions::new();
        options.create(true).append(true);
        filesystem::configure_file_creation(&mut options, 0o600);
        let stdout = options.open(&self.log_file).map_err(|source| {
            CliError::filesystem("open local service log", &self.log_file, source)
        })?;
        filesystem::protect(&self.log_file, 0o600).map_err(|source| {
            CliError::filesystem("protect local service log", &self.log_file, source)
        })?;
        let stderr = stdout.try_clone().map_err(|source| {
            CliError::filesystem("clone local service log", &self.log_file, source)
        })?;
        Ok((stdout, stderr))
    }

    fn wait_until_ready(
        &self,
        child: &mut Child,
        health_client: &reqwest::blocking::Client,
        health_url: &str,
    ) -> Result<(), CliError> {
        let started_at = Instant::now();
        while started_at.elapsed() < SERVICE_START_TIMEOUT {
            if http_ready(health_client, health_url) {
                return Ok(());
            }
            if let Some(status) = child.try_wait().map_err(|source| {
                CliError::filesystem("poll local managed service", &self.pid_file, source)
            })? {
                return Err(CliError::InvalidConfiguration(format!(
                    "{} exited before becoming ready with {status}; see {}",
                    self.name,
                    self.log_file.display()
                )));
            }
            thread::sleep(POLL_INTERVAL);
        }
        Err(CliError::InvalidConfiguration(format!(
            "{} did not become ready at {health_url}; see {}",
            self.name,
            self.log_file.display()
        )))
    }
}

impl ServiceStatus {
    pub(super) const fn is_running(&self) -> bool {
        matches!(self, Self::Running { .. })
    }

    pub(super) fn label(&self) -> String {
        match self {
            Self::Running { pid } => format!("running (pid {pid})"),
            Self::Stopped => "stopped".to_owned(),
            Self::Unhealthy { pid, reason } => pid.map_or_else(
                || format!("unhealthy ({reason})"),
                |pid| format!("unhealthy (pid {pid}, {reason})"),
            ),
        }
    }
}

impl StartDisposition {
    pub(super) const fn was_started(&self) -> bool {
        matches!(self, Self::Started)
    }
}

fn open_lock_file(path: &Path, label: &str) -> Result<fs::File, CliError> {
    let parent = path.parent().ok_or_else(|| {
        CliError::InvalidConfiguration(format!("{label} lock has no parent directory"))
    })?;
    ensure_private_directory(parent)?;
    let mut options = fs::OpenOptions::new();
    options.create(true).read(true).write(true).truncate(false);
    filesystem::configure_file_creation(&mut options, 0o600);
    let file = options
        .open(path)
        .map_err(|source| CliError::filesystem("open local deployment lock", path, source))?;
    filesystem::protect(path, 0o600)
        .map_err(|source| CliError::filesystem("protect local deployment lock", path, source))?;
    Ok(file)
}

fn write_process_record(path: &Path, record: &ProcessRecord) -> Result<(), CliError> {
    let mut contents = serde_json::to_vec(record)?;
    contents.push(b'\n');
    atomic_write(path, &contents, 0o600, "local process record")
}

fn read_process_record(path: &Path) -> Result<Option<ProcessRecord>, CliError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(CliError::InvalidConfiguration(format!(
                "local process record must be a regular non-symlink file: {}",
                path.display()
            )))
        }
        Ok(_) => fs::read(path)
            .map_err(|source| CliError::filesystem("read local process record", path, source))
            .and_then(|contents| serde_json::from_slice(&contents).map_err(CliError::from))
            .map(Some),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(CliError::filesystem(
            "inspect local process record",
            path,
            source,
        )),
    }
}

fn process_matches(record: &ProcessRecord) -> Result<bool, CliError> {
    let output = Command::new("ps")
        .args([
            OsStr::new("-p"),
            OsStr::new(&record.pid.to_string()),
            OsStr::new("-o"),
            OsStr::new("command="),
        ])
        .output()
        .map_err(|source| CliError::filesystem("inspect local managed process", "ps", source))?;
    if !output.status.success() {
        return Ok(false);
    }
    Ok(String::from_utf8_lossy(&output.stdout).contains(&*record.marker.to_string_lossy()))
}

fn require_process_match(record: &ProcessRecord, name: &str) -> Result<(), CliError> {
    if process_matches(record)? {
        return Ok(());
    }
    Err(CliError::InvalidConfiguration(format!(
        "refusing to signal {name} process {} because its identity no longer matches {}",
        record.pid,
        record.marker.display()
    )))
}

fn signal_process(pid: u32, signal: Signal, name: &str) -> Result<(), CliError> {
    let raw_pid = i32::try_from(pid).map_err(|_| {
        CliError::InvalidConfiguration(format!("{name} process ID is outside the supported range"))
    })?;
    kill(Pid::from_raw(raw_pid), signal).map_err(|error| {
        CliError::InvalidConfiguration(format!(
            "failed to send {signal:?} to {name} process {pid}: {error}"
        ))
    })
}

fn wait_for_unlock(file: &fs::File, timeout: Duration) -> Result<bool, CliError> {
    let started_at = Instant::now();
    while started_at.elapsed() < timeout {
        match file.try_lock() {
            Ok(()) => {
                file.unlock().map_err(|source| {
                    CliError::filesystem(
                        "unlock stopped local service",
                        "local service lock",
                        source,
                    )
                })?;
                return Ok(true);
            }
            Err(fs::TryLockError::WouldBlock) => thread::sleep(POLL_INTERVAL),
            Err(fs::TryLockError::Error(source)) => {
                return Err(CliError::filesystem(
                    "wait for local service lifetime",
                    "local service lock",
                    source,
                ));
            }
        }
    }
    Ok(false)
}

fn http_ready(client: &reqwest::blocking::Client, url: &str) -> bool {
    client
        .get(url)
        .send()
        .is_ok_and(|response| response.status().is_success())
}

fn terminate_child(child: &mut Child) {
    drop(child.kill());
    drop(child.wait());
}

#[cfg(test)]
mod tests {
    use super::ServiceStatus;

    #[test]
    fn status_labels_include_owned_process_identity() {
        assert_eq!(
            ServiceStatus::Running { pid: 42 }.label(),
            "running (pid 42)"
        );
        assert_eq!(ServiceStatus::Stopped.label(), "stopped");
        assert!(
            ServiceStatus::Unhealthy {
                pid: Some(7),
                reason: "not ready".to_owned()
            }
            .label()
            .contains("pid 7")
        );
    }
}
