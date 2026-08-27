//! File-lock ownership for one CLI-managed delivery worker process.
//!
//! A short-lived lock serializes launch decisions. A second lock is transferred
//! to worker standard input and remains held for exactly the worker lifetime.

use std::{
    fs,
    path::Path,
    process::Stdio,
    thread,
    time::{Duration, Instant},
};

use crate::{error::CliError, filesystem, paths::CliPaths};

const LOCK_WAIT_INTERVAL: Duration = Duration::from_millis(50);

/// Exclusive ownership of one foreground startup decision.
pub(super) struct WorkerStartLock {
    file: fs::File,
}

/// Exclusive ownership transferred from the launcher to the worker process.
pub(super) struct WorkerLifetimeLock {
    file: fs::File,
}

impl WorkerStartLock {
    /// Waits for a concurrent foreground command to finish its launch decision.
    pub(super) fn acquire(paths: &CliPaths, timeout: Duration) -> Result<Self, CliError> {
        let path = paths.delivery_worker_start_lock_file();
        let file = open_lock_file(&path, "delivery worker start")?;
        let started_at = Instant::now();
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(Self { file }),
                Err(fs::TryLockError::WouldBlock) if started_at.elapsed() < timeout => {
                    thread::sleep(LOCK_WAIT_INTERVAL);
                }
                Err(fs::TryLockError::WouldBlock) => {
                    return Err(CliError::InvalidConfiguration(
                        "another Abyss CLI command did not finish delivery worker startup before the timeout"
                            .to_owned(),
                    ));
                }
                Err(fs::TryLockError::Error(source)) => {
                    return Err(CliError::filesystem(
                        "lock delivery worker start lock",
                        path,
                        source,
                    ));
                }
            }
        }
    }
}

impl Drop for WorkerStartLock {
    fn drop(&mut self) {
        drop(self.file.unlock());
    }
}

impl WorkerLifetimeLock {
    /// Acquires a vacant worker lifetime or reports that a process still owns it.
    pub(super) fn try_acquire(paths: &CliPaths) -> Result<Option<Self>, CliError> {
        let path = paths.delivery_worker_lifetime_lock_file();
        let file = open_lock_file(&path, "delivery worker lifetime")?;
        match file.try_lock() {
            Ok(()) => Ok(Some(Self { file })),
            Err(fs::TryLockError::WouldBlock) => Ok(None),
            Err(fs::TryLockError::Error(source)) => Err(CliError::filesystem(
                "lock delivery worker lifetime lock",
                path,
                source,
            )),
        }
    }

    /// Transfers the locked handle to worker standard input.
    pub(super) fn into_stdio(self) -> Stdio {
        Stdio::from(self.file)
    }
}

fn open_lock_file(path: &Path, label: &'static str) -> Result<fs::File, CliError> {
    let parent = path.parent().ok_or_else(|| {
        CliError::InvalidConfiguration(format!("{label} lock has no parent directory"))
    })?;
    fs::create_dir_all(parent).map_err(|source| {
        CliError::filesystem("create delivery worker runtime directory", parent, source)
    })?;
    filesystem::protect(parent, 0o700).map_err(|source| {
        CliError::filesystem("protect delivery worker runtime directory", parent, source)
    })?;
    let mut options = fs::OpenOptions::new();
    options.create(true).read(true).write(true).truncate(false);
    filesystem::configure_file_creation(&mut options, 0o600);
    let file = options
        .open(path)
        .map_err(|source| CliError::filesystem("open delivery worker lock", path, source))?;
    filesystem::protect(path, 0o600)
        .map_err(|source| CliError::filesystem("protect delivery worker lock", path, source))?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    use std::{fs, thread, time::Duration};

    #[cfg(unix)]
    use std::process::Command;

    use super::{WorkerLifetimeLock, WorkerStartLock};
    use crate::paths::CliPaths;

    #[test]
    fn start_lock_waits_for_the_current_foreground_owner() {
        let paths = test_paths("start");
        let first = WorkerStartLock::acquire(&paths, Duration::from_millis(50))
            .expect("first start lock should succeed");
        let Err(error) = WorkerStartLock::acquire(&paths, Duration::from_millis(100)) else {
            panic!("second start lock should time out");
        };
        assert!(error.to_string().contains("another Abyss CLI command"));

        drop(first);
        WorkerStartLock::acquire(&paths, Duration::from_millis(50))
            .expect("released start lock should be reusable");
        fs::remove_dir_all(paths.root()).expect("test root should be removed");
    }

    #[test]
    #[cfg(unix)]
    fn worker_child_holds_the_inherited_lifetime_lock() {
        let paths = test_paths("lifetime");
        let lifetime = WorkerLifetimeLock::try_acquire(&paths)
            .expect("lifetime lock should open")
            .expect("lifetime lock should be vacant");
        let mut child = Command::new("/bin/sleep")
            .arg("30")
            .stdin(lifetime.into_stdio())
            .spawn()
            .expect("test child should start");

        assert!(
            WorkerLifetimeLock::try_acquire(&paths)
                .expect("lifetime lock should be inspected")
                .is_none()
        );
        child.kill().expect("test child should stop");
        child.wait().expect("test child should be reaped");
        thread::sleep(Duration::from_millis(10));
        assert!(
            WorkerLifetimeLock::try_acquire(&paths)
                .expect("released lifetime lock should be inspected")
                .is_some()
        );
        fs::remove_dir_all(paths.root()).expect("test root should be removed");
    }

    fn test_paths(label: &str) -> CliPaths {
        CliPaths::at(std::env::temp_dir().join(format!(
            "abyss-cli-delivery-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("test clock should follow Unix epoch")
                .as_nanos()
        )))
    }
}
