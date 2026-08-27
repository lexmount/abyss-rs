//! Inherited file-lock ownership for the macOS CLI broker lifetime.
//!
//! Rust file locks remain held by duplicated or inherited handles. The
//! launcher therefore transfers the locked file as broker standard input, so
//! ownership is continuous across `spawn` and ends with the broker process.

use std::{fs, path::PathBuf, process::Stdio};

use crate::{error::CliError, filesystem, paths::CliPaths};

const BROKER_LIFECYCLE_LOCK_FILE_NAME: &str = "broker.lock";

/// Exclusive lock held by either the launching CLI or the broker process.
pub(super) struct BrokerLifecycleLock {
    file: fs::File,
}

impl BrokerLifecycleLock {
    /// Attempts to acquire the broker process-lifetime lock without blocking.
    pub(super) fn try_acquire(paths: &CliPaths) -> Result<Option<Self>, CliError> {
        let path = broker_lifecycle_lock_path(paths);
        let parent = path.parent().ok_or_else(|| {
            CliError::InvalidConfiguration("broker lifecycle lock has no parent".to_owned())
        })?;
        fs::create_dir_all(parent).map_err(|source| {
            CliError::filesystem("create broker runtime directory", parent, source)
        })?;
        filesystem::protect(parent, 0o700).map_err(|source| {
            CliError::filesystem("protect broker runtime directory", parent, source)
        })?;
        let mut options = fs::OpenOptions::new();
        options.create(true).read(true).write(true).truncate(false);
        filesystem::configure_file_creation(&mut options, 0o600);
        let file = options
            .open(&path)
            .map_err(|source| CliError::filesystem("open broker lifecycle lock", &path, source))?;
        filesystem::protect(&path, 0o600).map_err(|source| {
            CliError::filesystem("protect broker lifecycle lock", &path, source)
        })?;
        match file.try_lock() {
            Ok(()) => Ok(Some(Self { file })),
            Err(fs::TryLockError::WouldBlock) => Ok(None),
            Err(fs::TryLockError::Error(source)) => Err(CliError::filesystem(
                "lock broker lifecycle lock",
                &path,
                source,
            )),
        }
    }

    /// Transfers the locked file into child standard input for inheritance.
    pub(super) fn into_stdio(self) -> Stdio {
        Stdio::from(self.file)
    }
}

fn broker_lifecycle_lock_path(paths: &CliPaths) -> PathBuf {
    paths
        .root()
        .join("runtime")
        .join(BROKER_LIFECYCLE_LOCK_FILE_NAME)
}

#[cfg(test)]
mod tests {
    use std::{fs, process::Command, thread, time::Duration};

    use super::BrokerLifecycleLock;
    use crate::paths::CliPaths;

    #[test]
    fn child_inherits_lifecycle_lock_until_process_exit() {
        let paths = test_paths("inherited");
        let launcher = BrokerLifecycleLock::try_acquire(&paths)
            .expect("launcher lock should open")
            .expect("launcher lock should be free");
        let mut child = Command::new("/bin/sleep")
            .arg("30")
            .stdin(launcher.into_stdio())
            .spawn()
            .expect("child should inherit lifecycle lock");
        assert!(
            BrokerLifecycleLock::try_acquire(&paths)
                .expect("contender probe should succeed")
                .is_none(),
            "the child must retain inherited lifecycle ownership"
        );
        child.kill().expect("test child should terminate");
        child.wait().expect("child should exit");
        thread::sleep(Duration::from_millis(10));
        assert!(
            BrokerLifecycleLock::try_acquire(&paths)
                .expect("released lifecycle lock should be probed")
                .is_some()
        );
        drop(fs::remove_dir_all(paths.root()));
    }

    fn test_paths(label: &str) -> CliPaths {
        let root = std::env::temp_dir().join(format!(
            "abyss-cli-macos-lifecycle-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("test clock should follow Unix epoch")
                .as_nanos()
        ));
        CliPaths::at(root)
    }
}
