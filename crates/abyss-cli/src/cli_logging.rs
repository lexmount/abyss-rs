//! Endpoint CLI logging for support bundles.
//!
//! The CLI is a short-lived process, so it keeps a small private rolling log
//! under its platform state directory. The logger is
//! deliberately best-effort: a logging failure must never change the result
//! of the user command being executed.

use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    path::PathBuf,
};

use chrono::Utc;

use crate::{filesystem, paths::CliPaths};

const MAX_LOG_BYTES: u64 = 5 * 1024 * 1024;
const LOG_FILE_NAME: &str = "cli.log";
const ROTATED_LOG_FILE_NAME: &str = "cli.1.log";

/// Best-effort file logger owned by the CLI.
pub struct CliLogger {
    log_file: PathBuf,
    rotated_log_file: PathBuf,
}

impl CliLogger {
    /// Creates a logger rooted at the platform CLI state directory.
    #[must_use]
    pub fn from_paths(paths: &CliPaths) -> Self {
        let logs = paths.logs_dir();
        Self {
            log_file: logs.join(LOG_FILE_NAME),
            rotated_log_file: logs.join(ROTATED_LOG_FILE_NAME),
        }
    }

    /// Writes one command lifecycle record; support-bundle collection redacts it.
    pub fn record(&self, level: &str, message: &str) {
        drop(self.try_record(level, message));
    }

    fn try_record(&self, level: &str, message: &str) -> std::io::Result<()> {
        let directory = self.log_file.parent().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "CLI log has no directory")
        })?;
        fs::create_dir_all(directory)?;
        filesystem::protect(directory, 0o700)?;
        self.rotate_if_needed()?;
        let line = format!("{} {} {}\n", Utc::now().to_rfc3339(), level, message);
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        filesystem::configure_file_creation(&mut options, 0o600);
        let mut file = options.open(&self.log_file)?;
        filesystem::protect(&self.log_file, 0o600)?;
        file.write_all(line.as_bytes())?;
        Ok(())
    }

    fn rotate_if_needed(&self) -> std::io::Result<()> {
        let Ok(metadata) = fs::metadata(&self.log_file) else {
            return Ok(());
        };
        if metadata.len() < MAX_LOG_BYTES {
            return Ok(());
        }
        if self.rotated_log_file.exists() {
            fs::remove_file(&self.rotated_log_file)?;
        }
        fs::rename(&self.log_file, &self.rotated_log_file)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;

    use super::CliLogger;
    use crate::paths::CliPaths;

    #[test]
    fn writes_cli_log_with_platform_file_policy() {
        let root = std::env::temp_dir().join(format!("abyss-cli-log-{}", std::process::id()));
        let paths = CliPaths::at(root.clone());
        CliLogger::from_paths(&paths).record("INFO", "command_started command=status");
        let log =
            fs::read_to_string(root.join("logs/cli.log")).expect("CLI log should be readable");
        assert!(log.contains("command=status"));
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(root.join("logs/cli.log"))
                .expect("CLI log metadata should read")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        drop(fs::remove_dir_all(root));
    }
}
