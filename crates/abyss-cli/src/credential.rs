//! Endpoint CLI credential-store adapter.
//!
//! The terminal-auth crate owns the credential schema and storage contract.
//! `CliPaths` selects the endpoint-specific platform location while this
//! adapter reuses the shared private, atomic file implementation.

use std::path::{Path, PathBuf};

use abyss_terminal_auth::{
    CredentialFile, CredentialStore, FileCredentialStore, TerminalAuthError,
};

use crate::{error::CliError, paths::CliPaths};

/// Credential store used by the cross-platform endpoint CLI.
pub struct CliCredentialStore {
    path: PathBuf,
    file: FileCredentialStore,
}

impl CliCredentialStore {
    /// Creates the endpoint credential store at the active CLI state root.
    pub fn from_paths(paths: &CliPaths) -> Result<Self, CliError> {
        Self::at(paths.credential_file())
    }

    /// Creates a store at an explicit path, primarily for isolated tests.
    pub fn at(path: PathBuf) -> Result<Self, CliError> {
        let file = FileCredentialStore::for_app(
            Some(Path::new(&path)),
            "abyss-cli",
            "ABYSS_LINUX_CREDENTIAL_FILE",
        )?;
        Ok(Self { path, file })
    }

    /// Returns the credential file path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl CredentialStore for CliCredentialStore {
    fn read(&self) -> Result<CredentialFile, TerminalAuthError> {
        self.file.read()
    }

    fn write(&self, credential: &CredentialFile) -> Result<(), TerminalAuthError> {
        self.file.write(credential)
    }

    fn remove(&self) -> Result<(), TerminalAuthError> {
        self.file.remove()
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;

    use abyss_terminal_auth::{AuthenticatedUser, CredentialFile, CredentialStore};
    use chrono::{DateTime, Utc};
    use uuid::Uuid;

    use super::CliCredentialStore;

    #[test]
    fn store_round_trips_credential_with_platform_file_policy() {
        let directory =
            std::env::temp_dir().join(format!("abyss-cli-credential-{}", std::process::id()));
        let path = directory.join("auth").join("credentials.json");
        let store = CliCredentialStore::at(path.clone()).expect("store should build");
        let expires_at = "2099-01-01T00:00:00Z"
            .parse::<DateTime<Utc>>()
            .expect("timestamp should parse");
        let credential = CredentialFile::from_session(
            "https://abyss.example.invalid".to_owned(),
            abyss_terminal_auth::NativeSessionCredential {
                token: "token".to_owned(),
                expires_at,
                user: AuthenticatedUser {
                    id: Uuid::nil(),
                    email: "user@example.invalid".to_owned(),
                    name: None,
                    roles: Vec::new(),
                },
            },
        );

        store.write(&credential).expect("credential should write");
        assert_eq!(store.read().expect("credential should read").token, "token");
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&path)
                .expect("metadata should read")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        store.remove().expect("credential should remove");
        assert!(!path.exists());
        drop(fs::remove_dir_all(directory));
    }

    #[test]
    fn explicit_store_path_is_not_rewritten() {
        let path = PathBuf::from("/tmp/abyss-cli-custom/credentials.json");
        let store = CliCredentialStore::at(path.clone()).expect("store should build");

        assert_eq!(store.path(), path.as_path());
    }
}
