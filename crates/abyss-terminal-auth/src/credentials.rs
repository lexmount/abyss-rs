//! Local credential persistence for terminal SSO clients.

use std::{
    env, fs,
    io::Write as _,
    path::{Path, PathBuf},
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{error::TerminalAuthError, session::NativeSessionCredential};

const CREDENTIAL_FILE_NAME: &str = "credentials.json";

/// Versioned credential-file format shared by Abyss terminal clients.
#[derive(Deserialize, Serialize)]
pub struct CredentialFile {
    version: u16,
    /// Control-plane base URL this credential was issued by.
    pub control_plane: String,
    /// Native bearer token used by command-line clients.
    pub token: String,
    /// Expiration timestamp for the bearer token.
    pub expires_at: DateTime<Utc>,
    /// Authenticated user metadata.
    pub user: crate::session::AuthenticatedUser,
}

/// Storage boundary for reading, writing, and deleting local credentials.
pub trait CredentialStore {
    /// Reads a credential from storage.
    ///
    /// # Errors
    ///
    /// Returns an error when the credential is missing, unreadable, or cannot
    /// be decoded.
    fn read(&self) -> Result<CredentialFile, TerminalAuthError>;

    /// Writes a credential to storage.
    ///
    /// # Errors
    ///
    /// Returns an error when the credential cannot be encoded or persisted.
    fn write(&self, credential: &CredentialFile) -> Result<(), TerminalAuthError>;

    /// Removes the credential from storage.
    ///
    /// # Errors
    ///
    /// Returns an error when an existing credential cannot be removed.
    fn remove(&self) -> Result<(), TerminalAuthError>;
}

/// Filesystem-backed credential store.
pub struct FileCredentialStore {
    path: PathBuf,
}

impl CredentialFile {
    /// Builds a persisted credential from a completed terminal SSO session.
    #[must_use]
    pub fn from_session(control_plane: String, session: NativeSessionCredential) -> Self {
        Self {
            version: 1,
            control_plane,
            token: session.token,
            expires_at: session.expires_at,
            user: session.user,
        }
    }
}

impl FileCredentialStore {
    /// Builds a filesystem credential store for an application namespace.
    ///
    /// The explicit path override takes precedence over the environment
    /// override. Without either override, the path is placed in the
    /// platform-specific Abyss state directory.
    ///
    /// # Errors
    ///
    /// Returns an error when the application namespace is unsafe for a state
    /// directory component or a default state directory cannot be found.
    pub fn for_app(
        path_override: Option<&Path>,
        app_name: &str,
        env_override: &str,
    ) -> Result<Self, TerminalAuthError> {
        Ok(Self {
            path: path_override.map_or_else(
                || default_credential_file(app_name, env_override),
                |path| Ok(path.to_path_buf()),
            )?,
        })
    }

    /// Returns the concrete credential-file path used by this store.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Writes a credential to this store.
    ///
    /// # Errors
    ///
    /// Returns an error when the credential cannot be encoded or persisted.
    pub fn write(&self, credential: &CredentialFile) -> Result<(), TerminalAuthError> {
        self.write_file(credential)
    }

    /// Reads a credential from this store.
    ///
    /// # Errors
    ///
    /// Returns an error when the credential is missing, unreadable, or cannot
    /// be decoded.
    pub fn read(&self) -> Result<CredentialFile, TerminalAuthError> {
        self.read_file()
    }

    /// Removes a credential from this store.
    ///
    /// # Errors
    ///
    /// Returns an error when an existing credential cannot be removed.
    pub fn remove(&self) -> Result<(), TerminalAuthError> {
        self.remove_file()
    }

    fn write_file(&self, credential: &CredentialFile) -> Result<(), TerminalAuthError> {
        let parent = self.path.parent().ok_or_else(|| {
            TerminalAuthError::filesystem(
                self.path.clone(),
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "credential path has no parent",
                ),
            )
        })?;
        fs::create_dir_all(parent)
            .map_err(|source| TerminalAuthError::filesystem(parent.to_path_buf(), source))?;
        write_private_json(&self.path, credential)
    }

    fn read_file(&self) -> Result<CredentialFile, TerminalAuthError> {
        let content = fs::read_to_string(&self.path).map_err(|source| {
            if source.kind() == std::io::ErrorKind::NotFound {
                TerminalAuthError::MissingCredential
            } else {
                TerminalAuthError::filesystem(self.path.clone(), source)
            }
        })?;
        serde_json::from_str(&content).map_err(TerminalAuthError::InvalidCredential)
    }

    fn remove_file(&self) -> Result<(), TerminalAuthError> {
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(TerminalAuthError::filesystem(self.path.clone(), error)),
        }
    }
}

impl CredentialStore for FileCredentialStore {
    fn read(&self) -> Result<CredentialFile, TerminalAuthError> {
        self.read_file()
    }

    fn write(&self, credential: &CredentialFile) -> Result<(), TerminalAuthError> {
        self.write_file(credential)
    }

    fn remove(&self) -> Result<(), TerminalAuthError> {
        self.remove_file()
    }
}

fn default_credential_file(
    app_name: &str,
    env_override: &str,
) -> Result<PathBuf, TerminalAuthError> {
    let app_name = validated_state_dir_component(app_name)?;
    if let Ok(path) = env::var(env_override) {
        return Ok(PathBuf::from(path));
    }
    Ok(default_state_dir(app_name)?.join(CREDENTIAL_FILE_NAME))
}

fn validated_state_dir_component(value: &str) -> Result<&str, TerminalAuthError> {
    if value.is_empty()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        || value.bytes().any(|byte| matches!(byte, b'/' | b'\\'))
    {
        return Err(TerminalAuthError::InvalidCredentialStoreName(
            value.to_owned(),
        ));
    }
    Ok(value)
}

#[cfg(target_os = "macos")]
fn default_state_dir(app_name: &str) -> Result<PathBuf, TerminalAuthError> {
    let home = home_dir()?;
    Ok(home
        .join("Library")
        .join("Application Support")
        .join("Abyss")
        .join(app_name))
}

#[cfg(target_os = "windows")]
fn default_state_dir(app_name: &str) -> Result<PathBuf, TerminalAuthError> {
    let app_data = env::var_os("APPDATA")
        .map(PathBuf::from)
        .ok_or(TerminalAuthError::MissingHomeDirectory)?;
    Ok(app_data.join("Abyss").join(app_name))
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn default_state_dir(app_name: &str) -> Result<PathBuf, TerminalAuthError> {
    if let Ok(path) = env::var("XDG_STATE_HOME") {
        return Ok(PathBuf::from(path).join("abyss").join(app_name));
    }
    Ok(home_dir()?
        .join(".local")
        .join("state")
        .join("abyss")
        .join(app_name))
}

#[cfg(not(target_os = "windows"))]
fn home_dir() -> Result<PathBuf, TerminalAuthError> {
    env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or(TerminalAuthError::MissingHomeDirectory)
}

fn write_private_json<T>(path: &Path, value: &T) -> Result<(), TerminalAuthError>
where
    T: Serialize,
{
    let temporary_path = path.with_extension(format!("tmp.{}", std::process::id()));
    let bytes = serde_json::to_vec_pretty(value).map_err(TerminalAuthError::CredentialEncoding)?;
    {
        let mut file = private_create(&temporary_path)?;
        file.write_all(&bytes)
            .and_then(|()| file.write_all(b"\n"))
            .and_then(|()| file.sync_all())
            .map_err(|source| TerminalAuthError::filesystem(temporary_path.clone(), source))?;
    }
    replace_file(&temporary_path, path).map_err(|source| {
        match fs::remove_file(&temporary_path) {
            Ok(()) => {}
            Err(_cleanup_error) => {}
        }
        TerminalAuthError::filesystem(path.to_path_buf(), source)
    })?;
    #[cfg(unix)]
    restrict_permissions(path)?;
    Ok(())
}

fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(unix)]
fn private_create(path: &Path) -> Result<fs::File, TerminalAuthError> {
    use std::os::unix::fs::OpenOptionsExt as _;

    fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|source| TerminalAuthError::filesystem(path.to_path_buf(), source))
}

#[cfg(not(unix))]
fn private_create(path: &Path) -> Result<fs::File, TerminalAuthError> {
    fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)
        .map_err(|source| TerminalAuthError::filesystem(path.to_path_buf(), source))
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) -> Result<(), TerminalAuthError> {
    use std::os::unix::fs::PermissionsExt as _;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|source| TerminalAuthError::filesystem(path.to_path_buf(), source))
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use chrono::{DateTime, Utc};
    use uuid::Uuid;

    use super::{CredentialFile, FileCredentialStore};
    use crate::session::{AuthenticatedUser, NativeSessionCredential};

    static TEST_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn credential_store_round_trips_json() {
        let directory = unique_test_dir();
        let path = directory.join("credentials.json");
        let store =
            FileCredentialStore::for_app(Some(&path), "abyss-test", "ABYSS_TEST_CREDENTIAL_FILE")
                .expect("store should build");
        let expires_at = "2099-01-01T00:00:00Z"
            .parse::<DateTime<Utc>>()
            .expect("timestamp should parse");

        store
            .write(&CredentialFile::from_session(
                "http://127.0.0.1:8080".to_owned(),
                NativeSessionCredential {
                    token: "secret-token".to_owned(),
                    expires_at,
                    user: AuthenticatedUser {
                        id: Uuid::nil(),
                        email: "user@example.invalid".to_owned(),
                        name: Some("User".to_owned()),
                        roles: vec!["admin".to_owned()],
                    },
                },
            ))
            .expect("credential should write");

        let credential = store.read().expect("credential should read");
        assert_eq!(
            credential.control_plane, "http://127.0.0.1:8080",
            "control plane should round-trip"
        );
        assert_eq!(
            credential.user.email, "user@example.invalid",
            "user email should round-trip"
        );
        store
            .write(&CredentialFile::from_session(
                "http://127.0.0.1:8081".to_owned(),
                NativeSessionCredential {
                    token: "replacement-token".to_owned(),
                    expires_at,
                    user: AuthenticatedUser {
                        id: Uuid::nil(),
                        email: "user@example.invalid".to_owned(),
                        name: None,
                        roles: Vec::new(),
                    },
                },
            ))
            .expect("existing credential should be replaced");
        assert_eq!(
            store.read().expect("replacement should read").token,
            "replacement-token"
        );
        cleanup_dir(directory);
    }

    #[cfg(unix)]
    #[test]
    fn credential_store_writes_owner_only_file() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = unique_test_dir();
        let path = directory.join("credentials.json");
        let store =
            FileCredentialStore::for_app(Some(&path), "abyss-test", "ABYSS_TEST_CREDENTIAL_FILE")
                .expect("store should build");
        let expires_at = "2099-01-01T00:00:00Z"
            .parse::<DateTime<Utc>>()
            .expect("timestamp should parse");

        store
            .write(&CredentialFile::from_session(
                "http://127.0.0.1:8080".to_owned(),
                NativeSessionCredential {
                    token: "secret-token".to_owned(),
                    expires_at,
                    user: AuthenticatedUser {
                        id: Uuid::nil(),
                        email: "user@example.invalid".to_owned(),
                        name: None,
                        roles: Vec::new(),
                    },
                },
            ))
            .expect("credential should write");

        let mode = fs::metadata(&path)
            .expect("credential should exist")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "credential file should be owner-only");
        cleanup_dir(directory);
    }

    #[test]
    fn credential_store_rejects_path_like_app_name() {
        let error =
            match FileCredentialStore::for_app(None, "../abyss-test", "ABYSS_TEST_CREDENTIAL_FILE")
            {
                Ok(_store) => panic!("path-like app names should be rejected"),
                Err(error) => error,
            };

        assert!(
            error.to_string().contains("credential store name"),
            "unexpected error: {error}"
        );
    }

    fn unique_test_dir() -> PathBuf {
        let counter = TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "abyss-terminal-auth-credential-test-{}-{}",
            std::process::id(),
            counter
        ))
    }

    fn cleanup_dir(directory: PathBuf) {
        match fs::remove_dir_all(directory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("failed to clean test directory: {error}"),
        }
    }
}
