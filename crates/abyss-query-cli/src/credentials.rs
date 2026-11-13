//! Profile-bound secret storage and explicit bearer-source resolution.

use std::path::PathBuf;

use abyss_data_client::ApiEndpoint;
use abyss_terminal_auth::NativeSessionCredential;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    args::CredentialStore,
    config::{Authentication, ConfigFile, Profile, TokenSource, atomic_write, read_bounded},
    error::QueryError as Error,
};

#[derive(Deserialize, Serialize)]
pub struct StoredCredential {
    binding: String,
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

pub struct CredentialVault {
    binding: String,
    store: CredentialStore,
    path: PathBuf,
}
impl CredentialVault {
    pub fn new(config: &ConfigFile, name: &str, profile: &Profile) -> Result<Self, Error> {
        let Authentication::Terminal { endpoint, store } = &profile.auth else {
            return Err(Error::Config(
                "this command requires terminal authentication",
            ));
        };
        if cfg!(windows) && matches!(store, CredentialStore::File) {
            return Err(Error::Config(
                "file credential storage is supported on Unix; select keyring on Windows",
            ));
        }
        let binding = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&(
                name,
                ApiEndpoint::parse_with_http(&profile.endpoint, profile.allow_http)?.as_str(),
                ApiEndpoint::parse_with_http(endpoint, profile.allow_http)?.as_str()
            ))?)
        );
        let path = config
            .path
            .parent()
            .ok_or(Error::Config("config path has no parent"))?
            .join("credentials")
            .join(format!("{binding}.json"));
        Ok(Self {
            binding,
            store: *store,
            path,
        })
    }
    fn entry(&self) -> Result<keyring::Entry, Error> {
        keyring::Entry::new("net.lexmount.abyss-query", &self.binding)
            .map_err(|_| Error::Auth("OS credential store is unavailable"))
    }
    pub fn read(&self) -> Result<StoredCredential, Error> {
        let bytes = match self.store {
            CredentialStore::Keyring => self.entry()?.get_password().map_err(|_| Error::Auth("credential unavailable; run auth login or select a usable credential store"))?.into_bytes(),
            CredentialStore::File => {
                #[cfg(unix)]
                self.check_permissions()?;
                read_bounded(&self.path, 64 * 1024).map_err(|_| Error::Auth("credential file unavailable; run auth login"))?
            }
        };
        let credential: StoredCredential = serde_json::from_slice(&bytes)
            .map_err(|_| Error::Auth("stored credential is invalid; run auth login again"))?;
        if credential.binding != self.binding {
            return Err(Error::Auth(
                "credential belongs to a different profile or endpoint",
            ));
        }
        Ok(credential)
    }
    pub fn write(&self, session: NativeSessionCredential) -> Result<(), Error> {
        validate_token(&session.token)?;
        if session.expires_at <= Utc::now() {
            return Err(Error::Auth("login returned an expired credential"));
        }
        let value = serde_json::to_string(&StoredCredential {
            binding: self.binding.clone(),
            token: session.token,
            expires_at: session.expires_at,
        })?;
        match self.store {
            CredentialStore::Keyring => self
                .entry()?
                .set_password(&value)
                .map_err(|_| Error::Auth("cannot persist login in OS credential store")),
            CredentialStore::File => atomic_write(&self.path, value.as_bytes()),
        }
    }
    pub fn remove(&self) -> Result<(), Error> {
        match self.store {
            CredentialStore::Keyring => match self.entry()?.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                Err(_) => Err(Error::Auth("cannot remove OS credential")),
            },
            CredentialStore::File => match std::fs::remove_file(&self.path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error.into()),
            },
        }
    }
    #[cfg(unix)]
    fn check_permissions(&self) -> Result<(), Error> {
        {
            use std::os::unix::fs::PermissionsExt as _;
            let metadata = std::fs::symlink_metadata(&self.path)
                .map_err(|_| Error::Auth("credential file unavailable; run auth login"))?;
            if metadata.file_type().is_symlink() || metadata.permissions().mode() & 0o077 != 0 {
                return Err(Error::Auth(
                    "credential file must not be a symlink and must have mode 0600",
                ));
            }
        }
        Ok(())
    }
}

pub struct CredentialResolver;
impl CredentialResolver {
    pub fn resolve(
        config: &ConfigFile,
        name: &str,
        profile: &Profile,
    ) -> Result<Option<String>, Error> {
        match &profile.auth {
            Authentication::None => Ok(None),
            Authentication::Bearer { source } => {
                let token = match source {
                    TokenSource::Env(name) => std::env::var(name).map_err(|_| {
                        Error::Auth("bearer environment variable is missing or not UTF-8")
                    })?,
                    TokenSource::File(path) => String::from_utf8(read_bounded(path, 64 * 1024).map_err(|_| Error::Auth("cannot read bearer credential file (missing, unreadable or oversized)"))?)
                        .map_err(|_| Error::Auth("token file is not UTF-8"))?,
                    TokenSource::HeaderFile(path) => {
                        let header = String::from_utf8(read_bounded(path, 64 * 1024).map_err(|_| Error::Auth("cannot read bearer credential file (missing, unreadable or oversized)"))?)
                            .map_err(|_| Error::Auth("header file is not UTF-8"))?;
                        let (name, value) = header
                            .trim()
                            .split_once(':')
                            .ok_or(Error::Auth("expected one Authorization: Bearer header"))?;
                        let (scheme, token) = value
                            .trim()
                            .split_once(' ')
                            .ok_or(Error::Auth("expected a Bearer authorization header"))?;
                        if !name.eq_ignore_ascii_case("authorization")
                            || !scheme.eq_ignore_ascii_case("bearer")
                        {
                            return Err(Error::Auth("expected one Authorization: Bearer header"));
                        }
                        token.into()
                    }
                };
                let token = token.trim().to_owned();
                validate_token(&token)?;
                Ok(Some(token))
            }
            Authentication::Terminal { .. } => {
                let credential = CredentialVault::new(config, name, profile)?.read()?;
                if credential.expires_at <= Utc::now() {
                    return Err(Error::Auth("credential expired; run auth login"));
                }
                validate_token(&credential.token)?;
                Ok(Some(credential.token))
            }
        }
    }
}
fn validate_token(token: &str) -> Result<(), Error> {
    if token.is_empty() || !token.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(Error::Auth(
            "bearer token must contain only nonempty visible ASCII without whitespace",
        ));
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::{CredentialResolver, CredentialVault, StoredCredential};
    use crate::{
        args::CredentialStore,
        config::{Authentication, ConfigFile, Profile},
    };
    use abyss_terminal_auth::{AuthenticatedUser, NativeSessionCredential};
    use chrono::Utc;
    use std::os::unix::fs::PermissionsExt as _;

    fn profile() -> Profile {
        Profile {
            endpoint: "https://data.example.test/api/".into(),
            allow_http: false,
            auth: Authentication::Terminal {
                endpoint: "https://auth.example.test/".into(),
                store: CredentialStore::File,
            },
            ca_file: None,
            timeout: 30,
            max_response_bytes: 1024,
            retries: 0,
        }
    }
    #[test]
    fn rejects_expiry_wrong_binding_and_readable_secret_files() {
        let directory = tempfile::tempdir().expect("temporary config");
        let config =
            ConfigFile::new(Some(&directory.path().join("profiles.json"))).expect("config path");
        let profile = profile();
        let vault = CredentialVault::new(&config, "test", &profile).expect("vault");
        let expires_at = Utc::now()
            .checked_add_signed(chrono::Duration::hours(1))
            .expect("expiry");
        vault
            .write(NativeSessionCredential {
                token: "secret".into(),
                expires_at,
                user: AuthenticatedUser {
                    id: uuid::Uuid::nil(),
                    email: "test@example.test".into(),
                    name: None,
                    roles: Vec::new(),
                },
            })
            .expect("persist");
        assert_eq!(
            CredentialResolver::resolve(&config, "test", &profile)
                .expect("valid token")
                .as_deref(),
            Some("secret"),
            "valid credential resolves"
        );
        std::fs::set_permissions(&vault.path, std::fs::Permissions::from_mode(0o644))
            .expect("change mode");
        assert!(vault.read().is_err(), "reject world-readable credential");
        std::fs::set_permissions(&vault.path, std::fs::Permissions::from_mode(0o600))
            .expect("restore mode");
        let mut stored: StoredCredential =
            serde_json::from_slice(&std::fs::read(&vault.path).expect("read fixture"))
                .expect("parse fixture");
        stored.expires_at = Utc::now()
            .checked_sub_signed(chrono::Duration::hours(1))
            .expect("past");
        std::fs::write(&vault.path, serde_json::to_vec(&stored).expect("encode"))
            .expect("write expired");
        assert!(
            CredentialResolver::resolve(&config, "test", &profile).is_err(),
            "expired credentials never authorize a query"
        );
        stored.binding = "wrong-endpoint".into();
        std::fs::write(&vault.path, serde_json::to_vec(&stored).expect("encode"))
            .expect("write mismatch");
        assert!(
            vault.read().is_err(),
            "reject copied credential from another endpoint"
        );
        assert!(
            CredentialVault::new(&config, "other", &profile)
                .expect("other vault")
                .read()
                .is_err(),
            "profile identities are isolated"
        );
    }
}
