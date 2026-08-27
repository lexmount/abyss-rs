//! Discovery and ownership validation for the CLI-managed broker endpoint.

use std::{fs, io, net::SocketAddr, path::Path, path::PathBuf};

use serde::Deserialize;

use super::{BrokerClient, ProxyMode};
use crate::{error::CliError, paths::CliPaths, platform::PlatformAdapter};

/// Resolved REST connection used by one CLI invocation.
pub struct BrokerConnection {
    source: BrokerConnectionSource,
}

enum BrokerConnectionSource {
    Discovered(BrokerEndpoint),
    Override {
        api_addr: SocketAddr,
        auth_token_file: PathBuf,
    },
}

/// Runtime identity published by the CLI-managed broker after binding its API.
pub struct BrokerEndpoint {
    api_addr: SocketAddr,
    auth_token_file: PathBuf,
    pid: u32,
}

#[derive(Deserialize)]
struct StartupInfoFile {
    api_addr: SocketAddr,
    auth_token_file: PathBuf,
    pid: u32,
}

impl BrokerConnection {
    /// Resolves an explicit test override or discovers the platform-owned endpoint.
    pub fn discover(
        paths: &CliPaths,
        platform: &dyn PlatformAdapter,
        api_override: Option<&str>,
        token_override: Option<&Path>,
    ) -> Result<Option<Self>, CliError> {
        if let Some(api) = api_override {
            let api_addr = BrokerClient::parse_api_addr(api)?;
            return Ok(Some(Self {
                source: BrokerConnectionSource::Override {
                    api_addr,
                    auth_token_file: token_override
                        .map_or_else(|| paths.broker_token_file(), Path::to_path_buf),
                },
            }));
        }
        let Some(endpoint) = platform.broker_endpoint(paths)? else {
            return Ok(None);
        };
        if let Some(token_file) = token_override
            && token_file != endpoint.auth_token_file()
        {
            return Ok(Some(Self {
                source: BrokerConnectionSource::Override {
                    api_addr: endpoint.api_addr(),
                    auth_token_file: token_file.to_path_buf(),
                },
            }));
        }
        Ok(Some(Self {
            source: BrokerConnectionSource::Discovered(endpoint),
        }))
    }

    /// Resolves a connection or reports that the CLI broker is stopped.
    pub fn require(
        paths: &CliPaths,
        platform: &dyn PlatformAdapter,
        api_override: Option<&str>,
        token_override: Option<&Path>,
    ) -> Result<Self, CliError> {
        Self::discover(paths, platform, api_override, token_override)?.ok_or_else(|| {
            CliError::InvalidConfiguration(
                "abyss-broker is not running; run `abyss proxy start` first".to_owned(),
            )
        })
    }

    /// Returns the concrete REST address.
    #[must_use]
    pub const fn api_addr(&self) -> SocketAddr {
        match &self.source {
            BrokerConnectionSource::Discovered(endpoint) => endpoint.api_addr(),
            BrokerConnectionSource::Override { api_addr, .. } => *api_addr,
        }
    }

    /// Builds an unauthenticated client for public broker routes.
    pub fn public_client(&self) -> Result<BrokerClient, CliError> {
        BrokerClient::from_addr(self.api_addr())
    }

    /// Builds a bearer-authenticated client for private broker routes.
    pub fn authenticated_client(&self) -> Result<BrokerClient, CliError> {
        match &self.source {
            BrokerConnectionSource::Discovered(endpoint) => endpoint.owned_explicit_client(),
            BrokerConnectionSource::Override {
                api_addr,
                auth_token_file,
            } => BrokerClient::from_addr_and_token(*api_addr, auth_token_file),
        }
    }
}

impl BrokerEndpoint {
    /// Reads the current broker endpoint, returning `None` when no identity exists.
    pub fn discover(paths: &CliPaths) -> Result<Option<Self>, CliError> {
        let path = paths.broker_startup_info_file();
        let contents = match fs::read(&path) {
            Ok(contents) => contents,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(CliError::filesystem(
                    "read broker startup identity",
                    path,
                    source,
                ));
            }
        };
        let identity = serde_json::from_slice::<StartupInfoFile>(&contents).map_err(|error| {
            CliError::InvalidConfiguration(format!(
                "broker startup identity is invalid at {}: {error}",
                path.display()
            ))
        })?;
        Self::validate(identity, paths).map(Some)
    }

    /// Returns the concrete loopback REST address selected by the operating system.
    #[must_use]
    pub const fn api_addr(&self) -> SocketAddr {
        self.api_addr
    }

    /// Returns the broker-owned bearer-token file.
    #[must_use]
    pub fn auth_token_file(&self) -> &Path {
        &self.auth_token_file
    }

    /// Returns the process that published this endpoint.
    #[must_use]
    pub const fn pid(&self) -> u32 {
        self.pid
    }

    /// Builds an unauthenticated client for public health and proxy status.
    pub fn public_client(&self) -> Result<BrokerClient, CliError> {
        BrokerClient::from_addr(self.api_addr)
    }

    /// Builds an authenticated client using the token path in the startup identity.
    pub fn authenticated_client(&self) -> Result<BrokerClient, CliError> {
        BrokerClient::from_addr_and_token(self.api_addr, &self.auth_token_file)
    }

    /// Verifies that the endpoint is the expected CLI-owned explicit broker.
    pub fn require_owned_explicit(&self) -> Result<BrokerClient, CliError> {
        let broker = self.owned_explicit_client()?;
        broker.diagnostics().map_err(|error| {
            self.identity_error(&format!(
                "the startup-info token does not authenticate this broker: {error}"
            ))
        })?;
        Ok(broker)
    }

    /// Verifies public identity fields and builds the authenticated client.
    fn owned_explicit_client(&self) -> Result<BrokerClient, CliError> {
        let public = self.public_client()?;
        let status = public.proxy_status().map_err(|error| {
            self.identity_error(&format!("broker status could not be read: {error}"))
        })?;
        let mode = status.mode.as_ref();
        if !matches!(mode, Some(ProxyMode::Explicit)) {
            return Err(self.identity_error(&format!(
                "the endpoint is serving mode={}",
                mode.map_or("unknown", ProxyMode::as_str)
            )));
        }
        if status.process_id != self.pid {
            return Err(
                self.identity_error("the responding broker process does not match startup-info")
            );
        }
        let broker = self.authenticated_client().map_err(|error| {
            self.identity_error(&format!("the broker token could not be loaded: {error}"))
        })?;
        Ok(broker)
    }

    fn validate(identity: StartupInfoFile, paths: &CliPaths) -> Result<Self, CliError> {
        if !identity.api_addr.ip().is_loopback() || identity.api_addr.port() == 0 {
            return Err(CliError::InvalidConfiguration(format!(
                "broker startup identity contains invalid API address {}",
                identity.api_addr
            )));
        }
        if identity.auth_token_file != paths.broker_token_file() {
            return Err(CliError::InvalidConfiguration(format!(
                "broker startup identity contains unexpected token path {}",
                identity.auth_token_file.display()
            )));
        }
        if identity.pid == 0 {
            return Err(CliError::InvalidConfiguration(
                "broker startup identity contains process ID 0".to_owned(),
            ));
        }
        Ok(Self {
            api_addr: identity.api_addr,
            auth_token_file: identity.auth_token_file,
            pid: identity.pid,
        })
    }

    fn identity_error(&self, details: &str) -> CliError {
        CliError::InvalidConfiguration(format!(
            "broker startup identity at {} is not usable: {details}",
            self.api_addr
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use serde_json::json;

    use super::BrokerEndpoint;
    use crate::paths::CliPaths;

    #[test]
    fn discovers_dynamic_loopback_endpoint() {
        let paths = test_paths("valid");
        write_identity(&paths, "127.0.0.1:29401", &paths.broker_token_file(), 42);

        let endpoint = BrokerEndpoint::discover(&paths)
            .expect("startup identity should load")
            .expect("startup identity should exist");

        assert_eq!(endpoint.api_addr().to_string(), "127.0.0.1:29401");
        assert_eq!(endpoint.auth_token_file(), paths.broker_token_file());
        assert_eq!(endpoint.pid(), 42);
        drop(fs::remove_dir_all(paths.root()));
    }

    #[test]
    fn missing_startup_identity_is_not_a_running_endpoint() {
        let paths = test_paths("missing");

        assert!(
            BrokerEndpoint::discover(&paths)
                .expect("missing identity should not fail")
                .is_none()
        );
    }

    #[test]
    fn rejects_zero_non_loopback_and_foreign_identity_fields() {
        let paths = test_paths("invalid");
        let cases = [
            ("127.0.0.1:0", paths.broker_token_file(), 42),
            ("192.0.2.10:29401", paths.broker_token_file(), 42),
            ("127.0.0.1:29401", paths.root().join("foreign.token"), 42),
            ("127.0.0.1:29401", paths.broker_token_file(), 0),
        ];

        for (api_addr, token_file, pid) in cases {
            write_identity(&paths, api_addr, &token_file, pid);
            assert!(BrokerEndpoint::discover(&paths).is_err());
        }
        drop(fs::remove_dir_all(paths.root()));
    }

    fn test_paths(label: &str) -> CliPaths {
        let root = std::env::temp_dir().join(format!(
            "abyss-cli-broker-endpoint-{label}-{}-{}",
            std::process::id(),
            rand_suffix()
        ));
        CliPaths::at(root)
    }

    fn write_identity(paths: &CliPaths, api_addr: &str, token_file: &Path, pid: u32) {
        let path = paths.broker_startup_info_file();
        fs::create_dir_all(path.parent().expect("identity path should have parent"))
            .expect("identity directory should be created");
        fs::write(
            path,
            serde_json::to_vec(&json!({
                "api_addr": api_addr,
                "auth_token_file": token_file,
                "pid": pid,
            }))
            .expect("identity fixture should serialize"),
        )
        .expect("identity fixture should write");
    }

    fn rand_suffix() -> u128 {
        use std::time::{SystemTime, UNIX_EPOCH};

        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock should follow Unix epoch")
            .as_nanos()
    }
}
