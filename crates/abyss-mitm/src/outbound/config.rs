//! Shared startup configuration for protocol-based next-hop connections.

use std::{path::PathBuf, time::Duration};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio_rustls::rustls::pki_types::{CertificateDer, pem::PemObject as _};

use crate::TargetAuthority;

/// Supported next-hop handshake protocols.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum UpstreamProxyProtocol {
    /// HTTP/1.1 CONNECT over TCP or verified TLS, selected by the endpoint scheme.
    HttpConnect,
}

/// Static next-hop settings shared by the broker and its configuration editors.
#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamProxyConfig {
    /// The handshake spoken to the next hop, independent of its implementation.
    pub protocol: UpstreamProxyProtocol,
    /// HTTP or HTTPS endpoint with an explicit port and no credentials or URL parameters.
    pub endpoint: String,
    /// Absolute path to additional PEM roots for the HTTPS proxy only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_file: Option<PathBuf>,
    /// Absolute path to a JSON object containing Basic proxy username and password.
    /// Contents are loaded when the configuration is applied, never serialized here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials_file: Option<PathBuf>,
    /// Shared budget for proxy DNS and TCP connection establishment.
    #[serde(default = "default_timeout_ms")]
    pub connect_timeout_ms: u64,
    /// Shared budget for proxy TLS, writing CONNECT and receiving its response headers.
    #[serde(default = "default_timeout_ms")]
    pub handshake_timeout_ms: u64,
}

/// An invalid upstream configuration, without echoing potentially secret input.
#[derive(Debug, Error)]
#[error("invalid upstream proxy configuration: {0}")]
pub struct UpstreamProxyConfigError(pub(super) &'static str);

/// Parsed Basic credentials, deliberately without Debug/Serialize to avoid exposing secrets.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProxyCredentials {
    pub(super) username: String,
    pub(super) password: String,
}

impl ProxyCredentials {
    fn validate(&self) -> Result<(), UpstreamProxyConfigError> {
        if self.username.contains(':')
            || self
                .username
                .chars()
                .chain(self.password.chars())
                .any(char::is_control)
        {
            return Err(UpstreamProxyConfigError(
                "proxy username must not contain ':' and credentials must not contain control characters",
            ));
        }
        Ok(())
    }
}

impl UpstreamProxyConfig {
    /// Validates endpoint syntax and bounded positive timeouts without using DNS.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported transports, credentials, or invalid limits.
    pub fn validate(&self) -> Result<(), UpstreamProxyConfigError> {
        let _endpoint = self.target()?;
        if self.ca_file.is_some() && !self.endpoint.starts_with("https://") {
            return Err(UpstreamProxyConfigError(
                "ca_file requires an https:// proxy",
            ));
        }
        for path in self.ca_file.iter().chain(&self.credentials_file) {
            if !path.is_absolute() {
                return Err(UpstreamProxyConfigError(
                    "proxy file paths must be absolute",
                ));
            }
        }
        for timeout in [self.connect_timeout_ms, self.handshake_timeout_ms] {
            if !(1..=120_000).contains(&timeout) {
                return Err(UpstreamProxyConfigError(
                    "timeouts must be in 1..=120000 ms",
                ));
            }
        }
        Ok(())
    }

    /// Loads and validates credentials when preparing a route snapshot.
    /// Serialized configuration retains only the path, never these secret values.
    pub(super) fn load_credentials(
        &self,
    ) -> Result<Option<ProxyCredentials>, UpstreamProxyConfigError> {
        self.credentials_file
            .as_deref()
            .map(|path| {
                let bytes = std::fs::read(path)
                    .map_err(|_| UpstreamProxyConfigError("cannot read proxy credentials file"))?;
                let credentials: ProxyCredentials =
                    serde_json::from_slice(&bytes).map_err(|_| {
                        UpstreamProxyConfigError(
                            "proxy credentials must be a JSON username/password object",
                        )
                    })?;
                credentials.validate()?;
                Ok(credentials)
            })
            .transpose()
    }

    /// Reads the configured PEM bundle when preparing a route snapshot.
    pub(super) fn load_ca_certificates(
        &self,
    ) -> Result<Vec<CertificateDer<'static>>, UpstreamProxyConfigError> {
        let Some(path) = &self.ca_file else {
            return Ok(Vec::new());
        };
        let pem = std::fs::read(path)
            .map_err(|_| UpstreamProxyConfigError("cannot read proxy CA file"))?;
        let certificates = CertificateDer::pem_slice_iter(&pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| UpstreamProxyConfigError("invalid proxy CA PEM bundle"))?;
        if certificates.is_empty() {
            return Err(UpstreamProxyConfigError(
                "proxy CA PEM bundle contains no certificates",
            ));
        }
        Ok(certificates)
    }

    pub(super) fn target(&self) -> Result<TargetAuthority, UpstreamProxyConfigError> {
        let authority = self
            .endpoint
            .strip_prefix("http://")
            .or_else(|| self.endpoint.strip_prefix("https://"))
            .ok_or(UpstreamProxyConfigError(
                "endpoint must use http:// or https://",
            ))?;
        let authority = authority.strip_suffix('/').unwrap_or(authority);
        if authority.contains(['/', '?', '#', '@']) {
            return Err(UpstreamProxyConfigError(
                "endpoint must not contain credentials, paths, queries, or fragments",
            ));
        }
        TargetAuthority::parse(authority).map_err(|_error| {
            UpstreamProxyConfigError("endpoint must contain a valid host and explicit nonzero port")
        })
    }

    pub(super) const fn connect_timeout(&self) -> Duration {
        Duration::from_millis(self.connect_timeout_ms)
    }

    pub(super) const fn handshake_timeout(&self) -> Duration {
        Duration::from_millis(self.handshake_timeout_ms)
    }
}

const fn default_timeout_ms() -> u64 {
    10_000
}
