//! Shared startup configuration for protocol-based next-hop connections.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::TargetAuthority;

/// Supported next-hop handshake protocols.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum UpstreamProxyProtocol {
    /// HTTP/1.1 CONNECT over a plain TCP connection to the proxy.
    HttpConnect,
}

/// Static next-hop settings shared by the broker and its configuration editors.
#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamProxyConfig {
    /// The handshake spoken to the next hop, independent of its implementation.
    pub protocol: UpstreamProxyProtocol,
    /// HTTP endpoint with an explicit port and no credentials or URL parameters.
    pub endpoint: String,
    /// Shared budget for proxy DNS and TCP connection establishment.
    #[serde(default = "default_timeout_ms")]
    pub connect_timeout_ms: u64,
    /// Budget for writing CONNECT and receiving its complete response headers.
    #[serde(default = "default_timeout_ms")]
    pub handshake_timeout_ms: u64,
}

/// An invalid upstream configuration, without echoing potentially secret input.
#[derive(Debug, Error)]
#[error("invalid upstream proxy configuration: {0}")]
pub struct UpstreamProxyConfigError(&'static str);

impl UpstreamProxyConfig {
    /// Validates endpoint syntax and bounded positive timeouts without using DNS.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported transports, credentials, or invalid limits.
    pub fn validate(&self) -> Result<(), UpstreamProxyConfigError> {
        let _endpoint = self.target()?;
        for timeout in [self.connect_timeout_ms, self.handshake_timeout_ms] {
            if !(1..=120_000).contains(&timeout) {
                return Err(UpstreamProxyConfigError(
                    "timeouts must be in 1..=120000 ms",
                ));
            }
        }
        Ok(())
    }

    pub(super) fn target(&self) -> Result<TargetAuthority, UpstreamProxyConfigError> {
        let authority = self
            .endpoint
            .strip_prefix("http://")
            .ok_or(UpstreamProxyConfigError(
                "endpoint must use http://; proxy TLS is not supported",
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
