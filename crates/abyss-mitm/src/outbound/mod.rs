//! Next-hop proxy negotiation producing a target byte stream for existing TLS.
//!
//! This layer owns only proxy TCP and CONNECT. It neither changes CA trust nor
//! handles target TLS, HTTP requests, Agent parsing, or proxy product APIs.

mod config;
mod http_connect;

#[cfg(test)]
mod tests;

pub use config::{UpstreamProxyConfig, UpstreamProxyConfigError, UpstreamProxyProtocol};
pub use http_connect::{ConnectedTunnel, HttpConnectProxy};

use std::{io, net::SocketAddr, time::Duration};

use thiserror::Error;

/// Establishment phase used to attribute next-hop failures.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum ProxyConnectStage {
    /// Resolve only the configured proxy endpoint.
    ResolveProxy,
    /// Connect to the proxy's TCP listener.
    ConnectProxy,
    /// Negotiate the target tunnel with HTTP CONNECT.
    Handshake,
}

/// Failures before a next-hop tunnel can be handed to the target pipeline.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum UpstreamProxyError {
    /// A bounded establishment stage exceeded the remaining deadline.
    #[error("upstream proxy {stage:?} timed out within {timeout:?}")]
    Timeout {
        stage: ProxyConnectStage,
        timeout: Duration,
    },
    /// A DNS, TCP, or handshake operation failed.
    #[error("upstream proxy {stage:?}: {source}")]
    Io {
        stage: ProxyConnectStage,
        #[source]
        source: io::Error,
    },
    /// Proxy response framing was invalid or exceeded a limit.
    #[error("upstream proxy CONNECT response: {reason}")]
    Protocol { reason: &'static str },
    /// The proxy rejected CONNECT; response bodies and authentication challenges
    /// are deliberately not exposed to the agent or audit stream.
    #[error("upstream proxy rejected CONNECT with HTTP {status}")]
    Rejected { status: u16 },
    /// The next hop would send traffic back into this broker listener.
    #[error("upstream proxy resolves to broker listener {address}")]
    Loop { address: SocketAddr },
}

impl UpstreamProxyError {
    /// Returns whether a gateway timeout response is appropriate.
    #[must_use]
    pub const fn is_timeout(&self) -> bool {
        matches!(self, Self::Timeout { .. })
    }

    /// Returns the phase at which the error was observed.
    #[must_use]
    pub const fn stage(&self) -> ProxyConnectStage {
        match self {
            Self::Timeout { stage, .. } | Self::Io { stage, .. } => *stage,
            Self::Protocol { .. } | Self::Rejected { .. } => ProxyConnectStage::Handshake,
            Self::Loop { .. } => ProxyConnectStage::ResolveProxy,
        }
    }
}
