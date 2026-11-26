//! Next-hop proxy negotiation producing a target byte stream for existing TLS.
//!
//! This layer owns proxy TCP, optional verified TLS and protocol negotiation. It never changes target CA trust nor
//! handles target TLS, HTTP requests, Agent parsing, or proxy product APIs.

mod authentication;
mod config;
mod connector;
mod http_connect;
mod listener;
mod socks5;
mod transport;
mod wireguard;

#[cfg(test)]
mod secure_tests;
#[cfg(test)]
mod socks5_tests;
#[cfg(test)]
mod tests;

pub use config::{
    NetworkConfig, UpstreamProxyConfig, UpstreamProxyConfigError, UpstreamProxyProtocol,
};
pub use connector::{AccountProxyHop, ConnectedTunnel, UpstreamProxy, UpstreamProxyFactory};
/// Compatibility name for the shared next-hop connector.
pub type HttpConnectProxy = UpstreamProxy;
pub use listener::ListenerEndpoint;

use std::{io, net::SocketAddr, time::Duration};

use thiserror::Error;

/// Per-flow socket setup performed before connecting to a next-hop address.
///
/// Platform adapters use this to associate native connection tracking records.
/// An error aborts that socket attempt; the connector never retries without setup.
pub trait ProxySocketInitializer: Send + Sync {
    /// Initializes a fresh, unconnected socket. Called for every address attempt.
    ///
    /// # Errors
    /// Returns an error when the platform cannot associate its connection state.
    fn initialize(&self, socket: &tokio::net::TcpSocket) -> io::Result<()>;
}

/// Establishment phase used to attribute next-hop failures.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum ProxyConnectStage {
    /// Resolve only the configured proxy endpoint.
    ResolveProxy,
    /// Connect to the proxy's TCP listener.
    ConnectProxy,
    /// Verify and establish TLS with the HTTPS proxy.
    TlsHandshake,
    /// Negotiate the target tunnel using the configured proxy protocol.
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
    #[error("upstream proxy response: {reason}")]
    Protocol { reason: &'static str },
    /// The proxy rejected CONNECT; response bodies and authentication challenges
    /// are deliberately not exposed to the agent or audit stream.
    #[error("upstream proxy rejected CONNECT with HTTP {status}")]
    Rejected { status: u16 },
    /// The SOCKS5 server rejected the target connection. This is not an HTTP status.
    #[error("upstream SOCKS5 CONNECT rejected with reply {reply}")]
    Socks5Rejected { reply: u8 },
    /// No configured authentication method was accepted, or credentials were rejected.
    #[error("upstream SOCKS5 authentication rejected")]
    Authentication,
    /// The next hop would send traffic back into this broker listener.
    #[error("upstream route returns to broker listener {address}")]
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
            Self::Protocol { .. }
            | Self::Rejected { .. }
            | Self::Socks5Rejected { .. }
            | Self::Authentication => ProxyConnectStage::Handshake,
            Self::Loop { .. } => ProxyConnectStage::ResolveProxy,
        }
    }
}

/// Attribute protocol I/O to the handshake without recording peer-supplied data.
const fn handshake_io(source: io::Error) -> UpstreamProxyError {
    UpstreamProxyError::Io {
        stage: ProxyConnectStage::Handshake,
        source,
    }
}
