//! Shared next-hop transport, loop prevention and bounded protocol negotiation.

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use futures_util::{StreamExt as _, stream::FuturesUnordered};
use tokio::{
    net::{TcpSocket, TcpStream, lookup_host},
    time::{self, Instant},
};

use crate::{BoxedDuplexStream, TargetAuthority, transparent::PrefixedDuplexStream};

use super::{
    ListenerEndpoint, ProxyConnectStage, ProxySocketInitializer, UpstreamProxyConfig,
    UpstreamProxyConfigError, UpstreamProxyError, UpstreamProxyProtocol,
    http_connect::HttpConnectHandshake,
    socks5::Socks5Handshake,
    transport::ProxyTransport,
    wireguard::{RouteRegistry, WireguardRoute},
};

/// A validated protocol-specific next hop. Target TLS is applied after negotiation.
#[derive(Clone)]
pub struct UpstreamProxy {
    endpoint: TargetAuthority,
    transport: ProxyTransport,
    handshake: ProxyHandshake,
    connect_timeout: Duration,
    handshake_timeout: Duration,
    socket_initializer: Option<Arc<dyn ProxySocketInitializer>>,
    excluded_endpoints: Vec<SocketAddr>,
}

/// A target tunnel plus its actual next-hop transport peer.
pub struct ConnectedTunnel {
    /// Target stream, preserving any bytes received with the handshake reply.
    pub stream: BoxedDuplexStream,
    /// Proxy socket peer, not the resolved target endpoint.
    pub proxy_peer: SocketAddr,
}

/// Prepares next hops with `WireGuard` identity reuse scoped to one route manager.
///
/// Share this factory across configuration snapshots. Independent factories do
/// not coordinate identities; active routes and streams own their transports.
#[derive(Default)]
pub struct UpstreamProxyFactory {
    wireguard: RouteRegistry,
}

impl UpstreamProxyFactory {
    /// Validates configuration and reuses matching identities without network I/O.
    ///
    /// # Errors
    ///
    /// Returns an error when the endpoint, timeouts, CA bundle or credentials are invalid.
    pub fn prepare(
        &self,
        config: &UpstreamProxyConfig,
    ) -> Result<UpstreamProxy, UpstreamProxyConfigError> {
        config.validate()?;
        let endpoint = config.target()?;
        let transport = ProxyTransport::new(config, &endpoint)?;
        let credentials = config.load_credentials()?;
        let handshake = match config.protocol {
            UpstreamProxyProtocol::HttpConnect => {
                ProxyHandshake::Http(HttpConnectHandshake::new(credentials.as_ref()))
            }
            UpstreamProxyProtocol::Socks5 => {
                ProxyHandshake::Socks5(Socks5Handshake::new(credentials.as_ref())?)
            }
            UpstreamProxyProtocol::Wireguard => {
                ProxyHandshake::Wireguard(self.wireguard.load(config)?)
            }
        };
        Ok(UpstreamProxy {
            endpoint,
            transport,
            handshake,
            connect_timeout: config.connect_timeout(),
            handshake_timeout: config.handshake_timeout(),
            socket_initializer: None,
            excluded_endpoints: Vec::new(),
        })
    }
}

impl UpstreamProxy {
    /// Creates an independent next hop without performing network operations.
    ///
    /// Clone the returned connector for per-flow use. For configuration reloads,
    /// retain an [`UpstreamProxyFactory`] to reuse active `WireGuard` identities.
    ///
    /// # Errors
    /// Returns an error when the endpoint, timeouts, CA bundle or credentials are invalid.
    pub fn new(config: &UpstreamProxyConfig) -> Result<Self, UpstreamProxyConfigError> {
        UpstreamProxyFactory::default().prepare(config)
    }

    /// Associates this flow's platform state with every next-hop socket before TCP connect.
    #[must_use]
    pub fn with_socket_initializer(mut self, initializer: Arc<dyn ProxySocketInitializer>) -> Self {
        self.socket_initializer = Some(initializer);
        self
    }

    /// Excludes a bound ingress listener when tunneling is deferred until protocol detection.
    #[must_use]
    pub fn excluding_endpoint(mut self, endpoint: SocketAddr) -> Self {
        self.excluded_endpoints.push(endpoint);
        self
    }

    /// Returns the configured proxy authority without credentials or URL details.
    #[must_use]
    pub const fn endpoint(&self) -> &TargetAuthority {
        &self.endpoint
    }

    /// Establishes a target tunnel using the selected protocol's resolver policy.
    ///
    /// `listener` is the actual bound broker endpoint, including dynamic ports.
    ///
    /// # Errors
    ///
    /// Returns typed DNS, TCP, timeout, loop, rejection, and framing errors.
    pub async fn connect(
        &self,
        target: &TargetAuthority,
        listener: SocketAddr,
    ) -> Result<ConnectedTunnel, UpstreamProxyError> {
        self.connect_tunnel(target, &[listener]).await
    }

    /// Establishes a tunnel while excluding any broker-owned TCP listeners.
    /// Unix-socket ingress supplies an empty exclusion list.
    ///
    /// # Errors
    ///
    /// Returns typed connection, timeout, loop, or CONNECT negotiation errors.
    pub async fn connect_tunnel(
        &self,
        target: &TargetAuthority,
        excluded_endpoints: &[SocketAddr],
    ) -> Result<ConnectedTunnel, UpstreamProxyError> {
        // Keep the explicit ingress loop check at the selected-route boundary.
        // Target DNS still belongs to the proxy; only literal local endpoints are checked.
        for listener in excluded_endpoints.iter().chain(&self.excluded_endpoints) {
            if ListenerEndpoint::new(*listener)
                .contains_target(target)
                .map_err(|source| UpstreamProxyError::Io {
                    stage: ProxyConnectStage::ConnectProxy,
                    source,
                })?
            {
                return Err(UpstreamProxyError::Loop { address: *listener });
            }
        }
        let deadline = Instant::now().checked_add(self.connect_timeout).ok_or(
            UpstreamProxyError::Protocol {
                reason: "connection deadline exceeds the monotonic clock range",
            },
        )?;
        let addresses = self.resolve(deadline).await?;
        for address in &addresses {
            for listener in excluded_endpoints.iter().chain(&self.excluded_endpoints) {
                if ListenerEndpoint::new(*listener)
                    .contains(*address)
                    .map_err(|source| UpstreamProxyError::Io {
                        stage: ProxyConnectStage::ConnectProxy,
                        source,
                    })?
                {
                    return Err(UpstreamProxyError::Loop { address: *address });
                }
            }
        }
        if let ProxyHandshake::Wireguard(route) = &self.handshake {
            // The outer transport is UDP, not a WFP-redirected TCP connection.
            // TCP socket initializers belong only to the other proxy protocols.
            return route
                .connect(target, &addresses, self.handshake_timeout)
                .await;
        }
        let stream = self.connect_tcp(&addresses, deadline).await?;
        let proxy_peer = stream
            .peer_addr()
            .map_err(|source| UpstreamProxyError::Io {
                stage: ProxyConnectStage::ConnectProxy,
                source,
            })?;
        let deadline = Instant::now().checked_add(self.handshake_timeout).ok_or(
            UpstreamProxyError::Protocol {
                reason: "handshake deadline exceeds the monotonic clock range",
            },
        )?;
        let mut stream = self
            .transport
            .connect(stream, deadline, self.handshake_timeout)
            .await?;
        let prefix = time::timeout_at(deadline, self.handshake.negotiate(&mut stream, target))
            .await
            .map_err(|_elapsed| UpstreamProxyError::Timeout {
                stage: ProxyConnectStage::Handshake,
                timeout: self.handshake_timeout,
            })??;
        Ok(ConnectedTunnel {
            stream: PrefixedDuplexStream::new(prefix.into_boxed_slice(), stream).boxed(),
            proxy_peer,
        })
    }

    async fn resolve(&self, deadline: Instant) -> Result<Box<[SocketAddr]>, UpstreamProxyError> {
        if let Some(ip) = self.endpoint.host().as_ip_addr() {
            return Ok(Box::new([SocketAddr::new(ip, self.endpoint.port())]));
        }
        let host = self
            .endpoint
            .host()
            .as_dns_name()
            .ok_or(UpstreamProxyError::Protocol {
                reason: "unsupported proxy hostname",
            })?;
        let addresses = time::timeout_at(deadline, lookup_host((host, self.endpoint.port())))
            .await
            .map_err(|_elapsed| UpstreamProxyError::Timeout {
                stage: ProxyConnectStage::ResolveProxy,
                timeout: self.connect_timeout,
            })?
            .map_err(|source| UpstreamProxyError::Io {
                stage: ProxyConnectStage::ResolveProxy,
                source,
            })?
            .collect::<Box<[SocketAddr]>>();
        if addresses.is_empty() {
            return Err(UpstreamProxyError::Io {
                stage: ProxyConnectStage::ResolveProxy,
                source: io::Error::new(io::ErrorKind::NotFound, "proxy resolved to no addresses"),
            });
        }
        Ok(addresses)
    }

    async fn connect_tcp(
        &self,
        addresses: &[SocketAddr],
        deadline: Instant,
    ) -> Result<TcpStream, UpstreamProxyError> {
        let attempts = async {
            let mut pending = addresses
                .iter()
                .map(|address| self.connect_address(*address))
                .collect::<FuturesUnordered<_>>();
            let mut last_error =
                io::Error::new(io::ErrorKind::NotFound, "proxy resolved to no addresses");
            while let Some(result) = pending.next().await {
                match result {
                    Ok(stream) => return Ok(stream),
                    Err(error) => last_error = error,
                }
            }
            Err(last_error)
        };
        time::timeout_at(deadline, attempts)
            .await
            .map_err(|_elapsed| UpstreamProxyError::Timeout {
                stage: ProxyConnectStage::ConnectProxy,
                timeout: self.connect_timeout,
            })?
            .map_err(|source| UpstreamProxyError::Io {
                stage: ProxyConnectStage::ConnectProxy,
                source,
            })
    }

    async fn connect_address(&self, address: SocketAddr) -> io::Result<TcpStream> {
        let socket = if address.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        if let Some(initializer) = &self.socket_initializer {
            initializer.initialize(&socket)?;
        }
        socket.connect(address).await
    }
}

/// Protocol-owned framing is separate from shared transport and route policy.
#[derive(Clone)]
enum ProxyHandshake {
    Http(HttpConnectHandshake),
    Socks5(Socks5Handshake),
    Wireguard(Arc<WireguardRoute>),
}

impl ProxyHandshake {
    async fn negotiate(
        &self,
        stream: &mut BoxedDuplexStream,
        target: &TargetAuthority,
    ) -> Result<Vec<u8>, UpstreamProxyError> {
        match self {
            Self::Http(handshake) => handshake.handshake(stream, target).await,
            Self::Socks5(handshake) => {
                handshake.negotiate(stream, target).await?;
                Ok(Vec::new())
            }
            Self::Wireguard(_) => Err(UpstreamProxyError::Protocol {
                reason: "WireGuard does not negotiate on a TCP proxy socket",
            }),
        }
    }
}
