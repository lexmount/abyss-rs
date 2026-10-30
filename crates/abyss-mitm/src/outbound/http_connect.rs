//! Bounded HTTP CONNECT negotiation with no target DNS or direct fallback.

use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use futures_util::{StreamExt as _, stream::FuturesUnordered};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpSocket, TcpStream, lookup_host},
    time::{self, Instant},
};

use crate::{BoxedDuplexStream, TargetAuthority, transparent::PrefixedDuplexStream};

use super::{
    ProxyConnectStage, ProxySocketInitializer, UpstreamProxyConfig, UpstreamProxyConfigError,
    UpstreamProxyError,
};

const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_HEADERS: usize = 64;
const MAX_INFORMATIONAL_RESPONSES: usize = 8;

/// A validated HTTP CONNECT endpoint. Target TLS is applied after negotiation.
#[derive(Clone)]
pub struct HttpConnectProxy {
    endpoint: TargetAuthority,
    connect_timeout: Duration,
    handshake_timeout: Duration,
    socket_initializer: Option<Arc<dyn ProxySocketInitializer>>,
    excluded_endpoints: Vec<SocketAddr>,
}

/// A target tunnel plus its actual next-hop transport peer.
pub struct ConnectedTunnel {
    /// Stream including bytes read beyond the CONNECT response header boundary.
    pub stream: BoxedDuplexStream,
    /// Proxy socket peer, not the resolved target endpoint.
    pub proxy_peer: SocketAddr,
}

impl HttpConnectProxy {
    /// Validates a static configuration without performing network operations.
    ///
    /// # Errors
    ///
    /// Returns an error when the endpoint or timeouts are invalid.
    pub fn new(config: &UpstreamProxyConfig) -> Result<Self, UpstreamProxyConfigError> {
        config.validate()?;
        Ok(Self {
            endpoint: config.target()?,
            connect_timeout: config.connect_timeout(),
            handshake_timeout: config.handshake_timeout(),
            socket_initializer: None,
            excluded_endpoints: Vec::new(),
        })
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

    /// Establishes a tunnel without resolving the logical target locally.
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
        let deadline = Instant::now().checked_add(self.connect_timeout).ok_or(
            UpstreamProxyError::Protocol {
                reason: "connection deadline exceeds the monotonic clock range",
            },
        )?;
        let addresses = self.resolve(deadline).await?;
        if let Some(address) = addresses.iter().find(|address| {
            excluded_endpoints
                .iter()
                .chain(&self.excluded_endpoints)
                .any(|listener| same_endpoint(**address, *listener))
        }) {
            return Err(UpstreamProxyError::Loop { address: *address });
        }
        let mut stream = self.connect_tcp(&addresses, deadline).await?;
        let proxy_peer = stream
            .peer_addr()
            .map_err(|source| UpstreamProxyError::Io {
                stage: ProxyConnectStage::ConnectProxy,
                source,
            })?;
        let prefix = time::timeout(self.handshake_timeout, Self::handshake(&mut stream, target))
            .await
            .map_err(|_elapsed| UpstreamProxyError::Timeout {
                stage: ProxyConnectStage::Handshake,
                timeout: self.handshake_timeout,
            })??;
        Ok(ConnectedTunnel {
            stream: PrefixedDuplexStream::new(prefix.into_boxed_slice(), Box::new(stream)).boxed(),
            proxy_peer,
        })
    }

    async fn resolve(&self, deadline: Instant) -> Result<Vec<SocketAddr>, UpstreamProxyError> {
        if let Some(ip) = self.endpoint.host().as_ip_addr() {
            return Ok(vec![SocketAddr::new(ip, self.endpoint.port())]);
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
            .collect::<Vec<_>>();
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

    async fn handshake(
        stream: &mut TcpStream,
        target: &TargetAuthority,
    ) -> Result<Vec<u8>, UpstreamProxyError> {
        let request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(handshake_io)?;
        let mut buffer = Vec::new();
        let mut informational = 0_usize;
        loop {
            let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
            let mut response = httparse::Response::new(&mut headers);
            if let httparse::Status::Complete(length) =
                response
                    .parse(&buffer)
                    .map_err(|_error| UpstreamProxyError::Protocol {
                        reason: "malformed or excessive response headers",
                    })?
            {
                if length > MAX_HEADER_BYTES {
                    return Err(UpstreamProxyError::Protocol {
                        reason: "response headers exceed 16 KiB",
                    });
                }
                let status = response.code.ok_or(UpstreamProxyError::Protocol {
                    reason: "missing status code",
                })?;
                if (200..300).contains(&status) {
                    return Ok(buffer.split_off(length));
                }
                if (100..200).contains(&status)
                    && status != 101
                    && informational < MAX_INFORMATIONAL_RESPONSES
                {
                    informational = informational.saturating_add(1);
                    buffer.drain(..length);
                    continue;
                }
                if (100..200).contains(&status) {
                    return Err(UpstreamProxyError::Protocol {
                        reason: "unsupported or excessive informational responses",
                    });
                }
                return Err(UpstreamProxyError::Rejected { status });
            }
            if buffer.len() >= MAX_HEADER_BYTES {
                return Err(UpstreamProxyError::Protocol {
                    reason: "response headers exceed 16 KiB",
                });
            }
            let mut chunk = [0; 2048];
            let count = stream.read(&mut chunk).await.map_err(handshake_io)?;
            if count == 0 {
                return Err(UpstreamProxyError::Protocol {
                    reason: "EOF before CONNECT response headers",
                });
            }
            buffer.extend_from_slice(&chunk[..count]);
        }
    }
}

const fn handshake_io(source: io::Error) -> UpstreamProxyError {
    UpstreamProxyError::Io {
        stage: ProxyConnectStage::Handshake,
        source,
    }
}

/// Compares loopback listener endpoints, including mapped IPv6 and wildcard IPs.
fn same_endpoint(candidate: SocketAddr, listener: SocketAddr) -> bool {
    let canonical = |ip| match ip {
        IpAddr::V6(ipv6) => ipv6.to_ipv4_mapped().map_or(IpAddr::V6(ipv6), IpAddr::V4),
        IpAddr::V4(_) => ip,
    };
    candidate.port() == listener.port()
        && (canonical(candidate.ip()).is_unspecified()
            || canonical(candidate.ip()) == canonical(listener.ip()))
}
