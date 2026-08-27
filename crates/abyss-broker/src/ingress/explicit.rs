//! Loopback HTTP explicit-proxy ingress.
//!
//! This adapter accepts opt-in proxy clients, decodes their initial proxy
//! request, resolves and connects the declared target, then hands normalized
//! client IO and metadata to the shared MITM pipeline. Provider parsing,
//! policy, auditing, and upload behavior remain outside this module.

use std::{
    io,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use abyss_mitm::{
    ExplicitProxyErrorCategory, ExplicitProxyProtocol, ExplicitRequestDecoder,
    ExplicitRequestError, FlowIngress, TargetAuthority,
};
use futures_util::{StreamExt as _, stream::FuturesUnordered};
use thiserror::Error;
use tokio::{
    io::AsyncWriteExt as _,
    net::{TcpListener, TcpStream, lookup_host},
    time,
};

use super::{
    Ingress, IngressConnection, IngressError, IngressFactory, IngressRuntimeStatus, PlatformFlow,
    PlatformFlowMetadata, StartedIngress,
};
use crate::connection::OriginalDestination;

const TARGET_RESOLUTION_TIMEOUT: Duration = Duration::from_secs(10);
const TARGET_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Explicit HTTP proxy endpoint requested by CLI or configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct ExplicitIngressEndpoint {
    listen_addr: SocketAddr,
}

impl ExplicitIngressEndpoint {
    /// Creates an endpoint. Startup performs defense-in-depth loopback validation.
    #[must_use]
    pub const fn new(listen_addr: SocketAddr) -> Self {
        Self { listen_addr }
    }

    /// Returns a compact requested-endpoint label.
    #[must_use]
    pub fn endpoint_label(&self) -> String {
        self.listen_addr.to_string()
    }

    /// Converts this endpoint into its zero-sized startup boundary.
    #[must_use]
    pub const fn into_factory(self) -> ExplicitIngressFactory {
        ExplicitIngressFactory {
            listen_addr: self.listen_addr,
        }
    }
}

/// Factory that binds one explicit HTTP proxy listener.
pub struct ExplicitIngressFactory {
    listen_addr: SocketAddr,
}

impl IngressFactory for ExplicitIngressFactory {
    type Ingress = ExplicitIngress;

    async fn start(self) -> Result<StartedIngress<Self::Ingress>, IngressError> {
        if !self.listen_addr.ip().is_loopback() {
            return Err(ExplicitIngressError::NonLoopbackListener {
                listen_addr: self.listen_addr,
            }
            .into());
        }
        let listener = TcpListener::bind(self.listen_addr)
            .await
            .map_err(|source| ExplicitIngressError::Bind {
                listen_addr: self.listen_addr,
                source,
            })?;
        let listen_addr = listener
            .local_addr()
            .map_err(|source| ExplicitIngressError::ListenerAddress { source })?;
        Ok(StartedIngress::new(
            ExplicitIngress {
                listener,
                listen_addr,
            },
            IngressRuntimeStatus::explicit_http(listen_addr),
        ))
    }
}

/// Bound explicit HTTP proxy listener.
pub struct ExplicitIngress {
    listener: TcpListener,
    listen_addr: SocketAddr,
}

impl Ingress for ExplicitIngress {
    type Accepted = ExplicitConnection;

    async fn accept(&mut self) -> Result<Self::Accepted, IngressError> {
        let (client, peer_addr) = self
            .listener
            .accept()
            .await
            .map_err(|source| ExplicitIngressError::Accept { source })?;
        Ok(ExplicitConnection {
            client,
            peer_addr,
            listen_addr: self.listen_addr,
        })
    }
}

/// Accepted client connection awaiting proxy-protocol normalization.
pub struct ExplicitConnection {
    client: TcpStream,
    peer_addr: SocketAddr,
    listen_addr: SocketAddr,
}

impl IngressConnection for ExplicitConnection {
    async fn into_flow(mut self) -> Result<PlatformFlow, IngressError> {
        let decoded = match ExplicitRequestDecoder::default()
            .decode(&mut self.client)
            .await
        {
            Ok(decoded) => decoded,
            Err(source) => {
                self.reject_decoder_error(&source).await?;
                return Err(ExplicitIngressError::Request { source }.into());
            }
        };
        let (target, protocol, client_prefix) = decoded.into_parts();
        let resolved = match self.resolve_target(&target).await {
            Ok(resolved) => resolved,
            Err(error) => {
                self.reject(error.response()).await?;
                return Err(error.into());
            }
        };
        if resolved
            .iter()
            .copied()
            .any(|address| same_endpoint(address, self.listen_addr))
        {
            self.reject(ProxyResponse::Forbidden).await?;
            return Err(ExplicitIngressError::SelfTarget {
                target: target.authority(),
                listen_addr: self.listen_addr,
            }
            .into());
        }
        let upstream = match self.connect_target(&target, &resolved).await {
            Ok(upstream) => upstream,
            Err(error) => {
                self.reject(error.response()).await?;
                return Err(error.into());
            }
        };
        let upstream_addr = match upstream.peer_addr() {
            Ok(address) => address,
            Err(source) => {
                self.reject(ProxyResponse::BadGateway).await?;
                return Err(ExplicitIngressError::UpstreamAddress {
                    target: target.authority(),
                    source,
                }
                .into());
            }
        };

        if protocol == ExplicitProxyProtocol::HttpConnect {
            self.write_response(ProxyResponse::ConnectionEstablished)
                .await?;
        }

        let destination_host = Some(target.host().to_string());
        let ingress = FlowIngress::ExplicitProxy { protocol, target };
        let metadata = PlatformFlowMetadata::from_parts(
            Some(self.peer_addr),
            Some(self.listen_addr),
            OriginalDestination::from(upstream_addr),
            destination_host,
            None,
        );
        Ok(PlatformFlow::new(self.client, metadata)
            .with_ingress(ingress)
            .with_prepared_upstream(upstream)
            .with_read_prefix(client_prefix))
    }
}

impl ExplicitConnection {
    async fn resolve_target(
        &self,
        target: &TargetAuthority,
    ) -> Result<Vec<SocketAddr>, ExplicitIngressError> {
        if let Some(ip) = target.host().as_ip_addr() {
            return Ok(vec![SocketAddr::new(ip, target.port())]);
        }
        if let Some(host) = target.host().as_dns_name() {
            let addresses = time::timeout(
                TARGET_RESOLUTION_TIMEOUT,
                lookup_host((host, target.port())),
            )
            .await
            .map_err(|_elapsed| ExplicitIngressError::ResolveTimeout {
                target: target.authority(),
                timeout: TARGET_RESOLUTION_TIMEOUT,
            })?
            .map_err(|source| ExplicitIngressError::Resolve {
                target: target.authority(),
                source,
            })?
            .collect::<Vec<_>>();
            if addresses.is_empty() {
                return Err(ExplicitIngressError::NoResolvedAddresses {
                    target: target.authority(),
                });
            }
            return Ok(addresses);
        }
        Err(ExplicitIngressError::UnsupportedTargetHost {
            target: target.authority(),
        })
    }

    async fn connect_target(
        &self,
        target: &TargetAuthority,
        addresses: &[SocketAddr],
    ) -> Result<TcpStream, ExplicitIngressError> {
        let mut attempts = FuturesUnordered::new();
        for address in addresses {
            attempts.push(TcpStream::connect(*address));
        }
        let connect = async {
            let mut last_error = None;
            while let Some(result) = attempts.next().await {
                match result {
                    Ok(stream) => return Ok(stream),
                    Err(error) => last_error = Some(error),
                }
            }
            Err(last_error.unwrap_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "target resolved to no addresses")
            }))
        };
        time::timeout(TARGET_CONNECT_TIMEOUT, connect)
            .await
            .map_err(|_elapsed| ExplicitIngressError::ConnectTimeout {
                target: target.authority(),
                timeout: TARGET_CONNECT_TIMEOUT,
            })?
            .map_err(|source| ExplicitIngressError::Connect {
                target: target.authority(),
                source,
            })
    }

    async fn reject_decoder_error(
        &mut self,
        error: &ExplicitRequestError,
    ) -> Result<(), ExplicitIngressError> {
        let response = match error.category() {
            ExplicitProxyErrorCategory::RequestTimeout => Some(ProxyResponse::RequestTimeout),
            ExplicitProxyErrorCategory::HeaderTooLarge => {
                Some(ProxyResponse::RequestHeaderFieldsTooLarge)
            }
            ExplicitProxyErrorCategory::VersionNotSupported => {
                Some(ProxyResponse::HttpVersionNotSupported)
            }
            ExplicitProxyErrorCategory::ConnectionIo => None,
            _ => Some(ProxyResponse::BadRequest),
        };
        if let Some(response) = response {
            self.reject(response).await?;
        }
        Ok(())
    }

    async fn reject(&mut self, response: ProxyResponse) -> Result<(), ExplicitIngressError> {
        self.write_response(response).await?;
        self.client
            .shutdown()
            .await
            .map_err(|source| ExplicitIngressError::WriteResponse {
                status: response.status_code(),
                source,
            })
    }

    async fn write_response(
        &mut self,
        response: ProxyResponse,
    ) -> Result<(), ExplicitIngressError> {
        self.client
            .write_all(response.bytes())
            .await
            .map_err(|source| ExplicitIngressError::WriteResponse {
                status: response.status_code(),
                source,
            })
    }
}

#[derive(Debug, Clone, Copy)]
enum ProxyResponse {
    ConnectionEstablished,
    BadRequest,
    Forbidden,
    RequestTimeout,
    BadGateway,
    GatewayTimeout,
    RequestHeaderFieldsTooLarge,
    HttpVersionNotSupported,
}

impl ProxyResponse {
    const fn status_code(self) -> u16 {
        match self {
            Self::ConnectionEstablished => 200,
            Self::BadRequest => 400,
            Self::Forbidden => 403,
            Self::RequestTimeout => 408,
            Self::BadGateway => 502,
            Self::GatewayTimeout => 504,
            Self::RequestHeaderFieldsTooLarge => 431,
            Self::HttpVersionNotSupported => 505,
        }
    }

    const fn bytes(self) -> &'static [u8] {
        match self {
            Self::ConnectionEstablished => b"HTTP/1.1 200 Connection Established\r\n\r\n",
            Self::BadRequest => response_bytes::BAD_REQUEST,
            Self::Forbidden => response_bytes::FORBIDDEN,
            Self::RequestTimeout => response_bytes::REQUEST_TIMEOUT,
            Self::BadGateway => response_bytes::BAD_GATEWAY,
            Self::GatewayTimeout => response_bytes::GATEWAY_TIMEOUT,
            Self::RequestHeaderFieldsTooLarge => response_bytes::REQUEST_HEADER_FIELDS_TOO_LARGE,
            Self::HttpVersionNotSupported => response_bytes::HTTP_VERSION_NOT_SUPPORTED,
        }
    }
}

mod response_bytes {
    pub(super) const BAD_REQUEST: &[u8] =
        b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
    pub(super) const FORBIDDEN: &[u8] =
        b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
    pub(super) const REQUEST_TIMEOUT: &[u8] =
        b"HTTP/1.1 408 Request Timeout\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
    pub(super) const BAD_GATEWAY: &[u8] =
        b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
    pub(super) const GATEWAY_TIMEOUT: &[u8] =
        b"HTTP/1.1 504 Gateway Timeout\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
    pub(super) const REQUEST_HEADER_FIELDS_TOO_LARGE: &[u8] = b"HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
    pub(super) const HTTP_VERSION_NOT_SUPPORTED: &[u8] = b"HTTP/1.1 505 HTTP Version Not Supported\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
}

/// Errors raised while binding or preparing explicit HTTP proxy connections.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ExplicitIngressError {
    /// Explicit proxy listeners are intentionally restricted to loopback.
    #[error("explicit proxy listener `{listen_addr}` must use a loopback address")]
    NonLoopbackListener { listen_addr: SocketAddr },
    /// Binding the explicit listener failed.
    #[error("bind explicit proxy listener at {listen_addr}: {source}")]
    Bind {
        listen_addr: SocketAddr,
        #[source]
        source: io::Error,
    },
    /// Reading the listener's bound address failed.
    #[error("read explicit proxy listener address: {source}")]
    ListenerAddress {
        #[source]
        source: io::Error,
    },
    /// Accepting an explicit proxy client failed.
    #[error("accept explicit proxy connection: {source}")]
    Accept {
        #[source]
        source: io::Error,
    },
    /// The client's first proxy request was invalid.
    #[error("decode explicit proxy request: {source}")]
    Request {
        #[source]
        source: ExplicitRequestError,
    },
    /// DNS resolution exceeded its deadline.
    #[error("resolve explicit proxy target `{target}` timed out after {timeout:?}")]
    ResolveTimeout { target: String, timeout: Duration },
    /// DNS resolution failed.
    #[error("resolve explicit proxy target `{target}`: {source}")]
    Resolve {
        target: String,
        #[source]
        source: io::Error,
    },
    /// DNS resolution completed without any usable address.
    #[error("explicit proxy target `{target}` resolved to no addresses")]
    NoResolvedAddresses { target: String },
    /// The parser returned a target kind this broker version does not support.
    #[error("explicit proxy target `{target}` uses an unsupported host kind")]
    UnsupportedTargetHost { target: String },
    /// A request attempted to route back into this explicit listener.
    #[error("explicit proxy target `{target}` resolves to listener `{listen_addr}`")]
    SelfTarget {
        target: String,
        listen_addr: SocketAddr,
    },
    /// Opening the upstream TCP connection exceeded its deadline.
    #[error("connect explicit proxy target `{target}` timed out after {timeout:?}")]
    ConnectTimeout { target: String, timeout: Duration },
    /// Opening the upstream TCP connection failed.
    #[error("connect explicit proxy target `{target}`: {source}")]
    Connect {
        target: String,
        #[source]
        source: io::Error,
    },
    /// Reading the selected upstream socket address failed.
    #[error("read connected explicit proxy target `{target}` address: {source}")]
    UpstreamAddress {
        target: String,
        #[source]
        source: io::Error,
    },
    /// Writing a proxy protocol response to the client failed.
    #[error("write explicit proxy HTTP {status} response: {source}")]
    WriteResponse {
        status: u16,
        #[source]
        source: io::Error,
    },
}

impl ExplicitIngressError {
    const fn response(&self) -> ProxyResponse {
        match self {
            Self::ResolveTimeout { .. } | Self::ConnectTimeout { .. } => {
                ProxyResponse::GatewayTimeout
            }
            Self::SelfTarget { .. } => ProxyResponse::Forbidden,
            _ => ProxyResponse::BadGateway,
        }
    }
}

fn same_endpoint(candidate: SocketAddr, listener: SocketAddr) -> bool {
    candidate.port() == listener.port()
        && (candidate.ip().is_unspecified()
            || canonical_ip(candidate.ip()) == canonical_ip(listener.ip()))
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ipv6) => ipv6.to_ipv4_mapped().map_or(IpAddr::V6(ipv6), IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::TcpStream,
    };

    use super::{ExplicitIngressEndpoint, ProxyResponse, same_endpoint};
    use crate::ingress::{Ingress as _, IngressConnection as _, IngressFactory as _};

    #[tokio::test]
    async fn startup_rejects_non_loopback_listener() {
        let error = ExplicitIngressEndpoint::new(SocketAddr::from(([0, 0, 0, 0], 0)))
            .into_factory()
            .start()
            .await
            .err()
            .expect("wildcard explicit listener should fail");

        assert!(error.to_string().contains("loopback"));
    }

    #[test]
    fn self_target_comparison_normalizes_ipv4_mapped_ipv6() {
        assert!(same_endpoint(
            "[::ffff:127.0.0.1]:28999"
                .parse()
                .expect("mapped address should parse"),
            "127.0.0.1:28999"
                .parse()
                .expect("IPv4 address should parse")
        ));
        assert!(same_endpoint(
            "0.0.0.0:28999"
                .parse()
                .expect("unspecified IPv4 address should parse"),
            "127.0.0.1:28999"
                .parse()
                .expect("IPv4 address should parse")
        ));
        assert!(same_endpoint(
            "[::]:28999"
                .parse()
                .expect("unspecified IPv6 address should parse"),
            "[::1]:28999".parse().expect("IPv6 address should parse")
        ));
    }

    #[tokio::test]
    async fn malformed_request_receives_bad_request() {
        let (mut client, accepted) = accepted_connection().await;
        client
            .write_all(b"GET /origin-form HTTP/1.1\r\nHost: example.test\r\n\r\n")
            .await
            .expect("malformed proxy request should write");

        let worker = tokio::spawn(async move { accepted.into_flow().await });
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("rejection response should read");
        let error = match worker.await.expect("worker should join") {
            Ok(_flow) => panic!("origin-form proxy request should fail"),
            Err(error) => error,
        };

        assert!(response.starts_with(ProxyResponse::BadRequest.bytes()));
        assert!(error.to_string().contains("decode explicit proxy request"));
    }

    #[tokio::test]
    async fn request_targeting_listener_receives_forbidden() {
        let endpoint = ExplicitIngressEndpoint::new(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)));
        let started = endpoint
            .into_factory()
            .start()
            .await
            .expect("explicit listener should start");
        let (mut ingress, status) = started.into_parts();
        let listen_addr = status
            .listen_addr()
            .expect("explicit listener should report address");
        let mut client = TcpStream::connect(listen_addr)
            .await
            .expect("test client should connect");
        let accepted = ingress
            .accept()
            .await
            .expect("listener should accept client");
        client
            .write_all(
                format!("CONNECT {listen_addr} HTTP/1.1\r\nHost: {listen_addr}\r\n\r\n").as_bytes(),
            )
            .await
            .expect("CONNECT should write");

        let worker = tokio::spawn(async move { accepted.into_flow().await });
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("forbidden response should read");
        let error = match worker.await.expect("worker should join") {
            Ok(_flow) => panic!("self target should fail"),
            Err(error) => error,
        };

        assert!(response.starts_with(ProxyResponse::Forbidden.bytes()));
        assert!(error.to_string().contains("resolves to listener"));
    }

    async fn accepted_connection() -> (TcpStream, super::ExplicitConnection) {
        let started = ExplicitIngressEndpoint::new(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .into_factory()
            .start()
            .await
            .expect("explicit listener should start");
        let (mut ingress, status) = started.into_parts();
        let listen_addr = status
            .listen_addr()
            .expect("explicit listener should report address");
        let client = TcpStream::connect(listen_addr)
            .await
            .expect("test client should connect");
        let accepted = ingress
            .accept()
            .await
            .expect("listener should accept client");
        (client, accepted)
    }
}
