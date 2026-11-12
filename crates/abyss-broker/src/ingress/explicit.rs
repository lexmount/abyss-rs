//! Configurable IPv4 and IPv6 HTTP explicit-proxy ingress.
//!
//! This adapter accepts opt-in proxy clients, decodes their initial proxy
//! request, acknowledges CONNECT, then hands client IO and unresolved target metadata
//! to MITM. Policy selects the final route before DNS or connection setup. Provider parsing,
//! policy, auditing, and upload behavior remain outside this module.

use std::{io, net::SocketAddr};

use abyss_mitm::{
    ExplicitProxyErrorCategory, ExplicitProxyProtocol, ExplicitRequestDecoder,
    ExplicitRequestError, FlowIngress,
};
use thiserror::Error;
use tokio::{
    io::AsyncWriteExt as _,
    net::{TcpListener, TcpStream},
};

use super::{
    Ingress, IngressConnection, IngressError, IngressFactory, IngressRuntimeStatus, PlatformFlow,
    PlatformFlowMetadata, StartedIngress,
};
use abyss_mitm::outbound::{HttpConnectProxy, ListenerEndpoint};

use crate::network_config::NetworkRuntime;

/// Explicit HTTP proxy endpoint requested by CLI or configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct ExplicitIngressEndpoint {
    listen_addr: SocketAddr,
}

impl ExplicitIngressEndpoint {
    /// Creates an endpoint. The operating system validates the address at bind time.
    #[must_use]
    pub const fn new(listen_addr: SocketAddr) -> Self {
        Self { listen_addr }
    }

    /// Returns a compact requested-endpoint label.
    #[must_use]
    pub fn endpoint_label(&self) -> String {
        self.listen_addr.to_string()
    }

    /// Binds this endpoint to the broker's shared outbound policy.
    #[must_use]
    pub const fn into_factory(self, network: NetworkRuntime) -> ExplicitIngressFactory {
        ExplicitIngressFactory {
            listen_addr: self.listen_addr,
            network,
        }
    }
}

/// Factory that binds one explicit HTTP proxy listener.
pub struct ExplicitIngressFactory {
    network: NetworkRuntime,
    listen_addr: SocketAddr,
}

impl IngressFactory for ExplicitIngressFactory {
    type Ingress = ExplicitIngress;

    async fn start(self) -> Result<StartedIngress<Self::Ingress>, IngressError> {
        let listener = TcpListener::bind(self.listen_addr)
            .await
            .map_err(|source| ExplicitIngressError::Bind {
                listen_addr: self.listen_addr,
                source,
            })?;
        let listen_addr = listener
            .local_addr()
            .map_err(|source| ExplicitIngressError::ListenerAddress { source })?;
        if let Some(proxy) = self.network.snapshot().proxy()
            && let Some(ip) = proxy.endpoint().host().as_ip_addr()
            && same_endpoint(SocketAddr::new(ip, proxy.endpoint().port()), listen_addr)?
        {
            return Err(ExplicitIngressError::SelfTarget {
                target: proxy.endpoint().authority(),
                listen_addr,
            }
            .into());
        }
        Ok(StartedIngress::new(
            ExplicitIngress {
                network: self.network,
                listener,
                listen_addr,
            },
            IngressRuntimeStatus::explicit_http(listen_addr),
        ))
    }
}

/// Bound explicit HTTP proxy listener.
pub struct ExplicitIngress {
    network: NetworkRuntime,
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
            upstream: self.network.snapshot().proxy().cloned(),
        })
    }
}

/// Accepted client connection awaiting proxy-protocol normalization.
pub struct ExplicitConnection {
    client: TcpStream,
    peer_addr: SocketAddr,
    listen_addr: SocketAddr,
    upstream: Option<HttpConnectProxy>,
}

impl IngressConnection for ExplicitConnection {
    async fn into_flow(mut self) -> Result<PlatformFlow, IngressError> {
        let local_addr = self
            .client
            .local_addr()
            .map_err(|source| ExplicitIngressError::ListenerAddress { source })?;
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
        if protocol == ExplicitProxyProtocol::HttpConnect {
            self.write_response(ProxyResponse::ConnectionEstablished)
                .await?;
        }

        let destination = target
            .host()
            .as_ip_addr()
            .map_or(abyss_mitm::DestinationAddress::Unknown, |ip| {
                abyss_mitm::DestinationAddress::Known(SocketAddr::new(ip, target.port()))
            });
        let destination_host = Some(target.host().to_string());
        let route_target = target.clone();
        let ingress = FlowIngress::ExplicitProxy {
            protocol,
            target,
            upstream_proxy: None,
            proxy_endpoint: self
                .upstream
                .as_ref()
                .map(|proxy| proxy.endpoint().authority()),
        };
        let metadata = PlatformFlowMetadata::from_destination_parts(
            Some(self.peer_addr),
            Some(local_addr),
            destination,
            destination_host,
            None,
        );
        let mut flow = PlatformFlow::new(self.client, metadata).with_ingress(ingress);
        if let Some(proxy) = self.upstream {
            flow =
                flow.with_upstream_proxy(proxy.excluding_endpoint(self.listen_addr), route_target);
        }
        Ok(flow.with_read_prefix(client_prefix))
    }
}

impl ExplicitConnection {
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
    RequestTimeout,
    RequestHeaderFieldsTooLarge,
    HttpVersionNotSupported,
}

impl ProxyResponse {
    const fn status_code(self) -> u16 {
        match self {
            Self::ConnectionEstablished => 200,
            Self::BadRequest => 400,
            Self::RequestTimeout => 408,
            Self::RequestHeaderFieldsTooLarge => 431,
            Self::HttpVersionNotSupported => 505,
        }
    }

    const fn bytes(self) -> &'static [u8] {
        match self {
            Self::ConnectionEstablished => b"HTTP/1.1 200 Connection Established\r\n\r\n",
            Self::BadRequest => response_bytes::BAD_REQUEST,
            Self::RequestTimeout => response_bytes::REQUEST_TIMEOUT,
            Self::RequestHeaderFieldsTooLarge => response_bytes::REQUEST_HEADER_FIELDS_TOO_LARGE,
            Self::HttpVersionNotSupported => response_bytes::HTTP_VERSION_NOT_SUPPORTED,
        }
    }
}

mod response_bytes {
    pub(super) const BAD_REQUEST: &[u8] =
        b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
    pub(super) const REQUEST_TIMEOUT: &[u8] =
        b"HTTP/1.1 408 Request Timeout\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
    pub(super) const REQUEST_HEADER_FIELDS_TOO_LARGE: &[u8] = b"HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
    pub(super) const HTTP_VERSION_NOT_SUPPORTED: &[u8] = b"HTTP/1.1 505 HTTP Version Not Supported\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
}

/// Errors raised while binding or preparing explicit HTTP proxy connections.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ExplicitIngressError {
    /// Binding the explicit listener failed.
    #[error("bind explicit proxy listener at {listen_addr}: {source}")]
    Bind {
        listen_addr: SocketAddr,
        #[source]
        source: io::Error,
    },
    /// Reading the listener or accepted socket's local address failed.
    #[error("read explicit proxy local address: {source}")]
    ListenerAddress {
        #[source]
        source: io::Error,
    },
    /// Local interface discovery failed while checking for a proxy loop.
    #[error("inspect explicit proxy listener interfaces: {source}")]
    ListenerInterfaces {
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
    /// A request attempted to route back into this explicit listener.
    #[error("explicit proxy target `{target}` resolves to listener `{listen_addr}`")]
    SelfTarget {
        target: String,
        listen_addr: SocketAddr,
    },
    /// Writing a proxy protocol response to the client failed.
    #[error("write explicit proxy HTTP {status} response: {source}")]
    WriteResponse {
        status: u16,
        #[source]
        source: io::Error,
    },
}

fn same_endpoint(
    candidate: SocketAddr,
    listener: SocketAddr,
) -> Result<bool, ExplicitIngressError> {
    ListenerEndpoint::new(listener)
        .contains(candidate)
        .map_err(|source| ExplicitIngressError::ListenerInterfaces { source })
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::TcpStream,
    };

    use super::{ExplicitIngressEndpoint, ProxyResponse};
    use crate::ingress::{Ingress as _, IngressConnection as _, IngressFactory as _};

    fn test_network() -> crate::network_config::NetworkRuntime {
        crate::network_config::NetworkRuntime::new(None, None)
            .expect("test network policy should be valid")
    }

    #[tokio::test]
    async fn startup_accepts_ipv4_and_ipv6_wildcard_listeners() {
        for address in ["0.0.0.0:0", "[::]:0"] {
            let requested: SocketAddr = address.parse().expect("listener");
            let started = ExplicitIngressEndpoint::new(requested)
                .into_factory(test_network())
                .start()
                .await
                .expect("wildcard listener should bind");
            let (ingress, status) = started.into_parts();
            let actual = status.listen_addr().expect("bound address");
            assert_eq!(actual.ip(), requested.ip());
            assert_ne!(actual.port(), 0);
            ingress.shutdown().await;
        }
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
    async fn unresolved_target_is_accepted_without_upstream_connection() {
        let (mut client, accepted) = accepted_connection().await;
        client.write_all(b"CONNECT unavailable.invalid:443 HTTP/1.1\r\nHost: unavailable.invalid:443\r\n\r\n").await.unwrap();
        let flow = accepted.into_flow().await.expect("routing belongs to MITM");
        assert!(flow.original_destination().socket_addr().is_none());
        assert_eq!(flow.destination_host(), Some("unavailable.invalid"));
        let mut response = [0; 39];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"HTTP/1.1 200 Connection Established\r\n\r\n");
    }

    async fn accepted_connection() -> (TcpStream, super::ExplicitConnection) {
        let started = ExplicitIngressEndpoint::new(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .into_factory(test_network())
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
