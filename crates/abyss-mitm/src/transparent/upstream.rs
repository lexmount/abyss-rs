//! Upstream connection helpers for transparent flows.
//!
//! Direct routing preserves the OS destination. Configured routes delegate the
//! logical target to the next-hop proxy. Explicit ingress defers connection until
//! policy selects the target. All routes use the same upstream TLS identity and trust
//! checks, independently of socket selection.

use std::{sync::Arc, time::Duration};

use tokio::{net::TcpStream, time};
use tokio_rustls::{TlsConnector, rustls};

use crate::tls;

mod direct;

use super::{
    BoxedDuplexStream, DestinationAddress, FlowOperation, TlsErrorSide, TrafficDirection,
    TrafficObserver, TransparentFlowError, accepted_flow::UpstreamConnection, io::ObservedStream,
};

/// One selected HTTP route, including the independent upstream TLS identity.
pub(super) struct HttpUpstream {
    connection: UpstreamConnection,
    server_name: Option<String>,
}

impl HttpUpstream {
    pub(super) fn new(
        connection: UpstreamConnection,
        flow: &super::FlowContext,
        redirect: Option<&super::RedirectTarget>,
    ) -> Result<Self, TransparentFlowError> {
        let server_name = match &flow.protocol {
            super::TransparentProtocol::TlsHttp { server_name } => Some(
                redirect
                    .map_or(server_name.as_str(), super::RedirectTarget::host)
                    .to_owned(),
            ),
            _ => None,
        };
        let connection = match redirect {
            Some(target) => connection.redirect(target.host(), flow)?,
            None => connection,
        };
        Ok(Self {
            connection,
            server_name,
        })
    }

    pub(super) async fn connect(
        self,
        original: &DestinationAddress,
        engine: &super::MitmEngine,
        observer: Option<Arc<dyn TrafficObserver>>,
    ) -> Result<BoxedDuplexStream, TransparentFlowError> {
        match self.server_name {
            Some(name) => Ok(Box::new(
                connect_upstream_tls_with_observer(
                    self.connection,
                    original,
                    &name,
                    engine.upstream_tls_config.clone(),
                    engine.timeouts.upstream_connect,
                    engine.timeouts.upstream_tls_handshake,
                    observer,
                )
                .await?,
            )),
            None => {
                connect_upstream_with_observer(
                    self.connection,
                    original,
                    engine.timeouts.upstream_connect,
                    observer,
                )
                .await
            }
        }
    }
}

/// Opens or reuses an upstream stream and observes bytes read from it.
pub(super) async fn connect_upstream_with_observer(
    upstream: UpstreamConnection,
    original_destination: &DestinationAddress,
    connect_timeout: Duration,
    observer: Option<Arc<dyn TrafficObserver>>,
) -> Result<BoxedDuplexStream, TransparentFlowError> {
    match upstream {
        UpstreamConnection::Direct {
            target,
            excluded_listener,
        } => {
            tracing::info!(%target, "MITM connecting selected upstream target");
            let stream = direct::DirectTarget {
                target,
                excluded_listener,
            }
            .connect(connect_timeout)
            .await?;
            return Ok(observe_upstream(Box::new(stream), observer));
        }
        UpstreamConnection::Prepared(stream) => {
            tracing::info!(
                original_destination = %original_destination,
                "MITM reusing ingress-prepared upstream connection"
            );
            return Ok(observe_upstream(stream, observer));
        }
        UpstreamConnection::HttpConnect { proxy, target } => {
            let tunnel = proxy.connect_tunnel(&target, &[]).await.map_err(|source| {
                TransparentFlowError::UpstreamProxy {
                    target: target.clone(),
                    endpoint: proxy.endpoint().authority(),
                    source,
                }
            })?;
            if let Some(observer) = &observer {
                observer.record_proxy_peer(tunnel.proxy_peer);
            }
            tracing::info!(%target, proxy_peer = %tunnel.proxy_peer, "MITM connected configured upstream tunnel");
            return Ok(observe_upstream(tunnel.stream, observer));
        }
        UpstreamConnection::Deferred => {}
    }

    let stream = connect_original_destination(original_destination, connect_timeout).await?;
    Ok(observe_upstream(stream, observer))
}

async fn connect_original_destination(
    original_destination: &DestinationAddress,
    connect_timeout: Duration,
) -> Result<BoxedDuplexStream, TransparentFlowError> {
    tracing::info!(
        original_destination = %original_destination,
        "MITM connecting original upstream destination"
    );
    let stream = time::timeout(
        connect_timeout,
        TcpStream::connect(original_destination.socket_addr().ok_or_else(|| {
            TransparentFlowError::Io {
                operation: FlowOperation::ConnectProviderTcp,
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "unresolved target requires a prepared upstream tunnel",
                ),
            }
        })?),
    )
    .await
    .map_err(|_elapsed| TransparentFlowError::Timeout {
        operation: FlowOperation::ConnectProviderTcp,
        timeout: connect_timeout,
    })?
    .map_err(|source| TransparentFlowError::Io {
        operation: FlowOperation::ConnectProviderTcp,
        source,
    })?;
    tracing::info!(
        original_destination = %original_destination,
        "MITM connected original upstream destination"
    );
    Ok(Box::new(stream))
}

/// Opens upstream TLS over the selected direct connection or proxy tunnel.
///
/// Direct transparent MITM must not re-resolve the hostname from SNI. The client has
/// already chosen an IP:port before WFP redirected the connection, and that
/// original destination is the direct TCP endpoint. Configured proxies instead
/// resolve the selected logical target. The SNI is still
/// passed to rustls so the upstream TLS handshake sends the expected server
/// name and verifies the upstream certificate against that name.
///
/// # Errors
///
/// Returns an error when the TCP connection fails, the SNI cannot be represented
/// as a rustls server name, or the upstream TLS handshake fails.
/// Opens upstream TLS over an observed upstream stream.
pub(super) async fn connect_upstream_tls_with_observer(
    upstream: UpstreamConnection,
    original_destination: &DestinationAddress,
    server_name: &str,
    upstream_tls_config: Arc<rustls::ClientConfig>,
    connect_timeout: Duration,
    handshake_timeout: Duration,
    observer: Option<Arc<dyn TrafficObserver>>,
) -> Result<tokio_rustls::client::TlsStream<BoxedDuplexStream>, TransparentFlowError> {
    // Direct connections retain the OS endpoint. Configured proxies receive the
    // logical hostname when only an IP was available from the platform.
    let upstream = upstream.with_server_name(Some(server_name))?;
    let upstream_tcp =
        connect_upstream_with_observer(upstream, original_destination, connect_timeout, observer)
            .await?;

    // TLS identity follows the selected route (original SNI or redirect host). rustls uses this value both as
    // outbound SNI and as the name for certificate verification.
    let upstream_name =
        tls::validate_server_name(server_name).map_err(|source| TransparentFlowError::Tls {
            side: TlsErrorSide::Upstream,
            source,
        })?;
    let upstream_tls = time::timeout(
        handshake_timeout,
        TlsConnector::from(upstream_tls_config).connect(upstream_name, upstream_tcp),
    )
    .await
    .map_err(|_elapsed| TransparentFlowError::Timeout {
        operation: FlowOperation::ConnectProviderTls,
        timeout: handshake_timeout,
    })?
    .map_err(|source| TransparentFlowError::Io {
        operation: FlowOperation::ConnectProviderTls,
        source,
    })?;
    tracing::info!(
        %original_destination,
        %server_name,
        "MITM connected upstream TLS"
    );

    // Reads and writes on this stream are decrypted HTTP bytes on our side and
    // encrypted TLS records on the upstream network side.
    Ok(upstream_tls)
}

fn observe_upstream(
    stream: BoxedDuplexStream,
    observer: Option<Arc<dyn TrafficObserver>>,
) -> BoxedDuplexStream {
    match observer {
        Some(observer) => Box::new(ObservedStream::new(
            stream,
            observer,
            TrafficDirection::UpstreamToClient,
        )),
        None => stream,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    #[tokio::test]
    async fn unresolved_target_requires_and_uses_the_prepared_stream() {
        let result = connect_upstream_with_observer(
            UpstreamConnection::Deferred,
            &DestinationAddress::Unknown,
            Duration::from_secs(1),
            None,
        )
        .await;
        assert!(matches!(
            result,
            Err(TransparentFlowError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::InvalidInput
        ));

        let (prepared, mut peer) = tokio::io::duplex(32);
        let mut stream = connect_upstream_with_observer(
            UpstreamConnection::Prepared(Box::new(prepared)),
            &DestinationAddress::Unknown,
            Duration::from_secs(1),
            None,
        )
        .await
        .expect("an unresolved target should use its prepared tunnel");
        peer.write_all(b"tunnel").await.expect("peer should write");
        let mut bytes = [0; 6];
        stream
            .read_exact(&mut bytes)
            .await
            .expect("tunnel should read");
        assert_eq!(&bytes, b"tunnel");
        stream
            .write_all(b"reply!")
            .await
            .expect("tunnel should write");
        peer.read_exact(&mut bytes).await.expect("peer should read");
        assert_eq!(&bytes, b"reply!");
    }
}
