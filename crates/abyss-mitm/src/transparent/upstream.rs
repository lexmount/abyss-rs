//! Upstream connection helpers for transparent flows.
//!
//! Direct routing preserves the OS destination. Configured routes delegate the
//! logical target to the next-hop proxy; explicit ingress can supply an already
//! prepared tunnel. All routes use the same upstream TLS identity and trust
//! checks, independently of socket selection.

use std::{sync::Arc, time::Duration};

use http::Uri;
use tokio::{net::TcpStream, time};
use tokio_rustls::{TlsConnector, rustls};

use crate::tls;

use super::{
    BoxedDuplexStream, DestinationAddress, FlowContext, FlowOperation, LocalRejection, MitmEngine,
    MitmTimeouts, TlsDecryptionAction, TlsDecryptionContext, TlsDecryptionPolicy, TlsErrorSide,
    TrafficDirection, TrafficObserver, TransparentFlowError, accepted_flow::UpstreamConnection,
    io::ObservedStream,
};

/// Opens the final HTTP upstream after request inspection has selected its target.
pub(super) struct RequestUpstream {
    connection: UpstreamConnection,
    server_name: Option<String>,
    tls_config: Arc<rustls::ClientConfig>,
    timeouts: MitmTimeouts,
    policy: Arc<TlsDecryptionPolicy>,
    observer: Option<Arc<dyn TrafficObserver>>,
}

impl RequestUpstream {
    pub(super) fn new(
        connection: UpstreamConnection,
        server_name: Option<String>,
        engine: &MitmEngine,
        observer: Option<Arc<dyn TrafficObserver>>,
    ) -> Self {
        Self {
            connection,
            server_name,
            tls_config: engine.upstream_tls_config.clone(),
            timeouts: engine.timeouts.clone(),
            policy: engine.tls_decryption_policy(),
            observer,
        }
    }

    pub(super) async fn connect(
        self,
        target: Option<&Uri>,
        flow: &FlowContext,
    ) -> Result<BoxedDuplexStream, TransparentFlowError> {
        let Some(target) = target else {
            return self.connect_original(flow).await;
        };
        let default_port = if target.scheme_str() == Some("https") {
            443
        } else {
            80
        };
        let authority = crate::TargetAuthority::from_host_port(
            target.host().unwrap_or_default(),
            target.port_u16().unwrap_or(default_port),
        )
        .map_err(|_| TransparentFlowError::Io {
            operation: FlowOperation::ConnectProviderTcp,
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid upstream target",
            ),
        })?;
        let hostname = match authority.host() {
            crate::TargetHost::Dns(name) => name.clone(),
            crate::TargetHost::Ip(address) => address.to_string(),
        };
        let decision = self.policy.decide(TlsDecryptionContext::new(
            Some(&hostname),
            flow.source_process.as_ref(),
        ));
        if decision.action() == TlsDecryptionAction::Block {
            let mut rejection = LocalRejection::new(
                http::StatusCode::FORBIDDEN,
                "network_blocked",
                "Model service target blocked by abyss-broker",
                flow.flow_id.to_string(),
            );
            rejection.rule_id = decision.matched_rule_id().map(str::to_owned);
            return Err(rejection.into());
        }
        let proxy = match self.connection {
            UpstreamConnection::HttpConnect { proxy, .. }
            | UpstreamConnection::Prepared {
                proxy: Some(proxy), ..
            } => Some(proxy),
            _ => None,
        };
        let connection = if let Some(proxy) = proxy {
            UpstreamConnection::HttpConnect {
                proxy,
                target: authority.clone(),
            }
        } else {
            let stream = time::timeout(
                self.timeouts.upstream_connect,
                TcpStream::connect((hostname.as_str(), authority.port())),
            )
            .await
            .map_err(|_| TransparentFlowError::Timeout {
                operation: FlowOperation::ConnectProviderTcp,
                timeout: self.timeouts.upstream_connect,
            })?
            .map_err(|source| TransparentFlowError::Io {
                operation: FlowOperation::ConnectProviderTcp,
                source,
            })?;
            UpstreamConnection::Prepared {
                stream: Box::new(stream),
                proxy: None,
            }
        };
        if target.scheme_str() == Some("https") {
            Ok(Box::new(
                connect_upstream_tls_with_observer(
                    connection,
                    &DestinationAddress::Unknown,
                    &hostname,
                    self.tls_config,
                    self.timeouts.upstream_connect,
                    self.timeouts.upstream_tls_handshake,
                    self.observer,
                )
                .await?,
            ))
        } else {
            connect_upstream_with_observer(
                connection,
                &DestinationAddress::Unknown,
                self.timeouts.upstream_connect,
                self.observer,
            )
            .await
        }
    }

    async fn connect_original(
        self,
        flow: &FlowContext,
    ) -> Result<BoxedDuplexStream, TransparentFlowError> {
        if let Some(server_name) = self.server_name {
            Ok(Box::new(
                connect_upstream_tls_with_observer(
                    self.connection,
                    &flow.original_destination,
                    &server_name,
                    self.tls_config,
                    self.timeouts.upstream_connect,
                    self.timeouts.upstream_tls_handshake,
                    self.observer,
                )
                .await?,
            ))
        } else {
            connect_upstream_with_observer(
                self.connection,
                &flow.original_destination,
                self.timeouts.upstream_connect,
                self.observer,
            )
            .await
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
        UpstreamConnection::Prepared { stream, .. } => {
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

    // TLS identity follows the ClientHello SNI. rustls uses this value both as
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
            UpstreamConnection::Prepared {
                stream: Box::new(prepared),
                proxy: None,
            },
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
