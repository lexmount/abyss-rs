//! Upstream connection helpers for transparent flows.
//!
//! Transparent MITM keeps two pieces of routing information separate: the OS
//! original destination decides which IP:port to connect, while the TLS SNI
//! decides which server name to send and verify during upstream TLS. Explicit
//! ingress may instead supply a prepared tunnel with an unresolved target IP.

use std::{sync::Arc, time::Duration};

use tokio::{net::TcpStream, time};
use tokio_rustls::{TlsConnector, rustls};

use crate::tls;

use super::{
    BoxedDuplexStream, DestinationAddress, FlowOperation, TlsErrorSide, TrafficDirection,
    TrafficObserver, TransparentFlowError, accepted_flow::UpstreamConnection, io::ObservedStream,
};

/// Opens or reuses an upstream stream and observes bytes read from it.
pub(super) async fn connect_upstream_with_observer(
    upstream: UpstreamConnection,
    original_destination: &DestinationAddress,
    connect_timeout: Duration,
    observer: Option<Arc<dyn TrafficObserver>>,
) -> Result<BoxedDuplexStream, TransparentFlowError> {
    match upstream {
        UpstreamConnection::Prepared(stream) => {
            tracing::info!(
                original_destination = %original_destination,
                "MITM reusing ingress-prepared upstream connection"
            );
            return Ok(observe_upstream(stream, observer));
        }
        UpstreamConnection::Deferred => {}
    }

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
    Ok(observe_upstream(Box::new(stream), observer))
}

/// Opens upstream TLS to the original redirected endpoint.
///
/// Transparent MITM must not re-resolve the hostname from SNI. The client has
/// already chosen an IP:port before WFP redirected the connection, and that
/// original destination is the TCP endpoint we preserve here. The SNI is still
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
    // Reuse the prepared tunnel or route to the OS destination; never resolve SNI.
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
