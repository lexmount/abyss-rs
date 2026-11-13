//! Client-side TLS termination for transparent HTTPS flows.
//!
//! This module reads the `ClientHello`, extracts SNI, asks the MITM authority for
//! a matching leaf certificate, and returns a stream that yields decrypted HTTP
//! bytes to the higher-level request decoder.

use std::net::SocketAddr;

use tokio_rustls::StartHandshake;

use crate::tls::MitmTlsAuthority;

use super::{
    BoxedDuplexStream, DestinationAddress, FlowOperation, TlsErrorSide, TransparentFlowError,
    client_hello::InspectedClientHello,
};

pub(super) struct ClientTlsFlow<S> {
    /// Stream after the broker has accepted client TLS.
    ///
    /// Reads from this stream yield decrypted application bytes, not raw TLS
    /// records.
    pub(super) stream: S,
}

impl ClientTlsFlow<tokio_rustls::server::TlsStream<BoxedDuplexStream>> {
    /// Resumes TLS with the protocol already selected by the origin.
    pub(super) async fn accept_inspected_with_alpn(
        inspected: InspectedClientHello,
        peer_addr: Option<SocketAddr>,
        original_destination: &DestinationAddress,
        tls_authority: &MitmTlsAuthority,
        alpn: Option<Vec<u8>>,
    ) -> Result<Self, TransparentFlowError> {
        let InspectedClientHello {
            stream,
            accepted,
            server_name,
            raw_bytes: _,
        } = inspected;
        let server_name = server_name.ok_or(TransparentFlowError::MissingSni)?;
        tracing::info!(
            peer_addr = ?peer_addr,
            %original_destination,
            server_name = %server_name,
            "MITM received inspected TLS ClientHello"
        );

        let server_config = tls_authority
            .server_config_for_sni(&server_name)
            .await
            .map_err(|source| TransparentFlowError::Tls {
                side: TlsErrorSide::Client,
                source,
            })?;
        let mut server_config = (*server_config).clone();
        server_config.alpn_protocols = alpn.into_iter().collect();
        let stream = StartHandshake::from_parts(accepted, stream)
            .into_stream(std::sync::Arc::new(server_config))
            .await
            .map_err(|source| TransparentFlowError::Io {
                operation: FlowOperation::AcceptAgentTls,
                source,
            })?;
        tracing::info!(
            peer_addr = ?peer_addr,
            %original_destination,
            server_name = %server_name,
            "MITM accepted inspected client TLS"
        );

        Ok(Self { stream })
    }
}
