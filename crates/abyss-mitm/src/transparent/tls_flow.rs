//! Client-side TLS termination for transparent HTTPS flows.
//!
//! This module reads the `ClientHello`, extracts SNI, asks the MITM authority for
//! a matching leaf certificate, and returns a stream that yields decrypted HTTP
//! bytes to the higher-level request decoder.

use std::net::SocketAddr;

use tokio_rustls::{LazyConfigAcceptor, StartHandshake, rustls};

use crate::tls::MitmTlsAuthority;

use super::{
    BoxedDuplexStream, FlowOperation, OriginalDestination, TlsErrorSide, TransparentFlowError,
    client_hello::InspectedClientHello,
};

pub(super) struct ClientTlsFlow<S> {
    /// Stream after the broker has accepted client TLS.
    ///
    /// Reads from this stream yield decrypted application bytes, not raw TLS
    /// records.
    pub(super) stream: S,
    /// SNI from the client's `ClientHello`.
    ///
    /// The HTTPS path reuses this name for upstream TLS SNI and certificate
    /// verification.
    pub(super) server_name: String,
}

impl ClientTlsFlow<tokio_rustls::server::TlsStream<BoxedDuplexStream>> {
    /// Accepts client TLS and returns a flow that yields decrypted HTTP bytes.
    ///
    /// This is the state transition from raw redirected TCP to client-side TLS
    /// termination. The method reads the `ClientHello`, extracts SNI, creates a
    /// matching MITM server config, and completes the TLS server handshake.
    ///
    /// # Errors
    ///
    /// Returns an error when the `ClientHello` cannot be read, the client did
    /// not send SNI, the MITM certificate cannot be prepared, or the TLS
    /// handshake fails.
    #[tracing::instrument(level = "trace", skip_all)]
    pub(super) async fn accept(
        stream: BoxedDuplexStream,
        peer_addr: Option<SocketAddr>,
        original_destination: &OriginalDestination,
        tls_authority: &MitmTlsAuthority,
    ) -> Result<Self, TransparentFlowError> {
        let start_handshake = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream)
            .await
            .map_err(|source| TransparentFlowError::Io {
                operation: FlowOperation::ReadAgentTlsClientHello,
                source,
            })?;

        // SNI is the only host name available before TLS is decrypted. It is
        // used for the generated leaf certificate and later for upstream TLS.
        let server_name = start_handshake
            .client_hello()
            .server_name()
            .ok_or(TransparentFlowError::MissingSni)?
            .to_owned();
        tracing::info!(
            peer_addr = ?peer_addr,
            %original_destination,
            server_name = %server_name,
            "MITM received TLS ClientHello"
        );

        // The generated leaf certificate must match the client SNI, otherwise
        // ordinary clients reject the MITM TLS server handshake.
        let server_config = tls_authority
            .server_config_for_sni(&server_name)
            .await
            .map_err(|source| TransparentFlowError::Tls {
                side: TlsErrorSide::Client,
                source,
            })?;
        let stream = start_handshake
            .into_stream(server_config)
            .await
            .map_err(|source| TransparentFlowError::Io {
                operation: FlowOperation::AcceptAgentTls,
                source,
            })?;
        tracing::info!(
            peer_addr = ?peer_addr,
            %original_destination,
            server_name = %server_name,
            "MITM accepted client TLS"
        );

        // From this point on, the next layer can parse HTTP from `stream`
        // directly. The encrypted TLS records have been consumed by rustls.
        Ok(Self {
            stream,
            server_name,
        })
    }

    /// Continues client TLS after policy inspection already read `ClientHello`.
    ///
    /// Domain-based decryption policy consumes the raw `ClientHello` before it
    /// knows whether a flow should be intercepted. When the decision is
    /// intercept, this method resumes the rustls server handshake from the
    /// accepted state returned by that inspection instead of reading the
    /// `ClientHello` from the socket again.
    ///
    /// # Errors
    ///
    /// Returns an error when SNI is absent, the MITM certificate cannot be
    /// prepared, or the remaining TLS handshake fails.
    #[tracing::instrument(level = "trace", skip_all)]
    pub(super) async fn accept_inspected(
        inspected: InspectedClientHello,
        peer_addr: Option<SocketAddr>,
        original_destination: &OriginalDestination,
        tls_authority: &MitmTlsAuthority,
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
        let stream = StartHandshake::from_parts(accepted, stream)
            .into_stream(server_config)
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

        Ok(Self {
            stream,
            server_name,
        })
    }
}
