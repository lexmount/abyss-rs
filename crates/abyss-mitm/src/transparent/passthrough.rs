//! Raw TCP passthrough for transparent flows that should not be decrypted.
//!
//! This path preserves connectivity for redirected TLS flows whose SNI does not
//! match the MITM decryption policy. No TLS or HTTP parsing happens here; Abyss
//! only relays bytes between the client socket and the original destination.

use std::time::Duration;

use tokio::io::{self, AsyncWriteExt as _};

use super::{
    AcceptedTcpFlow, FlowOperation, TransparentFlowError, TransparentPassthroughOutcome,
    TransparentPassthroughProtocol, upstream::connect_upstream_with_observer,
};

/// Raw TLS passthrough pipeline for flows that policy chooses not to decrypt.
pub(super) struct TlsPassthroughFlow {
    flow: AcceptedTcpFlow,
    server_name: Option<String>,
    initial_client_bytes: Box<[u8]>,
}

impl TlsPassthroughFlow {
    pub(super) const fn new(
        flow: AcceptedTcpFlow,
        server_name: Option<String>,
        initial_client_bytes: Box<[u8]>,
    ) -> Self {
        Self {
            flow,
            server_name,
            initial_client_bytes,
        }
    }

    #[tracing::instrument(level = "trace", skip_all)]
    pub(super) async fn handle(
        self,
        connect_timeout: Duration,
    ) -> Result<TransparentPassthroughOutcome, TransparentFlowError> {
        let Self {
            flow,
            server_name,
            initial_client_bytes,
        } = self;
        let AcceptedTcpFlow {
            flow_id: _,
            mut stream,
            peer_addr,
            local_addr,
            original_destination,
            destination_host: _,
            source_process: _,
            ingress: _,
            upstream,
            traffic_observer,
        } = flow;
        let mut upstream = connect_upstream_with_observer(
            upstream,
            &original_destination,
            connect_timeout,
            traffic_observer,
        )
        .await?;
        tracing::info!(
            peer_addr = ?peer_addr,
            local_addr = ?local_addr,
            %original_destination,
            server_name = ?server_name,
            "MITM passing through TLS flow without decryption"
        );

        if !initial_client_bytes.is_empty() {
            upstream
                .write_all(&initial_client_bytes)
                .await
                .map_err(|source| TransparentFlowError::Io {
                    operation: FlowOperation::WriteProviderTlsClientHello,
                    source,
                })?;
        }
        let initial_client_bytes_len = u64::try_from(initial_client_bytes.len())
            .map_err(|_error| TransparentFlowError::ByteCountOverflow)?;

        let (remaining_client_to_upstream_bytes, upstream_to_client_bytes) =
            io::copy_bidirectional(&mut stream, &mut upstream)
                .await
                .map_err(|source| TransparentFlowError::Io {
                    operation: FlowOperation::RelayPassthrough,
                    source,
                })?;
        let client_to_upstream_bytes = initial_client_bytes_len
            .checked_add(remaining_client_to_upstream_bytes)
            .ok_or(TransparentFlowError::ByteCountOverflow)?;

        Ok(TransparentPassthroughOutcome {
            peer_addr,
            local_addr,
            original_destination,
            protocol: TransparentPassthroughProtocol::Tls { server_name },
            client_to_upstream_bytes,
            upstream_to_client_bytes,
        })
    }
}
