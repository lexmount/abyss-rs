//! HTTPS transparent flow handling.
//!
//! HTTPS flows require two TLS roles: accept client TLS with a generated leaf
//! certificate, then open upstream TLS to the original destination using the
//! client's SNI as the server name.

use std::{net::SocketAddr, sync::Arc};

use tokio::time;

use super::{
    AcceptedTcpFlow, BoxedDuplexStream, FlowContext, FlowId, FlowIngress, InterceptedHttpOutcome,
    MitmEngine, OriginalDestination, SourceProcess, TransparentFlowError, TransparentFlowOutcome,
    TransparentProtocol, accepted_flow::UpstreamConnection, client_hello::InspectedClientHello,
    relay::DecodedClientFlow, tls_flow::ClientTlsFlow,
    upstream::connect_upstream_tls_with_observer, utils::request_host,
};

pub(super) struct TlsHttpFlow {
    client: TlsHttpClient,
    metadata: TlsHttpMetadata,
}

pub(super) struct TlsHttpMetadata {
    pub(super) flow_id: FlowId,
    pub(super) peer_addr: Option<SocketAddr>,
    pub(super) local_addr: Option<SocketAddr>,
    pub(super) original_destination: OriginalDestination,
    pub(super) destination_host: Option<String>,
    pub(super) source_process: Option<SourceProcess>,
    pub(super) ingress: FlowIngress,
    pub(super) upstream: UpstreamConnection,
    pub(super) traffic_observer: Option<Arc<dyn super::TrafficObserver>>,
}

enum TlsHttpClient {
    Raw(BoxedDuplexStream),
    Inspected(Box<InspectedClientHello>),
}

impl From<AcceptedTcpFlow> for TlsHttpFlow {
    fn from(flow: AcceptedTcpFlow) -> Self {
        Self {
            client: TlsHttpClient::Raw(flow.stream),
            metadata: TlsHttpMetadata {
                flow_id: flow.flow_id,
                peer_addr: flow.peer_addr,
                local_addr: flow.local_addr,
                original_destination: flow.original_destination,
                destination_host: flow.destination_host,
                source_process: flow.source_process,
                ingress: flow.ingress,
                upstream: flow.upstream,
                traffic_observer: flow.traffic_observer,
            },
        }
    }
}

impl TlsHttpFlow {
    pub(super) fn from_inspected(
        inspected: InspectedClientHello,
        metadata: TlsHttpMetadata,
    ) -> Self {
        Self {
            client: TlsHttpClient::Inspected(Box::new(inspected)),
            metadata,
        }
    }

    #[tracing::instrument(level = "trace", skip_all)]
    pub(super) async fn handle(
        self,
        engine: &MitmEngine,
    ) -> Result<TransparentFlowOutcome, TransparentFlowError> {
        let Self { client, metadata } = self;
        let TlsHttpMetadata {
            flow_id,
            peer_addr,
            local_addr,
            original_destination,
            destination_host,
            source_process,
            ingress,
            upstream,
            traffic_observer,
        } = metadata;
        // For HTTPS, the raw accepted TCP stream only contains TLS records.
        // Client TLS must be accepted first so the HTTP decoder sees plaintext.
        let accept_client_tls = async {
            match client {
                TlsHttpClient::Raw(stream) => {
                    ClientTlsFlow::accept(
                        stream,
                        peer_addr,
                        &original_destination,
                        &engine.tls_authority,
                    )
                    .await
                }
                TlsHttpClient::Inspected(inspected) => {
                    ClientTlsFlow::accept_inspected(
                        *inspected,
                        peer_addr,
                        &original_destination,
                        &engine.tls_authority,
                    )
                    .await
                }
            }
        };
        let client_tls = time::timeout(engine.timeouts.client_tls_handshake, accept_client_tls)
            .await
            .map_err(|_elapsed| TransparentFlowError::Timeout {
                operation: super::FlowOperation::AcceptAgentTls,
                timeout: engine.timeouts.client_tls_handshake,
            })??;
        ingress.validate_tls_server_name(Some(&client_tls.server_name))?;

        // Preserve transparent routing semantics: connect to the OS original
        // destination IP:port, but use the ClientHello SNI as upstream TLS
        // server name for SNI and certificate verification.
        let upstream_tls = connect_upstream_tls_with_observer(
            upstream,
            &original_destination,
            &client_tls.server_name,
            engine.upstream_tls_config.clone(),
            engine.timeouts.upstream_connect,
            engine.timeouts.upstream_tls_handshake,
            traffic_observer.clone(),
        )
        .await?;

        let protocol = TransparentProtocol::TlsHttp {
            server_name: client_tls.server_name,
        };
        let context = FlowContext::from_optional_addrs(
            peer_addr,
            local_addr,
            original_destination.clone(),
            protocol,
            source_process,
        )
        .with_flow_id(flow_id)
        .with_destination_host(destination_host)
        .with_ingress(ingress);

        // After client TLS is terminated, the next layer is identical to plain
        // HTTP: decode the first HTTP/1 request, relay bytes to the upstream TLS
        // stream, and invoke hooks once the first response is captured.
        let decoded =
            DecodedClientFlow::from_http1(client_tls.stream, context, engine.timeouts.clone())
                .await?;
        tracing::info!(
            peer_addr = ?peer_addr,
            original_destination = %original_destination,
            method = %decoded.first_request.method(),
            target_path = %decoded.first_request.uri().path(),
            host = ?request_host(&decoded.first_request),
            "MITM decoded TLS HTTP/1 request head"
        );
        let relay = Box::pin(decoded.relay_to(
            upstream_tls,
            &engine.hooks,
            engine.timeouts.clone(),
            engine.max_http1_body_bytes,
        ))
        .await?;

        Ok(TransparentFlowOutcome::Intercepted(Box::new(
            InterceptedHttpOutcome {
                peer_addr,
                local_addr,
                original_destination,
                protocol: relay.protocol,
                first_request: relay.first_request,
                first_response: relay.first_response,
                client_to_upstream_bytes: relay.client_to_upstream_bytes,
                upstream_to_client_bytes: relay.upstream_to_client_bytes,
            },
        )))
    }
}
