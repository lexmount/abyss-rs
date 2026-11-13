//! HTTPS transparent flow handling.
//!
//! HTTPS flows require two TLS roles: accept client TLS with a generated leaf
//! certificate for the client name, then connect the policy-selected upstream.
//! Redirects use their target domain's TLS identity independently of client TLS.

use std::{net::SocketAddr, sync::Arc};

use tokio::time;

use super::{
    BoxedDuplexStream, DestinationAddress, FlowContext, FlowId, FlowIngress,
    InterceptedHttpOutcome, MitmEngine, SourceProcess, TransparentFlowError,
    TransparentFlowOutcome, TransparentProtocol, accepted_flow::UpstreamConnection,
    client_hello::InspectedClientHello, relay::DecodedClientFlow, tls_flow::ClientTlsFlow,
    upstream::HttpUpstream,
};

pub(super) struct TlsHttpFlow {
    client: InspectedClientHello,
    metadata: TlsHttpMetadata,
}

pub(super) struct TlsHttpMetadata {
    pub(super) flow_id: FlowId,
    pub(super) peer_addr: Option<SocketAddr>,
    pub(super) local_addr: Option<SocketAddr>,
    pub(super) original_destination: DestinationAddress,
    pub(super) destination_host: Option<String>,
    pub(super) source_process: Option<SourceProcess>,
    pub(super) ingress: FlowIngress,
    pub(super) upstream: UpstreamConnection,
    pub(super) traffic_observer: Option<Arc<dyn super::TrafficObserver>>,
    pub(super) redirect: Option<super::RedirectTarget>,
}

enum HttpRoute {
    Deferred(Box<HttpUpstream>),
    Connected(BoxedDuplexStream),
}

impl TlsHttpFlow {
    pub(super) const fn from_inspected(
        inspected: InspectedClientHello,
        metadata: TlsHttpMetadata,
    ) -> Self {
        Self {
            client: inspected,
            metadata,
        }
    }

    fn offered_protocols(client: &InspectedClientHello) -> Vec<Vec<u8>> {
        client
            .accepted
            .client_hello()
            .alpn()
            .map(|protocols| {
                protocols
                    .filter(|protocol| *protocol == b"h2" || *protocol == b"http/1.1")
                    .map(<[u8]>::to_vec)
                    .collect()
            })
            .unwrap_or_default()
    }

    #[tracing::instrument(level = "trace", skip_all)]
    pub(super) async fn handle<C: super::RequestForwardingControl>(
        self,
        engine: &MitmEngine,
        control: &C,
    ) -> Result<TransparentFlowOutcome, TransparentFlowError> {
        let Self { client, metadata } = self;
        let server_name = client
            .server_name
            .clone()
            .ok_or(TransparentFlowError::MissingSni)?;
        let offered = Self::offered_protocols(&client);
        let negotiate_h2 = offered.iter().any(|protocol| protocol == b"h2");
        let context = metadata.context(server_name);
        let selected = HttpUpstream::new(metadata.upstream, &context, metadata.redirect.as_ref())?;
        let (route, alpn) = if negotiate_h2 {
            let (stream, alpn) = selected
                .connect_with_alpn(
                    &metadata.original_destination,
                    engine,
                    metadata.traffic_observer.clone(),
                    offered,
                )
                .await?;
            (HttpRoute::Connected(stream), alpn)
        } else {
            (HttpRoute::Deferred(Box::new(selected)), None)
        };
        let http2 = alpn.as_deref() == Some(b"h2");
        let client_tls = time::timeout(
            engine.timeouts.client_tls_handshake,
            ClientTlsFlow::accept_inspected_with_alpn(
                client,
                metadata.peer_addr,
                &metadata.original_destination,
                &engine.tls_authority,
                alpn,
            ),
        )
        .await
        .map_err(|_| TransparentFlowError::Timeout {
            operation: super::FlowOperation::AcceptAgentTls,
            timeout: engine.timeouts.client_tls_handshake,
        })??;
        let relay = match route {
            HttpRoute::Connected(upstream) => {
                if http2 {
                    super::http2::Http2Relay::new(
                        context,
                        engine,
                        control,
                        metadata.redirect.as_ref(),
                    )
                    .relay(client_tls.stream, upstream)
                    .await?
                } else {
                    let mut decoded = DecodedClientFlow::from_http1(
                        client_tls.stream,
                        context,
                        engine.timeouts.clone(),
                    )
                    .await?;
                    decoded.redirect(metadata.redirect.as_ref())?;
                    Box::pin(decoded.relay_to(
                        upstream,
                        &engine.hooks,
                        engine.timeouts.clone(),
                        engine.max_http1_body_bytes,
                        control,
                    ))
                    .await?
                }
            }
            HttpRoute::Deferred(selected) => {
                let mut decoded = DecodedClientFlow::from_http1(
                    client_tls.stream,
                    context,
                    engine.timeouts.clone(),
                )
                .await?;
                decoded.redirect(metadata.redirect.as_ref())?;
                let upstream = decoded
                    .connect_upstream(*selected, engine, metadata.traffic_observer)
                    .await?;
                Box::pin(decoded.relay_to(
                    upstream,
                    &engine.hooks,
                    engine.timeouts.clone(),
                    engine.max_http1_body_bytes,
                    control,
                ))
                .await?
            }
        };
        Ok(Self::outcome(
            metadata.peer_addr,
            metadata.local_addr,
            metadata.original_destination,
            relay,
        ))
    }

    fn outcome(
        peer_addr: Option<SocketAddr>,
        local_addr: Option<SocketAddr>,
        original_destination: DestinationAddress,
        relay: super::relay::RelayOutcome,
    ) -> TransparentFlowOutcome {
        TransparentFlowOutcome::Intercepted(Box::new(InterceptedHttpOutcome {
            peer_addr,
            local_addr,
            original_destination,
            protocol: relay.protocol,
            first_request: relay.first_request,
            first_response: relay.first_response,
            client_to_upstream_bytes: relay.client_to_upstream_bytes,
            upstream_to_client_bytes: relay.upstream_to_client_bytes,
        }))
    }
}

impl TlsHttpMetadata {
    fn context(&self, server_name: String) -> FlowContext {
        FlowContext::from_destination_parts(
            self.peer_addr,
            self.local_addr,
            self.original_destination.clone(),
            TransparentProtocol::TlsHttp { server_name },
            self.source_process.clone(),
        )
        .with_flow_id(self.flow_id.clone())
        .with_destination_host(self.destination_host.clone())
        .with_ingress(self.ingress.clone())
    }
}
