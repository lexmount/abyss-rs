//! Plain HTTP transparent flow handling.
//!
//! Plain HTTP is the shortest path through transparent MITM: the accepted TCP
//! stream already contains HTTP bytes, so it can be decoded without TLS state.

use std::{net::SocketAddr, sync::Arc};

use super::{
    AcceptedTcpFlow, BoxedDuplexStream, FlowContext, FlowId, FlowIngress, InterceptedHttpOutcome,
    MitmEngine, OriginalDestination, SourceProcess, TransparentFlowError, TransparentFlowOutcome,
    TransparentProtocol, accepted_flow::UpstreamConnection, relay::DecodedClientFlow,
    upstream::connect_upstream_with_observer, utils::request_host,
};

pub(super) struct PlainHttpFlow {
    flow_id: FlowId,
    stream: BoxedDuplexStream,
    peer_addr: Option<SocketAddr>,
    local_addr: Option<SocketAddr>,
    original_destination: OriginalDestination,
    destination_host: Option<String>,
    source_process: Option<SourceProcess>,
    ingress: FlowIngress,
    upstream: UpstreamConnection,
    traffic_observer: Option<Arc<dyn super::TrafficObserver>>,
}

impl From<AcceptedTcpFlow> for PlainHttpFlow {
    fn from(flow: AcceptedTcpFlow) -> Self {
        Self {
            flow_id: flow.flow_id,
            stream: flow.stream,
            peer_addr: flow.peer_addr,
            local_addr: flow.local_addr,
            original_destination: flow.original_destination,
            destination_host: flow.destination_host,
            source_process: flow.source_process,
            ingress: flow.ingress,
            upstream: flow.upstream,
            traffic_observer: flow.traffic_observer,
        }
    }
}

impl PlainHttpFlow {
    #[tracing::instrument(level = "trace", skip_all)]
    pub(super) async fn handle(
        self,
        engine: &MitmEngine,
    ) -> Result<TransparentFlowOutcome, TransparentFlowError> {
        let context = FlowContext::from_optional_addrs(
            self.peer_addr,
            self.local_addr,
            self.original_destination.clone(),
            TransparentProtocol::PlainHttp,
            self.source_process,
        )
        .with_flow_id(self.flow_id)
        .with_destination_host(self.destination_host)
        .with_ingress(self.ingress);
        // Plain HTTP needs no TLS state. The request decoder can immediately
        // read HTTP/1 bytes from the accepted TCP stream.
        let decoded =
            DecodedClientFlow::from_http1(self.stream, context, engine.timeouts.clone()).await?;
        tracing::info!(
            peer_addr = ?self.peer_addr,
            original_destination = %self.original_destination,
            method = %decoded.first_request.method(),
            target_path = %decoded.first_request.uri().path(),
            host = ?request_host(&decoded.first_request),
            "MITM decoded plain HTTP/1 request head"
        );

        // Plain HTTP connects directly to the original destination and then
        // enters the shared relay path. That relay path is responsible for
        // capturing the first complete exchange and invoking hooks.
        let upstream = connect_upstream_with_observer(
            self.upstream,
            &self.original_destination,
            engine.timeouts.upstream_connect,
            self.traffic_observer,
        )
        .await?;
        let relay = Box::pin(decoded.relay_to(
            upstream,
            &engine.hooks,
            engine.timeouts.clone(),
            engine.max_http1_body_bytes,
        ))
        .await?;

        Ok(TransparentFlowOutcome::Intercepted(Box::new(
            InterceptedHttpOutcome {
                peer_addr: self.peer_addr,
                local_addr: self.local_addr,
                original_destination: self.original_destination,
                protocol: relay.protocol,
                first_request: relay.first_request,
                first_response: relay.first_response,
                client_to_upstream_bytes: relay.client_to_upstream_bytes,
                upstream_to_client_bytes: relay.upstream_to_client_bytes,
            },
        )))
    }
}
