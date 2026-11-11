//! Plain HTTP transparent flow handling.
//!
//! Plain HTTP is the shortest path through transparent MITM: the accepted TCP
//! stream already contains HTTP bytes, so it can be decoded without TLS state.

use std::{net::SocketAddr, sync::Arc};

use super::{
    AcceptedTcpFlow, BoxedDuplexStream, DestinationAddress, FlowContext, FlowId, FlowIngress,
    InterceptedHttpOutcome, MitmEngine, SourceProcess, TransparentFlowError,
    TransparentFlowOutcome, TransparentProtocol, accepted_flow::UpstreamConnection,
    relay::DecodedClientFlow, upstream::RequestUpstream, utils::request_host,
};

pub(super) struct PlainHttpFlow {
    flow_id: FlowId,
    stream: BoxedDuplexStream,
    peer_addr: Option<SocketAddr>,
    local_addr: Option<SocketAddr>,
    original_destination: DestinationAddress,
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
    pub(super) async fn handle<C: super::RequestForwardingControl>(
        self,
        engine: &MitmEngine,
        control: &C,
    ) -> Result<TransparentFlowOutcome, TransparentFlowError> {
        let context = FlowContext::from_destination_parts(
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
        let mut decoded =
            DecodedClientFlow::from_http1(self.stream, context, engine.timeouts.clone()).await?;
        tracing::info!(
            peer_addr = ?self.peer_addr,
            original_destination = %self.original_destination,
            method = %decoded.first_request.method(),
            target_path = %decoded.first_request.uri().path(),
            host = ?request_host(&decoded.first_request),
            "MITM decoded plain HTTP/1 request head"
        );

        let authority = request_host(&decoded.first_request)
            .and_then(|host| host.parse::<http::uri::Authority>().ok());
        let decision = engine
            .tls_decryption_policy()
            .decide(super::TlsDecryptionContext::new(
                authority
                    .as_ref()
                    .map(http::uri::Authority::host)
                    .or(decoded.context.destination_host.as_deref()),
                decoded.context.source_process.as_ref(),
            ));
        if decision.action() == super::TlsDecryptionAction::Block {
            let mut rejection = super::LocalRejection::new(
                http::StatusCode::FORBIDDEN,
                "network_blocked",
                "Network request blocked by abyss-broker",
                decoded.context.flow_id.to_string(),
            );
            rejection.rule_id = decision.matched_rule_id().map(str::to_owned);
            rejection.response_error(&mut decoded.stream).await?;
            return Err(rejection.into());
        }

        // Inspection selects the final target before the shared relay connects.
        let authority = request_host(&decoded.first_request)
            .and_then(|host| host.parse::<http::uri::Authority>().ok());
        let upstream = RequestUpstream::new(
            self.upstream
                .with_server_name(authority.as_ref().map(http::uri::Authority::host))?,
            None,
            engine,
            self.traffic_observer,
        );
        let relay = Box::pin(decoded.relay_to(
            upstream,
            &engine.hooks,
            engine.timeouts.clone(),
            engine.max_http1_body_bytes,
            control,
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
