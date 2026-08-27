//! TLS transparent flow routing.
//!
//! A detected TLS flow still needs one more decision before the HTTP MITM
//! pipeline can run: policy may require decrypting it, or may require raw TCP
//! passthrough after reading SNI from `ClientHello`. `TlsFlow` owns that TLS
//! layer routing decision and delegates the chosen lower-level path.

use std::sync::Arc;

use super::{
    AcceptedTcpFlow, MitmEngine, TlsDecryptionAction, TlsDecryptionContext, TlsDecryptionPolicy,
    TransparentFlowError, TransparentFlowOutcome,
    client_hello::{ClientHelloInspector, InspectedClientHello},
    passthrough::TlsPassthroughFlow,
    tls_http::{TlsHttpFlow, TlsHttpMetadata},
};

pub(super) struct TlsFlow {
    flow: AcceptedTcpFlow,
}

impl From<AcceptedTcpFlow> for TlsFlow {
    fn from(flow: AcceptedTcpFlow) -> Self {
        Self { flow }
    }
}

impl TlsFlow {
    #[tracing::instrument(level = "trace", skip_all)]
    pub(super) async fn handle(
        self,
        engine: &MitmEngine,
    ) -> Result<TransparentFlowOutcome, TransparentFlowError> {
        let policy = engine.tls_decryption_policy();
        if !policy.requires_sni_peek() && !self.flow.ingress.requires_tls_server_name_validation() {
            return TlsHttpFlow::from(self.flow).handle(engine).await;
        }

        self.handle_with_decryption_policy(engine, policy).await
    }

    #[tracing::instrument(level = "trace", skip_all)]
    async fn handle_with_decryption_policy(
        self,
        engine: &MitmEngine,
        policy: Arc<TlsDecryptionPolicy>,
    ) -> Result<TransparentFlowOutcome, TransparentFlowError> {
        let AcceptedTcpFlow {
            flow_id,
            stream,
            peer_addr,
            local_addr,
            original_destination,
            destination_host,
            source_process,
            ingress,
            upstream,
            traffic_observer,
        } = self.flow;
        let inspected = ClientHelloInspector::default()
            // Reading the complete ClientHello is part of the Agent-side TLS
            // handshake, not initial protocol detection. This matters even for
            // default-intercept policies when configured rules select exceptions
            // from SNI before Abyss accepts client TLS.
            .read_client_hello(stream, engine.timeouts.client_tls_handshake)
            .await?;
        let server_name = inspected.server_name.clone();
        ingress.validate_tls_server_name(server_name.as_deref())?;
        let target_domain =
            policy_target_domain(server_name.as_deref(), destination_host.as_deref());
        let decision = policy.decide(TlsDecryptionContext::new(
            target_domain,
            source_process.as_ref(),
        ));
        tracing::info!(
            peer_addr = ?peer_addr,
            local_addr = ?local_addr,
            original_destination = %original_destination,
            server_name = ?server_name,
            policy_target_domain = ?target_domain,
            action = ?decision.action(),
            matched_rule_id = ?decision.matched_rule_id(),
            "MITM TLS decryption policy selected action"
        );

        match decision.action() {
            TlsDecryptionAction::Intercept => {
                TlsHttpFlow::from_inspected(
                    inspected,
                    TlsHttpMetadata {
                        flow_id,
                        peer_addr,
                        local_addr,
                        original_destination,
                        destination_host,
                        source_process,
                        ingress,
                        upstream,
                        traffic_observer,
                    },
                )
                .handle(engine)
                .await
            }
            TlsDecryptionAction::Passthrough => {
                let InspectedClientHello {
                    stream,
                    accepted: _,
                    server_name: _,
                    raw_bytes,
                } = inspected;
                let flow = AcceptedTcpFlow::from_boxed_parts(
                    stream,
                    peer_addr,
                    local_addr,
                    original_destination,
                    source_process,
                )
                .with_flow_id(flow_id)
                .with_destination_host(destination_host)
                .with_ingress(ingress)
                .with_upstream_connection(upstream);
                let flow = match traffic_observer {
                    Some(observer) => flow.with_existing_traffic_observer(observer),
                    None => flow,
                };
                let outcome = TlsPassthroughFlow::new(flow, server_name, raw_bytes)
                    .handle(engine.timeouts.upstream_connect)
                    .await?;
                Ok(TransparentFlowOutcome::Passthrough(outcome))
            }
        }
    }
}

fn policy_target_domain<'a>(
    server_name: Option<&'a str>,
    platform_destination_host: Option<&'a str>,
) -> Option<&'a str> {
    server_name.or(platform_destination_host)
}

#[cfg(test)]
mod tests {
    use super::policy_target_domain;

    #[test]
    fn policy_target_prefers_client_hello_sni() {
        assert_eq!(
            policy_target_domain(Some("sni.example"), Some("platform.example")),
            Some("sni.example")
        );
    }

    #[test]
    fn policy_target_falls_back_to_platform_destination_host_without_sni() {
        assert_eq!(
            policy_target_domain(None, Some("platform.example")),
            Some("platform.example")
        );
        assert_eq!(policy_target_domain(None, None), None);
    }
}
