//! Durable observations for failures before an explicit upstream tunnel exists.

use abyss_mitm::{
    FlowOperation,
    outbound::{ProxyConnectStage, UpstreamProxyError},
};
use uuid::Uuid;

use super::{
    NetworkErrorCode, NetworkFailureClass, NetworkHop, NetworkLocation, NetworkObservation,
    NetworkOutcome, NetworkTiming,
};
use crate::ingress::{IngressError, explicit::ExplicitIngressError};

impl NetworkObservation {
    /// Captures next-hop preparation failures without treating proxy HTTP as provider HTTP.
    pub(crate) fn from_ingress_error(
        error: &IngressError,
        started_at: u64,
        ended_at: u64,
    ) -> Option<Self> {
        let IngressError::Explicit(ExplicitIngressError::UpstreamProxy {
            target,
            endpoint,
            source,
        }) = error
        else {
            return None;
        };
        let operation = match source.stage() {
            ProxyConnectStage::ResolveProxy => FlowOperation::ResolveProxy,
            ProxyConnectStage::ConnectProxy => FlowOperation::ConnectProxyTcp,
            _ => FlowOperation::ProxyConnectHandshake,
        };
        let location = NetworkLocation::from(operation);
        let failure_class = match source {
            UpstreamProxyError::Timeout { .. } => NetworkFailureClass::Timeout,
            UpstreamProxyError::Io {
                stage: ProxyConnectStage::ResolveProxy,
                ..
            } => NetworkFailureClass::DnsError,
            UpstreamProxyError::Io { source, .. } => NetworkFailureClass::from(source),
            UpstreamProxyError::Rejected { .. } => NetworkFailureClass::HttpError,
            UpstreamProxyError::Protocol { .. } | UpstreamProxyError::Loop { .. } => {
                NetworkFailureClass::InvalidProtocol
            }
            _ => NetworkFailureClass::Unknown,
        };
        let proxy_status = match source {
            UpstreamProxyError::Rejected { status } => Some(*status),
            _ => None,
        };
        let technical_error_code = if proxy_status == Some(407) {
            Some(NetworkErrorCode::UpstreamProxyAuthRequired)
        } else {
            NetworkErrorCode::from_observation(
                location.hop,
                location.stage,
                NetworkOutcome::Failed,
                Some(failure_class),
                None,
            )
        };
        Some(Self {
            observation_id: Uuid::new_v4(),
            flow_id: Some(Uuid::new_v4()),
            observed_at_unix_ms: ended_at,
            ingress_source: "explicit_proxy".to_owned(),
            destination_host: Some(target.host().to_string()),
            destination_addr: target
                .host()
                .as_ip_addr()
                .map(|ip| std::net::SocketAddr::new(ip, target.port()).to_string()),
            target_authority: Some(target.authority()),
            proxy_endpoint: Some(endpoint.clone()),
            proxy_peer: None,
            proxy_status,
            source_pid: None,
            source_process_name: None,
            source_executable_path: None,
            source_bundle_id: None,
            hop: NetworkHop::AbyssToUpstreamProxy,
            direction: Some(location.direction),
            operation: Some(operation),
            stage: location.stage,
            outcome: NetworkOutcome::Failed,
            failure_class: Some(failure_class),
            technical_error_code,
            timing: NetworkTiming::from_unix_ms(started_at, ended_at),
            http_status: None,
            request_method: None,
            request_path: None,
            bytes_up: 0,
            bytes_down: 0,
            error: Some(
                source
                    .to_string()
                    .chars()
                    .take(super::MAX_ERROR_DETAIL_CHARS)
                    .collect(),
            ),
        })
    }
}
