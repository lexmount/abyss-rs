//! Classification of failures while establishing the configured upstream tunnel.

use super::{NetworkFailureClass, NetworkLocation};
use abyss_mitm::{
    FlowOperation,
    outbound::{ProxyConnectStage, UpstreamProxyError},
};

impl From<&UpstreamProxyError> for NetworkLocation {
    fn from(source: &UpstreamProxyError) -> Self {
        Self::from(match source.stage() {
            ProxyConnectStage::ResolveProxy => FlowOperation::ResolveProxy,
            ProxyConnectStage::ConnectProxy => FlowOperation::ConnectProxyTcp,
            ProxyConnectStage::TlsHandshake => FlowOperation::ConnectProxyTls,
            _ => FlowOperation::ProxyConnectHandshake,
        })
    }
}

impl From<&UpstreamProxyError> for NetworkFailureClass {
    fn from(source: &UpstreamProxyError) -> Self {
        match source {
            UpstreamProxyError::Timeout { .. } => Self::Timeout,
            UpstreamProxyError::Io {
                stage: ProxyConnectStage::TlsHandshake,
                ..
            } => Self::TlsError,
            UpstreamProxyError::Io {
                stage: ProxyConnectStage::ResolveProxy,
                ..
            } => Self::DnsError,
            UpstreamProxyError::Io { source, .. } => Self::from(source),
            UpstreamProxyError::Rejected { .. } => Self::HttpError,
            UpstreamProxyError::Protocol { .. } | UpstreamProxyError::Loop { .. } => {
                Self::InvalidProtocol
            }
            _ => Self::Unknown,
        }
    }
}
