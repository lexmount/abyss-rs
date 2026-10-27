//! Shared next-hop policy and platform capability boundary.
//!
//! Ingress takes a snapshot for each accepted connection. Configuration is
//! validated before durable publication; protocol negotiation remains in
//! abyss-mitm and Windows redirect-context handling remains platform-owned.

use std::sync::Arc;

use abyss_mitm::outbound::{HttpConnectProxy, UpstreamProxyConfig};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::{config::ProxyIngressMode, error::BrokerError};

/// Editable outbound route. No upstream means direct routing.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    /// Optional next hop using the shared upstream protocol configuration.
    pub upstream: Option<UpstreamProxyConfig>,
}

/// Transport capabilities of the selected ingress, independent of UI platform.
#[derive(Clone, Copy)]
enum OutboundCapability {
    HttpConnect,
    /// WFP must supply redirect context before proxy socket creation is enabled.
    DirectOnly,
}

/// Validated policy retained for the complete lifetime of one connection.
pub struct NetworkSnapshot {
    config: NetworkConfig,
    proxy: Option<HttpConnectProxy>,
}

impl NetworkSnapshot {
    /// Returns the validated next hop without changing this connection's route.
    pub fn proxy(&self) -> Option<HttpConnectProxy> {
        self.proxy.clone()
    }
}

/// Shared policy publisher; only the runtime configuration transaction writes it.
#[derive(Clone)]
pub struct NetworkRuntime {
    capability: OutboundCapability,
    current: Arc<RwLock<Arc<NetworkSnapshot>>>,
    persisted: Option<NetworkConfig>,
}

impl NetworkRuntime {
    /// Resolves a durable override over startup defaults and validates support.
    pub fn new(
        mode: ProxyIngressMode,
        startup_upstream: Option<UpstreamProxyConfig>,
        persisted: Option<NetworkConfig>,
    ) -> Result<Self, BrokerError> {
        let capability = match mode {
            ProxyIngressMode::Explicit | ProxyIngressMode::MacosNetworkExtension => {
                OutboundCapability::HttpConnect
            }
            ProxyIngressMode::WindowsWfp => OutboundCapability::DirectOnly,
        };
        let config = persisted.clone().unwrap_or(NetworkConfig {
            upstream: startup_upstream,
        });
        let snapshot = Self::validate_for(capability, config)?;
        Ok(Self {
            capability,
            current: Arc::new(RwLock::new(snapshot)),
            persisted,
        })
    }

    pub fn snapshot(&self) -> Arc<NetworkSnapshot> {
        Arc::clone(&self.current.read())
    }

    pub fn config(&self) -> NetworkConfig {
        self.snapshot().config.clone()
    }

    /// Initial durable override, kept separate from inherited startup defaults.
    pub fn persisted_config(&self) -> Option<NetworkConfig> {
        self.persisted.clone()
    }

    pub fn validate(&self, config: NetworkConfig) -> Result<Arc<NetworkSnapshot>, BrokerError> {
        Self::validate_for(self.capability, config)
    }

    fn validate_for(
        capability: OutboundCapability,
        config: NetworkConfig,
    ) -> Result<Arc<NetworkSnapshot>, BrokerError> {
        if config.upstream.is_some() && matches!(capability, OutboundCapability::DirectOnly) {
            return Err(BrokerError::invalid_config(
                "configured upstream is not supported by Windows WFP ingress",
            ));
        }
        let proxy = config
            .upstream
            .as_ref()
            .map(HttpConnectProxy::new)
            .transpose()
            .map_err(|error| BrokerError::invalid_config(error.to_string()))?;
        Ok(Arc::new(NetworkSnapshot { config, proxy }))
    }

    /// Infallible publication after the durable configuration commit.
    pub fn publish(&self, snapshot: Arc<NetworkSnapshot>) {
        *self.current.write() = snapshot;
    }
}
