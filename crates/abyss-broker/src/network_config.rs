//! Shared next-hop policy for explicit and platform transparent ingress.
//!
//! Startup files initialize one runtime, which is required by every ingress
//! supporting configured routes. REST updates publish to that same runtime;
//! ingress never reloads files or retains a separate startup-route fallback.
//! Each accepted connection retains its selected snapshot. Configuration is
//! validated before durable publication; protocol negotiation remains in
//! abyss-mitm and Windows redirect-context handling remains platform-owned.

use std::sync::Arc;

use abyss_mitm::outbound::{HttpConnectProxy, UpstreamProxyConfig};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::error::BrokerError;

/// Editable outbound route. No upstream means direct routing.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    /// Optional next hop using the shared upstream protocol configuration.
    pub upstream: Option<UpstreamProxyConfig>,
}

/// Validated policy retained for the complete lifetime of one connection.
pub struct NetworkSnapshot {
    config: NetworkConfig,
    proxy: Option<HttpConnectProxy>,
}

impl NetworkSnapshot {
    /// Borrows the validated next hop without changing this connection's route.
    pub const fn proxy(&self) -> Option<&HttpConnectProxy> {
        self.proxy.as_ref()
    }
}

/// Shared policy publisher; only the runtime configuration transaction writes it.
#[derive(Clone)]
pub struct NetworkRuntime {
    current: Arc<RwLock<Arc<NetworkSnapshot>>>,
    persisted: Option<NetworkConfig>,
}

impl NetworkRuntime {
    /// Resolves a durable override over startup defaults and validates the route.
    pub fn new(
        startup_upstream: Option<UpstreamProxyConfig>,
        persisted: Option<NetworkConfig>,
    ) -> Result<Self, BrokerError> {
        let config = persisted.clone().unwrap_or(NetworkConfig {
            upstream: startup_upstream,
        });
        let snapshot = Self::validate(config)?;
        Ok(Self {
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

    pub fn validate(config: NetworkConfig) -> Result<Arc<NetworkSnapshot>, BrokerError> {
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
