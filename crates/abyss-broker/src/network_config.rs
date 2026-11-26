//! Shared next-hop policy for explicit and platform transparent ingress.
//!
//! Startup files initialize one runtime, which is required by every ingress
//! supporting configured routes. REST updates publish to that same runtime;
//! ingress never reloads files or retains a separate startup-route fallback.
//! Each accepted connection retains its selected snapshot. Configuration is
//! validated before durable publication; protocol negotiation remains in
//! abyss-mitm and Windows redirect-context handling remains platform-owned.

use std::sync::Arc;

use abyss_mitm::outbound::{UpstreamProxy, UpstreamProxyConfig, UpstreamProxyFactory};
use parking_lot::RwLock;

use crate::error::BrokerError;

#[cfg(test)]
mod tests;

pub use abyss_mitm::outbound::NetworkConfig;

/// Validated policy retained for the complete lifetime of one connection.
pub struct NetworkSnapshot {
    config: NetworkConfig,
    proxy: Option<UpstreamProxy>,
}

impl NetworkSnapshot {
    fn new(config: NetworkConfig, routes: &UpstreamProxyFactory) -> Result<Arc<Self>, BrokerError> {
        let proxy = config
            .upstream
            .as_ref()
            .map(|config| routes.prepare(config))
            .transpose()
            .map_err(|error| BrokerError::invalid_config(error.to_string()))?;
        Ok(Arc::new(Self { config, proxy }))
    }

    /// Borrows the validated next hop without changing this connection's route.
    pub const fn proxy(&self) -> Option<&UpstreamProxy> {
        self.proxy.as_ref()
    }
}

/// Shared policy publisher and owner of reusable next-hop identities.
/// Clones share the factory across updates, including time spent in direct mode.
/// Only the runtime configuration transaction writes the active snapshot.
#[derive(Clone)]
pub struct NetworkRuntime {
    current: Arc<RwLock<Arc<NetworkSnapshot>>>,
    routes: Arc<UpstreamProxyFactory>,
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
        let routes = Arc::new(UpstreamProxyFactory::default());
        let snapshot = NetworkSnapshot::new(config, &routes)?;
        Ok(Self {
            current: Arc::new(RwLock::new(snapshot)),
            routes,
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
        NetworkSnapshot::new(config, &self.routes)
    }

    /// Infallible publication after the durable configuration commit.
    pub fn publish(&self, snapshot: Arc<NetworkSnapshot>) {
        *self.current.write() = snapshot;
    }
}
