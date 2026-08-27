//! Harness detection and LLM usage MITM pipeline.
//!
//! This crate transforms decoded HTTP exchanges from `abyss-mitm` into typed
//! Agent events. Harness, protocol, provider, correlation, and normalization
//! remain independent internal dimensions behind one Broker hook.

#![expect(
    clippy::multiple_crate_versions,
    reason = "abyss-mitm's TLS and WebSocket dependency graph requires distinct transitive versions."
)]

mod config;
pub(crate) mod correlation;
mod delivery;
pub(crate) mod event;
pub(crate) mod harness;
mod hook;
pub(crate) mod protocol;
pub(crate) mod provider;

pub use config::{
    DeviceIdentity, HarnessConfig, HarnessMatcherConfig, HarnessUsageConfig,
    HarnessUsageContentConfig, HarnessUsageHookConfig, HookConfig, HooksConfig, HooksRuntimeConfig,
    platform_device_identity,
};
pub use delivery::AgentEventSink;
pub use harness::{BuiltInHarness, HarnessId};
pub use hook::HarnessUsageHook;
