#![expect(
    clippy::multiple_crate_versions,
    reason = "the workspace TLS stack and Tokio currently retain distinct transitive untrusted/windows-sys versions"
)]

//! Public Rust contracts for integrating with `abyss-broker`.
//!
//! A single `BrokerClient` owns the REST and plugin endpoints for one broker.
//! It provides management APIs and creates `plugin::BrokerPlugin` event consumers. It never handles
//! control-plane APIs, event upload, or remote authentication.

pub mod broker;
pub mod event;
pub mod plugin;

pub use broker::BrokerClient;
