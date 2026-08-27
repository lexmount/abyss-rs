#![expect(
    clippy::multiple_crate_versions,
    reason = "the workspace TLS stack and Tokio currently retain distinct transitive untrusted/windows-sys versions"
)]

//! Public Rust contracts for integrating with `abyss-broker`.
//!
//! The SDK exposes two independent local integration surfaces: the broker REST
//! management API and the versioned plugin event stream. It never handles
//! control-plane APIs, event upload, or remote authentication.

pub mod broker;
pub mod event;
pub mod plugin;

pub use broker::BrokerClient;
