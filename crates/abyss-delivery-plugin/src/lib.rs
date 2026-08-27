//! Reusable configuration and HTTP delivery implementation for the official plugin.

#![expect(
    clippy::multiple_crate_versions,
    reason = "the SDK transport and reqwest TLS dependency graphs require distinct transitive versions"
)]

mod authentication;
mod config;
mod control;
mod error;
mod startup_info;
mod uploader;

pub use authentication::{
    DeliveryAuthenticationManager, DeliveryAuthenticationMode, DeliveryAuthenticationState,
};
pub use config::{
    AuthenticationConfig, DeliveryAuthentication, DeliveryConfig, DeliveryPluginConfig,
};
pub use control::DeliveryControlServer;
pub use error::DeliveryPluginError;
pub use startup_info::WorkerStartupInfoGuard;
pub use uploader::{EventUploader, ReplaySummary};
