//! Read-only, deployment-independent clients for the public Abyss data API.
//!
//! Callers supply the API root and credentials. This crate never discovers a
//! broker, opens a database, reads CLI profiles, or performs interactive login.

#![expect(
    clippy::multiple_crate_versions,
    reason = "reqwest TLS dependencies retain multiple transitive versions"
)]

mod client;
mod endpoint;
mod error;
pub mod models;
pub mod query;
mod transport;

pub use client::{DataClient, DataClientOptions};
pub use endpoint::ApiEndpoint;
pub use error::DataClientError;
pub use transport::HttpTransport;
