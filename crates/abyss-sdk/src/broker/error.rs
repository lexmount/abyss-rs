//! Errors produced by the broker REST client.

use std::path::PathBuf;

use reqwest::StatusCode;
use thiserror::Error;

/// Failure returned by a broker REST operation.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BrokerClientError {
    /// The configured broker base URL is invalid.
    #[error("invalid broker base URL `{base_url}`: {reason}")]
    InvalidBaseUrl {
        /// Rejected URL text.
        base_url: String,
        /// URL parser diagnostic.
        reason: String,
    },
    /// The configured URL is not the loopback HTTP boundary exposed by the broker.
    #[error("broker base URL must use HTTP and a loopback host: `{0}`")]
    NonLoopbackBaseUrl(String),
    /// A statically selected broker route could not be joined to the base URL.
    #[error("invalid broker REST path `{path}`: {reason}")]
    InvalidRequestPath {
        /// Relative request path.
        path: String,
        /// URL parser diagnostic.
        reason: String,
    },
    /// A client-side argument is outside the published REST contract.
    #[error("invalid broker REST argument: {0}")]
    InvalidArgument(String),
    /// Startup information or its auth token could not be read.
    #[error("read broker discovery file `{path}`: {source}")]
    DiscoveryIo {
        /// File that could not be read.
        path: PathBuf,
        /// Filesystem failure.
        #[source]
        source: std::io::Error,
    },
    /// Startup information is not valid JSON.
    #[error("decode broker startup info `{path}`: {source}")]
    StartupInfoJson {
        /// Startup-info file that could not be decoded.
        path: PathBuf,
        /// JSON contract failure.
        #[source]
        source: serde_json::Error,
    },
    /// The HTTP request failed before a response was available.
    #[error("broker REST transport failed: {0}")]
    Transport(#[from] reqwest::Error),
    /// The broker returned a non-success status.
    #[error("broker REST request failed with HTTP {status}: {message}")]
    Api {
        /// HTTP response status.
        status: StatusCode,
        /// Broker-provided error or bounded response text.
        message: String,
    },
}
