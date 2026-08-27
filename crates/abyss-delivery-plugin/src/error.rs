//! Errors reported by the official Agent event delivery plugin.

use std::path::PathBuf;

use thiserror::Error;

/// Configuration, translation, transport, and persistence failures.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DeliveryPluginError {
    /// The product-owned configuration file could not be read.
    #[error("read delivery plugin config `{path}`: {source}")]
    ReadConfig {
        /// Configuration path.
        path: PathBuf,
        /// File-system failure.
        #[source]
        source: std::io::Error,
    },
    /// The configuration was not valid JSON.
    #[error("decode delivery plugin config `{path}`: {source}")]
    DecodeConfig {
        /// Configuration path.
        path: PathBuf,
        /// JSON failure.
        #[source]
        source: serde_json::Error,
    },
    /// The selected product configuration schema is unsupported.
    #[error(
        "product config `{path}` uses unsupported schema_version {actual}; expected {expected}"
    )]
    UnsupportedProductConfigSchema {
        /// Configuration path.
        path: PathBuf,
        /// Version read from the file.
        actual: u32,
        /// Version supported by this worker.
        expected: u32,
    },
    /// The product lifecycle readiness record could not be published.
    #[error("{operation} delivery worker startup info `{path}`: {source}")]
    StartupInfo {
        /// File-system operation being performed.
        operation: &'static str,
        /// Product-owned readiness record path.
        path: PathBuf,
        /// File-system failure.
        #[source]
        source: std::io::Error,
    },
    /// The broker startup record used for product lifecycle identity was invalid.
    #[error("decode broker startup info `{path}`: {source}")]
    DecodeBrokerStartupInfo {
        /// Broker-owned startup record path.
        path: PathBuf,
        /// JSON decoding failure.
        #[source]
        source: serde_json::Error,
    },
    /// Product readiness was requested without a broker process identity source.
    #[error("delivery worker startup info requires --broker-pid or ABYSS_BROKER_STARTUP_INFO")]
    MissingBrokerIdentity,
    /// A configured credential file could not be read.
    #[error("read delivery credential `{path}`: {source}")]
    ReadCredential {
        /// Credential path.
        path: PathBuf,
        /// File-system failure.
        #[source]
        source: std::io::Error,
    },
    /// Delivery or credential audience URL was invalid.
    #[error("invalid delivery URL: {0}")]
    InvalidDeliveryEndpoint(String),
    /// A managed credential update was invalid.
    #[error("invalid managed delivery credential: {0}")]
    InvalidCredentialUpdate(String),
    /// Credential mutation was attempted outside managed mode.
    #[error("delivery authentication mode does not accept runtime credential updates")]
    AuthenticationMutationUnsupported,
    /// Managed authentication is required before remote delivery can proceed.
    #[error("delivery authentication is not configured")]
    AuthenticationUnavailable,
    /// The product-local delivery control boundary failed an IO operation.
    #[error("{operation} for delivery control{path_suffix}: {source}", path_suffix = path.as_ref().map_or_else(String::new, |path| format!(" `{}`", path.display())))]
    ControlIo {
        /// Control operation being performed.
        operation: &'static str,
        /// Optional file path associated with the operation.
        path: Option<PathBuf>,
        /// IO failure.
        #[source]
        source: std::io::Error,
    },
    /// The loopback control server task failed.
    #[error("delivery control task failed: {0}")]
    ControlTask(String),
    /// An Agent event could not be represented by the current backend API.
    #[error("translate Agent event: {0}")]
    Translate(String),
    /// The destination request failed before an HTTP response was received.
    #[error("deliver Agent event: {0}")]
    Request(String),
    /// The destination rejected the request.
    #[error("delivery destination returned HTTP {0}")]
    HttpStatus(reqwest::StatusCode),
    /// The destination response could not be decoded.
    #[error("decode delivery response: {0}")]
    Response(String),
    /// The destination reported rejected events.
    #[error("delivery destination rejected {rejected} events: {errors:?}")]
    Rejected {
        /// Number of rejected events.
        rejected: usize,
        /// Destination-provided error descriptions.
        errors: Vec<String>,
    },
    /// The failed-delivery spool could not be created or written.
    #[error("persist failed delivery in `{path}`: {detail}")]
    Spool {
        /// Spool path.
        path: PathBuf,
        /// File-system or serialization failure.
        detail: String,
    },
    /// The broker plugin runtime failed.
    #[error(transparent)]
    Plugin(#[from] abyss_sdk::plugin::AbyssPluginError),
}
