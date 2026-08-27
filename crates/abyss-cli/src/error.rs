//! Errors returned by the Abyss endpoint CLI.

use std::{io, path::PathBuf, process::ExitStatus};

use thiserror::Error;

/// Endpoint CLI operation failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CliError {
    /// Standard input/output failure while printing or invoking local tools.
    #[error("I/O operation failed: {0}")]
    Io(#[from] io::Error),
    /// Terminal authentication or credential-store failure.
    #[error("terminal authentication failed: {0}")]
    TerminalAuth(#[from] abyss_terminal_auth::TerminalAuthError),
    /// MITM CA lifecycle failure.
    #[error("CA operation failed: {0}")]
    Ca(#[from] abyss_mitm::CaError),
    /// JSON encoding or decoding failure.
    #[error("JSON operation failed: {0}")]
    Json(#[from] serde_json::Error),
    /// TOML decoding failure.
    #[error("TOML decode failed: {0}")]
    TomlDecode(#[from] toml::de::Error),
    /// TOML encoding failure.
    #[error("TOML encode failed: {0}")]
    TomlEncode(#[from] toml::ser::Error),
    /// Filesystem operation failed.
    #[error("filesystem operation {operation} failed at {path}: {source}")]
    Filesystem {
        /// Operation being performed.
        operation: &'static str,
        /// Path involved in the failure.
        path: PathBuf,
        /// Source filesystem error.
        #[source]
        source: io::Error,
    },
    /// Broker HTTP request failed before a response arrived.
    #[error("broker request failed: {0}")]
    BrokerRequest(#[source] reqwest::Error),
    /// Broker returned a non-success status.
    #[error("broker returned HTTP {status} during {operation}: {body}")]
    BrokerStatus {
        /// Operation being performed.
        operation: &'static str,
        /// HTTP status code.
        status: reqwest::StatusCode,
        /// Response body, bounded by the broker client.
        body: String,
    },
    /// Delivery control request failed before a response arrived.
    #[error("delivery control request failed: {0}")]
    DeliveryRequest(#[source] reqwest::Error),
    /// Delivery worker returned a non-success status.
    #[error("delivery worker returned HTTP {status} during {operation}: {body}")]
    DeliveryStatus {
        /// Operation being performed.
        operation: &'static str,
        /// HTTP status code.
        status: reqwest::StatusCode,
        /// Bounded response body.
        body: String,
    },
    /// The destination immediately rejected a newly installed credential.
    #[error("delivery destination rejected the credential while replaying queued events")]
    DeliveryCredentialRejected,
    /// A platform lifecycle or child command failed.
    #[error("command `{program}` failed with {status}: {stderr}")]
    Command {
        /// Executable name.
        program: String,
        /// Exit status.
        status: ExitStatus,
        /// Captured standard error.
        stderr: String,
    },
    /// A required local setting is missing or invalid.
    #[error("invalid CLI configuration: {0}")]
    InvalidConfiguration(String),
}

impl CliError {
    pub(crate) fn filesystem(
        operation: &'static str,
        path: impl Into<PathBuf>,
        source: io::Error,
    ) -> Self {
        Self::Filesystem {
            operation,
            path: path.into(),
            source,
        }
    }
}
