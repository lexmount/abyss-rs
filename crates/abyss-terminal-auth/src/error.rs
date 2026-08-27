//! Error types for terminal SSO clients.

use std::path::PathBuf;

/// Errors returned while starting terminal SSO, polling for completion, or
/// persisting the resulting local credential.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TerminalAuthError {
    /// The configured control-plane base URL could not be parsed.
    #[error("invalid control plane URL {url}: {reason}")]
    InvalidControlPlaneUrl { url: String, reason: String },
    /// A request to the control plane failed before a usable HTTP response was
    /// available.
    #[error("control plane request failed: {0}")]
    ControlPlaneRequest(#[source] reqwest::Error),
    /// The control plane returned a non-success HTTP status.
    #[error("control plane returned HTTP {status}: {body}")]
    ControlPlaneStatus {
        status: reqwest::StatusCode,
        body: String,
    },
    /// Local credential-file IO failed.
    #[error("filesystem error at {path}: {source}")]
    Filesystem {
        path: PathBuf,
        source: std::io::Error,
    },
    /// No local credential file exists.
    #[error("credential file is missing; run terminal login first")]
    MissingCredential,
    /// The local credential file exists but is not valid JSON for the expected
    /// schema.
    #[error("credential file is invalid: {0}")]
    InvalidCredential(#[source] serde_json::Error),
    /// A credential value could not be encoded before writing it to disk.
    #[error("credential file could not be encoded: {0}")]
    CredentialEncoding(#[source] serde_json::Error),
    /// The credential-store application name is not safe to use as a state
    /// directory component.
    #[error("invalid credential store name: {0}")]
    InvalidCredentialStoreName(String),
    /// The user did not complete browser SSO before the polling deadline.
    #[error("terminal login timed out after {seconds} seconds")]
    TerminalLoginTimeout { seconds: u64 },
    /// The configured polling timeout cannot produce a valid deadline.
    #[error("invalid timeout: timeout-seconds must be greater than zero")]
    InvalidTimeout,
    /// A default credential path could not be built because the platform home
    /// directory is not available.
    #[error("home directory is not available; pass an explicit credential file")]
    MissingHomeDirectory,
}

impl TerminalAuthError {
    /// Builds a filesystem error that retains the path involved in the failed
    /// operation.
    #[must_use]
    pub const fn filesystem(path: PathBuf, source: std::io::Error) -> Self {
        Self::Filesystem { path, source }
    }
}
