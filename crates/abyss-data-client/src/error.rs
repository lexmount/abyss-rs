//! Sanitized errors from HTTP transport and public query validation.

/// Failures safe to report without exposing credentials, response bodies or URLs.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DataClientError {
    /// Invalid endpoint or transport configuration.
    #[error("invalid configuration: {0}")]
    Configuration(&'static str),
    /// Invalid query parameters.
    #[error("invalid query: {0}")]
    Query(&'static str),
    /// HTTP transport failure; the underlying error is deliberately not displayed.
    #[error("HTTP transport failed")]
    Transport(#[source] reqwest::Error),
    /// The destination rejected the request. Response text is never echoed.
    #[error("backend returned HTTP {status}")]
    Http {
        /// HTTP status code.
        status: u16,
    },
    /// Decoding failed; untrusted payload values are not included in the message.
    #[error("backend returned an invalid JSON response")]
    Decode(#[source] serde_json::Error),
    /// Reading a response failed.
    #[error("could not read the HTTP response")]
    Read(#[source] std::io::Error),
    /// A bounded response exceeded the configured memory budget.
    #[error("HTTP response exceeds the {limit} byte limit")]
    ResponseTooLarge {
        /// Maximum accepted bytes.
        limit: usize,
    },
    /// An internally inconsistent response cannot be paginated safely.
    #[error("backend protocol violation: {0}")]
    Protocol(&'static str),
}
