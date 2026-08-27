//! Error types shared by the broker REST server and proxy worker.

use std::io;

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

/// Broker error with operation context.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BrokerError {
    #[error("I/O error during {operation}: {source}")]
    Io {
        operation: &'static str,
        source: io::Error,
    },
    #[error("background task failed during {operation}: {source}")]
    Task {
        operation: &'static str,
        source: tokio::task::JoinError,
    },
    #[error("proxy ingress is already running on {current}; requested {requested}")]
    ProxyAlreadyRunning { current: String, requested: String },
    #[error("proxy ingress error: {0}")]
    Ingress(#[from] crate::ingress::IngressError),
    #[error("broker plugin server error: {0}")]
    Plugin(#[from] crate::plugin::PluginServerError),
    #[error("unauthorized broker REST request")]
    Unauthorized,
    #[error("MITM CA error: {0}")]
    Ca(#[from] abyss_mitm::CaError),
    #[error("MITM runtime error: {0}")]
    Mitm(#[from] abyss_mitm::TransparentFlowError),
    #[error("network observation storage error: {0}")]
    NetworkObservationStorage(#[from] crate::network_diagnostics::NetworkObservationStoreError),
    #[error("broker configuration error: {0}")]
    Config(#[from] crate::config::BrokerConfigError),
    #[error("broker runtime policy error: {0}")]
    RuntimePolicy(#[from] crate::runtime_config::RuntimePolicyError),
    #[error("failed to serialize broker startup info: {source}")]
    StartupInfo {
        #[source]
        source: serde_json::Error,
    },
    #[error("invalid broker configuration: {message}")]
    InvalidConfig { message: String },
    #[error("invalid broker arguments: {message}")]
    InvalidArguments { message: String },
}

impl BrokerError {
    pub const fn io(operation: &'static str, source: io::Error) -> Self {
        Self::Io { operation, source }
    }

    pub const fn task(operation: &'static str, source: tokio::task::JoinError) -> Self {
        Self::Task { operation, source }
    }

    pub const fn unauthorized() -> Self {
        Self::Unauthorized
    }

    pub fn invalid_arguments<T>(message: T) -> Self
    where
        T: Into<String>,
    {
        Self::InvalidArguments {
            message: message.into(),
        }
    }

    pub fn invalid_config<T>(message: T) -> Self
    where
        T: Into<String>,
    {
        Self::InvalidConfig {
            message: message.into(),
        }
    }

    const fn response_status(&self) -> StatusCode {
        match self {
            Self::ProxyAlreadyRunning { .. } => StatusCode::CONFLICT,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::InvalidConfig { .. } | Self::InvalidArguments { .. } => StatusCode::BAD_REQUEST,
            Self::Io { .. }
            | Self::Task { .. }
            | Self::Ingress(_)
            | Self::Plugin(_)
            | Self::Ca(_)
            | Self::Mitm(_)
            | Self::NetworkObservationStorage(_)
            | Self::Config(_)
            | Self::RuntimePolicy(_)
            | Self::StartupInfo { .. } => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for BrokerError {
    fn into_response(self) -> Response {
        let status = self.response_status();
        if status.is_server_error() {
            tracing::error!(error = %self, "broker REST request failed");
        }
        (
            status,
            Json(ErrorResponse {
                error: self.to_string(),
            }),
        )
            .into_response()
    }
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}
