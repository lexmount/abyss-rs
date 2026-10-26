//! Stable, sanitized errors for noninteractive callers.

use abyss_data_client::DataClientError;
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum QueryError {
    #[error("{0}")]
    Config(&'static str),
    #[error("{0}")]
    Auth(&'static str),
    #[error("{0}")]
    Protocol(&'static str),
    #[error(transparent)]
    Data(#[from] DataClientError),
    #[error("local filesystem operation failed")]
    Io(#[from] std::io::Error),
    #[error("invalid local JSON or output encoding")]
    Json(#[from] serde_json::Error),
}
impl QueryError {
    pub const fn code(&self) -> (&'static str, u8) {
        match self {
            Self::Config(_)
            | Self::Data(DataClientError::Configuration(_) | DataClientError::Query(_)) => {
                ("configuration", 2)
            }
            Self::Auth(_) | Self::Data(DataClientError::Http { status: 401 }) => {
                ("authentication", 3)
            }
            Self::Data(DataClientError::Http { status: 403 }) => ("forbidden", 4),
            Self::Data(DataClientError::Http { status: 404 }) => ("not_found", 5),
            Self::Data(DataClientError::Http { status: 429 }) => ("rate_limited", 6),
            Self::Data(DataClientError::Transport(_) | DataClientError::Read(_)) => {
                ("transport", 7)
            }
            Self::Data(DataClientError::Http { .. }) => ("http", 8),
            Self::Data(_) | Self::Protocol(_) => ("protocol", 9),
            Self::Io(_) | Self::Json(_) => ("local_io", 10),
        }
    }
    pub fn diagnostic(&self) -> serde_json::Value {
        let (code, _) = self.code();
        let status = match self {
            Self::Data(DataClientError::Http { status }) => Some(*status),
            _ => None,
        };
        json!({"schema_version":1_u32,"error":{"code":code,"message":self.to_string(),"http_status":status}})
    }
}
