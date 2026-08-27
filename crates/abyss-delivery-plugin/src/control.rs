//! Loopback product-control API for delivery authentication and status.

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse as _, Response},
    routing::{get, put},
};
use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq as _;
use tokio::{fs, io::AsyncWriteExt as _, net::TcpListener, sync::oneshot, task::JoinHandle};

use crate::{DeliveryAuthenticationManager, DeliveryPluginError, EventUploader, ReplaySummary};

const TOKEN_BYTES: usize = 32;

/// Running loopback control server and its product discovery information.
pub struct DeliveryControlServer {
    endpoint: String,
    token_path: PathBuf,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<Result<(), std::io::Error>>,
}

struct ControlState {
    authorization: String,
    authentication: Arc<DeliveryAuthenticationManager>,
    uploader: Arc<EventUploader>,
}

#[derive(Deserialize)]
struct SetCredentialRequest {
    bearer_token: String,
    audience: String,
}

#[derive(Serialize)]
struct DeliveryStatus<'a> {
    endpoint: &'a str,
    authentication_mode: &'a crate::DeliveryAuthenticationMode,
    authentication_state: crate::DeliveryAuthenticationState,
    spooled_events: usize,
}

#[derive(Serialize)]
struct CredentialUpdateResponse {
    authentication_state: crate::DeliveryAuthenticationState,
    replay: ReplaySummary,
}

#[derive(Serialize)]
struct CredentialClearResponse {
    authentication_state: crate::DeliveryAuthenticationState,
}

#[derive(Serialize)]
struct ErrorResponse<'a> {
    error: &'a str,
}

impl DeliveryControlServer {
    /// Binds the loopback API and writes its per-process local bearer token.
    ///
    /// # Errors
    ///
    /// Returns an error when loopback binding, token creation, or task startup fails.
    pub async fn start(
        token_path: PathBuf,
        group_readable_files: bool,
        authentication: Arc<DeliveryAuthenticationManager>,
        uploader: Arc<EventUploader>,
    ) -> Result<Self, DeliveryPluginError> {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .map_err(|source| DeliveryPluginError::ControlIo {
                operation: "bind loopback listener",
                path: None,
                source,
            })?;
        let address = listener
            .local_addr()
            .map_err(|source| DeliveryPluginError::ControlIo {
                operation: "read loopback listener address",
                path: None,
                source,
            })?;
        let token = Self::generate_token();
        Self::write_token(&token_path, &token, group_readable_files).await?;
        let state = Arc::new(ControlState {
            authorization: format!("Bearer {token}"),
            authentication,
            uploader,
        });
        let router = Router::new()
            .route("/v1/delivery/status", get(Self::status))
            .route(
                "/v1/delivery/auth",
                put(Self::set_credential).delete(Self::clear_credential),
            )
            .with_state(state);
        let (shutdown, receiver) = oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    drop(receiver.await);
                })
                .await
        });
        Ok(Self {
            endpoint: format!("http://{address}"),
            token_path,
            shutdown: Some(shutdown),
            task,
        })
    }

    /// Returns the concrete loopback origin advertised to the owning product.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Returns the token-file path advertised to the owning product.
    #[must_use]
    pub fn token_path(&self) -> &Path {
        &self.token_path
    }

    /// Stops the API, observes task failure, and removes its local token.
    ///
    /// # Errors
    ///
    /// Returns an error when the server task or token cleanup fails.
    pub async fn shutdown(mut self) -> Result<(), DeliveryPluginError> {
        if let Some(shutdown) = self.shutdown.take()
            && shutdown.send(()).is_err()
        {
            // The server task already exited and will report its own result below.
        }
        let serve_result = self
            .task
            .await
            .map_err(|source| DeliveryPluginError::ControlTask(source.to_string()))?;
        let remove_result = Self::remove_token(&self.token_path).await;
        serve_result.map_err(|source| DeliveryPluginError::ControlIo {
            operation: "serve loopback API",
            path: None,
            source,
        })?;
        remove_result
    }

    async fn status(State(state): State<Arc<ControlState>>, headers: HeaderMap) -> Response {
        if !Self::authorized(&state, &headers) {
            return Self::error(StatusCode::UNAUTHORIZED, "unauthorized");
        }
        let Ok(spooled_events) = state.uploader.spooled_event_count().await else {
            return Self::error(StatusCode::INTERNAL_SERVER_ERROR, "status unavailable");
        };
        Json(DeliveryStatus {
            endpoint: state.uploader.endpoint(),
            authentication_mode: state.authentication.mode(),
            authentication_state: state.authentication.state().await,
            spooled_events,
        })
        .into_response()
    }

    async fn set_credential(
        State(state): State<Arc<ControlState>>,
        headers: HeaderMap,
        Json(request): Json<SetCredentialRequest>,
    ) -> Response {
        if !Self::authorized(&state, &headers) {
            return Self::error(StatusCode::UNAUTHORIZED, "unauthorized");
        }
        let replay = match state
            .uploader
            .set_managed_bearer_and_replay(&request.bearer_token, &request.audience)
            .await
        {
            Ok(replay) => replay,
            Err(error) => return Self::credential_error(&error),
        };
        Json(CredentialUpdateResponse {
            authentication_state: state.authentication.state().await,
            replay,
        })
        .into_response()
    }

    async fn clear_credential(
        State(state): State<Arc<ControlState>>,
        headers: HeaderMap,
    ) -> Response {
        if !Self::authorized(&state, &headers) {
            return Self::error(StatusCode::UNAUTHORIZED, "unauthorized");
        }
        if let Err(error) = state.uploader.clear_managed_bearer().await {
            return Self::credential_error(&error);
        }
        Json(CredentialClearResponse {
            authentication_state: state.authentication.state().await,
        })
        .into_response()
    }

    fn credential_error(error: &DeliveryPluginError) -> Response {
        match error {
            DeliveryPluginError::AuthenticationMutationUnsupported => Self::error(
                StatusCode::CONFLICT,
                "authentication mode is not managed_bearer",
            ),
            DeliveryPluginError::InvalidCredentialUpdate(_)
            | DeliveryPluginError::InvalidDeliveryEndpoint(_) => {
                Self::error(StatusCode::BAD_REQUEST, "invalid credential update")
            }
            _ => Self::error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "credential update failed",
            ),
        }
    }

    fn authorized(state: &ControlState, headers: &HeaderMap) -> bool {
        let Some(received) = headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
        else {
            return false;
        };
        state
            .authorization
            .as_bytes()
            .ct_eq(received.as_bytes())
            .into()
    }

    fn error(status: StatusCode, message: &'static str) -> Response {
        (status, Json(ErrorResponse { error: message })).into_response()
    }

    async fn write_token(
        path: &Path,
        token: &str,
        group_readable: bool,
    ) -> Result<(), DeliveryPluginError> {
        #[cfg(not(unix))]
        let _ = group_readable;
        let parent = path
            .parent()
            .ok_or_else(|| DeliveryPluginError::ControlIo {
                operation: "resolve token parent",
                path: Some(path.to_owned()),
                source: std::io::Error::other("control token path has no parent"),
            })?;
        let parent_existed =
            fs::try_exists(parent)
                .await
                .map_err(|source| DeliveryPluginError::ControlIo {
                    operation: "inspect token directory",
                    path: Some(parent.to_owned()),
                    source,
                })?;
        fs::create_dir_all(parent)
            .await
            .map_err(|source| DeliveryPluginError::ControlIo {
                operation: "create token directory",
                path: Some(parent.to_owned()),
                source,
            })?;
        #[cfg(unix)]
        if !parent_existed {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
                .await
                .map_err(|source| DeliveryPluginError::ControlIo {
                    operation: "protect token directory",
                    path: Some(parent.to_owned()),
                    source,
                })?;
        }
        #[cfg(not(unix))]
        let _ = parent_existed;

        let mut options = fs::OpenOptions::new();
        options.create(true).write(true).truncate(true);
        #[cfg(unix)]
        {
            options.mode(if group_readable { 0o640 } else { 0o600 });
        }
        let mut file =
            options
                .open(path)
                .await
                .map_err(|source| DeliveryPluginError::ControlIo {
                    operation: "create token",
                    path: Some(path.to_owned()),
                    source,
                })?;
        file.write_all(token.as_bytes()).await.map_err(|source| {
            DeliveryPluginError::ControlIo {
                operation: "write token",
                path: Some(path.to_owned()),
                source,
            }
        })?;
        file.flush()
            .await
            .map_err(|source| DeliveryPluginError::ControlIo {
                operation: "flush token",
                path: Some(path.to_owned()),
                source,
            })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(
                path,
                std::fs::Permissions::from_mode(if group_readable { 0o640 } else { 0o600 }),
            )
            .await
            .map_err(|source| DeliveryPluginError::ControlIo {
                operation: "protect token",
                path: Some(path.to_owned()),
                source,
            })?;
        }
        Ok(())
    }

    async fn remove_token(path: &Path) -> Result<(), DeliveryPluginError> {
        match fs::remove_file(path).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(DeliveryPluginError::ControlIo {
                operation: "remove token",
                path: Some(path.to_owned()),
                source,
            }),
        }
    }

    fn generate_token() -> String {
        let mut bytes = [0_u8; TOKEN_BYTES];
        rand::rng().fill_bytes(&mut bytes);
        let mut encoded = String::with_capacity(TOKEN_BYTES.saturating_mul(2));
        for byte in bytes {
            use std::fmt::Write as _;
            write!(encoded, "{byte:02x}").expect("writing hexadecimal to a String cannot fail");
        }
        encoded
    }
}
