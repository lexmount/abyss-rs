//! Shared authenticated session types returned by terminal SSO.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Control-plane user identity associated with a native terminal credential.
#[derive(Deserialize, Serialize)]
pub struct AuthenticatedUser {
    /// Stable control-plane user ID.
    pub id: Uuid,
    /// Primary user email.
    pub email: String,
    /// Display name when the identity provider supplies one.
    pub name: Option<String>,
    /// Control-plane roles attached to the authenticated user.
    pub roles: Vec<String>,
}

/// Bearer credential returned when a terminal SSO attempt is authenticated.
#[derive(Deserialize)]
pub struct NativeSessionCredential {
    /// Native bearer token used by command-line clients.
    pub token: String,
    /// Expiration timestamp for the bearer token.
    pub expires_at: DateTime<Utc>,
    /// Authenticated user metadata.
    pub user: AuthenticatedUser,
}
