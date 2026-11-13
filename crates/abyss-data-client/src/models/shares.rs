//! Typed session-share creation response; snapshot policy is server-owned.

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Lifecycle state reported by the sharing service.
#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum SessionShareStatus {
    /// Available until expiry or revocation.
    Active,
    /// The configured lifetime has elapsed.
    Expired,
    /// The owner revoked the share.
    Revoked,
}

/// Snapshot identity and lifecycle metadata, without the access capability.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct SessionShareSummary {
    /// Backend share UUID, distinct from the session UUID.
    pub id: Uuid,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Frozen snapshot time.
    pub snapshot_at: DateTime<Utc>,
    /// Server-controlled expiry.
    pub expires_at: DateTime<Utc>,
    /// Owner revocation time, when revoked.
    pub revoked_at: Option<DateTime<Utc>>,
    /// Current lifecycle state.
    pub status: SessionShareStatus,
    /// Forward-compatible server metadata.
    #[serde(flatten)]
    pub fields: super::Extensions,
}

/// One-time creation result. Never log or persist the returned capability.
#[derive(Deserialize)]
pub struct CreatedSessionShare {
    /// Share identity and lifecycle.
    pub share: SessionShareSummary,
    /// Capability returned only at creation, for the browser URL fragment.
    pub token: String,
}
