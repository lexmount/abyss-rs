//! Session identity, page windows, and ordered backend projections.

use super::Extensions;
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Session identity shared by list and detail responses.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct Session {
    /// Backend primary key used by detail routes.
    pub session_pk: Uuid,
    /// Agent-declared session identity; not a detail-route key.
    pub session_id: String,
    /// Observed Agent name.
    pub agent_name: String,
    /// Earliest observation in the session.
    pub started_at: DateTime<Utc>,
    /// Backend metadata, counts, titles and content availability fields.
    #[serde(flatten)]
    pub fields: Extensions,
}

/// One page of sessions ordered by the backend.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct SessionPage {
    /// Total matching sessions.
    pub total_sessions: u64,
    /// One-based page.
    pub page: u32,
    /// Requested page size.
    pub page_size: u32,
    /// Whether another page is available.
    pub has_more: bool,
    /// Session summaries.
    pub items: Vec<Session>,
    /// Additional server fields.
    #[serde(flatten)]
    pub fields: Extensions,
}

/// One search hit with backend-provided fragments and event references.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct SearchSession {
    /// Session identity and metadata.
    #[serde(flatten)]
    pub session: Session,
    /// Matching event fragments, preserving their structured highlight segments.
    pub matches: Vec<serde_json::Value>,
}

/// One page of full-text search results.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct SearchPage {
    /// Search expression echoed by the backend.
    pub query: String,
    /// Total matching sessions.
    pub total_sessions: u64,
    /// One-based page.
    pub page: u32,
    /// Requested page size.
    pub page_size: u32,
    /// Whether another page is available.
    pub has_more: bool,
    /// Ranked session hits.
    pub items: Vec<SearchSession>,
    /// Additional server fields.
    #[serde(flatten)]
    pub fields: Extensions,
}

/// A complete timeline or a content-free outline, as returned by the backend.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct SessionTimeline {
    /// Authoritative session identity.
    pub session: Session,
    /// Turns in backend order; event fields differ between outline and full views.
    pub turns: Vec<Turn>,
    /// Additional server fields.
    #[serde(flatten)]
    pub fields: Extensions,
}

/// A turn whose events preserve the selected backend content projection.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct Turn {
    /// Backend primary key.
    pub turn_pk: Uuid,
    /// Backend-normalized turn number.
    pub turn_index: i32,
    /// Events in authoritative order, including partial/content-free projections.
    pub events: Vec<serde_json::Value>,
    /// Timing and future turn metadata.
    #[serde(flatten)]
    pub fields: Extensions,
}

/// Backend-assembled trajectory, preserving content and provenance unchanged.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct SessionTrajectory {
    /// Authoritative session identity.
    pub session: Session,
    /// Ordered messages, tool activity and compactions.
    pub items: Vec<serde_json::Value>,
    /// Per-event usage and provenance, including events with no new content.
    pub events: Vec<serde_json::Value>,
    /// Additional server fields.
    #[serde(flatten)]
    pub fields: Extensions,
}
