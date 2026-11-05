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
