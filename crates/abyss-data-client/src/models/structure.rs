//! Session page structure and event content previews served by the
//! standalone backend: header, streams, turns, segments, in-session search,
//! conversation previews and event locations.

use super::Extensions;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Session summary shown above a session page.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct SessionHeader {
    /// Backend primary key.
    pub session_pk: Uuid,
    /// Agent-declared session identity.
    pub session_id: String,
    /// Title, agents, time span, counts, tokens, providers and models.
    #[serde(flatten)]
    pub fields: Extensions,
}

/// Every segment of a session, in backend order.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct SessionStreams {
    /// Backend primary key.
    pub session_pk: Uuid,
    /// Segments with their heads, kinds and exchange summaries.
    pub segments: Vec<serde_json::Value>,
    /// Additional server fields.
    #[serde(flatten)]
    pub fields: Extensions,
}

/// The turn tree of a session.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct SessionTurns {
    /// Backend primary key.
    pub session_pk: Uuid,
    /// Turns in backend order.
    pub turns: Vec<serde_json::Value>,
    /// Additional server fields.
    #[serde(flatten)]
    pub fields: Extensions,
}

/// One segment's exchanges with request and response previews.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct Segment {
    /// Backend primary key of the session.
    pub session_pk: Uuid,
    /// Segment head.
    pub segment: String,
    /// Exchanges in segment order.
    pub exchanges: Vec<serde_json::Value>,
    /// Additional server fields.
    #[serde(flatten)]
    pub fields: Extensions,
}

/// Matches of one literal query inside a session.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct SessionSearch {
    /// Query echoed by the backend.
    pub query: String,
    /// Distinct matched texts.
    pub texts: Vec<serde_json::Value>,
    /// Hits referring to the matched texts.
    pub hits: Vec<serde_json::Value>,
    /// Whether the backend stopped at its hit budget.
    pub truncated: bool,
    /// Additional server fields.
    #[serde(flatten)]
    pub fields: Extensions,
}

/// Selected entries of one event's conversation.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct ConversationPreview {
    /// Backend primary key of the event.
    pub event_pk: Uuid,
    /// Total entries in the conversation.
    pub entries_total: u64,
    /// Contiguous runs of selected entries.
    pub chunks: Vec<serde_json::Value>,
    /// Completeness, omitted counts and attachments.
    #[serde(flatten)]
    pub fields: Extensions,
}

/// Where an event currently sits in its session structure.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct EventLocation {
    /// Backend primary key of the session.
    pub session_pk: Uuid,
    /// Backend primary key of the event.
    pub event_pk: Uuid,
    /// Segment, turn, segment kind and exchange.
    #[serde(flatten)]
    pub fields: Extensions,
}
