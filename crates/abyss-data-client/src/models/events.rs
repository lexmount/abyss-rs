//! Persisted event identities and offset-based listing responses.

use super::Extensions;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A persisted event; content fields are retained exactly as the API supplies them.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct UsageEvent {
    /// Backend primary key, used by the event detail route.
    pub id: Uuid,
    /// Collector idempotency key, distinct from the backend primary key.
    pub event_id: String,
    /// Backend session primary key.
    pub session_pk: Uuid,
    /// Metadata, counters and optional content for the selected projection.
    #[serde(flatten)]
    pub fields: Extensions,
}

/// One page of persisted events, newest first.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct EventPage {
    /// Persisted events.
    pub events: Vec<UsageEvent>,
    /// Decimal offset of the next page; absent at the end.
    pub next_page_token: Option<String>,
    /// Additional server fields.
    #[serde(flatten)]
    pub fields: Extensions,
}
