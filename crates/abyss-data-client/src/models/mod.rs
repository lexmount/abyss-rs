//! Public read API responses, independent of broker/plugin event wire types.
//!
//! Identity and pagination fields are validated. Flattened extension maps retain
//! backend-owned content and newly added fields without silently discarding them.

mod events;
mod sessions;
mod summary;

pub use events::{EventPage, UsageEvent};
pub use sessions::{
    SearchPage, SearchSession, Session, SessionPage, SessionTimeline, SessionTrajectory, Turn,
};
pub use summary::UsageSummary;

/// Backend-owned metadata and forward-compatible response fields.
pub type Extensions = std::collections::BTreeMap<String, serde_json::Value>;
