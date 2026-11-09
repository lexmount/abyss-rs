//! In-process plugin commands and caller-visible decisions, independent of network forwarding.

use std::sync::Arc;

use abyss_plugin_protocol::{event::AgentEvent, inspection::AgentRequestContext};
use thiserror::Error;
use tokio::{sync::oneshot, time::Instant};
use uuid::Uuid;

/// Immutable connection identities selected before request retention.
/// Callers cannot address sessions or replace the participants of a plan.
pub struct InspectionPlan {
    pub(super) sessions: Arc<[Uuid]>,
}

/// Final decision after all selected plugin sessions have been considered.
#[derive(Debug, PartialEq)]
pub enum InspectionDecision {
    Allow,
    Block { reason: Option<String> },
}

/// Plugin-service failures; the caller owns their HTTP or WebSocket representation.
#[derive(Debug, Error, PartialEq)]
pub enum InspectionError {
    #[error("Request context exceeds the plugin frame limit")]
    PayloadTooLarge,
    #[error("Request context could not be encoded")]
    Encoding,
    #[error("Request inspection unavailable")]
    Unavailable,
}

pub(super) enum PluginCommand {
    PublishEvent(Arc<AgentEvent>),
    InspectRequest {
        plan: InspectionPlan,
        context: Arc<AgentRequestContext>,
        first_deadline: Instant,
        reply: oneshot::Sender<Result<InspectionDecision, InspectionError>>,
    },
}
