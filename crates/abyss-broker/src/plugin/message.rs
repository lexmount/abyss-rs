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

/// Opaque participant selected for one request; session ownership stays in the server.
pub struct InspectionParticipant {
    pub(super) id: Uuid,
}

impl InspectionPlan {
    /// Iterates the request's fixed registration order without selecting new sessions.
    pub fn participants(&self) -> impl Iterator<Item = InspectionParticipant> + '_ {
        self.sessions
            .iter()
            .map(|id| InspectionParticipant { id: *id })
    }
}

pub use abyss_plugin_protocol::inspection::RequestDecision as InspectionDecision;

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
        participant: InspectionParticipant,
        context: Arc<AgentRequestContext>,
        first_deadline: Instant,
        reply: oneshot::Sender<Result<InspectionDecision, InspectionError>>,
    },
}
