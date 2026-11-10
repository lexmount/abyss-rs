//! Channel-only handle for event publication and synchronous plugin decisions.
//! Session membership, IPC encoding and decision dispatch belong to `PluginServer`.

use std::{convert::Infallible, future::Future, sync::Arc};

use abyss_agent_hook::AgentEventSink;
use abyss_plugin_protocol::{event::AgentEvent, inspection::AgentRequestContext};
use tokio::{
    sync::{mpsc, oneshot, watch},
    time::{Instant, timeout_at},
};
use uuid::Uuid;

use super::{
    inspection::DECISION_TIMEOUT,
    message::{
        InspectionDecision, InspectionError, InspectionParticipant, InspectionPlan, PluginCommand,
    },
};

#[derive(Debug, Clone)]
pub struct PluginClient {
    commands: mpsc::Sender<PluginCommand>,
    participants: watch::Receiver<Arc<[Uuid]>>,
}

impl PluginClient {
    pub(super) const fn new(
        commands: mpsc::Sender<PluginCommand>,
        participants: watch::Receiver<Arc<[Uuid]>>,
    ) -> Self {
        Self {
            commands,
            participants,
        }
    }

    /// Reads the server-published snapshot without a request/response round trip.
    pub fn inspection_plan(&self) -> Option<InspectionPlan> {
        let participants = self.participants.borrow();
        (!self.commands.is_closed() && !participants.is_empty()).then(|| InspectionPlan {
            sessions: participants.clone(),
        })
    }

    /// Submits already parsed context to one selected participant.
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "five seconds per live local session cannot exhaust Instant's range"
    )]
    pub async fn inspect(
        &self,
        participant: InspectionParticipant,
        context: Arc<AgentRequestContext>,
    ) -> Result<InspectionDecision, InspectionError> {
        let first_deadline = Instant::now() + DECISION_TIMEOUT;
        let (reply, response) = oneshot::channel();
        timeout_at(first_deadline, async {
            self.commands
                .send(PluginCommand::InspectRequest {
                    participant,
                    context,
                    first_deadline,
                    reply,
                })
                .await
                .map_err(|_| InspectionError::Unavailable)?;
            response.await.map_err(|_| InspectionError::Unavailable)?
        })
        .await
        .map_err(|_| InspectionError::Unavailable)?
    }
}

impl AgentEventSink for PluginClient {
    type Error = Infallible;

    fn publish(&self, event: AgentEvent) -> impl Future<Output = Result<(), Self::Error>> + Send {
        // Live audit publication never waits for plugin service or socket capacity.
        let _sent = self
            .commands
            .try_send(PluginCommand::PublishEvent(Arc::new(event)));
        std::future::ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn event_publication_is_best_effort_and_inspection_queueing_has_a_deadline() {
        let (commands, mut receiver) = mpsc::channel(1);
        let (_participants, snapshot) = watch::channel(Arc::from([Uuid::new_v4()]));
        let client = PluginClient::new(commands, snapshot);
        for _ in 0_u8..2 {
            let event = serde_json::from_str(include_str!("fixtures/agent-event.json")).unwrap();
            client.publish(event).await.unwrap();
        }
        let message = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../specs/broker-plugin-protocol/v2/fixtures/inspect-request.json"
        )))
        .unwrap();
        let abyss_plugin_protocol::message::BrokerMessage::InspectRequest { context } = message
        else {
            panic!("fixture");
        };
        let started = Instant::now();
        assert_eq!(
            client
                .inspect(
                    client
                        .inspection_plan()
                        .unwrap()
                        .participants()
                        .next()
                        .unwrap(),
                    context.clone()
                )
                .await,
            Err(InspectionError::Unavailable)
        );
        assert_eq!(Instant::now() - started, DECISION_TIMEOUT);
        assert!(matches!(
            receiver.try_recv().unwrap(),
            PluginCommand::PublishEvent(_)
        ));
        assert!(
            receiver.try_recv().is_err(),
            "cancelled sends must not enter the queue"
        );

        // A submitted command is also bounded when the server does not reply.
        let started = Instant::now();
        assert_eq!(
            client
                .inspect(
                    client
                        .inspection_plan()
                        .unwrap()
                        .participants()
                        .next()
                        .unwrap(),
                    context
                )
                .await,
            Err(InspectionError::Unavailable)
        );
        assert_eq!(Instant::now() - started, DECISION_TIMEOUT);
        let PluginCommand::InspectRequest { reply, .. } = receiver.try_recv().unwrap() else {
            panic!("inspection");
        };
        assert!(reply.is_closed());
        drop(receiver);
        assert!(client.inspection_plan().is_none());
    }
}
