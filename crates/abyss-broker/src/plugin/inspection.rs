//! Server-owned inspection tasks and connected-session decisions.
//! Callers submit context through the plugin command channel; sessions never escape it.

#[cfg(test)]
mod tests;

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use abyss_plugin_protocol::inspection::{AgentRequestContext, InspectResponse};
use abyss_plugin_protocol::message::BrokerMessage;
use parking_lot::Mutex;
use tokio::{
    sync::{mpsc, oneshot, watch},
    time::Instant,
};
use uuid::Uuid;

use super::message::{InspectionDecision, InspectionError, InspectionParticipant, SessionIdentity};

/// A decision includes queueing and reply time. There are no retries.
pub(super) const DECISION_TIMEOUT: Duration = Duration::from_secs(5);
const SESSION_CAPACITY: usize = 64;

/// Encoded context for one selected participant. Oversized contexts fail before writes.
pub(super) struct InspectionRequest {
    pub(super) request_id: String,
    pub(super) frame: super::codec::EncodedFrame,
}

impl InspectionRequest {
    fn new(context: Arc<AgentRequestContext>) -> Result<Self, super::codec::PluginFrameError> {
        let request_id = context.request_id.clone();
        let frame = super::codec::EncodedFrame::new(&BrokerMessage::InspectRequest { context })?;
        Ok(Self { request_id, frame })
    }
}

pub(super) struct InspectionRegistry {
    sessions: Mutex<Vec<Arc<InspectionSession>>>,
    participants: watch::Sender<Arc<[SessionIdentity]>>,
}

impl Default for InspectionRegistry {
    fn default() -> Self {
        Self {
            sessions: Mutex::new(Vec::new()),
            participants: watch::channel(Arc::from([])).0,
        }
    }
}

pub(super) struct InspectionSession {
    id: Uuid,
    plugin_id: String,
    sender: mpsc::Sender<Arc<InspectionRequest>>,
    pending: Mutex<HashMap<String, oneshot::Sender<InspectResponse>>>,
    closed: AtomicBool,
}

pub(super) struct SessionRegistration {
    registry: Arc<InspectionRegistry>,
    pub(super) session: Arc<InspectionSession>,
}

impl InspectionRegistry {
    pub(super) fn subscribe(&self) -> watch::Receiver<Arc<[SessionIdentity]>> {
        self.participants.subscribe()
    }

    fn publish_participants(&self, sessions: &[Arc<InspectionSession>]) {
        self.participants.send_replace(
            sessions
                .iter()
                .map(|session| SessionIdentity {
                    id: session.id,
                    plugin_id: session.plugin_id.clone(),
                })
                .collect(),
        );
    }

    fn select(
        &self,
        participant: &InspectionParticipant,
    ) -> Result<Arc<InspectionSession>, InspectionError> {
        self.sessions
            .lock()
            .iter()
            .find(|session| session.id == participant.id)
            .cloned()
            .ok_or(InspectionError::Unavailable)
    }

    pub(super) fn register(
        self: &Arc<Self>,
        plugin_id: String,
    ) -> (SessionRegistration, mpsc::Receiver<Arc<InspectionRequest>>) {
        let (sender, receiver) = mpsc::channel(SESSION_CAPACITY);
        let session = Arc::new(InspectionSession {
            id: Uuid::new_v4(),
            plugin_id,
            sender,
            pending: Mutex::new(HashMap::new()),
            closed: AtomicBool::new(false),
        });
        {
            let mut sessions = self.sessions.lock();
            sessions.push(session.clone());
            self.publish_participants(&sessions);
            drop(sessions);
        }
        (
            SessionRegistration {
                registry: self.clone(),
                session,
            },
            receiver,
        )
    }
}

impl Drop for SessionRegistration {
    fn drop(&mut self) {
        self.session.closed.store(true, Ordering::Release);
        {
            let mut sessions = self.registry.sessions.lock();
            sessions.retain(|session| session.id != self.session.id);
            self.registry.publish_participants(&sessions);
            drop(sessions);
        }
        self.session.pending.lock().clear();
    }
}

struct PendingDecision<'a> {
    session: &'a InspectionSession,
    request_id: String,
}

impl Drop for PendingDecision<'_> {
    fn drop(&mut self) {
        self.session.pending.lock().remove(&self.request_id);
    }
}

impl InspectionSession {
    pub(super) fn is_pending(&self, request_id: &str) -> bool {
        self.pending.lock().contains_key(request_id)
    }

    pub(super) fn reply(&self, response: InspectResponse) {
        let waiter = self.pending.lock().remove(&response.request_id);
        if let Some(waiter) = waiter {
            let _sent = waiter.send(response);
        }
    }

    async fn inspect(
        &self,
        context: Arc<InspectionRequest>,
        deadline: Instant,
    ) -> Result<InspectResponse, ()> {
        let (sender, receiver) = oneshot::channel();
        {
            let mut pending = self.pending.lock();
            if self.closed.load(Ordering::Acquire) || pending.len() >= SESSION_CAPACITY {
                return Err(());
            }
            pending.insert(context.request_id.clone(), sender);
        }
        // Dropping the request future (timeout or caller cancellation) removes its waiter.
        let _pending = PendingDecision {
            session: self,
            request_id: context.request_id.clone(),
        };
        tokio::time::timeout_at(deadline, async {
            self.sender.send(context).await.map_err(|_| ())?;
            receiver.await.map_err(|_| ())
        })
        .await
        .map_err(|_| ())?
    }
}

/// One server-dispatched command; the server owns its task and cancellation.
pub(super) struct InspectionTask {
    session: Result<Arc<InspectionSession>, InspectionError>,
    context: Arc<AgentRequestContext>,
    first_deadline: Instant,
    reply: oneshot::Sender<Result<InspectionDecision, InspectionError>>,
}

impl InspectionTask {
    pub(super) fn new(
        registry: &InspectionRegistry,
        participant: &InspectionParticipant,
        context: Arc<AgentRequestContext>,
        first_deadline: Instant,
        reply: oneshot::Sender<Result<InspectionDecision, InspectionError>>,
    ) -> Self {
        Self {
            session: registry.select(participant),
            context,
            first_deadline,
            reply,
        }
    }

    #[expect(
        clippy::integer_division_remainder_used,
        reason = "tokio::select! expansion uses remainder internally"
    )]
    pub(super) async fn run(self) {
        let Self {
            session,
            context,
            first_deadline,
            mut reply,
        } = self;
        let result = tokio::select! {
            biased;
            () = reply.closed() => return,
            result = Self::decide(session, context, first_deadline) => result,
        };
        let _sent = reply.send(result);
    }

    async fn decide(
        session: Result<Arc<InspectionSession>, InspectionError>,
        context: Arc<AgentRequestContext>,
        deadline: Instant,
    ) -> Result<InspectionDecision, InspectionError> {
        let session = session?;
        let request = Arc::new(
            InspectionRequest::new(context).map_err(|error| match error {
                super::codec::PluginFrameError::PayloadTooLarge { .. } => {
                    InspectionError::PayloadTooLarge
                }
                _ => InspectionError::Encoding,
            })?,
        );
        let response = session
            .inspect(request, deadline)
            .await
            .map_err(|()| InspectionError::Unavailable)?;
        Ok(response.decision)
    }
}
