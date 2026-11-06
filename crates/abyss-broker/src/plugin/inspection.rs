//! Connected-session request decisions; membership never persists beyond a connection.

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

use abyss_agent_hook::{AgentRequestParser, HooksRuntimeConfig};
use abyss_mitm::{LocalRejection, RequestForwardingControl, RequestView};
use abyss_plugin_protocol::inspection::{AgentRequestContext, InspectResponse};
use abyss_plugin_protocol::message::BrokerMessage;
use axum::http::StatusCode;
use parking_lot::Mutex;
use tokio::sync::{mpsc, oneshot};

/// A decision includes queueing and reply time. There are no retries.
pub(super) const DECISION_TIMEOUT: Duration = Duration::from_secs(5);
const SESSION_CAPACITY: usize = 64;

/// The same encoded context is sent to every selected plugin without re-parsing
/// or re-serializing the request. Oversized contexts fail before session writes.
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

#[derive(Default)]
pub struct InspectionRegistry {
    sessions: Mutex<Vec<Arc<InspectionSession>>>,
}

pub struct InspectionSession {
    sender: mpsc::Sender<Arc<InspectionRequest>>,
    pending: Mutex<HashMap<String, oneshot::Sender<InspectResponse>>>,
    closed: AtomicBool,
}

pub(super) struct SessionRegistration {
    registry: Arc<InspectionRegistry>,
    pub(super) session: Arc<InspectionSession>,
}

impl InspectionRegistry {
    pub(super) fn register(
        self: &Arc<Self>,
    ) -> (SessionRegistration, mpsc::Receiver<Arc<InspectionRequest>>) {
        let (sender, receiver) = mpsc::channel(SESSION_CAPACITY);
        let session = Arc::new(InspectionSession {
            sender,
            pending: Mutex::new(HashMap::new()),
            closed: AtomicBool::new(false),
        });
        self.sessions.lock().push(session.clone());
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
        self.registry
            .sessions
            .lock()
            .retain(|session| !Arc::ptr_eq(session, &self.session));
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

    async fn inspect(&self, context: Arc<InspectionRequest>) -> Result<InspectResponse, ()> {
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
        tokio::time::timeout(DECISION_TIMEOUT, async {
            self.sender.send(context).await.map_err(|_| ())?;
            receiver.await.map_err(|_| ())
        })
        .await
        .map_err(|_| ())?
    }
}

/// Broker-owned Agent parsing and plugin decision stage.
#[derive(Clone)]
pub struct AgentRequestInspector {
    registry: Arc<InspectionRegistry>,
    hooks: HooksRuntimeConfig,
}

impl Default for AgentRequestInspector {
    fn default() -> Self {
        Self::new(
            Arc::new(InspectionRegistry::default()),
            HooksRuntimeConfig::default_enabled(),
        )
    }
}

impl AgentRequestInspector {
    pub(crate) const fn new(registry: Arc<InspectionRegistry>, hooks: HooksRuntimeConfig) -> Self {
        Self { registry, hooks }
    }
}

impl RequestForwardingControl for AgentRequestInspector {
    type Plan = Vec<Arc<InspectionSession>>;

    fn plan(&self) -> Option<Self::Plan> {
        let sessions = self.registry.sessions.lock();
        (!sessions.is_empty()).then(|| sessions.clone())
    }

    async fn before_forward(
        &self,
        sessions: Self::Plan,
        request: RequestView<'_>,
    ) -> Result<(), LocalRejection> {
        let request_id = uuid::Uuid::new_v4().to_string();
        let context = Arc::new(AgentRequestParser::parse(
            &request,
            &self.hooks.snapshot().harness_usage.config,
            request_id.clone(),
        ));
        let request = Arc::new(InspectionRequest::new(context).map_err(|error| {
            let (status, code, reason) = if matches!(
                error,
                super::codec::PluginFrameError::PayloadTooLarge { .. }
            ) {
                (
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "inspection_body_too_large",
                    "Request context exceeds the plugin frame limit",
                )
            } else {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "inspection_unavailable",
                    "Request context could not be encoded",
                )
            };
            LocalRejection::new(status, code, reason, request_id.clone())
        })?);
        for session in sessions {
            let response = session.inspect(request.clone()).await.map_err(|()| {
                LocalRejection::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "inspection_unavailable",
                    "Request inspection unavailable",
                    request_id.clone(),
                )
            })?;
            if !response.allow {
                return Err(LocalRejection::new(
                    StatusCode::FORBIDDEN,
                    "agent_request_blocked",
                    response
                        .reason
                        .unwrap_or_else(|| "Request blocked by abyss-broker".to_owned()),
                    request_id,
                ));
            }
        }
        Ok(())
    }
}
