//! Local plugin listener, live event broadcaster, and connection lifecycle.
//!
//! The broker owns this server. Public plugin clients use `abyss-sdk`; this
//! module depends only on the shared wire contract and Agent Hook sink boundary.

mod client;
mod codec;
mod inspection;
mod message;
mod session;
mod transport;

use std::{path::Path, sync::Arc};

use abyss_plugin_protocol::event::AgentEvent;
use thiserror::Error;
use tokio::{
    sync::{broadcast, mpsc, watch},
    task::JoinSet,
};

pub use client::PluginClient;
pub use message::{InspectionDecision, InspectionError, InspectionPlan};

use self::{
    inspection::InspectionTask,
    message::PluginCommand,
    session::PluginSession,
    transport::{PluginTransport as _, platform::PlatformPluginTransport},
};

const EVENT_BROADCAST_CAPACITY: usize = 64;
const COMMAND_CAPACITY: usize = 64;

/// Failure that prevents the broker plugin service from continuing.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PluginServerError {
    /// A local transport operation failed.
    #[error("{operation}: {source}")]
    Io {
        /// Operation that failed.
        operation: &'static str,
        /// Operating-system failure.
        #[source]
        source: std::io::Error,
    },
}

impl PluginServerError {
    pub(super) const fn io(operation: &'static str, source: std::io::Error) -> Self {
        Self::Io { operation, source }
    }
}

/// Bound local plugin listener and its shared live event source.
pub struct PluginServer {
    listener: PlatformPluginTransport,
    events: broadcast::Sender<Arc<AgentEvent>>,
    client: PluginClient,
    commands: mpsc::Receiver<PluginCommand>,
    inspections: Arc<inspection::InspectionRegistry>,
}

impl PluginServer {
    /// Binds the platform-default endpoint beneath the broker product root.
    pub async fn bind(abyss_home: &Path) -> Result<Self, PluginServerError> {
        let listener = PlatformPluginTransport::bind(abyss_home).await?;
        let (events, _receiver) = broadcast::channel(EVENT_BROADCAST_CAPACITY);
        let (commands, receiver) = mpsc::channel(COMMAND_CAPACITY);
        let inspections = Arc::new(inspection::InspectionRegistry::default());
        let client = PluginClient::new(commands, inspections.subscribe());
        tracing::info!(
            endpoint = %listener.endpoint_label(),
            event_capacity = EVENT_BROADCAST_CAPACITY,
            "abyss-broker plugin listener bound"
        );
        Ok(Self {
            listener,
            inspections,
            events,
            client,
            commands: receiver,
        })
    }

    /// Requires exactly one connected inspector for each configured local plugin name.
    /// An absent inspector keeps request retention active and fails requests closed.
    pub fn require_inspectors(mut self, required: Vec<String>) -> Self {
        self.client.required = required.into();
        self
    }

    /// Returns the concrete local endpoint advertised to product launchers.
    #[must_use]
    pub fn endpoint_label(&self) -> String {
        self.listener.endpoint_label()
    }

    /// Returns a channel-only handle for event publication and request decisions.
    pub fn client(&self) -> PluginClient {
        self.client.clone()
    }

    /// Accepts plugin connections until broker shutdown is requested.
    #[expect(
        clippy::integer_division_remainder_used,
        reason = "tokio::select! expands through runtime code that uses remainder internally"
    )]
    pub async fn run(
        mut self,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(), PluginServerError> {
        let mut sessions = JoinSet::new();
        let mut inspections = JoinSet::new();
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                accepted = self.listener.accept() => {
                    let stream = accepted?;
                    sessions.spawn(
                        PluginSession::new(
                            stream,
                            self.events.clone(),
                            shutdown.clone(),
                        )
                        .with_inspections(self.inspections.clone())
                        .run(),
                    );
                }
                completed = sessions.join_next(), if !sessions.is_empty() => {
                    Self::log_completed_session(completed);
                }
                command = self.commands.recv() => {
                    match command {
                        Some(PluginCommand::Connect(stream)) => {
                            sessions.spawn(PluginSession::new(stream, self.events.clone(), shutdown.clone())
                                .with_inspections(self.inspections.clone()).run());
                        }
                        Some(PluginCommand::PublishEvent(event)) => {
                            // A live event has no receipt or replay if nobody subscribes.
                            drop(self.events.send(event));
                        }
                        Some(PluginCommand::InspectRequest { participant, context, first_deadline, reply }) => {
                            // Completed tasks must not consume active request capacity.
                            while let Some(completed) = inspections.try_join_next() {
                                Self::log_completed_inspection(completed);
                            }
                            if inspections.len() >= COMMAND_CAPACITY {
                                let _sent = reply.send(Err(InspectionError::Unavailable));
                            } else {
                                inspections.spawn(InspectionTask::new(
                                    &self.inspections, &participant, context, first_deadline, reply,
                                ).run());
                            }
                        }
                        None => break,
                    }
                }
                completed = inspections.join_next(), if !inspections.is_empty() => {
                    if let Some(completed) = completed {
                        Self::log_completed_inspection(completed);
                    }
                }
            }
        }

        self.commands.close();
        // Dropping queued reply senders wakes callers before waiting for sockets.
        while let Ok(command) = self.commands.try_recv() {
            drop(command);
        }
        inspections.shutdown().await;
        self.listener.shutdown().await;
        while let Some(completed) = sessions.join_next().await {
            Self::log_completed_session(Some(completed));
        }
        Ok(())
    }

    fn log_completed_inspection(completed: Result<(), tokio::task::JoinError>) {
        if let Err(error) = completed {
            tracing::error!(%error, "broker plugin inspection task failed");
        }
    }

    fn log_completed_session(
        completed: Option<Result<Result<(), session::PluginSessionError>, tokio::task::JoinError>>,
    ) {
        match completed {
            Some(Ok(Ok(()))) | None => {}
            Some(Ok(Err(error))) => {
                tracing::warn!(%error, "broker plugin session ended with an error");
            }
            Some(Err(error)) => {
                tracing::error!(%error, "broker plugin session task failed");
            }
        }
    }
}

#[cfg(all(test, unix))]
mod tests;
