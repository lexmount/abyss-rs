//! Local plugin listener, live event broadcaster, and connection lifecycle.
//!
//! The broker owns this server. Public plugin clients use `abyss-sdk`; this
//! module depends only on the shared wire contract and Agent Hook sink boundary.

mod codec;
mod session;
mod transport;

use std::{convert::Infallible, future::Future, path::Path, sync::Arc};

use abyss_agent_hook::AgentEventSink;
use abyss_plugin_protocol::event::AgentEvent;
use thiserror::Error;
use tokio::{
    sync::{broadcast, watch},
    task::JoinSet,
};

use self::{
    session::PluginSession,
    transport::{PluginTransport as _, platform::PlatformPluginTransport},
};

const EVENT_BROADCAST_CAPACITY: usize = 64;

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

/// Non-blocking Agent Hook sink backed by the shared broadcast ring.
#[derive(Debug, Clone)]
pub struct PluginEventBroadcaster {
    sender: broadcast::Sender<Arc<AgentEvent>>,
}

impl AgentEventSink for PluginEventBroadcaster {
    type Error = Infallible;

    fn publish(&self, event: AgentEvent) -> impl Future<Output = Result<(), Self::Error>> + Send {
        // A live stream intentionally drops events when there are no receivers.
        drop(self.sender.send(Arc::new(event)));
        std::future::ready(Ok(()))
    }
}

/// Bound local plugin listener and its shared live event source.
pub struct PluginServer {
    listener: PlatformPluginTransport,
    broadcaster: Arc<PluginEventBroadcaster>,
}

impl PluginServer {
    /// Binds the platform-default endpoint beneath the broker product root.
    pub async fn bind(abyss_home: &Path) -> Result<Self, PluginServerError> {
        let listener = PlatformPluginTransport::bind(abyss_home).await?;
        let (sender, _receiver) = broadcast::channel(EVENT_BROADCAST_CAPACITY);
        tracing::info!(
            endpoint = %listener.endpoint_label(),
            event_capacity = EVENT_BROADCAST_CAPACITY,
            "abyss-broker plugin listener bound"
        );
        Ok(Self {
            listener,
            broadcaster: Arc::new(PluginEventBroadcaster { sender }),
        })
    }

    /// Returns the concrete local endpoint advertised to product launchers.
    #[must_use]
    pub fn endpoint_label(&self) -> String {
        self.listener.endpoint_label()
    }

    /// Returns the non-blocking Agent Hook publication boundary.
    #[must_use]
    pub(super) fn event_sink(&self) -> Arc<PluginEventBroadcaster> {
        self.broadcaster.clone()
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
        loop {
            tokio::select! {
                biased;
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
                            self.broadcaster.sender.clone(),
                            shutdown.clone(),
                        )
                        .run(),
                    );
                }
                completed = sessions.join_next(), if !sessions.is_empty() => {
                    Self::log_completed_session(completed);
                }
            }
        }

        self.listener.shutdown().await;
        while let Some(completed) = sessions.join_next().await {
            Self::log_completed_session(Some(completed));
        }
        Ok(())
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
mod tests {
    use std::path::PathBuf;

    use abyss_agent_hook::AgentEventSink as _;
    use abyss_plugin_protocol::{
        event::AgentEvent,
        message::{BrokerClose, BrokerHello, PluginHello},
    };
    use tokio::net::UnixStream;

    use super::{
        PluginServer,
        codec::{read_payload, write_json},
    };

    #[tokio::test]
    async fn one_real_listener_broadcasts_the_same_event_to_two_plugins() {
        let root = test_root();
        let server = PluginServer::bind(&root)
            .await
            .expect("plugin server should bind");
        let endpoint = PathBuf::from(server.endpoint_label());
        let sink = server.broadcaster.clone();
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let server_task = tokio::spawn(server.run(shutdown_rx));

        let mut first = connect_plugin(&endpoint, "first-plugin").await;
        let mut second = connect_plugin(&endpoint, "second-plugin").await;
        let event: AgentEvent = serde_json::from_str(include_str!(
            "../../../../specs/broker-plugin-protocol/v1/fixtures/agent-event.json"
        ))
        .expect("published AgentEvent fixture should decode");
        sink.publish(event)
            .await
            .expect("broker event sink should accept the event");

        let first_event: AgentEvent = read_json(&mut first).await;
        let second_event: AgentEvent = read_json(&mut second).await;
        assert_eq!(first_event.event_id, "evt-123");
        assert_eq!(second_event.event_id, first_event.event_id);

        shutdown_tx
            .send(true)
            .expect("server should retain shutdown receiver");
        let first_close: BrokerClose = read_json(&mut first).await;
        let second_close: BrokerClose = read_json(&mut second).await;
        assert_eq!(first_close.code, 100_u32);
        assert_eq!(second_close.code, 100_u32);
        server_task
            .await
            .expect("plugin server task should finish")
            .expect("plugin server should stop cleanly");
        assert!(
            !endpoint.exists(),
            "orderly shutdown should remove the Unix socket"
        );
        if tokio::fs::try_exists(&root)
            .await
            .expect("plugin server test root should be queryable")
        {
            tokio::fs::remove_dir_all(root)
                .await
                .expect("plugin server test root should remove");
        }
    }

    async fn connect_plugin(endpoint: &std::path::Path, plugin_id: &str) -> UnixStream {
        let mut stream = UnixStream::connect(endpoint)
            .await
            .expect("plugin should connect to the Unix socket");
        write_json(&mut stream, &PluginHello::new(plugin_id.to_owned()))
            .await
            .expect("PluginHello should write");
        let hello: BrokerHello = read_json(&mut stream).await;
        assert_eq!(
            hello.protocol_version.wire_value(),
            1_u16,
            "broker should negotiate plugin protocol version 1"
        );
        stream
    }

    async fn read_json<T>(stream: &mut UnixStream) -> T
    where
        T: serde::de::DeserializeOwned,
    {
        let payload = read_payload(stream)
            .await
            .expect("plugin frame should read")
            .expect("plugin frame should be present");
        serde_json::from_slice(&payload).expect("plugin frame JSON should decode")
    }

    fn test_root() -> PathBuf {
        std::env::temp_dir().join(format!(
            "abyss-plugin-server-test-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ))
    }
}
