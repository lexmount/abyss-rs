//! Handshake state machine and live event writer for one plugin connection.

use std::{sync::Arc, time::Duration};

use abyss_plugin_protocol::{
    event::AgentEvent,
    message::{
        BrokerClose, BrokerCloseCode, BrokerError, BrokerErrorCode, BrokerHello,
        PluginProtocolVersion,
    },
};
use serde::Deserialize;
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{broadcast, watch},
};

use super::codec::{PluginFrameError, read_payload, write_json};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Failure while serving an accepted plugin connection.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PluginSessionError {
    /// A frame could not be read or written.
    #[error("plugin frame error: {0}")]
    Frame(#[from] PluginFrameError),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPluginHello {
    protocol_version: u16,
    plugin_id: String,
}

/// One accepted stream before and after protocol negotiation.
pub struct PluginSession<S> {
    stream: S,
    events: broadcast::Sender<Arc<AgentEvent>>,
    shutdown: watch::Receiver<bool>,
}

enum StreamAction {
    Continue,
    Close,
}

impl<S> PluginSession<S>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    /// Creates a session around one accepted local stream.
    pub const fn new(
        stream: S,
        events: broadcast::Sender<Arc<AgentEvent>>,
        shutdown: watch::Receiver<bool>,
    ) -> Self {
        Self {
            stream,
            events,
            shutdown,
        }
    }

    /// Negotiates version 1 and writes events until this connection ends.
    pub async fn run(mut self) -> Result<(), PluginSessionError> {
        let Some((plugin_id, mut events)) = self.handshake().await? else {
            return Ok(());
        };
        tracing::info!(%plugin_id, "broker plugin session accepted");

        self.stream_events(&plugin_id, &mut events).await?;
        tracing::info!(%plugin_id, "broker plugin session closed");
        Ok(())
    }

    #[expect(
        clippy::integer_division_remainder_used,
        reason = "tokio::select! expands through runtime code that uses remainder internally"
    )]
    async fn stream_events(
        &mut self,
        plugin_id: &str,
        events: &mut broadcast::Receiver<Arc<AgentEvent>>,
    ) -> Result<(), PluginSessionError> {
        loop {
            tokio::select! {
                biased;
                changed = self.shutdown.changed() => {
                    if changed.is_err() || *self.shutdown.borrow() {
                        self.close(
                            BrokerCloseCode::BrokerShutdown,
                            "broker is shutting down",
                        )
                        .await?;
                        break;
                    }
                }
                received = events.recv() => {
                    if matches!(
                        self.handle_event(plugin_id, received).await?,
                        StreamAction::Close
                    ) {
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    async fn handle_event(
        &mut self,
        plugin_id: &str,
        received: Result<Arc<AgentEvent>, broadcast::error::RecvError>,
    ) -> Result<StreamAction, PluginSessionError> {
        match received {
            Ok(event) => {
                write_json(&mut self.stream, event.as_ref()).await?;
                Ok(StreamAction::Continue)
            }
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                tracing::warn!(
                    %plugin_id,
                    skipped,
                    "closing slow broker plugin session"
                );
                self.close(
                    BrokerCloseCode::EventStreamTooSlow,
                    "plugin event stream is too slow",
                )
                .await?;
                Ok(StreamAction::Close)
            }
            Err(broadcast::error::RecvError::Closed) => {
                self.close(
                    BrokerCloseCode::BrokerShutdown,
                    "broker event stream closed",
                )
                .await?;
                Ok(StreamAction::Close)
            }
        }
    }

    async fn handshake(
        &mut self,
    ) -> Result<Option<(String, broadcast::Receiver<Arc<AgentEvent>>)>, PluginSessionError> {
        let payload = match self.read_handshake_payload().await {
            Ok(Some(payload)) => payload,
            Ok(None) => return Ok(None),
            Err(error @ PluginFrameError::PayloadTooLarge { .. }) => {
                self.reject(BrokerErrorCode::InvalidHandshake, error.to_string())
                    .await?;
                return Ok(None);
            }
            Err(error) => return Err(error.into()),
        };
        let hello = match serde_json::from_slice::<RawPluginHello>(&payload) {
            Ok(hello) => hello,
            Err(error) => {
                self.reject(
                    BrokerErrorCode::InvalidHandshake,
                    format!("invalid PluginHello: {error}"),
                )
                .await?;
                return Ok(None);
            }
        };
        if PluginProtocolVersion::try_from(hello.protocol_version).is_err() {
            self.reject(
                BrokerErrorCode::UnsupportedProtocolVersion,
                format!("unsupported protocol version {}", hello.protocol_version),
            )
            .await?;
            return Ok(None);
        }
        if !Self::valid_plugin_id(&hello.plugin_id) {
            self.reject(
                BrokerErrorCode::InvalidHandshake,
                "plugin_id must contain 1 to 128 ASCII letters, digits, '.', '_', or '-'",
            )
            .await?;
            return Ok(None);
        }

        let events = self.events.subscribe();
        write_json(&mut self.stream, &BrokerHello::v1()).await?;
        Ok(Some((hello.plugin_id, events)))
    }

    #[expect(
        clippy::integer_division_remainder_used,
        reason = "tokio::select! expands through runtime code that uses remainder internally"
    )]
    async fn read_handshake_payload(&mut self) -> Result<Option<Vec<u8>>, PluginFrameError> {
        loop {
            tokio::select! {
                biased;
                changed = self.shutdown.changed() => {
                    if changed.is_err() || *self.shutdown.borrow() {
                        return Ok(None);
                    }
                }
                payload = tokio::time::timeout(
                    HANDSHAKE_TIMEOUT,
                    read_payload(&mut self.stream),
                ) => {
                    return match payload {
                        Ok(payload) => payload,
                        Err(_elapsed) => {
                            tracing::debug!(
                                timeout_seconds = HANDSHAKE_TIMEOUT.as_secs(),
                                "broker plugin handshake timed out"
                            );
                            Ok(None)
                        }
                    };
                }
            }
        }
    }

    async fn reject<T>(
        &mut self,
        code: BrokerErrorCode,
        reason: T,
    ) -> Result<(), PluginSessionError>
    where
        T: Into<String>,
    {
        write_json(&mut self.stream, &BrokerError::new(code, reason))
            .await
            .map_err(Into::into)
    }

    async fn close(
        &mut self,
        code: BrokerCloseCode,
        reason: &'static str,
    ) -> Result<(), PluginSessionError> {
        write_json(&mut self.stream, &BrokerClose::new(code, reason))
            .await
            .map_err(Into::into)
    }

    fn valid_plugin_id(plugin_id: &str) -> bool {
        (1..=128).contains(&plugin_id.len())
            && plugin_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use abyss_plugin_protocol::{
        event::AgentEvent,
        message::{BrokerClose, BrokerError, BrokerHello, PluginHello},
    };
    use tokio::{io::duplex, sync::broadcast};

    use super::{HANDSHAKE_TIMEOUT, PluginSession};
    use crate::plugin::codec::{read_payload, write_json};

    #[tokio::test]
    async fn accepts_v1_then_streams_events_and_a_shutdown_close() {
        let (mut client, server) = duplex(32 * 1024);
        let (events, _receiver) = broadcast::channel(64);
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let session = tokio::spawn(PluginSession::new(server, events.clone(), shutdown_rx).run());

        write_json(&mut client, &PluginHello::new("test-plugin".to_owned()))
            .await
            .expect("PluginHello should write");
        let hello: BrokerHello = read_json(&mut client).await;
        assert_eq!(hello.protocol_version.wire_value(), 1_u16);

        let event: AgentEvent = serde_json::from_str(include_str!(
            "../../../../specs/broker-plugin-protocol/v1/fixtures/agent-event.json"
        ))
        .expect("published AgentEvent fixture should decode");
        events
            .send(Arc::new(event))
            .expect("accepted session should subscribe to events");
        let received: AgentEvent = read_json(&mut client).await;
        assert_eq!(received.event_id, "evt-123");

        shutdown_tx
            .send(true)
            .expect("session should retain shutdown receiver");
        let close: BrokerClose = read_json(&mut client).await;
        assert_eq!(close.code, 100_u32);
        session
            .await
            .expect("session task should finish")
            .expect("session should close cleanly");
    }

    #[tokio::test]
    async fn rejects_an_unsupported_protocol_version_with_a_typed_error() {
        let (mut client, server) = duplex(1024);
        let (events, _receiver) = broadcast::channel(64);
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let session = tokio::spawn(PluginSession::new(server, events, shutdown_rx).run());

        write_json(
            &mut client,
            &serde_json::json!({
                "protocol_version": 77_u16,
                "plugin_id": "future-plugin"
            }),
        )
        .await
        .expect("unsupported PluginHello should write");
        let error: BrokerError = read_json(&mut client).await;

        assert_eq!(error.code, 1_u32);
        assert!(error.reason.contains("77"));
        session
            .await
            .expect("session task should finish")
            .expect("rejected session should finish cleanly");
    }

    #[tokio::test]
    async fn rejects_a_malformed_plugin_identifier() {
        let (mut client, server) = duplex(1024);
        let (events, _receiver) = broadcast::channel(64);
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let session = tokio::spawn(PluginSession::new(server, events, shutdown_rx).run());

        write_json(
            &mut client,
            &serde_json::json!({
                "protocol_version": 1_u16,
                "plugin_id": "invalid plugin id"
            }),
        )
        .await
        .expect("invalid PluginHello should write");
        let error: BrokerError = read_json(&mut client).await;

        assert_eq!(error.code, 2_u32);
        session
            .await
            .expect("session task should finish")
            .expect("rejected session should finish cleanly");
    }

    #[tokio::test]
    async fn closes_only_a_session_that_lags_behind_its_event_ring() {
        let (mut client, server) = duplex(64);
        let (events, _receiver) = broadcast::channel(1);
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let session = tokio::spawn(PluginSession::new(server, events.clone(), shutdown_rx).run());

        write_json(&mut client, &PluginHello::new("slow-plugin".to_owned()))
            .await
            .expect("PluginHello should write");
        let _hello: BrokerHello = read_json(&mut client).await;
        for _index in 0_u8..3_u8 {
            let event: AgentEvent = serde_json::from_str(include_str!(
                "../../../../specs/broker-plugin-protocol/v1/fixtures/agent-event.json"
            ))
            .expect("published AgentEvent fixture should decode");
            events
                .send(Arc::new(event))
                .expect("accepted session should remain subscribed");
        }

        let close = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let payload = read_payload(&mut client)
                    .await
                    .expect("slow plugin frame should read")
                    .expect("slow plugin frame should be present");
                let value: serde_json::Value =
                    serde_json::from_slice(&payload).expect("slow plugin frame should be JSON");
                if value.get("code").is_some() {
                    break serde_json::from_value::<BrokerClose>(value)
                        .expect("control frame should decode as BrokerClose");
                }
            }
        })
        .await
        .expect("lagged session should be closed promptly");

        assert_eq!(close.code, 101_u32);
        session
            .await
            .expect("session task should finish")
            .expect("lagged session should close cleanly");
    }

    #[tokio::test]
    async fn shutdown_drops_a_connection_that_never_sends_its_handshake() {
        let (_client, server) = duplex(1024);
        let (events, _receiver) = broadcast::channel(64);
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let session = tokio::spawn(PluginSession::new(server, events, shutdown_rx).run());

        shutdown_tx
            .send(true)
            .expect("session should retain shutdown receiver");
        session
            .await
            .expect("session task should finish")
            .expect("unhandshaken session should stop cleanly");
    }

    #[tokio::test(start_paused = true)]
    async fn handshake_timeout_drops_a_connection_that_never_sends_plugin_hello() {
        let (_client, server) = duplex(1024);
        let (events, _receiver) = broadcast::channel(64);
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let session = tokio::spawn(PluginSession::new(server, events, shutdown_rx).run());

        tokio::time::timeout(
            HANDSHAKE_TIMEOUT + std::time::Duration::from_secs(1),
            session,
        )
        .await
        .expect("unhandshaken session should stop after the handshake timeout")
        .expect("session task should finish")
        .expect("timed out session should finish cleanly");
    }

    async fn read_json<T>(stream: &mut tokio::io::DuplexStream) -> T
    where
        T: serde::de::DeserializeOwned,
    {
        let payload = read_payload(stream)
            .await
            .expect("frame should read")
            .expect("frame should be present");
        serde_json::from_slice(&payload).expect("frame JSON should decode")
    }
}
