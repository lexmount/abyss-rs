//! Handshake state machine and live event writer for one plugin connection.

use std::{sync::Arc, time::Duration};

use abyss_plugin_protocol::{
    event::AgentEvent,
    inspection::PluginCapability,
    message::{
        BrokerClose, BrokerCloseCode, BrokerError, BrokerErrorCode, BrokerHello, BrokerMessage,
        PluginMessage, PluginProtocolVersion,
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
    /// Unexpected frame after the handshake.
    #[error("invalid plugin session message")]
    InvalidMessage,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPluginHello {
    #[serde(rename = "type")]
    kind: HelloKind,
    capabilities: Vec<PluginCapability>,
    protocol_version: u16,
    plugin_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum HelloKind {
    PluginHello,
}

/// One accepted stream before and after protocol negotiation.
pub struct PluginSession<S> {
    stream: S,
    events: broadcast::Sender<Arc<AgentEvent>>,
    shutdown: watch::Receiver<bool>,
    inspections: Arc<super::inspection::InspectionRegistry>,
}

impl<S> PluginSession<S>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    /// Creates a session around one accepted local stream.
    pub fn new(
        stream: S,
        events: broadcast::Sender<Arc<AgentEvent>>,
        shutdown: watch::Receiver<bool>,
    ) -> Self {
        Self {
            stream,
            events,
            shutdown,
            inspections: Arc::new(super::inspection::InspectionRegistry::default()),
        }
    }

    pub(super) fn with_inspections(
        mut self,
        registry: Arc<super::inspection::InspectionRegistry>,
    ) -> Self {
        self.inspections = registry;
        self
    }

    /// Serves independent events and correlated decisions over one connection.
    #[expect(
        clippy::integer_division_remainder_used,
        reason = "tokio::select! expansion uses remainder internally"
    )]
    pub async fn run(mut self) -> Result<(), PluginSessionError> {
        let Some(hello) = self.handshake().await? else {
            return Ok(());
        };
        let mut events = self.events.subscribe();
        let (registration, mut requests) =
            if hello.capabilities.contains(&PluginCapability::AgentRequest) {
                let (registration, requests) = self.inspections.register();
                (Some(registration), requests)
            } else {
                (None, tokio::sync::mpsc::channel(1).1)
            };
        write_json(
            &mut self.stream,
            &BrokerMessage::BrokerHello(BrokerHello::v1()),
        )
        .await?;
        tracing::info!(plugin_id = %hello.plugin_id, "broker plugin session accepted");
        let (mut reader, mut writer) = tokio::io::split(self.stream);
        let registration_ref = registration.as_ref();
        let read = async {
            while let Some(payload) = read_payload(&mut reader).await? {
                let message: PluginMessage = serde_json::from_slice(&payload)
                    .map_err(|_| PluginSessionError::InvalidMessage)?;
                match (message, registration_ref) {
                    (PluginMessage::InspectResponse(response), Some(registration)) => {
                        registration.session.reply(response);
                    }
                    _ => return Err(PluginSessionError::InvalidMessage),
                }
            }
            Ok::<(), PluginSessionError>(())
        };
        let write = async {
            loop {
                tokio::select! {
                    request = requests.recv(), if registration_ref.is_some() => {
                        let Some(context) = request else { break; };
                        if registration_ref.is_some_and(|registration| registration.session.is_pending(&context.request_id)) {
                            context.frame.write(&mut writer).await?;
                        }
                    }
                    event = events.recv(), if hello.capabilities.contains(&PluginCapability::AgentEvents) => {
                        if let Ok(event) = event {
                            write_json(&mut writer, &BrokerMessage::AgentEvent { event }).await?;
                        } else {
                            write_json(&mut writer, &BrokerMessage::BrokerClose(BrokerClose::new(BrokerCloseCode::EventStreamTooSlow, "plugin event stream is too slow"))).await?;
                            break;
                        }
                    }
                }
            }
            Ok::<(), PluginSessionError>(())
        };
        // The frame reader remains alive while writes are pending, so a slow
        // plugin cannot prevent replies or disconnect cleanup from progressing.
        let result = tokio::select! {
            result = read => result,
            result = write => result,
            _ = self.shutdown.changed() => Ok(()),
        };
        if *self.shutdown.borrow() {
            let _close = tokio::time::timeout(
                super::inspection::DECISION_TIMEOUT,
                write_json(
                    &mut writer,
                    &BrokerMessage::BrokerClose(BrokerClose::new(
                        BrokerCloseCode::BrokerShutdown,
                        "broker is shutting down",
                    )),
                ),
            )
            .await;
        }
        result
    }

    async fn handshake(&mut self) -> Result<Option<RawPluginHello>, PluginSessionError> {
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
        let Ok(_protocol_version) = PluginProtocolVersion::try_from(hello.protocol_version) else {
            self.reject(
                BrokerErrorCode::UnsupportedProtocolVersion,
                format!("unsupported protocol version {}", hello.protocol_version),
            )
            .await?;
            return Ok(None);
        };
        if hello.capabilities.is_empty() {
            self.reject(
                BrokerErrorCode::InvalidHandshake,
                "at least one plugin capability is required",
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

        let HelloKind::PluginHello = hello.kind;
        Ok(Some(hello))
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
        write_json(
            &mut self.stream,
            &BrokerMessage::BrokerError(BrokerError::new(code, reason)),
        )
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
        message::{BrokerClose, BrokerError, BrokerHello, PluginHello, PluginMessage},
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

        write_json(
            &mut client,
            &PluginMessage::PluginHello(PluginHello::new("test-plugin".to_owned())),
        )
        .await
        .expect("PluginHello should write");
        let hello: BrokerHello = read_json(&mut client).await;
        assert_eq!(hello.protocol_version.wire_value(), 1_u16);

        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("fixtures/agent-event.json"))
                .expect("published fixture should be JSON");
        let event: AgentEvent = serde_json::from_value(fixture.clone())
            .expect("published AgentEvent fixture should decode");
        events
            .send(Arc::new(event))
            .expect("accepted session should subscribe to events");
        let received: AgentEvent = read_json(&mut client).await;
        let received = serde_json::to_value(received).expect("event should serialize");
        assert_eq!(
            received, fixture,
            "v1 must forward every structured field unchanged"
        );
        assert!(received.get("turn_index").is_none());

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
                "type": "plugin_hello",
                "capabilities": ["agent_events"],
                "protocol_version": 2_u16,
                "plugin_id": "future-plugin"
            }),
        )
        .await
        .expect("unsupported PluginHello should write");
        let error: BrokerError = read_json(&mut client).await;

        assert_eq!(error.code, 1_u32);
        assert!(error.reason.contains("unsupported protocol version 2"));
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
                "type": "plugin_hello",
                "capabilities": ["agent_events"],
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

        write_json(
            &mut client,
            &PluginMessage::PluginHello(PluginHello::new("slow-plugin".to_owned())),
        )
        .await
        .expect("PluginHello should write");
        let _hello: BrokerHello = read_json(&mut client).await;
        for _index in 0_u8..3_u8 {
            let event: AgentEvent = serde_json::from_str(include_str!("fixtures/agent-event.json"))
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
                let mut value: serde_json::Value =
                    serde_json::from_slice(&payload).expect("slow plugin frame should be JSON");
                if value.get("code").is_some() {
                    value.as_object_mut().unwrap().remove("type");
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
        decode_payload(&payload)
    }
    fn decode_payload<T: serde::de::DeserializeOwned>(payload: &[u8]) -> T {
        let mut frame: serde_json::Value = serde_json::from_slice(payload).unwrap();
        assert!(frame["type"].is_string(), "session frames are tagged");
        let payload = if frame["type"] == "agent_event" {
            frame["event"].take()
        } else {
            frame.as_object_mut().unwrap().remove("type");
            frame
        };
        serde_json::from_value(payload).unwrap()
    }
}
