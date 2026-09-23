//! High-level plugin connection, handshake, and Agent event stream.

use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use abyss_plugin_protocol::{
    event::AgentEvent,
    message::{BrokerClose, BrokerError, BrokerHello, PluginHello},
};
use futures_core::Stream;
use futures_util::{StreamExt as _, stream};
use serde::Deserialize;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};

use super::{codec, transport};

/// Error returned by the public broker plugin runtime.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BrokerPluginError {
    /// The platform-local transport could not connect.
    #[error("connect to broker plugin endpoint `{endpoint}`: {source}")]
    Connect {
        /// Concrete Unix socket or Named Pipe endpoint.
        endpoint: String,
        /// Operating-system connection failure.
        #[source]
        source: std::io::Error,
    },
    /// A protocol frame could not be read or written.
    #[error("broker plugin protocol frame: {0}")]
    Frame(String),
    /// A broker payload did not match the active protocol phase.
    #[error("decode broker plugin {phase}: {source}")]
    Decode {
        /// Session phase being decoded.
        phase: &'static str,
        /// JSON contract failure.
        #[source]
        source: serde_json::Error,
    },
    /// The broker rejected the initial plugin handshake.
    #[error("broker rejected plugin handshake with code {code}: {reason}")]
    HandshakeRejected {
        /// Version 1 rejection code.
        code: u32,
        /// Broker diagnostic reason.
        reason: String,
    },
    /// The broker closed without the final frame required for a deliberate close.
    #[error("broker plugin stream ended without BrokerClose")]
    UnexpectedEof,
    /// The plugin's event handler failed.
    #[error("broker plugin event handler failed: {0}")]
    Handler(String),
}

impl From<super::codec::PluginFrameError> for BrokerPluginError {
    fn from(error: super::codec::PluginFrameError) -> Self {
        Self::Frame(error.to_string())
    }
}

/// Independent event consumer created by [`BrokerClient::plugin`](crate::BrokerClient::plugin).
pub struct BrokerPlugin {
    plugin_id: String,
    endpoint: String,
}

/// Stream of typed Agent events received after a successful handshake.
pub struct AgentEventStream {
    inner: Pin<Box<dyn Stream<Item = Result<AgentEvent, BrokerPluginError>> + Send>>,
    close: Arc<Mutex<Option<BrokerClose>>>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum HandshakeResponse {
    Accepted(BrokerHello),
    Rejected(BrokerError),
}

#[derive(Deserialize)]
#[serde(untagged)]
enum StreamMessage {
    Event(Box<AgentEvent>),
    Close(BrokerClose),
}

struct EventStreamState {
    stream: transport::ConnectedPluginStream,
    close: Arc<Mutex<Option<BrokerClose>>>,
    terminated: bool,
}

impl BrokerPlugin {
    /// Creates a plugin bound to its owning client's endpoint.
    pub(crate) const fn new(plugin_id: String, endpoint: String) -> Self {
        Self {
            plugin_id,
            endpoint,
        }
    }

    /// Connects, performs the version 1 handshake, and returns the Agent event stream.
    ///
    /// # Errors
    ///
    /// Returns an error when transport connection or the
    /// handshake fails.
    pub async fn connect(self) -> Result<AgentEventStream, BrokerPluginError> {
        let endpoint = self.endpoint.clone();
        let mut stream = transport::connect(&endpoint)
            .await
            .map_err(|source| BrokerPluginError::Connect { endpoint, source })?;
        self.handshake(stream.as_mut().get_mut()).await?;
        Ok(AgentEventStream::new(stream))
    }

    /// Connects and handles events until the broker deliberately closes the stream.
    ///
    /// # Errors
    ///
    /// Returns an error when transport, protocol handling,
    /// or the supplied event handler fails.
    pub async fn run<H, F, E>(self, mut handler: H) -> Result<BrokerClose, BrokerPluginError>
    where
        H: FnMut(AgentEvent) -> F,
        F: Future<Output = Result<(), E>>,
        E: std::fmt::Display,
    {
        let mut events = self.connect().await?;
        while let Some(event) = events.next().await {
            handler(event?)
                .await
                .map_err(|error| BrokerPluginError::Handler(error.to_string()))?;
        }
        events.take_close().ok_or(BrokerPluginError::UnexpectedEof)
    }

    #[cfg(test)]
    async fn connect_stream<S>(self, stream: S) -> Result<AgentEventStream, BrokerPluginError>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let mut stream: transport::ConnectedPluginStream = Box::pin(stream);
        self.handshake(stream.as_mut().get_mut()).await?;
        Ok(AgentEventStream::new(stream))
    }

    async fn handshake<S>(&self, stream: &mut S) -> Result<(), BrokerPluginError>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + ?Sized,
    {
        codec::write_json(stream, &PluginHello::new(self.plugin_id.clone())).await?;
        let payload = codec::read_payload(stream)
            .await?
            .ok_or(BrokerPluginError::UnexpectedEof)?;
        let response = serde_json::from_slice::<HandshakeResponse>(&payload).map_err(|source| {
            BrokerPluginError::Decode {
                phase: "handshake response",
                source,
            }
        })?;
        match response {
            HandshakeResponse::Accepted(_hello) => Ok(()),
            HandshakeResponse::Rejected(error) => Err(BrokerPluginError::HandshakeRejected {
                code: error.code,
                reason: error.reason,
            }),
        }
    }
}

impl AgentEventStream {
    fn new(stream: transport::ConnectedPluginStream) -> Self {
        let close = Arc::new(Mutex::new(None));
        let state = EventStreamState {
            stream,
            close: Arc::clone(&close),
            terminated: false,
        };
        let inner = stream::unfold(state, |mut state| async move {
            if state.terminated {
                return None;
            }
            match read_stream_message(state.stream.as_mut().get_mut()).await {
                Ok(StreamMessage::Event(event)) => Some((Ok(*event), state)),
                Ok(StreamMessage::Close(close)) => {
                    if let Ok(mut stored) = state.close.lock() {
                        *stored = Some(close);
                    }
                    None
                }
                Err(error) => {
                    state.terminated = true;
                    Some((Err(error), state))
                }
            }
        });
        Self {
            inner: Box::pin(inner),
            close,
        }
    }

    /// Takes the deliberate broker close frame after the stream has ended.
    #[must_use]
    pub fn take_close(&mut self) -> Option<BrokerClose> {
        self.close.lock().ok()?.take()
    }
}

impl Stream for AgentEventStream {
    type Item = Result<AgentEvent, BrokerPluginError>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.as_mut().poll_next(context)
    }
}

async fn read_stream_message<S>(stream: &mut S) -> Result<StreamMessage, BrokerPluginError>
where
    S: AsyncRead + Unpin + ?Sized,
{
    let payload = codec::read_payload(stream)
        .await?
        .ok_or(BrokerPluginError::UnexpectedEof)?;
    serde_json::from_slice(&payload).map_err(|source| BrokerPluginError::Decode {
        phase: "event stream frame",
        source,
    })
}

#[cfg(test)]
mod tests {
    use abyss_plugin_protocol::{
        event::AgentEvent,
        message::{BrokerClose, BrokerCloseCode, BrokerHello, PluginHello},
    };
    use futures_util::StreamExt as _;
    use tokio::io::duplex;

    use crate::BrokerClient;
    use crate::plugin::codec::{read_payload, write_json};

    #[tokio::test]
    async fn performs_handshake_and_exposes_agent_events_as_a_stream() {
        let (client, mut server) = duplex(32 * 1024);
        let server_task = tokio::spawn(async move {
            let hello: PluginHello = read_json(&mut server).await;
            assert_eq!(hello.plugin_id, "sdk-test-plugin");
            write_json(&mut server, &BrokerHello::v1())
                .await
                .expect("BrokerHello should write");
            let event: AgentEvent = serde_json::from_str(include_str!(
                "../../../../specs/broker-plugin-protocol/v1/fixtures/agent-event.json"
            ))
            .expect("published AgentEvent fixture should decode");
            write_json(&mut server, &event)
                .await
                .expect("AgentEvent should write");
            write_json(
                &mut server,
                &BrokerClose::new(BrokerCloseCode::BrokerShutdown, "test complete"),
            )
            .await
            .expect("BrokerClose should write");
        });
        let plugin = BrokerClient::new("http://127.0.0.1:18190", "/unused/test.sock")
            .expect("client should configure without connecting")
            .plugin("sdk-test-plugin");

        let mut events = plugin
            .connect_stream(client)
            .await
            .expect("plugin handshake should complete");
        let event = events
            .next()
            .await
            .expect("one event should be present")
            .expect("event should decode");
        assert_eq!(event.event_id, "evt-123");
        assert!(events.next().await.is_none());
        let close = events
            .take_close()
            .expect("deliberate close should be retained");
        assert_eq!(close.code, 100_u32);

        server_task.await.expect("test broker task should finish");
    }

    async fn read_json<T>(stream: &mut tokio::io::DuplexStream) -> T
    where
        T: serde::de::DeserializeOwned,
    {
        let payload = read_payload(stream)
            .await
            .expect("plugin frame should read")
            .expect("plugin frame should be present");
        serde_json::from_slice(&payload).expect("plugin frame JSON should decode")
    }
}
