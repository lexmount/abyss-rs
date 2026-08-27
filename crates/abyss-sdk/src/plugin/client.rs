//! High-level plugin connection, handshake, and Agent event stream.

use std::{
    future::Future,
    path::PathBuf,
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

const PLUGIN_ENDPOINT_ENV: &str = "ABYSS_BROKER_PLUGIN_ENDPOINT";
const STARTUP_INFO_ENV: &str = "ABYSS_BROKER_STARTUP_INFO";

/// Error returned by the public broker plugin runtime.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AbyssPluginError {
    /// No explicit or product-discovered local endpoint was available.
    #[error(
        "broker plugin endpoint is unavailable; configure {PLUGIN_ENDPOINT_ENV}, {STARTUP_INFO_ENV}, or ABYSS_HOME"
    )]
    MissingEndpoint,
    /// Startup information could not be read or decoded.
    #[error("read broker startup info `{path}`: {source}")]
    StartupInfo {
        /// Product-owned startup information path.
        path: PathBuf,
        /// Read or JSON decode failure.
        #[source]
        source: StartupInfoError,
    },
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

impl From<super::codec::PluginFrameError> for AbyssPluginError {
    fn from(error: super::codec::PluginFrameError) -> Self {
        Self::Frame(error.to_string())
    }
}

/// Failure while loading broker startup information.
#[derive(Debug, Error)]
pub enum StartupInfoError {
    /// The startup information file could not be read.
    #[error("read file: {0}")]
    Io(#[from] std::io::Error),
    /// The startup information was not valid JSON.
    #[error("decode JSON: {0}")]
    Json(#[from] serde_json::Error),
}

/// One configured out-of-process consumer of broker Agent events.
pub struct AbyssPlugin {
    plugin_id: String,
    endpoint: Option<String>,
}

/// Stream of typed Agent events received after a successful handshake.
pub struct AgentEventStream {
    inner: Pin<Box<dyn Stream<Item = Result<AgentEvent, AbyssPluginError>> + Send>>,
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

#[derive(Deserialize)]
struct StartupInfo {
    plugin_endpoint: String,
}

struct EventStreamState {
    stream: transport::ConnectedPluginStream,
    close: Arc<Mutex<Option<BrokerClose>>>,
    terminated: bool,
}

impl AbyssPlugin {
    /// Creates a plugin that discovers its endpoint from the product runtime.
    #[must_use]
    pub fn new<T>(plugin_id: T) -> Self
    where
        T: Into<String>,
    {
        Self {
            plugin_id: plugin_id.into(),
            endpoint: None,
        }
    }

    /// Overrides product discovery with one concrete Unix socket or Named Pipe.
    #[must_use]
    pub fn with_endpoint<T>(mut self, endpoint: T) -> Self
    where
        T: Into<String>,
    {
        self.endpoint = Some(endpoint.into());
        self
    }

    /// Connects, performs the version 1 handshake, and returns the Agent event stream.
    ///
    /// # Errors
    ///
    /// Returns an error when endpoint discovery, transport connection, or the
    /// handshake fails.
    pub async fn connect(self) -> Result<AgentEventStream, AbyssPluginError> {
        let endpoint = self.resolve_endpoint().await?;
        let mut stream = transport::connect(&endpoint)
            .await
            .map_err(|source| AbyssPluginError::Connect { endpoint, source })?;
        self.handshake(stream.as_mut().get_mut()).await?;
        Ok(AgentEventStream::new(stream))
    }

    /// Connects and handles events until the broker deliberately closes the stream.
    ///
    /// # Errors
    ///
    /// Returns an error when endpoint discovery, transport, protocol handling,
    /// or the supplied event handler fails.
    pub async fn run<H, F, E>(self, mut handler: H) -> Result<BrokerClose, AbyssPluginError>
    where
        H: FnMut(AgentEvent) -> F,
        F: Future<Output = Result<(), E>>,
        E: std::fmt::Display,
    {
        let mut events = self.connect().await?;
        while let Some(event) = events.next().await {
            handler(event?)
                .await
                .map_err(|error| AbyssPluginError::Handler(error.to_string()))?;
        }
        events.take_close().ok_or(AbyssPluginError::UnexpectedEof)
    }

    #[cfg(test)]
    async fn connect_stream<S>(self, stream: S) -> Result<AgentEventStream, AbyssPluginError>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let mut stream: transport::ConnectedPluginStream = Box::pin(stream);
        self.handshake(stream.as_mut().get_mut()).await?;
        Ok(AgentEventStream::new(stream))
    }

    async fn handshake<S>(&self, stream: &mut S) -> Result<(), AbyssPluginError>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + ?Sized,
    {
        codec::write_json(stream, &PluginHello::new(self.plugin_id.clone())).await?;
        let payload = codec::read_payload(stream)
            .await?
            .ok_or(AbyssPluginError::UnexpectedEof)?;
        let response = serde_json::from_slice::<HandshakeResponse>(&payload).map_err(|source| {
            AbyssPluginError::Decode {
                phase: "handshake response",
                source,
            }
        })?;
        match response {
            HandshakeResponse::Accepted(_hello) => Ok(()),
            HandshakeResponse::Rejected(error) => Err(AbyssPluginError::HandshakeRejected {
                code: error.code,
                reason: error.reason,
            }),
        }
    }

    async fn resolve_endpoint(&self) -> Result<String, AbyssPluginError> {
        if let Some(endpoint) = &self.endpoint {
            return Ok(endpoint.clone());
        }
        if let Some(endpoint) = Self::non_empty_env(PLUGIN_ENDPOINT_ENV) {
            return Ok(endpoint);
        }
        let startup_info_path = Self::non_empty_env(STARTUP_INFO_ENV)
            .map(PathBuf::from)
            .or_else(|| {
                Self::non_empty_env("ABYSS_HOME")
                    .map(PathBuf::from)
                    .map(|root| root.join("runtime").join("startup-info.json"))
            })
            .ok_or(AbyssPluginError::MissingEndpoint)?;
        Self::read_startup_info(startup_info_path).await
    }

    async fn read_startup_info(path: PathBuf) -> Result<String, AbyssPluginError> {
        let body =
            tokio::fs::read(&path)
                .await
                .map_err(|source| AbyssPluginError::StartupInfo {
                    path: path.clone(),
                    source: StartupInfoError::Io(source),
                })?;
        let info = serde_json::from_slice::<StartupInfo>(&body).map_err(|source| {
            AbyssPluginError::StartupInfo {
                path,
                source: StartupInfoError::Json(source),
            }
        })?;
        Ok(info.plugin_endpoint)
    }

    fn non_empty_env(name: &'static str) -> Option<String> {
        std::env::var_os(name)
            .map(|value| value.to_string_lossy().trim().to_owned())
            .filter(|value| !value.is_empty())
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
    type Item = Result<AgentEvent, AbyssPluginError>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.as_mut().poll_next(context)
    }
}

async fn read_stream_message<S>(stream: &mut S) -> Result<StreamMessage, AbyssPluginError>
where
    S: AsyncRead + Unpin + ?Sized,
{
    let payload = codec::read_payload(stream)
        .await?
        .ok_or(AbyssPluginError::UnexpectedEof)?;
    serde_json::from_slice(&payload).map_err(|source| AbyssPluginError::Decode {
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

    use super::AbyssPlugin;
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
        let plugin = AbyssPlugin::new("sdk-test-plugin");

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
