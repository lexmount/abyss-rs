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
    inspection::{AgentRequestContext, PluginCapability, RequestDecision},
    message::{BrokerClose, BrokerMessage, PluginHello, PluginMessage},
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
pub enum BrokerPluginError {
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

impl From<super::codec::PluginFrameError> for BrokerPluginError {
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
pub struct BrokerPlugin {
    plugin_id: String,
    endpoint: Option<String>,
}

/// Stream of typed Agent events received after a successful handshake.
pub struct AgentEventStream {
    inner: Pin<Box<dyn Stream<Item = Result<AgentEvent, BrokerPluginError>> + Send>>,
    close: Arc<Mutex<Option<BrokerClose>>>,
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

impl BrokerPlugin {
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

    /// Connects, requests protocol version 2, and returns the Agent event stream.
    ///
    /// # Errors
    ///
    /// Returns an error when endpoint discovery, transport connection, or the
    /// handshake fails.
    pub async fn connect(self) -> Result<AgentEventStream, BrokerPluginError> {
        Ok(AgentEventStream::new(
            self.connect_transport(vec![PluginCapability::AgentEvents])
                .await?,
        ))
    }

    /// Registers a request decision handler; connecting this plugin enables inspection.
    #[must_use]
    pub const fn on_agent_request<H, F, E>(self, handler: H) -> InspectingPlugin<H>
    where
        H: FnMut(Arc<AgentRequestContext>) -> F,
        F: Future<Output = Result<RequestDecision, E>>,
        E: std::fmt::Display,
    {
        InspectingPlugin {
            plugin: self,
            handler,
        }
    }

    async fn connect_transport(
        &self,
        capabilities: Vec<PluginCapability>,
    ) -> Result<transport::ConnectedPluginStream, BrokerPluginError> {
        let endpoint = self.resolve_endpoint().await?;
        let mut stream = transport::connect(&endpoint)
            .await
            .map_err(|source| BrokerPluginError::Connect { endpoint, source })?;
        self.handshake(stream.as_mut().get_mut(), capabilities)
            .await?;
        Ok(stream)
    }

    /// Connects and handles events until the broker deliberately closes the stream.
    ///
    /// # Errors
    ///
    /// Returns an error when endpoint discovery, transport, protocol handling,
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
        self.handshake(
            stream.as_mut().get_mut(),
            vec![PluginCapability::AgentEvents],
        )
        .await?;
        Ok(AgentEventStream::new(stream))
    }

    async fn handshake<S>(
        &self,
        stream: &mut S,
        capabilities: Vec<PluginCapability>,
    ) -> Result<(), BrokerPluginError>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + ?Sized,
    {
        let mut hello = PluginHello::new(self.plugin_id.clone());
        hello.capabilities = capabilities;
        codec::write_json(stream, &PluginMessage::PluginHello(hello)).await?;
        let payload = codec::read_payload(stream)
            .await?
            .ok_or(BrokerPluginError::UnexpectedEof)?;
        let response = serde_json::from_slice::<BrokerMessage>(&payload).map_err(|source| {
            BrokerPluginError::Decode {
                phase: "handshake response",
                source,
            }
        })?;
        match response {
            BrokerMessage::BrokerHello(_hello) => Ok(()),
            BrokerMessage::BrokerError(error) => Err(BrokerPluginError::HandshakeRejected {
                code: error.code,
                reason: error.reason,
            }),
            _ => Err(BrokerPluginError::Frame(
                "expected broker_hello or broker_error".to_owned(),
            )),
        }
    }

    async fn resolve_endpoint(&self) -> Result<String, BrokerPluginError> {
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
            .ok_or(BrokerPluginError::MissingEndpoint)?;
        Self::read_startup_info(startup_info_path).await
    }

    async fn read_startup_info(path: PathBuf) -> Result<String, BrokerPluginError> {
        let body =
            tokio::fs::read(&path)
                .await
                .map_err(|source| BrokerPluginError::StartupInfo {
                    path: path.clone(),
                    source: StartupInfoError::Io(source),
                })?;
        let info = serde_json::from_slice::<StartupInfo>(&body).map_err(|source| {
            BrokerPluginError::StartupInfo {
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
                Ok(BrokerMessage::AgentEvent { event }) => Some((
                    Ok(Arc::try_unwrap(event).expect("decoded event has one owner")),
                    state,
                )),
                Ok(BrokerMessage::BrokerClose(close)) => {
                    if let Ok(mut stored) = state.close.lock() {
                        *stored = Some(close);
                    }
                    None
                }
                Ok(_) => {
                    state.terminated = true;
                    Some((
                        Err(BrokerPluginError::Frame(
                            "unexpected event stream message".to_owned(),
                        )),
                        state,
                    ))
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

async fn read_stream_message<S>(stream: &mut S) -> Result<BrokerMessage, BrokerPluginError>
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

/// Plugin with a typed request handler, using the existing local connection.
pub struct InspectingPlugin<H> {
    plugin: BrokerPlugin,
    handler: H,
}

impl<H, F, E> InspectingPlugin<H>
where
    H: FnMut(Arc<AgentRequestContext>) -> F,
    F: Future<Output = Result<RequestDecision, E>>,
    E: std::fmt::Display,
{
    /// Runs an inspection-only connection.
    ///
    /// # Errors
    /// Returns transport, protocol, or handler errors and closes the connection.
    pub async fn run(self) -> Result<BrokerClose, BrokerPluginError> {
        self.run_session(
            None::<fn(AgentEvent) -> std::future::Ready<Result<(), std::convert::Infallible>>>,
        )
        .await
    }

    /// Runs inspection and independent event observation on the same connection.
    ///
    /// # Errors
    /// Returns transport, protocol, or handler errors and closes the connection.
    pub async fn run_with_events<A, G, D>(
        self,
        handler: A,
    ) -> Result<BrokerClose, BrokerPluginError>
    where
        A: FnMut(AgentEvent) -> G,
        G: Future<Output = Result<(), D>>,
        D: std::fmt::Display,
    {
        self.run_session(Some(handler)).await
    }

    async fn run_session<A, G, D>(
        mut self,
        mut events: Option<A>,
    ) -> Result<BrokerClose, BrokerPluginError>
    where
        A: FnMut(AgentEvent) -> G,
        G: Future<Output = Result<(), D>>,
        D: std::fmt::Display,
    {
        let mut capabilities = vec![PluginCapability::AgentRequest];
        if events.is_some() {
            capabilities.push(PluginCapability::AgentEvents);
        }
        let mut stream = self.plugin.connect_transport(capabilities).await?;
        loop {
            match read_stream_message(stream.as_mut().get_mut()).await? {
                BrokerMessage::InspectRequest { context } => {
                    let request_id = context.request_id.clone();
                    let decision = (self.handler)(context)
                        .await
                        .map_err(|error| BrokerPluginError::Handler(error.to_string()))?;
                    codec::write_json(
                        stream.as_mut().get_mut(),
                        &PluginMessage::InspectResponse(decision.into_response(request_id)),
                    )
                    .await?;
                }
                BrokerMessage::AgentEvent { event } => {
                    if let Some(handler) = events.as_mut() {
                        handler(Arc::try_unwrap(event).expect("decoded event has one owner"))
                            .await
                            .map_err(|error| BrokerPluginError::Handler(error.to_string()))?;
                    }
                }
                BrokerMessage::BrokerClose(close) => return Ok(close),
                _ => {
                    return Err(BrokerPluginError::Frame(
                        "unexpected session message".to_owned(),
                    ));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use abyss_plugin_protocol::{
        event::AgentEvent,
        message::{BrokerClose, BrokerCloseCode, BrokerHello, BrokerMessage, PluginHello},
    };
    use futures_util::StreamExt as _;
    use tokio::io::duplex;

    use super::BrokerPlugin;
    use crate::plugin::codec::{read_payload, write_json};

    #[cfg(unix)]
    fn handler_decisions() -> [crate::plugin::RequestDecision; 3] {
        use crate::plugin::{ModifyAction, RequestDecision};
        [
            RequestDecision::Allow,
            RequestDecision::Block("test policy".to_owned()),
            RequestDecision::Modify(Box::new([
                ModifyAction::SetAuthToken("allocated".to_owned()),
                ModifyAction::RemoveAuthToken,
                ModifyAction::SetModel("new".to_owned()),
                ModifyAction::RemoveModel,
            ])),
        ]
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn request_handler_uses_the_same_session_and_returns_a_correlated_decision() {
        let endpoint =
            std::env::temp_dir().join(format!("abyss-sdk-inspection-{}.sock", std::process::id()));
        let listener = tokio::net::UnixListener::bind(&endpoint).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let payload = read_payload(&mut stream).await.unwrap().unwrap();
            let message: abyss_plugin_protocol::message::PluginMessage =
                serde_json::from_slice(&payload).unwrap();
            let abyss_plugin_protocol::message::PluginMessage::PluginHello(hello) = message else {
                panic!("expected hello");
            };
            assert_eq!(
                hello.capabilities,
                vec![abyss_plugin_protocol::inspection::PluginCapability::AgentRequest]
            );
            write_json(&mut stream, &BrokerMessage::BrokerHello(BrokerHello::v2()))
                .await
                .unwrap();
            let request: BrokerMessage = serde_json::from_str(include_str!(
                "../../tests/fixtures/broker-plugin-protocol/v2/fixtures/inspect-request.json"
            ))
            .unwrap();
            for expected in handler_decisions() {
                write_json(&mut stream, &request).await.unwrap();
                let payload = read_payload(&mut stream).await.unwrap().unwrap();
                let reply: abyss_plugin_protocol::message::PluginMessage =
                    serde_json::from_slice(&payload).unwrap();
                let abyss_plugin_protocol::message::PluginMessage::InspectResponse(reply) = reply
                else {
                    panic!("expected decision");
                };
                assert_eq!(reply.request_id, "request-123");
                assert_eq!(reply.decision, expected);
            }
            write_json(
                &mut stream,
                &BrokerMessage::BrokerClose(BrokerClose::new(
                    BrokerCloseCode::BrokerShutdown,
                    "test complete",
                )),
            )
            .await
            .unwrap();
        });
        let mut decisions = handler_decisions().into_iter();
        let close = BrokerPlugin::new("sdk-inspector")
            .with_endpoint(endpoint.to_string_lossy())
            .on_agent_request(move |context| {
                assert_eq!(
                    context.agent.as_ref().unwrap().model.as_deref(),
                    Some("gpt-test")
                );
                let decision = decisions.next().unwrap();
                async move { Ok::<_, std::convert::Infallible>(decision) }
            })
            .run()
            .await
            .unwrap();
        assert_eq!(close.code, 100);
        server.await.unwrap();
        tokio::fs::remove_file(endpoint).await.unwrap();
    }

    #[tokio::test]
    async fn performs_handshake_and_exposes_agent_events_as_a_stream() {
        let (client, mut server) = duplex(32 * 1024);
        let server_task = tokio::spawn(async move {
            let hello: PluginHello = read_json(&mut server).await;
            assert_eq!(hello.plugin_id, "sdk-test-plugin");
            assert_eq!(hello.protocol_version.wire_value(), 2_u16);
            write_json(&mut server, &BrokerMessage::BrokerHello(BrokerHello::v2()))
                .await
                .expect("BrokerHello should write");
            let event: AgentEvent = serde_json::from_str(include_str!(
                "../../tests/fixtures/broker-plugin-protocol/v2/fixtures/agent-event.json"
            ))
            .expect("published AgentEvent fixture should decode");
            write_json(
                &mut server,
                &BrokerMessage::AgentEvent {
                    event: std::sync::Arc::new(event),
                },
            )
            .await
            .expect("AgentEvent should write");
            write_json(
                &mut server,
                &BrokerMessage::BrokerClose(BrokerClose::new(
                    BrokerCloseCode::BrokerShutdown,
                    "test complete",
                )),
            )
            .await
            .expect("BrokerClose should write");
        });
        let plugin = BrokerPlugin::new("sdk-test-plugin");

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
        {
            let message: abyss_plugin_protocol::message::PluginMessage =
                serde_json::from_slice(&payload).unwrap();
            let abyss_plugin_protocol::message::PluginMessage::PluginHello(hello) = message else {
                panic!("expected plugin hello");
            };
            serde_json::from_value(serde_json::to_value(hello).unwrap()).unwrap()
        }
    }
}
