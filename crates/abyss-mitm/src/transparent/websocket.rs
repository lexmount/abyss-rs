//! WebSocket message relay for upgraded transparent HTTP/1 flows.
//!
//! Once a request receives `101 Switching Protocols`, HTTP body framing no
//! longer applies. This module switches the two plaintext streams into
//! WebSocket message streams, forwards each message, and submits observe-only
//! hook events without blocking network forwarding.

use std::io::ErrorKind;

use futures_util::{SinkExt as _, StreamExt as _};
use http::Request;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{
        Error as WebSocketError, Message,
        protocol::{Role, WebSocketConfig},
    },
};

use super::{
    FlowContext, FlowOperation, TransparentFlowError, WebSocketDirection, WebSocketMessage,
    hook::HookDispatcher,
};

/// Payload byte counts forwarded after the HTTP 101 upgrade.
#[derive(Debug, Clone, Default)]
pub(super) struct WebSocketRelayOutcome {
    /// WebSocket payload bytes sent from client to upstream.
    pub(super) client_to_upstream_bytes: u64,
    /// WebSocket payload bytes sent from upstream back to the client.
    pub(super) upstream_to_client_bytes: u64,
}

struct DecodedWebSocketStream<S> {
    stream: WebSocketStream<S>,
    direction: WebSocketDirection,
}

struct ForwardedWebSocketMessage {
    direction: WebSocketDirection,
    message: Message,
    payload_bytes: u64,
    is_close: bool,
}

impl ForwardedWebSocketMessage {
    fn submit_hook_message(
        &self,
        flow: &FlowContext,
        upgrade_request: &Request<()>,
        sequence: &mut u64,
        hooks: &HookDispatcher,
    ) -> Result<(), TransparentFlowError> {
        let Some(hook_message) = hook_message_from_websocket(
            flow,
            upgrade_request,
            self.direction,
            next_sequence(sequence)?,
            &self.message,
        ) else {
            return Ok(());
        };
        hooks.submit_websocket_message(hook_message);
        Ok(())
    }
}

impl<S> DecodedWebSocketStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    async fn from_partially_read(
        stream: S,
        prefetch: Vec<u8>,
        role: Role,
        direction: WebSocketDirection,
    ) -> Self {
        Self {
            stream: WebSocketStream::from_partially_read(
                stream,
                prefetch,
                role,
                Some(WebSocketConfig::default()),
            )
            .await,
            direction,
        }
    }

    async fn next_forwarded_message(
        &mut self,
        operation: FlowOperation,
    ) -> Result<Option<ForwardedWebSocketMessage>, TransparentFlowError> {
        let Some(message) = self.stream.next().await else {
            return Ok(None);
        };
        let message = match message {
            Ok(message) => message,
            Err(source) if is_agent_stream_end(self.direction, &source) => {
                tracing::debug!(
                    direction = ?self.direction,
                    error = %source,
                    "Agent WebSocket stream ended without a close frame"
                );
                return Ok(None);
            }
            Err(source) => return Err(TransparentFlowError::websocket(operation, source)),
        };
        let payload_bytes = payload_len(&message)?;
        let is_close = message.is_close();
        Ok(Some(ForwardedWebSocketMessage {
            direction: self.direction,
            message,
            payload_bytes,
            is_close,
        }))
    }

    async fn send(
        &mut self,
        message: Message,
        operation: FlowOperation,
    ) -> Result<(), TransparentFlowError> {
        self.stream
            .send(message)
            .await
            .map_err(|source| TransparentFlowError::websocket(operation, source))?;
        Ok(())
    }
}

/// Returns whether an Agent-side transport error only means the local Agent
/// stopped using the upgraded connection.
fn is_agent_stream_end(direction: WebSocketDirection, error: &WebSocketError) -> bool {
    if direction != WebSocketDirection::ClientToServer {
        return false;
    }

    match error {
        WebSocketError::ConnectionClosed => true,
        WebSocketError::Io(source) => matches!(
            source.kind(),
            ErrorKind::BrokenPipe
                | ErrorKind::ConnectionAborted
                | ErrorKind::ConnectionReset
                | ErrorKind::NotConnected
                | ErrorKind::UnexpectedEof
        ),
        _ => false,
    }
}

/// Relays one upgraded WebSocket tunnel until either endpoint closes.
///
/// `client_prefetch` and `upstream_prefetch` contain bytes already consumed by
/// the HTTP/1 head decoders after the `\r\n\r\n` terminator. Passing those bytes
/// into `from_partially_read` preserves frames that arrive in the same read as
/// the upgrade head.
#[tracing::instrument(level = "trace", skip_all)]
pub(super) async fn relay_websocket_messages<C, U>(
    client: C,
    client_prefetch: Vec<u8>,
    upstream: U,
    upstream_prefetch: Vec<u8>,
    flow: FlowContext,
    upgrade_request: Request<()>,
    hooks: &HookDispatcher,
) -> Result<WebSocketRelayOutcome, TransparentFlowError>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let mut client_ws = DecodedWebSocketStream::from_partially_read(
        client,
        client_prefetch,
        Role::Server,
        WebSocketDirection::ClientToServer,
    )
    .await;
    let mut upstream_ws = DecodedWebSocketStream::from_partially_read(
        upstream,
        upstream_prefetch,
        Role::Client,
        WebSocketDirection::ServerToClient,
    )
    .await;
    let outcome = run_websocket_select_loop(
        &mut client_ws,
        &mut upstream_ws,
        &flow,
        &upgrade_request,
        hooks,
    )
    .await?;
    tracing::info!(
        original_destination = %flow.original_destination,
        method = %upgrade_request.method(),
        target_path = %upgrade_request.uri().path(),
        client_to_upstream_bytes = outcome.client_to_upstream_bytes,
        upstream_to_client_bytes = outcome.upstream_to_client_bytes,
        "MITM transparent WebSocket message relay closed"
    );
    Ok(outcome)
}

#[expect(
    clippy::integer_division_remainder_used,
    reason = "tokio::select! macro expansion uses remainder internally; relay code does not."
)]
#[tracing::instrument(level = "trace", skip_all)]
async fn run_websocket_select_loop<C, U>(
    client_ws: &mut DecodedWebSocketStream<C>,
    upstream_ws: &mut DecodedWebSocketStream<U>,
    flow: &FlowContext,
    upgrade_request: &Request<()>,
    hooks: &HookDispatcher,
) -> Result<WebSocketRelayOutcome, TransparentFlowError>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let mut sequence = 0_u64;
    let mut outcome = WebSocketRelayOutcome::default();

    loop {
        tokio::select! {
            client_message = client_ws.next_forwarded_message(FlowOperation::ReadAgentWebSocket) => {
                let Some(forwarded) = client_message? else {
                    break;
                };
                forwarded.submit_hook_message(flow, upgrade_request, &mut sequence, hooks)?;
                upstream_ws
                    .send(forwarded.message, FlowOperation::WriteProviderWebSocket)
                    .await?;
                outcome.client_to_upstream_bytes = add_bytes(
                    outcome.client_to_upstream_bytes,
                    forwarded.payload_bytes,
                )?;
                if forwarded.is_close {
                    break;
                }
            }
            upstream_message = upstream_ws.next_forwarded_message(FlowOperation::ReadProviderWebSocket) => {
                let Some(forwarded) = upstream_message? else {
                    break;
                };
                forwarded.submit_hook_message(flow, upgrade_request, &mut sequence, hooks)?;
                client_ws
                    .send(forwarded.message, FlowOperation::WriteAgentWebSocket)
                    .await?;
                outcome.upstream_to_client_bytes = add_bytes(
                    outcome.upstream_to_client_bytes,
                    forwarded.payload_bytes,
                )?;
                if forwarded.is_close {
                    break;
                }
            }
        }
    }

    Ok(outcome)
}

fn hook_message_from_websocket(
    flow: &FlowContext,
    upgrade_request: &Request<()>,
    direction: WebSocketDirection,
    sequence: u64,
    message: &Message,
) -> Option<WebSocketMessage> {
    match message {
        Message::Text(text) => Some(WebSocketMessage {
            flow: flow.clone(),
            upgrade_request: upgrade_request.clone(),
            direction,
            sequence,
            text: Some(text.to_string()),
            binary: None,
        }),
        Message::Binary(bytes) => Some(WebSocketMessage {
            flow: flow.clone(),
            upgrade_request: upgrade_request.clone(),
            direction,
            sequence,
            text: None,
            binary: Some(bytes.clone()),
        }),
        Message::Ping(_) | Message::Pong(_) | Message::Close(_) | Message::Frame(_) => None,
    }
}

fn next_sequence(sequence: &mut u64) -> Result<u64, TransparentFlowError> {
    *sequence = sequence
        .checked_add(1)
        .ok_or(TransparentFlowError::ByteCountOverflow)?;
    Ok(*sequence)
}

fn payload_len(message: &Message) -> Result<u64, TransparentFlowError> {
    u64::try_from(message.len()).map_err(|_error| TransparentFlowError::ByteCountOverflow)
}

fn add_bytes(left: u64, right: u64) -> Result<u64, TransparentFlowError> {
    left.checked_add(right)
        .ok_or(TransparentFlowError::ByteCountOverflow)
}

#[cfg(test)]
mod tests {
    use std::{io, net::SocketAddr};

    use tokio_tungstenite::tungstenite::{Error as WebSocketError, Message};

    use super::{WebSocketDirection, hook_message_from_websocket, is_agent_stream_end};
    use crate::transparent::{FlowContext, OriginalDestination, TransparentProtocol};

    #[test]
    fn text_message_becomes_hook_message() {
        let message = hook_message_from_websocket(
            &test_flow(),
            &test_upgrade_request(),
            WebSocketDirection::ClientToServer,
            1,
            &Message::text("{\"ok\":true}"),
        )
        .expect("text websocket message should be exposed to hooks");

        assert_eq!(message.sequence, 1);
        assert_eq!(message.text.as_deref(), Some("{\"ok\":true}"));
        assert!(
            message.binary.is_none(),
            "text messages should not expose binary bytes"
        );
    }

    #[test]
    fn ping_message_is_not_hooked() {
        assert!(
            hook_message_from_websocket(
                &test_flow(),
                &test_upgrade_request(),
                WebSocketDirection::ServerToClient,
                1,
                &Message::Ping(Vec::new().into()),
            )
            .is_none(),
            "control frames should be forwarded but not audited as payload messages"
        );
    }

    #[test]
    fn agent_transport_eof_ends_relay_without_a_network_error() {
        let error = WebSocketError::Io(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "peer closed without TLS close_notify",
        ));

        assert!(is_agent_stream_end(
            WebSocketDirection::ClientToServer,
            &error
        ));
        assert!(!is_agent_stream_end(
            WebSocketDirection::ServerToClient,
            &error
        ));

        let wrapped = crate::transparent::TransparentFlowError::websocket(
            crate::transparent::FlowOperation::ReadAgentWebSocket,
            WebSocketError::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "peer closed without TLS close_notify",
            )),
        );
        assert!(wrapped.is_agent_connection_close());
    }

    #[test]
    fn websocket_protocol_errors_are_not_treated_as_agent_shutdown() {
        let error = WebSocketError::Protocol(
            tokio_tungstenite::tungstenite::error::ProtocolError::ResetWithoutClosingHandshake,
        );

        assert!(!is_agent_stream_end(
            WebSocketDirection::ClientToServer,
            &error
        ));
    }

    fn test_flow() -> FlowContext {
        FlowContext::new(
            SocketAddr::from(([127, 0, 0, 1], 50000)),
            SocketAddr::from(([127, 0, 0, 1], 18090)),
            OriginalDestination::from(SocketAddr::from(([34, 117, 59, 81], 443))),
            TransparentProtocol::TlsHttp {
                server_name: "chatgpt.com".to_owned(),
            },
        )
    }

    fn test_upgrade_request() -> http::Request<()> {
        http::Request::builder()
            .method("GET")
            .uri("/backend-api/codex/responses")
            .body(())
            .expect("test upgrade request should build")
    }
}
