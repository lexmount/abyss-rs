//! WebSocket message relay for upgraded transparent HTTP/1 flows.
//!
//! Once a request receives `101 Switching Protocols`, HTTP body framing no
//! longer applies. This module switches the two plaintext streams into
//! WebSocket message streams, applies optional request decisions, and submits
//! observation events only for messages allowed to proceed.

use std::io::ErrorKind;

use futures_util::{SinkExt as _, StreamExt as _};
use http::{Request, Response};
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

/// HTTP handshake that opened one WebSocket tunnel, attached to every message.
pub(super) struct WebSocketUpgrade {
    /// Agent request that asked for the upgrade.
    pub(super) request: Request<()>,
    /// Upstream `101 Switching Protocols` response that accepted it.
    pub(super) response: Response<()>,
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
    captured_body: Option<super::CapturedBody>,
}

impl ForwardedWebSocketMessage {
    fn submit_hook_message(
        &mut self,
        flow: &FlowContext,
        upgrade: &WebSocketUpgrade,
        sequence: &mut u64,
        hooks: &HookDispatcher,
    ) -> Result<(), TransparentFlowError> {
        let Some(mut hook_message) = hook_message_from_websocket(
            flow,
            upgrade,
            self.direction,
            next_sequence(sequence)?,
            &self.message,
        ) else {
            return Ok(());
        };
        hook_message.captured_body = self.captured_body.take();
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
            captured_body: None,
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

    async fn reject(
        &mut self,
        rejection: &super::LocalRejection,
    ) -> Result<(), TransparentFlowError> {
        use tokio_tungstenite::tungstenite::protocol::{CloseFrame, frame::coding::CloseCode};

        let code = match rejection.code {
            "agent_request_blocked" => CloseCode::Policy,
            "inspection_body_too_large" => CloseCode::Size,
            _ => CloseCode::Error,
        };
        let reason = format!(
            "abyss-broker: {} {}: {}",
            rejection.code, rejection.request_id, rejection.reason
        );
        let end = reason.floor_char_boundary(123);
        self.send(
            Message::Close(Some(CloseFrame {
                code,
                reason: reason[..end].to_owned().into(),
            })),
            FlowOperation::WriteAgentWebSocket,
        )
        .await
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
pub(super) async fn relay_websocket_messages<C, U, F: super::RequestForwardingControl>(
    (client, client_prefetch): (C, Vec<u8>),
    (upstream, upstream_prefetch): (U, Vec<u8>),
    flow: FlowContext,
    upgrade: WebSocketUpgrade,
    hooks: &HookDispatcher,
    control: &F,
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
        &upgrade,
        hooks,
        control,
    )
    .await?;
    tracing::info!(
        original_destination = %flow.original_destination,
        method = %upgrade.request.method(),
        target_path = %upgrade.request.uri().path(),
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
async fn run_websocket_select_loop<C, U, F: super::RequestForwardingControl>(
    client_ws: &mut DecodedWebSocketStream<C>,
    upstream_ws: &mut DecodedWebSocketStream<U>,
    flow: &FlowContext,
    upgrade: &WebSocketUpgrade,
    hooks: &HookDispatcher,
    control: &F,
) -> Result<WebSocketRelayOutcome, TransparentFlowError>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let mut sequence = 0_u64;
    let mut client_sequence = 0_u64;
    let mut outcome = WebSocketRelayOutcome::default();

    loop {
        tokio::select! {
            client_message = client_ws.next_forwarded_message(FlowOperation::ReadAgentWebSocket) => {
                // Reassembly already uses tungstenite's bounded message/frame limits
                // for both modes. Inspection never sends an oversized prefix to a plugin.
                if matches!(&client_message, Err(TransparentFlowError::WebSocket { source: WebSocketError::Capacity(_), .. }))
                    && control.plan().is_some()
                {
                    let rejection = super::LocalRejection::new(http::StatusCode::PAYLOAD_TOO_LARGE,
                        "inspection_body_too_large", "WebSocket message exceeds the relay limit", flow.flow_id.to_string());
                    client_ws.reject(&rejection).await?;
                    return Err(rejection.into());
                }
                let Some(mut forwarded) = client_message? else {
                    break;
                };
                let transport = match &forwarded.message {
                    Message::Text(_) => Some(super::RequestTransport::WebSocketText { sequence: next_sequence(&mut client_sequence)? }),
                    Message::Binary(_) => Some(super::RequestTransport::WebSocketBinary { sequence: next_sequence(&mut client_sequence)? }),
                    _ => None,
                };
                if let Some(transport) = transport && let Some(plan) = control.plan() {
                    let mut body = super::CapturedBody::from_bytes(forwarded.message.clone().into_data());
                    let result = {
                    let decision = control.before_forward(plan, super::RequestView { flow, head: &upgrade.request, body: &body, transport, max_body_bytes: WebSocketConfig::default().max_message_size.unwrap_or(usize::MAX) });
                    tokio::pin!(decision);
                    loop {
                        tokio::select! {
                            result = &mut decision => {
                                match result {
                                    Ok(result) => break result,
                                    Err(rejection) => {
                                        client_ws.reject(&rejection).await?;
                                        return Err(rejection.into());
                                    }
                                }
                            }
                            message = upstream_ws.next_forwarded_message(FlowOperation::ReadProviderWebSocket) => {
                                if !forward_provider_message(message?, client_ws, flow, upgrade, &mut sequence, hooks, &mut outcome).await? {
                                    return Ok(outcome);
                                }
                            }
                        }
                    }
                    };
                    if let Some(replacement) = result.body {
                        forwarded.message = match transport {
                            super::RequestTransport::WebSocketText { .. } => {
                                let text = String::from_utf8(replacement.bytes().to_vec()).map_err(|_| {
                                    super::LocalRejection::new(http::StatusCode::BAD_GATEWAY,
                                        "invalid_agent_request_edit", "Edited text is not UTF-8", flow.flow_id.to_string())
                                })?;
                                Message::Text(text.into())
                            }
                            _ => Message::Binary(replacement.bytes_ref().clone()),
                        };
                        forwarded.payload_bytes = payload_len(&forwarded.message)?;
                        body = replacement;
                    }
                    body.extensions_mut().extend(result.annotations);
                    forwarded.captured_body = Some(body);
                }
                forwarded.submit_hook_message(flow, upgrade, &mut sequence, hooks)?;
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
                if !forward_provider_message(upstream_message?, client_ws, flow, upgrade, &mut sequence, hooks, &mut outcome).await? {
                    break;
                }
            }
        }
    }

    Ok(outcome)
}

async fn forward_provider_message<C: AsyncRead + AsyncWrite + Unpin>(
    message: Option<ForwardedWebSocketMessage>,
    client: &mut DecodedWebSocketStream<C>,
    flow: &FlowContext,
    upgrade: &WebSocketUpgrade,
    sequence: &mut u64,
    hooks: &HookDispatcher,
    outcome: &mut WebSocketRelayOutcome,
) -> Result<bool, TransparentFlowError> {
    let Some(mut forwarded) = message else {
        return Ok(false);
    };
    forwarded.submit_hook_message(flow, upgrade, sequence, hooks)?;
    client
        .send(forwarded.message, FlowOperation::WriteAgentWebSocket)
        .await?;
    outcome.upstream_to_client_bytes =
        add_bytes(outcome.upstream_to_client_bytes, forwarded.payload_bytes)?;
    Ok(!forwarded.is_close)
}

fn hook_message_from_websocket(
    flow: &FlowContext,
    upgrade: &WebSocketUpgrade,
    direction: WebSocketDirection,
    sequence: u64,
    message: &Message,
) -> Option<WebSocketMessage> {
    match message {
        Message::Text(text) => Some(WebSocketMessage {
            captured_body: None,
            flow: flow.clone(),
            upgrade_request: upgrade.request.clone(),
            upgrade_response: upgrade.response.clone(),
            direction,
            sequence,
            text: Some(text.to_string()),
            binary: None,
        }),
        Message::Binary(bytes) => Some(WebSocketMessage {
            captured_body: None,
            flow: flow.clone(),
            upgrade_request: upgrade.request.clone(),
            upgrade_response: upgrade.response.clone(),
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

    use super::{
        WebSocketDirection, WebSocketUpgrade, hook_message_from_websocket, is_agent_stream_end,
    };
    use crate::transparent::{FlowContext, OriginalDestination, TransparentProtocol};

    #[test]
    fn text_message_becomes_hook_message() {
        let message = hook_message_from_websocket(
            &test_flow(),
            &test_upgrade(),
            WebSocketDirection::ClientToServer,
            1,
            &Message::text("{\"ok\":true}"),
        )
        .expect("text websocket message should be exposed to hooks");

        assert_eq!(message.sequence, 1);
        assert_eq!(message.text.as_deref(), Some("{\"ok\":true}"));
        assert_eq!(message.upgrade_response.status(), 101);
        assert_eq!(
            message.upgrade_response.headers()["x-request-id"],
            "req-upgrade"
        );
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
                &test_upgrade(),
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

    fn test_upgrade() -> WebSocketUpgrade {
        WebSocketUpgrade {
            request: http::Request::builder()
                .method("GET")
                .uri("/backend-api/codex/responses")
                .body(())
                .expect("test upgrade request should build"),
            response: http::Response::builder()
                .status(101)
                .header("x-request-id", "req-upgrade")
                .body(())
                .expect("test upgrade response should build"),
        }
    }
}
