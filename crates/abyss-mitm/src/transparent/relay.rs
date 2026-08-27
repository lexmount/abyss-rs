//! HTTP/1 exchange capture and relay.
//!
//! This module converts a transparent byte stream into one complete HTTP/1
//! exchange for hooks while still forwarding bytes to the original upstream and
//! back to the client.
//!
//! Relay owns the first decoded request head plus any bytes already read after
//! the head terminator. Those buffered bytes are part of the client stream and
//! must be forwarded before reading more data from the socket. Regular HTTP
//! flows forward one request and one response. WebSocket upgrade flows first
//! relay the HTTP 101 handshake, then hand the remaining streams and prefetch
//! buffers to the WebSocket message relay.
//!
//! The current implementation captures the first request/response pair only;
//! persistent HTTP/1 connection multiplexing can be layered in once the
//! exchange hook model is stable.
//!
//! Capture limits are intentionally one-way: they protect hook/audit memory,
//! but they must never truncate bytes being relayed between the real client and
//! upstream. If a body grows beyond `max_body_bytes`, this module keeps only the
//! captured prefix for hooks and continues forwarding the full HTTP message on
//! the wire.

use std::borrow::Cow;

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::http1::{
    Http1ClientStream, Http1Error, Http1HeadBuffer, Http1UpstreamStream, MAX_HTTP1_HEADER_BYTES,
};

use super::{
    CapturedBody, FlowContext, FlowOperation, HttpExchange, MitmTimeouts, TransparentFlowError,
    TransparentProtocol,
    hook::HookDispatcher,
    utils::{
        content_length, has_expect_continue, http_request_head_without_relay_headers, is_chunked,
        is_websocket_upgrade_request, should_strip_accept_encoding, status_has_no_body,
        websocket_request_head_bytes,
    },
    websocket::{WebSocketRelayOutcome, relay_websocket_messages},
};

/// Bounded scratch buffer used while streaming HTTP bodies.
///
/// This is intentionally independent from the configured capture limit:
/// `max_body_bytes` controls how much decoded body data hooks may retain, while
/// this constant controls the size of each socket read/write step.
const RELAY_CHUNK_BYTES: usize = 16 * 1024;

/// Maximum allocation made from an untrusted Content-Length before bytes arrive.
///
/// A caller may intentionally configure an unbounded retention limit. A
/// peer-controlled Content-Length must still not trigger an equally unbounded
/// eager allocation; the vector can grow incrementally as the body is relayed.
const MAX_INITIAL_BODY_CAPTURE_CAPACITY: usize = 1024 * 1024;

/// Interim response used when the proxy handles `Expect: 100-continue` locally.
const HTTP1_100_CONTINUE: &[u8] = b"HTTP/1.1 100 Continue\r\n\r\n";

/// Client-side HTTP/1 flow after the first request head has been decoded.
///
/// The type deliberately keeps the original stream and the parsed request head
/// together. Once relay starts, every branch must preserve the bytes already
/// captured in `request_head_buffer`; losing them would corrupt request bodies
/// or early WebSocket frames that arrived with the head.
pub(super) struct DecodedClientFlow<S> {
    /// Client-side stream after any required TLS termination.
    stream: S,
    /// Stable metadata attached to the hook event produced by this flow.
    context: FlowContext,
    /// Structured HTTP request head decoded before opening the relay.
    pub(super) first_request: Request<()>,
    /// Exact bytes consumed while decoding the request head.
    ///
    /// The buffer may also contain early body bytes from the same read. Relay
    /// code must forward both the head and the buffered body bytes so the
    /// upstream observes exactly what the client sent.
    request_head_buffer: Http1HeadBuffer,
}

pub(super) struct RelayOutcome {
    /// Protocol label used by logging and hook consumers.
    pub(super) protocol: TransparentProtocol,
    /// First request exposed to hooks, with the captured decoded body.
    pub(super) first_request: Request<CapturedBody>,
    /// First response exposed to hooks, with the captured decoded body.
    pub(super) first_response: Response<CapturedBody>,
    /// Wire bytes forwarded from the client side into upstream.
    pub(super) client_to_upstream_bytes: u64,
    /// Wire bytes forwarded from upstream back to the client.
    pub(super) upstream_to_client_bytes: u64,
}

impl<S> DecodedClientFlow<S>
where
    S: AsyncRead + Unpin,
{
    #[tracing::instrument(level = "trace", skip_all)]
    pub(super) async fn from_http1(
        stream: S,
        context: FlowContext,
        timeouts: MitmTimeouts,
    ) -> Result<Self, TransparentFlowError> {
        // Decode only the first request head here. Body bytes are intentionally
        // left in `Http1HeadBuffer` so relay can forward and capture them using
        // the message framing rules.
        let decoded = Http1ClientStream::new(stream)
            .decode_request_head_with_timeout(timeouts.http1_request_head)
            .await
            .map_err(|source| {
                TransparentFlowError::http1(FlowOperation::ReadAgentRequestHead, source)
            })?;
        let (stream, first_request, request_head_buffer) = decoded.into_parts();
        context.validate_http_target(&first_request)?;
        Ok(Self {
            stream,
            context,
            first_request,
            request_head_buffer,
        })
    }
}

impl<S> DecodedClientFlow<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    #[tracing::instrument(level = "trace", skip_all)]
    pub(super) async fn relay_to<U>(
        self,
        upstream: U,
        hooks: &HookDispatcher,
        timeouts: MitmTimeouts,
        max_body_bytes: usize,
    ) -> Result<RelayOutcome, TransparentFlowError>
    where
        U: AsyncRead + AsyncWrite + Unpin + Send,
    {
        // Keep the top-level relay as a protocol dispatcher. All details about
        // body framing, downgrade handling, and WebSocket stream construction
        // live behind the branch-specific helpers.
        if is_websocket_upgrade_request(&self.first_request) {
            return self
                .relay_websocket_to(upstream, hooks, timeouts, max_body_bytes)
                .await;
        }

        self.relay_plain_http_to(upstream, hooks, timeouts, max_body_bytes)
            .await
    }

    #[tracing::instrument(level = "trace", skip_all)]
    async fn relay_plain_http_to<U>(
        mut self,
        mut upstream: U,
        hooks: &HookDispatcher,
        timeouts: MitmTimeouts,
        max_body_bytes: usize,
    ) -> Result<RelayOutcome, TransparentFlowError>
    where
        U: AsyncRead + AsyncWrite + Unpin + Send,
    {
        // The normal HTTP path is a single exchange:
        // client request -> upstream response -> captured hook event.
        //
        // `forward_http_response_and_submit` is also used by WebSocket upgrade
        // attempts whose upstream response is not 101, because those responses
        // are ordinary HTTP responses with ordinary body framing.
        // Forward the request first because the upstream cannot produce a
        // response until it receives the client's complete first request. The
        // helper mirrors bytes to upstream and captures the decoded body for
        // the eventual hook event.
        let request_capture =
            Box::pin(self.forward_http_request_to(&mut upstream, max_body_bytes)).await?;

        let response = decode_response_from_upstream(upstream, timeouts).await?;
        self.forward_http_response_and_submit(
            response,
            request_capture,
            hooks,
            max_body_bytes,
            CapturedExchangeLog::Http1,
        )
        .await
    }

    #[tracing::instrument(level = "trace", skip_all)]
    async fn forward_http_request_to<U>(
        &mut self,
        upstream: &mut U,
        max_body_bytes: usize,
    ) -> Result<MessageCapture, TransparentFlowError>
    where
        U: AsyncWrite + Unpin + Send,
    {
        // This method exists so the high-level flow does not need to know the
        // exact HTTP body framing rules. `forward_request` owns the byte-level
        // preservation and capture logic.
        forward_request(
            &mut self.stream,
            upstream,
            &self.first_request,
            &self.request_head_buffer,
            &self.context,
            max_body_bytes,
        )
        .await
    }

    #[tracing::instrument(level = "trace", skip_all)]
    async fn forward_http_response_and_submit<U>(
        mut self,
        response: DecodedUpstreamResponse<U>,
        request_capture: MessageCapture,
        hooks: &HookDispatcher,
        max_body_bytes: usize,
        log_kind: CapturedExchangeLog,
    ) -> Result<RelayOutcome, TransparentFlowError>
    where
        U: AsyncRead + Unpin + Send,
    {
        // Shared completion path for any first exchange that remains HTTP/1.
        // This covers regular HTTP and WebSocket upgrade attempts that did not
        // receive a 101 Switching Protocols response.
        let DecodedUpstreamResponse {
            mut stream,
            head,
            head_buffer,
        } = response;
        let response_capture = Box::pin(forward_response(
            &mut stream,
            &mut self.stream,
            &self.first_request,
            &head,
            &head_buffer,
            max_body_bytes,
        ))
        .await?;
        // For macOS transparent flows this client stream is backed by
        // `FramedFlowIo`, not a plain socket. Its `shutdown()` implementation
        // serializes a protocol-level FlowClose frame before closing the Unix
        // socket to the Network Extension.
        //
        // Do not rely on dropping `self.stream` here. A drop can surface as a
        // raw socket EOF on the Swift bridge while it still has a partial frame
        // buffered, which is reported as `unexpectedEOF` and can make Codex
        // report that the response body could not be decoded. `forward_response`
        // only returns after the HTTP/1 response body has been fully relayed, so
        // this is the earliest point where closing the client side is both
        // correct and framed-protocol safe.
        shutdown_completed_agent_stream(&mut self.stream).await?;

        Ok(submit_captured_exchange(
            self.context,
            self.first_request,
            head,
            request_capture,
            response_capture,
            hooks,
            log_kind,
        ))
    }

    #[tracing::instrument(level = "trace", skip_all)]
    async fn relay_websocket_to<U>(
        self,
        mut upstream: U,
        hooks: &HookDispatcher,
        timeouts: MitmTimeouts,
        max_body_bytes: usize,
    ) -> Result<RelayOutcome, TransparentFlowError>
    where
        U: AsyncRead + AsyncWrite + Unpin + Send,
    {
        // A WebSocket attempt still starts as HTTP/1. Only after upstream
        // returns 101 may both streams be interpreted as WebSocket frame
        // streams.
        let request_head = websocket_request_head_bytes(&self.first_request).map_err(|source| {
            TransparentFlowError::http1(FlowOperation::ReadAgentRequestHead, source)
        })?;
        let request_head_bytes =
            forward_websocket_request_head(&mut upstream, &request_head).await?;
        let response = decode_response_from_upstream(upstream, timeouts).await?;

        if response.head.status() != StatusCode::SWITCHING_PROTOCOLS {
            // Upstream declined the upgrade. The request we forwarded has no
            // HTTP body, but the response may have one, so reuse the normal
            // HTTP response path instead of switching protocols locally.
            return self
                .forward_http_response_and_submit(
                    response,
                    empty_message_capture(request_head_bytes),
                    hooks,
                    max_body_bytes,
                    CapturedExchangeLog::Http1,
                )
                .await;
        }

        let upgrade = self
            .forward_websocket_success(response, request_head_bytes, hooks)
            .await?;
        let ForwardedWebSocketUpgrade {
            client_stream,
            client_prefetch,
            upstream_stream,
            upstream_prefetch,
            context,
            request_head,
            outcome: upgrade_outcome,
        } = upgrade;

        // From this point on the HTTP handshake is complete. WebSocket message
        // relay owns both streams until either endpoint closes.
        let websocket_outcome = relay_websocket_messages(
            client_stream,
            client_prefetch,
            upstream_stream,
            upstream_prefetch,
            context,
            request_head,
            hooks,
        )
        .await?;

        combine_websocket_outcomes(upgrade_outcome, &websocket_outcome)
    }

    async fn forward_websocket_success<U>(
        mut self,
        response: DecodedUpstreamResponse<U>,
        request_head_bytes: u64,
        hooks: &HookDispatcher,
    ) -> Result<ForwardedWebSocketUpgrade<S, U>, TransparentFlowError>
    where
        U: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let DecodedUpstreamResponse {
            stream: upstream,
            head: response_head,
            head_buffer: response_head_buffer,
        } = response;

        // This helper only forwards the successful 101 head and records the
        // upgrade exchange. It deliberately does not enter the WebSocket
        // message loop; `relay_websocket_to` keeps that state transition
        // visible at the orchestration level.
        self.stream
            .write_all(response_head_buffer.head_bytes())
            .await
            .map_err(|source| TransparentFlowError::Io {
                operation: FlowOperation::WriteAgentResponseHead,
                source,
            })?;

        let upgrade_request = self.first_request.clone();
        let response_head_bytes = usize_to_u64(response_head_buffer.head_bytes().len())?;
        let upgrade_outcome = submit_captured_exchange(
            self.context.clone(),
            self.first_request,
            response_head,
            empty_message_capture(request_head_bytes),
            empty_message_capture(response_head_bytes),
            hooks,
            CapturedExchangeLog::WebSocketUpgrade,
        );

        Ok(ForwardedWebSocketUpgrade {
            client_stream: self.stream,
            client_prefetch: self.request_head_buffer.buffered_body().to_vec(),
            upstream_stream: upstream,
            upstream_prefetch: response_head_buffer.buffered_body().to_vec(),
            context: self.context,
            request_head: upgrade_request,
            outcome: upgrade_outcome,
        })
    }
}

/// Best-effort closes an Agent stream after its complete HTTP response has
/// already been forwarded.
///
/// At this point a peer-close error is lifecycle cleanup, not a failed network
/// exchange. The shutdown attempt is still required for framed platform flows
/// because it emits their protocol-level close frame when the peer remains.
async fn shutdown_completed_agent_stream<S>(stream: &mut S) -> Result<(), TransparentFlowError>
where
    S: AsyncWrite + Unpin,
{
    if let Err(source) = stream.shutdown().await {
        let error = TransparentFlowError::Io {
            operation: FlowOperation::ShutdownAgent,
            source,
        };
        if !error.is_agent_connection_close() {
            return Err(error);
        }
        tracing::debug!(
            %error,
            "Agent stream was already closed after the complete HTTP response"
        );
    }
    Ok(())
}

/// Upstream stream after its first response head has been decoded.
///
/// `head_buffer` preserves both the exact response head bytes and any response
/// body bytes already read by the decoder. The stream is returned with those
/// bytes removed from the socket, so callers must pass the buffered body into
/// the next forwarding stage.
struct DecodedUpstreamResponse<S> {
    /// Upstream stream positioned after the bytes held by `head_buffer`.
    stream: S,
    /// Structured response metadata for hooks and framing decisions.
    head: Response<()>,
    /// Exact wire bytes consumed while decoding the response head.
    head_buffer: Http1HeadBuffer,
}

/// Handshake state produced after forwarding a successful WebSocket upgrade.
///
/// The HTTP 101 response has already been sent to the client and submitted as
/// the first exchange. The contained streams and prefetch buffers are ready to
/// be passed to the WebSocket frame relay.
struct ForwardedWebSocketUpgrade<C, U> {
    /// Client stream after the HTTP upgrade response head was written.
    client_stream: C,
    /// Client bytes read while decoding the request head after `\r\n\r\n`.
    client_prefetch: Vec<u8>,
    /// Upstream stream after the HTTP upgrade response head was decoded.
    upstream_stream: U,
    /// Upstream bytes read while decoding the response head after `\r\n\r\n`.
    upstream_prefetch: Vec<u8>,
    /// Flow metadata reused by WebSocket message hook events.
    context: FlowContext,
    /// Original HTTP upgrade request used as the WebSocket conversation anchor.
    request_head: Request<()>,
    /// Outcome for the HTTP upgrade exchange before WebSocket payload bytes.
    outcome: RelayOutcome,
}

#[tracing::instrument(level = "trace", skip_all)]
async fn forward_websocket_request_head<U>(
    upstream: &mut U,
    request_head: &[u8],
) -> Result<u64, TransparentFlowError>
where
    U: AsyncWrite + Unpin + Send,
{
    upstream
        .write_all(request_head)
        .await
        .map_err(|source| TransparentFlowError::Io {
            operation: FlowOperation::WriteProviderRequestHead,
            source,
        })?;
    usize_to_u64(request_head.len())
}

/// Captured representation of one HTTP message as it was forwarded.
struct MessageCapture {
    /// Decoded body bytes exposed to hooks.
    body: CapturedBody,
    /// Raw wire bytes forwarded for the message, including head and framing.
    forwarded_bytes: u64,
}

/// Selects the log message for the first exchange just submitted to hooks.
#[derive(Clone, Copy)]
enum CapturedExchangeLog {
    Http1,
    WebSocketUpgrade,
}

/// Decode the first upstream response while preserving buffered body bytes.
///
/// The returned stream has already yielded the bytes stored in
/// `DecodedUpstreamResponse::head_buffer`, so callers must forward that buffer
/// before reading more from the stream.
#[tracing::instrument(level = "trace", skip_all)]
async fn decode_response_from_upstream<S>(
    upstream: S,
    timeouts: MitmTimeouts,
) -> Result<DecodedUpstreamResponse<S>, TransparentFlowError>
where
    S: AsyncRead + Unpin,
{
    let decoded = Http1UpstreamStream::new(upstream)
        .decode_response_head_with_timeout(timeouts.http1_response_head)
        .await
        .map_err(|source| {
            TransparentFlowError::http1(FlowOperation::ReadProviderResponseHead, source)
        })?;
    let (stream, head, head_buffer) = decoded.into_parts();
    Ok(DecodedUpstreamResponse {
        stream,
        head,
        head_buffer,
    })
}

/// Build a zero-body capture for protocol steps that only forward a head.
fn empty_message_capture(forwarded_bytes: u64) -> MessageCapture {
    MessageCapture {
        body: CapturedBody::from_bytes(Bytes::new()),
        forwarded_bytes,
    }
}

/// Merge the HTTP upgrade byte counts with the subsequent WebSocket payload
/// byte counts without changing the first exchange returned to callers.
fn combine_websocket_outcomes(
    upgrade_outcome: RelayOutcome,
    websocket_outcome: &WebSocketRelayOutcome,
) -> Result<RelayOutcome, TransparentFlowError> {
    Ok(RelayOutcome {
        protocol: upgrade_outcome.protocol,
        first_request: upgrade_outcome.first_request,
        first_response: upgrade_outcome.first_response,
        client_to_upstream_bytes: add_len(
            upgrade_outcome.client_to_upstream_bytes,
            websocket_outcome.client_to_upstream_bytes,
        )?,
        upstream_to_client_bytes: add_len(
            upgrade_outcome.upstream_to_client_bytes,
            websocket_outcome.upstream_to_client_bytes,
        )?,
    })
}

fn submit_captured_exchange(
    flow: FlowContext,
    request_head: Request<()>,
    response_head: Response<()>,
    request_capture: MessageCapture,
    response_capture: MessageCapture,
    hooks: &HookDispatcher,
    log_kind: CapturedExchangeLog,
) -> RelayOutcome {
    // Hook events are submitted only after the first exchange is complete. The
    // dispatcher owns hook execution on a background worker, so relay does not
    // wait for audit observers before returning to the caller.
    let protocol = flow.protocol.clone();
    let request = request_with_body(request_head, request_capture.body);
    let response = response_with_body(response_head, response_capture.body);
    let exchange = HttpExchange {
        flow,
        request,
        response,
    };
    hooks.submit(exchange.clone());
    log_captured_exchange(
        log_kind,
        &exchange,
        request_capture.forwarded_bytes,
        response_capture.forwarded_bytes,
    );

    RelayOutcome {
        protocol,
        first_request: exchange.request,
        first_response: exchange.response,
        client_to_upstream_bytes: request_capture.forwarded_bytes,
        upstream_to_client_bytes: response_capture.forwarded_bytes,
    }
}

fn log_captured_exchange(
    log_kind: CapturedExchangeLog,
    exchange: &HttpExchange,
    client_to_upstream_bytes: u64,
    upstream_to_client_bytes: u64,
) {
    match log_kind {
        CapturedExchangeLog::Http1 => {
            tracing::info!(
                protocol = ?exchange.flow.protocol,
                method = %exchange.request.method(),
                target_path = %exchange.request.uri().path(),
                status = %exchange.response.status(),
                client_to_upstream_bytes,
                upstream_to_client_bytes,
                "MITM transparent HTTP/1 exchange captured"
            );
        }
        CapturedExchangeLog::WebSocketUpgrade => {
            tracing::info!(
                protocol = ?exchange.flow.protocol,
                method = %exchange.request.method(),
                target_path = %exchange.request.uri().path(),
                status = %exchange.response.status(),
                client_to_upstream_bytes,
                upstream_to_client_bytes,
                "MITM transparent WebSocket upgrade captured"
            );
        }
    }
}

/// HTTP/1 body framing selected from the already decoded message head.
#[derive(Debug, Clone, Copy)]
enum BodyFraming {
    /// No body is expected for this HTTP message.
    Empty,
    /// Body length is known from `Content-Length`.
    ContentLength(usize),
    /// Body uses HTTP/1 chunk framing and is decoded before hooks see it.
    Chunked,
    /// Response body ends when upstream closes the connection.
    UntilEof,
}

/// Copy the first request to upstream and capture the decoded request body.
///
/// Relay preserves the original request head bytes unless the flow targets a
/// provider endpoint where hooks require uncompressed, parseable response
/// bodies. `head_buffer` still carries any body bytes already read while
/// decoding the head.
#[tracing::instrument(level = "trace", skip_all)]
async fn forward_request<R, W>(
    client: &mut R,
    upstream: &mut W,
    request: &Request<()>,
    head_buffer: &Http1HeadBuffer,
    flow: &FlowContext,
    max_body_bytes: usize,
) -> Result<MessageCapture, TransparentFlowError>
where
    R: AsyncRead + AsyncWrite + Unpin,
    W: AsyncWrite + Unpin,
{
    let body_framing = request_body_framing(request).map_err(|source| {
        TransparentFlowError::http1(FlowOperation::ReadAgentRequestBody, source)
    })?;
    let handle_expect_continue =
        has_expect_continue(request) && !matches!(body_framing, BodyFraming::Empty);
    let request_head = request_head_for_relay(request, head_buffer, flow, handle_expect_continue)?;

    upstream
        .write_all(&request_head)
        .await
        .map_err(|source| TransparentFlowError::Io {
            operation: FlowOperation::WriteProviderRequestHead,
            source,
        })?;

    if handle_expect_continue {
        send_continue_response_to_client(client, request, flow).await?;
    }

    let body_capture = Box::pin(forward_body(
        client,
        upstream,
        body_framing,
        head_buffer.buffered_body(),
        max_body_bytes,
        BodyDirection::Request,
    ))
    .await?;
    upstream
        .flush()
        .await
        .map_err(|source| TransparentFlowError::Io {
            operation: FlowOperation::WriteProviderRequestHead,
            source,
        })?;
    Ok(MessageCapture {
        forwarded_bytes: add_len(
            usize_to_u64(request_head.len())?,
            body_capture.forwarded_bytes,
        )?,
        body: body_capture.body,
    })
}

fn request_head_for_relay<'a>(
    request: &'a Request<()>,
    head_buffer: &'a Http1HeadBuffer,
    flow: &FlowContext,
    strip_expect_continue: bool,
) -> Result<Cow<'a, [u8]>, TransparentFlowError> {
    let strip_accept_encoding = should_strip_accept_encoding(flow, request);
    if strip_accept_encoding || strip_expect_continue {
        return Ok(Cow::Owned(
            http_request_head_without_relay_headers(
                request,
                strip_accept_encoding,
                strip_expect_continue,
            )
            .map_err(|source| {
                TransparentFlowError::http1(FlowOperation::WriteProviderRequestHead, source)
            })?,
        ));
    }
    Ok(Cow::Borrowed(head_buffer.head_bytes()))
}

async fn send_continue_response_to_client<W>(
    client: &mut W,
    request: &Request<()>,
    flow: &FlowContext,
) -> Result<(), TransparentFlowError>
where
    W: AsyncWrite + Unpin,
{
    // `Expect: 100-continue` is still part of the same HTTP request: the client
    // sends the head, waits for an interim `100 Continue`, and only then sends
    // the body. A full HTTP/1 proxy would forward the head upstream, relay the
    // upstream `100 Continue` back to the client, then continue with the final
    // response. This relay currently models the first exchange as
    // request-head + complete request-body -> final response-head, so it does
    // not read or expose upstream interim 1xx responses before the request body
    // has been copied. Reply locally and strip `Expect` from the upstream head
    // so the upstream receives a normal body-bearing request.
    client
        .write_all(HTTP1_100_CONTINUE)
        .await
        .map_err(|source| TransparentFlowError::Io {
            operation: FlowOperation::WriteAgentContinueResponse,
            source,
        })?;
    client
        .flush()
        .await
        .map_err(|source| TransparentFlowError::Io {
            operation: FlowOperation::WriteAgentContinueResponse,
            source,
        })?;
    tracing::info!(
        protocol = ?flow.protocol,
        method = %request.method(),
        target_path = %request.uri().path(),
        "MITM handled HTTP/1 Expect: 100-continue locally"
    );
    Ok(())
}

/// Copy the first response to the client and capture the decoded response body.
///
/// Response framing depends on both the request method and the response head:
/// `HEAD`, informational, 204, and 304 responses must not be treated as having
/// a body even if the socket stays open.
#[tracing::instrument(level = "trace", skip_all)]
async fn forward_response<R, W>(
    upstream: &mut R,
    client: &mut W,
    request: &Request<()>,
    response: &Response<()>,
    head_buffer: &Http1HeadBuffer,
    max_body_bytes: usize,
) -> Result<MessageCapture, TransparentFlowError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    // Preserve the exact upstream response head bytes, then capture/forward the
    // body according to the response framing rules.
    client
        .write_all(head_buffer.head_bytes())
        .await
        .map_err(|source| TransparentFlowError::Io {
            operation: FlowOperation::WriteAgentResponseHead,
            source,
        })?;

    let response_framing = response_body_framing(request.method(), response).map_err(|source| {
        TransparentFlowError::http1(FlowOperation::ReadProviderResponseBody, source)
    })?;
    let body_capture = Box::pin(forward_body(
        upstream,
        client,
        response_framing,
        head_buffer.buffered_body(),
        max_body_bytes,
        BodyDirection::Response,
    ))
    .await?;
    Ok(MessageCapture {
        forwarded_bytes: add_len(
            usize_to_u64(head_buffer.head_bytes().len())?,
            body_capture.forwarded_bytes,
        )?,
        body: body_capture.body,
    })
}

/// Body data captured while forwarding a single HTTP message.
struct BodyCapture {
    /// Decoded body bytes retained for hooks.
    ///
    /// This may be shorter than the body represented by `forwarded_bytes`. That
    /// means hook capture was truncated at `max_body_bytes`; it does not mean
    /// the network body was truncated.
    body: CapturedBody,
    /// Raw bytes forwarded for the body portion only.
    forwarded_bytes: u64,
}

/// Direction-specific context for diagnostics while copying a body.
#[derive(Clone, Copy)]
enum BodyDirection {
    Request,
    Response,
}

/// Forward a body according to the already selected HTTP/1 framing mode.
///
/// All variants preserve wire bytes on the network side while returning decoded
/// body bytes for hooks. The two byte streams differ for chunked bodies because
/// chunk size lines and trailers are wire framing, not message payload.
///
/// `max_body_bytes` applies only to the returned `CapturedBody`. Every framing
/// implementation must keep forwarding until the HTTP message is complete even
/// after capture has been disabled.
async fn forward_body<R, W>(
    reader: &mut R,
    writer: &mut W,
    framing: BodyFraming,
    buffered_body: &[u8],
    max_body_bytes: usize,
    direction: BodyDirection,
) -> Result<BodyCapture, TransparentFlowError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    // Each framing mode has different completion rules. All variants return the
    // decoded body seen by hooks and the exact byte count forwarded on the wire.
    match framing {
        BodyFraming::Empty => forward_empty_body(writer, buffered_body, direction).await,
        BodyFraming::ContentLength(length) => {
            Box::pin(forward_content_length_body(
                reader,
                writer,
                buffered_body,
                length,
                max_body_bytes,
                direction,
            ))
            .await
        }
        BodyFraming::Chunked => {
            Box::pin(forward_chunked_body(
                reader,
                writer,
                buffered_body,
                max_body_bytes,
                direction,
            ))
            .await
        }
        BodyFraming::UntilEof => {
            Box::pin(forward_until_eof_body(
                reader,
                writer,
                buffered_body,
                max_body_bytes,
                direction,
            ))
            .await
        }
    }
}

async fn forward_empty_body<W>(
    writer: &mut W,
    buffered_body: &[u8],
    direction: BodyDirection,
) -> Result<BodyCapture, TransparentFlowError>
where
    W: AsyncWrite + Unpin,
{
    if !buffered_body.is_empty() {
        // Extra bytes after an empty-body head would belong to a pipelined
        // exchange, which the first-exchange hook path does not support yet.
        return Err(TransparentFlowError::http1(
            body_http1_operation(direction),
            Http1Error::UnsupportedBody("pipelined HTTP/1 bytes"),
        ));
    }
    // A flush is enough for an empty body because the head was already written
    // by the caller. This gives the peer a chance to observe the completed
    // message even if no more bytes are sent immediately.
    writer
        .flush()
        .await
        .map_err(|source| TransparentFlowError::Io {
            operation: body_forward_operation(direction),
            source,
        })?;
    Ok(BodyCapture {
        body: CapturedBody::from_bytes(Bytes::new()),
        forwarded_bytes: 0,
    })
}

#[tracing::instrument(level = "trace", skip_all)]
async fn forward_content_length_body<R, W>(
    reader: &mut R,
    writer: &mut W,
    buffered_body: &[u8],
    length: usize,
    max_body_bytes: usize,
    direction: BodyDirection,
) -> Result<BodyCapture, TransparentFlowError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    // Content-Length gives an exact byte count, so the relay can stop after the
    // declared number of payload bytes without waiting for EOF.
    if buffered_body.len() > length {
        // Reads may consume body bytes while decoding the head, but they must
        // not consume the next pipelined request.
        return Err(TransparentFlowError::http1(
            body_http1_operation(direction),
            Http1Error::UnsupportedBody("pipelined HTTP/1 bytes"),
        ));
    }

    // A known Content-Length lets us reserve only the capture budget up front.
    // Even when the declared body is too large to retain fully for hooks, the
    // exact number of bytes still has to be copied to preserve the
    // client/upstream exchange.
    let mut capture_body = true;
    let mut body = Vec::with_capacity(initial_body_capture_capacity(length, max_body_bytes));
    if !buffered_body.is_empty() {
        writer
            .write_all(buffered_body)
            .await
            .map_err(|source| TransparentFlowError::Io {
                operation: body_forward_operation(direction),
                source,
            })?;
        append_body_for_capture(&mut body, &mut capture_body, buffered_body, max_body_bytes);
    }

    let mut remaining = length.saturating_sub(buffered_body.len());
    let mut buffer = [0_u8; RELAY_CHUNK_BYTES];
    while remaining > 0 {
        let read_len = reader
            .read(&mut buffer[..remaining.min(RELAY_CHUNK_BYTES)])
            .await
            .map_err(|source| TransparentFlowError::Io {
                operation: body_read_operation(direction),
                source,
            })?;
        if read_len == 0 {
            return Err(TransparentFlowError::http1(
                body_http1_operation(direction),
                Http1Error::InvalidBody("content-length body ended early"),
            ));
        }
        writer
            .write_all(&buffer[..read_len])
            .await
            .map_err(|source| TransparentFlowError::Io {
                operation: body_forward_operation(direction),
                source,
            })?;
        append_body_for_capture(
            &mut body,
            &mut capture_body,
            &buffer[..read_len],
            max_body_bytes,
        );
        remaining = remaining
            .checked_sub(read_len)
            .ok_or(TransparentFlowError::ByteCountOverflow)?;
    }

    Ok(BodyCapture {
        body: captured_body(body, capture_body),
        forwarded_bytes: usize_to_u64(length)?,
    })
}

fn initial_body_capture_capacity(length: usize, max_body_bytes: usize) -> usize {
    length
        .min(max_body_bytes)
        .min(MAX_INITIAL_BODY_CAPTURE_CAPACITY)
}

#[tracing::instrument(level = "trace", skip_all)]
async fn forward_chunked_body<R, W>(
    reader: &mut R,
    writer: &mut W,
    buffered_body: &[u8],
    max_body_bytes: usize,
    direction: BodyDirection,
) -> Result<BodyCapture, TransparentFlowError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    // Hooks capture decoded chunk payloads only while they fit the configured
    // limit. The network side always receives the raw chunked wire bytes,
    // including size lines, CRLF delimiters, trailers, and the terminating
    // zero-sized chunk.
    let mut chunked = ChunkedBodyCapture::new(direction);
    let mut buffer = [0_u8; RELAY_CHUNK_BYTES];

    if !buffered_body.is_empty() {
        let capture = chunked.feed(buffered_body, max_body_bytes)?;
        writer
            .write_all(buffered_body)
            .await
            .map_err(|source| TransparentFlowError::Io {
                operation: body_forward_operation(direction),
                source,
            })?;
        if let Some(capture) = capture {
            return Ok(capture);
        }
    }

    loop {
        let read_len =
            reader
                .read(&mut buffer)
                .await
                .map_err(|source| TransparentFlowError::Io {
                    operation: body_read_operation(direction),
                    source,
                })?;
        if read_len == 0 {
            return Err(TransparentFlowError::http1(
                body_http1_operation(direction),
                Http1Error::InvalidBody("chunked body ended early"),
            ));
        }

        let capture = chunked.feed(&buffer[..read_len], max_body_bytes)?;
        writer
            .write_all(&buffer[..read_len])
            .await
            .map_err(|source| TransparentFlowError::Io {
                operation: body_forward_operation(direction),
                source,
            })?;
        if let Some(capture) = capture {
            return Ok(capture);
        }
    }
}

struct ChunkedBodyCapture {
    state: ChunkedParseState,
    pending: Vec<u8>,
    body: Vec<u8>,
    capture_body: bool,
    forwarded_bytes: u64,
    direction: BodyDirection,
}

#[derive(Clone, Copy)]
enum ChunkedParseState {
    Size,
    Data { remaining: usize },
    DataTerminator,
    Trailers,
}

impl ChunkedBodyCapture {
    const fn new(direction: BodyDirection) -> Self {
        Self {
            state: ChunkedParseState::Size,
            pending: Vec::new(),
            body: Vec::new(),
            capture_body: true,
            forwarded_bytes: 0,
            direction,
        }
    }

    #[expect(
        clippy::too_many_lines,
        reason = "The chunked-body framing state machine is clearer as one explicit transition loop."
    )]
    fn feed(
        &mut self,
        bytes: &[u8],
        max_body_bytes: usize,
    ) -> Result<Option<BodyCapture>, TransparentFlowError> {
        // Validate framing before the caller writes these bytes to the peer.
        // This ensures bytes after the terminal chunk cannot escape as an
        // unaudited pipelined request. Large payloads remain relayable after
        // hook capture reaches its bounded prefix budget.
        self.forwarded_bytes = add_len(self.forwarded_bytes, usize_to_u64(bytes.len())?)?;
        self.pending.extend_from_slice(bytes);

        loop {
            match self.state {
                ChunkedParseState::Size => {
                    let (size_line_len, chunk_size) =
                        match httparse::parse_chunk_size(&self.pending) {
                            Ok(httparse::Status::Complete(parsed)) => parsed,
                            Ok(httparse::Status::Partial) => {
                                if self.pending.len() > MAX_HTTP1_HEADER_BYTES {
                                    return Err(TransparentFlowError::http1(
                                        body_http1_operation(self.direction),
                                        Http1Error::HeaderTooLarge,
                                    ));
                                }
                                return Ok(None);
                            }
                            Err(_error) => {
                                return Err(TransparentFlowError::http1(
                                    body_http1_operation(self.direction),
                                    Http1Error::InvalidBody("invalid chunk size"),
                                ));
                            }
                        };
                    if size_line_len > MAX_HTTP1_HEADER_BYTES {
                        return Err(TransparentFlowError::http1(
                            body_http1_operation(self.direction),
                            Http1Error::HeaderTooLarge,
                        ));
                    }
                    let chunk_size = usize::try_from(chunk_size).map_err(|_error| {
                        TransparentFlowError::http1(
                            body_http1_operation(self.direction),
                            Http1Error::BodyTooLarge {
                                limit: max_body_bytes,
                            },
                        )
                    })?;
                    self.pending.drain(..size_line_len);
                    self.state = if chunk_size == 0 {
                        ChunkedParseState::Trailers
                    } else {
                        ChunkedParseState::Data {
                            remaining: chunk_size,
                        }
                    };
                }
                ChunkedParseState::Data { remaining } => {
                    if self.pending.is_empty() {
                        return Ok(None);
                    }
                    let payload_len = remaining.min(self.pending.len());
                    // Only chunk payload bytes enter hook capture. Wire framing
                    // was already forwarded before `feed` was called and is
                    // counted in `forwarded_bytes`.
                    append_body_for_capture(
                        &mut self.body,
                        &mut self.capture_body,
                        &self.pending[..payload_len],
                        max_body_bytes,
                    );
                    self.pending.drain(..payload_len);
                    let remaining = remaining
                        .checked_sub(payload_len)
                        .ok_or(TransparentFlowError::ByteCountOverflow)?;
                    self.state = if remaining == 0 {
                        ChunkedParseState::DataTerminator
                    } else {
                        ChunkedParseState::Data { remaining }
                    };
                }
                ChunkedParseState::DataTerminator => {
                    if self.pending.len() < 2 {
                        return Ok(None);
                    }
                    if &self.pending[..2] != b"\r\n" {
                        return Err(TransparentFlowError::http1(
                            body_http1_operation(self.direction),
                            Http1Error::InvalidBody("chunk data missing terminator"),
                        ));
                    }
                    self.pending.drain(..2);
                    self.state = ChunkedParseState::Size;
                }
                ChunkedParseState::Trailers => {
                    if self.pending.len() < 2 {
                        return Ok(None);
                    }
                    if &self.pending[..2] == b"\r\n" {
                        self.pending.drain(..2);
                        self.reject_pipelined_bytes()?;
                        return Ok(Some(self.finish()));
                    }
                    if self.pending.len() > MAX_HTTP1_HEADER_BYTES {
                        return Err(TransparentFlowError::http1(
                            body_http1_operation(self.direction),
                            Http1Error::HeaderTooLarge,
                        ));
                    }
                    let Some(relative_end) = self
                        .pending
                        .windows(4)
                        .position(|window| window == b"\r\n\r\n")
                    else {
                        return Ok(None);
                    };
                    let trailer_end = relative_end
                        .checked_add(4)
                        .ok_or(TransparentFlowError::ByteCountOverflow)?;
                    self.pending.drain(..trailer_end);
                    self.reject_pipelined_bytes()?;
                    return Ok(Some(self.finish()));
                }
            }
        }
    }

    const fn reject_pipelined_bytes(&self) -> Result<(), TransparentFlowError> {
        if self.pending.is_empty() {
            Ok(())
        } else {
            Err(TransparentFlowError::http1(
                body_http1_operation(self.direction),
                Http1Error::UnsupportedBody("pipelined HTTP/1 bytes"),
            ))
        }
    }

    fn finish(&mut self) -> BodyCapture {
        BodyCapture {
            body: captured_body(std::mem::take(&mut self.body), self.capture_body),
            forwarded_bytes: self.forwarded_bytes,
        }
    }
}

#[tracing::instrument(level = "trace", skip_all)]
async fn forward_until_eof_body<R, W>(
    reader: &mut R,
    writer: &mut W,
    buffered_body: &[u8],
    max_body_bytes: usize,
    direction: BodyDirection,
) -> Result<BodyCapture, TransparentFlowError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    // A response without Content-Length or Transfer-Encoding is delimited by
    // upstream closing its write side. This mode is intentionally used for
    // responses only; request bodies must have explicit framing.
    //
    // Because there is no advertised size, capture may start enabled and then
    // be disabled mid-stream once `max_body_bytes` is crossed. Relay still
    // copies until EOF so clients receive the complete response body.
    let mut body = Vec::new();
    let mut capture_body = true;
    let mut forwarded_bytes = usize_to_u64(buffered_body.len())?;
    append_body_for_capture(&mut body, &mut capture_body, buffered_body, max_body_bytes);
    if !buffered_body.is_empty() {
        writer
            .write_all(buffered_body)
            .await
            .map_err(|source| TransparentFlowError::Io {
                operation: body_forward_operation(direction),
                source,
            })?;
    }

    let mut buffer = [0_u8; RELAY_CHUNK_BYTES];
    loop {
        let read_len =
            reader
                .read(&mut buffer)
                .await
                .map_err(|source| TransparentFlowError::Io {
                    operation: body_read_operation(direction),
                    source,
                })?;
        if read_len == 0 {
            return Ok(BodyCapture {
                body: captured_body(body, capture_body),
                forwarded_bytes,
            });
        }
        writer
            .write_all(&buffer[..read_len])
            .await
            .map_err(|source| TransparentFlowError::Io {
                operation: body_forward_operation(direction),
                source,
            })?;
        forwarded_bytes = add_len(forwarded_bytes, usize_to_u64(read_len)?)?;
        append_body_for_capture(
            &mut body,
            &mut capture_body,
            &buffer[..read_len],
            max_body_bytes,
        );
    }
}

/// Attach a captured body to a request while preserving the parsed head parts.
fn request_with_body(request: Request<()>, body: CapturedBody) -> Request<CapturedBody> {
    let (parts, ()) = request.into_parts();
    Request::from_parts(parts, body)
}

/// Attach a captured body to a response while preserving the parsed head parts.
fn response_with_body(response: Response<()>, body: CapturedBody) -> Response<CapturedBody> {
    let (parts, ()) = response.into_parts();
    Response::from_parts(parts, body)
}

/// Determine request body framing from headers alone.
///
/// Transparent relay does not infer request bodies from connection close:
/// clients must use `Content-Length` or `Transfer-Encoding: chunked` for a body
/// on the first captured request.
fn request_body_framing(request: &Request<()>) -> Result<BodyFraming, Http1Error> {
    if is_chunked(request.headers()) {
        return Ok(BodyFraming::Chunked);
    }
    Ok(content_length(request.headers())?.map_or(BodyFraming::Empty, BodyFraming::ContentLength))
}

/// Determine response body framing using the request method and response head.
///
/// Responses have more no-body cases than requests, and HTTP/1 responses may
/// be delimited by EOF when neither `Content-Length` nor chunked transfer
/// coding is present.
fn response_body_framing(
    request_method: &Method,
    response: &Response<()>,
) -> Result<BodyFraming, Http1Error> {
    if *request_method == Method::HEAD || status_has_no_body(response.status()) {
        return Ok(BodyFraming::Empty);
    }
    if is_chunked(response.headers()) {
        return Ok(BodyFraming::Chunked);
    }
    Ok(content_length(response.headers())?
        .map_or(BodyFraming::UntilEof, BodyFraming::ContentLength))
}

/// Convert byte counts to the public `RelayOutcome` representation.
fn usize_to_u64(value: usize) -> Result<u64, TransparentFlowError> {
    u64::try_from(value).map_err(|_error| TransparentFlowError::ByteCountOverflow)
}

fn append_body_for_capture(
    body: &mut Vec<u8>,
    capture_body: &mut bool,
    bytes: &[u8],
    max_body_bytes: usize,
) {
    if !*capture_body {
        return;
    }
    let Some(next_len) = body.len().checked_add(bytes.len()) else {
        // Capture memory accounting overflow is treated as "stop extending the
        // captured prefix" so the relay path can continue. Forwarding has
        // already happened before this helper is called.
        *capture_body = false;
        return;
    };
    if next_len > max_body_bytes {
        // The capture budget is a hook/audit boundary, not a network boundary.
        // Keep the prefix that fits the budget and stop extending it; callers
        // keep relaying bytes until message completion.
        let remaining = max_body_bytes.saturating_sub(body.len());
        if remaining > 0 {
            body.extend_from_slice(&bytes[..remaining.min(bytes.len())]);
        }
        *capture_body = false;
        return;
    }
    body.extend_from_slice(bytes);
}

fn captured_body(body: Vec<u8>, capture_completed_within_limit: bool) -> CapturedBody {
    if capture_completed_within_limit {
        CapturedBody::from_bytes(Bytes::from(body))
    } else {
        CapturedBody::from_truncated_bytes(Bytes::from(body))
    }
}

/// Add forwarded byte counts without silently wrapping.
fn add_len(left: u64, right: u64) -> Result<u64, TransparentFlowError> {
    left.checked_add(right)
        .ok_or(TransparentFlowError::ByteCountOverflow)
}

/// Operation for reads from the side currently supplying a body.
const fn body_read_operation(direction: BodyDirection) -> FlowOperation {
    match direction {
        BodyDirection::Request => FlowOperation::ReadAgentRequestBody,
        BodyDirection::Response => FlowOperation::ReadProviderResponseBody,
    }
}

/// Operation for writes to the peer currently receiving a body.
const fn body_forward_operation(direction: BodyDirection) -> FlowOperation {
    match direction {
        BodyDirection::Request => FlowOperation::WriteProviderRequestBody,
        BodyDirection::Response => FlowOperation::WriteAgentResponseBody,
    }
}

/// Operation for HTTP/1 framing errors while forwarding a body.
const fn body_http1_operation(direction: BodyDirection) -> FlowOperation {
    match direction {
        BodyDirection::Request => FlowOperation::ReadAgentRequestBody,
        BodyDirection::Response => FlowOperation::ReadProviderResponseBody,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        net::SocketAddr,
        pin::Pin,
        task::{Context, Poll},
        time::Duration,
    };

    use tokio::io::{AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

    use super::{
        BodyDirection, ChunkedBodyCapture, HTTP1_100_CONTINUE, MAX_INITIAL_BODY_CAPTURE_CAPACITY,
        forward_chunked_body, forward_request, initial_body_capture_capacity,
        shutdown_completed_agent_stream,
    };

    #[test]
    fn unbounded_capture_does_not_trust_content_length_for_initial_allocation() {
        assert_eq!(
            initial_body_capture_capacity(usize::MAX, usize::MAX),
            MAX_INITIAL_BODY_CAPTURE_CAPACITY
        );
        assert_eq!(initial_body_capture_capacity(128, usize::MAX), 128);
        assert_eq!(initial_body_capture_capacity(128, 32), 32);
    }
    use crate::{
        http1::{Http1ClientStream, Http1Error, MAX_HTTP1_HEADER_BYTES},
        transparent::{
            FlowContext, FlowOperation, OriginalDestination, TransparentFlowError,
            TransparentProtocol,
        },
    };

    #[tokio::test]
    async fn chunked_body_rejects_pipelined_suffix_before_forwarding_it() {
        let mut reader = tokio::io::empty();
        let mut upstream = FlushRecorder::default();
        let result = Box::pin(forward_chunked_body(
            &mut reader,
            &mut upstream,
            b"4\r\nping\r\n0\r\n\r\nGET /bypass HTTP/1.1\r\nHost: other.example\r\n\r\n",
            1024,
            BodyDirection::Request,
        ))
        .await;
        let error = match result {
            Ok(_capture) => panic!("pipelined bytes after a terminal chunk should fail"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            TransparentFlowError::Http1 {
                operation: FlowOperation::ReadAgentRequestBody,
                source: Http1Error::UnsupportedBody("pipelined HTTP/1 bytes"),
            }
        ));
        assert!(
            upstream.bytes.is_empty(),
            "a read containing a pipelined suffix must not be forwarded"
        );
    }

    #[test]
    fn chunked_body_bounds_fragmented_size_extensions() {
        let mut chunked = ChunkedBodyCapture::new(BodyDirection::Request);
        let mut size_line = Vec::from(&b"1;extension="[..]);
        size_line.resize(MAX_HTTP1_HEADER_BYTES.saturating_add(1), b'a');

        let error = match chunked.feed(&size_line, 1024) {
            Ok(_capture) => panic!("oversized unterminated chunk extension should fail"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            TransparentFlowError::Http1 {
                operation: FlowOperation::ReadAgentRequestBody,
                source: Http1Error::HeaderTooLarge,
            }
        ));

        let mut chunked = ChunkedBodyCapture::new(BodyDirection::Request);
        let mut complete_size_line = Vec::from(&b"1;extension="[..]);
        complete_size_line.resize(MAX_HTTP1_HEADER_BYTES, b'a');
        complete_size_line.extend_from_slice(b"\r\n");
        let error = match chunked.feed(&complete_size_line, 1024) {
            Ok(_capture) => panic!("oversized complete chunk extension should fail"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            TransparentFlowError::Http1 {
                operation: FlowOperation::ReadAgentRequestBody,
                source: Http1Error::HeaderTooLarge,
            }
        ));
    }

    #[tokio::test]
    async fn expect_continue_request_gets_local_continue_and_stripped_upstream_head() {
        let request_head = concat!(
            "POST /v1/messages?beta=true HTTP/1.1\r\n",
            "Host: www.dmxapi.cn\r\n",
            "Accept-Encoding: gzip\r\n",
            "Expect: 100-continue\r\n",
            "Content-Length: 4\r\n",
            "\r\n"
        );
        let (mut client_peer, client_stream) = tokio::io::duplex(4096);
        client_peer
            .write_all(request_head.as_bytes())
            .await
            .expect("request head should write");

        let decoded = Http1ClientStream::new(client_stream)
            .decode_request_head_with_timeout(Duration::from_secs(1))
            .await
            .expect("request head should decode");
        let (mut relay_client, request, head_buffer) = decoded.into_parts();
        let (mut upstream_peer, mut upstream) = tokio::io::duplex(4096);
        let flow = test_flow();

        let forward = forward_request(
            &mut relay_client,
            &mut upstream,
            &request,
            &head_buffer,
            &flow,
            1024,
        );
        let client = async {
            let mut response = [0_u8; HTTP1_100_CONTINUE.len()];
            client_peer
                .read_exact(&mut response)
                .await
                .expect("client should receive local 100 Continue");
            assert_eq!(&response, HTTP1_100_CONTINUE);
            client_peer
                .write_all(b"ping")
                .await
                .expect("client body should write after 100 Continue");
        };
        let upstream_read = async {
            let mut seen = Vec::new();
            tokio::time::timeout(Duration::from_secs(1), async {
                loop {
                    let mut buffer = [0_u8; 512];
                    let read_len = upstream_peer
                        .read(&mut buffer)
                        .await
                        .expect("upstream should receive request bytes");
                    if read_len == 0 {
                        break;
                    }
                    seen.extend_from_slice(&buffer[..read_len]);
                    if seen.ends_with(b"ping") {
                        break;
                    }
                }
            })
            .await
            .expect("upstream should receive the complete first request");
            seen
        };

        let (forward_result, (), upstream_bytes) = tokio::join!(forward, client, upstream_read);
        let capture = forward_result.expect("request should forward");
        let upstream_text =
            String::from_utf8(upstream_bytes).expect("test request head should remain UTF-8");
        let lower = upstream_text.to_ascii_lowercase();

        assert_eq!(
            capture.body.bytes(),
            b"ping",
            "relay should capture the request body after sending 100 Continue"
        );
        assert!(
            upstream_text.starts_with("POST /v1/messages?beta=true HTTP/1.1\r\n"),
            "upstream request line should be preserved"
        );
        assert!(
            lower.contains("content-length: 4"),
            "upstream body framing should be preserved"
        );
        assert!(
            !lower.contains("expect:"),
            "locally-handled Expect must not be forwarded upstream"
        );
        assert!(
            !lower.contains("accept-encoding:"),
            "Claude-compatible gateway responses should remain parseable for hooks"
        );
        assert!(
            upstream_text.ends_with("ping"),
            "upstream should receive the request body"
        );
        assert_eq!(
            usize::try_from(capture.forwarded_bytes).expect("test byte count should fit usize"),
            upstream_text.len(),
            "forwarded byte accounting should match rewritten wire bytes"
        );
    }

    #[tokio::test]
    async fn content_length_request_is_flushed_after_body() {
        let request_bytes = concat!(
            "POST /v1/messages HTTP/1.1\r\n",
            "Host: api.anthropic.com\r\n",
            "Content-Length: 4\r\n",
            "\r\n",
            "ping"
        );
        let (mut client_peer, client_stream) = tokio::io::duplex(4096);
        client_peer
            .write_all(request_bytes.as_bytes())
            .await
            .expect("request should write");

        let decoded = Http1ClientStream::new(client_stream)
            .decode_request_head_with_timeout(Duration::from_secs(1))
            .await
            .expect("request head should decode");
        let (mut relay_client, request, head_buffer) = decoded.into_parts();
        let flow = test_flow();
        let mut upstream = FlushRecorder::default();

        let capture = forward_request(
            &mut relay_client,
            &mut upstream,
            &request,
            &head_buffer,
            &flow,
            1024,
        )
        .await
        .expect("request should forward");

        assert_eq!(capture.body.bytes(), b"ping");
        assert_eq!(
            upstream.flushes, 1,
            "relay should flush the complete upstream request before reading the response"
        );
        assert!(
            String::from_utf8_lossy(&upstream.bytes).ends_with("ping"),
            "upstream should receive the request body before the flush"
        );
    }

    #[tokio::test]
    async fn completed_response_shutdown_error_is_cleanup_only() {
        let mut stream = ShutdownErrorStream {
            shutdown_attempted: false,
            error_kind: io::ErrorKind::BrokenPipe,
        };

        shutdown_completed_agent_stream(&mut stream)
            .await
            .expect("an already-closed Agent stream should not fail a completed response");

        assert!(stream.shutdown_attempted);
    }

    #[tokio::test]
    async fn completed_response_shutdown_retains_unexpected_local_errors() {
        let mut stream = ShutdownErrorStream {
            shutdown_attempted: false,
            error_kind: io::ErrorKind::Other,
        };

        let error = shutdown_completed_agent_stream(&mut stream)
            .await
            .expect_err("an unexpected shutdown failure should remain diagnosable");

        assert!(matches!(
            error,
            TransparentFlowError::Io {
                operation: FlowOperation::ShutdownAgent,
                ..
            }
        ));
    }

    fn test_flow() -> FlowContext {
        FlowContext::new(
            SocketAddr::from(([127, 0, 0, 1], 50000)),
            SocketAddr::from(([127, 0, 0, 1], 18080)),
            OriginalDestination::from(SocketAddr::from(([110, 42, 10, 198], 443))),
            TransparentProtocol::TlsHttp {
                server_name: "www.dmxapi.cn".to_owned(),
            },
        )
    }

    #[derive(Default)]
    struct FlushRecorder {
        bytes: Vec<u8>,
        flushes: usize,
    }

    struct ShutdownErrorStream {
        shutdown_attempted: bool,
        error_kind: io::ErrorKind,
    }

    impl AsyncWrite for ShutdownErrorStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buffer.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            self.shutdown_attempted = true;
            Poll::Ready(Err(io::Error::new(self.error_kind, "Agent already closed")))
        }
    }

    impl AsyncWrite for FlushRecorder {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.bytes.extend_from_slice(buffer);
            Poll::Ready(Ok(buffer.len()))
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            self.flushes = self.flushes.checked_add(1).expect("flush counter overflow");
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
}
