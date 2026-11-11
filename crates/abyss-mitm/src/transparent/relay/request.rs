//! HTTP request preparation, inspection, and byte forwarding.
//! The parent relay selects the processing steps; this module owns their details.

use std::{borrow::Cow, time::Duration};

use http::{Request, StatusCode};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _};

use crate::{
    http1::Http1HeadBuffer,
    transparent::{
        BodyDecodingStatus, FlowContext, FlowOperation, LocalRejection, RequestForwardingControl,
        RequestForwardingResult, RequestTransport, RequestView, TransparentFlowError,
        content_encoding::ContentDecoder,
        utils::{
            has_expect_continue, http_request_head_without_relay_headers,
            is_websocket_upgrade_request, websocket_request_head_bytes,
        },
    },
};

use super::{
    BodyCapture, BodyDirection, BodyFraming, HTTP1_100_CONTINUE, MessageCapture, add_len,
    forward_body, request_body_framing, retained::RetainedBody, usize_to_u64,
};

/// Inspected requests must become complete within a finite retention window.
const INSPECTION_BODY_TIMEOUT: Duration = Duration::from_secs(30);

pub(super) struct RequestRelay<'a> {
    request: &'a mut Request<()>,
    head_buffer: &'a Http1HeadBuffer,
    buffered_body: &'a [u8],
    flow: &'a FlowContext,
    framing: BodyFraming,
    max_body_bytes: usize,
    handle_expect_continue: bool,
    edited_head: bool,
    retained: Option<(RetainedBody, BodyCapture)>,
}

impl<'a> RequestRelay<'a> {
    pub(super) fn new(
        request: &'a mut Request<()>,
        head_buffer: &'a Http1HeadBuffer,
        flow: &'a FlowContext,
        max_body_bytes: usize,
    ) -> Result<Self, TransparentFlowError> {
        let framing = request_body_framing(request).map_err(|source| {
            TransparentFlowError::http1(FlowOperation::ReadAgentRequestBody, source)
        })?;
        let handle_expect_continue =
            has_expect_continue(request) && !matches!(framing, BodyFraming::Empty);
        // Bytes prefetched after an upgrade head belong to WebSocket reassembly.
        let buffered_body = if is_websocket_upgrade_request(request) {
            &[][..]
        } else {
            head_buffer.buffered_body()
        };
        Ok(Self {
            request,
            head_buffer,
            buffered_body,
            flow,
            framing,
            max_body_bytes,
            handle_expect_continue,
            edited_head: false,
            retained: None,
        })
    }

    pub(super) async fn handle_expect_continue<W: AsyncWrite + Unpin>(
        &self,
        client: &mut W,
    ) -> Result<(), TransparentFlowError> {
        if !self.handle_expect_continue {
            return Ok(());
        }
        // Reply locally so the client sends its body before inspection. The
        // upstream head omits Expect because no interim response is needed there.
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
            protocol = ?self.flow.protocol,
            method = %self.request.method(),
            target_path = %self.request.uri().path(),
            "MITM handled HTTP/1 Expect: 100-continue locally"
        );
        Ok(())
    }

    pub(super) async fn inspect<R: AsyncRead + Unpin, C: RequestForwardingControl>(
        &mut self,
        client: &mut R,
        control: &C,
        plan: C::Plan,
    ) -> Result<(), LocalRejection> {
        let (wire, capture) = self.retain_body(client).await?;
        let capture = self.decode_body(capture).await?;
        let result = control
            .before_forward(
                plan,
                RequestView {
                    flow: self.flow,
                    head: self.request,
                    body: &capture.body,
                    transport: RequestTransport::Http,
                },
            )
            .await?;
        self.apply(result, wire, capture);
        Ok(())
    }

    /// Keep the forwarded bytes and observation data in sync in one place.
    fn apply(
        &mut self,
        result: RequestForwardingResult,
        mut wire: RetainedBody,
        mut capture: BodyCapture,
    ) {
        if let Some(head) = result.head {
            *self.request = head;
            self.edited_head = true;
        }
        if let Some(body) = result.body {
            wire.bytes = body.bytes().to_vec();
            capture.body = body;
        }
        capture.body.extensions_mut().extend(result.annotations);
        self.retained = Some((wire, capture));
    }

    pub(super) async fn forward<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        self,
        client: &mut R,
        upstream: &mut W,
    ) -> Result<MessageCapture, TransparentFlowError> {
        let head_bytes = self.forward_head(upstream).await?;
        let capture = self.forward_body(client, upstream).await?;
        upstream
            .flush()
            .await
            .map_err(|source| TransparentFlowError::Io {
                operation: FlowOperation::WriteProviderRequestHead,
                source,
            })?;
        Ok(MessageCapture {
            forwarded_bytes: add_len(head_bytes, capture.forwarded_bytes)?,
            body: capture.body,
            agent_write_error: capture.agent_write_error,
        })
    }

    async fn forward_head<W: AsyncWrite + Unpin>(
        &self,
        upstream: &mut W,
    ) -> Result<u64, TransparentFlowError> {
        let head = self.head_bytes()?;
        upstream
            .write_all(&head)
            .await
            .map_err(|source| TransparentFlowError::Io {
                operation: FlowOperation::WriteProviderRequestHead,
                source,
            })?;
        usize_to_u64(head.len())
    }

    fn head_bytes(&self) -> Result<Cow<'_, [u8]>, TransparentFlowError> {
        let encoded = if is_websocket_upgrade_request(self.request) {
            websocket_request_head_bytes(self.request)
        } else if self.edited_head || self.handle_expect_continue {
            http_request_head_without_relay_headers(self.request, self.handle_expect_continue)
        } else {
            return Ok(Cow::Borrowed(self.head_buffer.head_bytes()));
        };
        encoded.map(Cow::Owned).map_err(|source| {
            TransparentFlowError::http1(FlowOperation::WriteProviderRequestHead, source)
        })
    }

    async fn forward_body<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        self,
        client: &mut R,
        upstream: &mut W,
    ) -> Result<BodyCapture, TransparentFlowError> {
        if let Some((wire, mut capture)) = self.retained {
            capture.forwarded_bytes = usize_to_u64(wire.bytes.len())?;
            upstream
                .write_all(&wire.bytes)
                .await
                .map_err(|source| TransparentFlowError::Io {
                    operation: FlowOperation::WriteProviderRequestBody,
                    source,
                })?;
            Ok(capture)
        } else {
            Box::pin(forward_body(
                client,
                upstream,
                self.framing,
                self.buffered_body,
                self.max_body_bytes,
                BodyDirection::Request,
            ))
            .await
        }
    }

    async fn decode_body(&self, mut capture: BodyCapture) -> Result<BodyCapture, LocalRejection> {
        let headers = self.request.headers().clone();
        capture.body = tokio::task::spawn_blocking(move || {
            let mut body = capture.body;
            ContentDecoder::decode_body(&headers, &mut body, false);
            body
        })
        .await
        .map_err(|_| {
            self.reject(
                StatusCode::SERVICE_UNAVAILABLE,
                "inspection_unavailable",
                "Request decoder unavailable",
            )
        })?;
        match capture.body.decoding_status() {
            BodyDecodingStatus::Complete => Ok(capture),
            BodyDecodingStatus::Truncated | BodyDecodingStatus::BudgetExceeded => Err(self.reject(
                StatusCode::PAYLOAD_TOO_LARGE,
                "inspection_body_too_large",
                "Decoded request exceeds inspection limit",
            )),
            BodyDecodingStatus::UnsupportedEncoding
            | BodyDecodingStatus::UnsupportedTransferEncoding => Err(self.reject(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "unsupported_request_encoding",
                "Unsupported request encoding",
            )),
            _ => Err(self.reject(
                StatusCode::BAD_REQUEST,
                "invalid_request_encoding",
                "Invalid request encoding",
            )),
        }
    }

    async fn retain_body<R: AsyncRead + Unpin>(
        &self,
        client: &mut R,
    ) -> Result<(RetainedBody, BodyCapture), LocalRejection> {
        if matches!(self.framing, BodyFraming::ContentLength(length) if length > self.max_body_bytes)
        {
            return Err(self.reject(
                StatusCode::PAYLOAD_TOO_LARGE,
                "inspection_body_too_large",
                "Request exceeds inspection limit",
            ));
        }
        let mut wire = RetainedBody::new(self.max_body_bytes);
        let read = forward_body(
            client,
            &mut wire,
            self.framing,
            self.buffered_body,
            self.max_body_bytes,
            BodyDirection::Request,
        );
        let captured = tokio::time::timeout(INSPECTION_BODY_TIMEOUT, read)
            .await
            .map_err(|_| {
                self.reject(
                    StatusCode::REQUEST_TIMEOUT,
                    "inspection_body_timeout",
                    "Request body was not completed within 30 seconds",
                )
            })?;
        let capture = captured.map_err(|error| {
            if matches!(error, TransparentFlowError::Io { ref source, .. } if source.kind() == std::io::ErrorKind::FileTooLarge) {
                self.reject(StatusCode::PAYLOAD_TOO_LARGE, "inspection_body_too_large", "Request exceeds inspection limit")
            } else {
                self.reject(StatusCode::BAD_REQUEST, "invalid_request_body", "Incomplete or invalid request body")
            }
        })?;
        Ok((wire, capture))
    }

    fn reject(
        &self,
        status: StatusCode,
        code: &'static str,
        reason: &'static str,
    ) -> LocalRejection {
        LocalRejection::new(status, code, reason, self.flow.flow_id.to_string())
    }
}
