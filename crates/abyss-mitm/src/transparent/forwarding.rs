//! Request forwarding control supplied by the broker, independent of observation hooks.
//! The transport owns framing and local rejection; callers own request decisions.

use std::future::Future;

use http::{Request, StatusCode};
use tokio::io::{AsyncWrite, AsyncWriteExt as _};

use super::{CapturedBody, FlowContext, FlowOperation, TransparentFlowError};

/// Complete plaintext request made available immediately before forwarding.
pub struct RequestView<'a> {
    /// Network and available source metadata.
    pub flow: &'a FlowContext,
    /// HTTP request or WebSocket upgrade head.
    pub head: &'a Request<()>,
    /// Complete content-decoded body or reassembled client WebSocket message.
    pub body: &'a CapturedBody,
    /// HTTP request or complete WebSocket data message and its flow-local order.
    pub transport: RequestTransport,
    /// Maximum decoded replacement size at this forwarding boundary.
    pub max_body_bytes: usize,
}

/// Request transport facts known before forwarding.
#[derive(Clone, Copy)]
#[expect(
    clippy::exhaustive_enums,
    reason = "request parsing must handle every supported transport explicitly"
)]
pub enum RequestTransport {
    /// First HTTP request, including a WebSocket upgrade.
    Http,
    /// Reassembled WebSocket text message.
    WebSocketText { sequence: u64 },
    /// Reassembled WebSocket binary message.
    WebSocketBinary { sequence: u64 },
}

/// Static dispatch boundary for optional request inspection.
pub trait RequestForwardingControl: Send + Sync {
    /// Snapshot retained for one request or complete client message.
    type Plan: Send;

    /// Returns a snapshot when inspection is active. `None` keeps streaming.
    fn plan(&self) -> Option<Self::Plan>;

    /// Decides before any request bytes reach the provider and returns annotations
    /// to retain on the captured body for later observation.
    fn before_forward(
        &self,
        plan: Self::Plan,
        request: RequestView<'_>,
    ) -> impl Future<Output = Result<super::RequestForwardingResult, LocalRejection>> + Send;
}

/// Default transport behavior with no inspection stage or body retention.
pub struct UncontrolledForwarding;

impl RequestForwardingControl for UncontrolledForwarding {
    type Plan = ();

    fn plan(&self) -> Option<Self::Plan> {
        None
    }

    fn before_forward(
        &self,
        (): (),
        _request: RequestView<'_>,
    ) -> impl Future<Output = Result<super::RequestForwardingResult, LocalRejection>> + Send {
        std::future::ready(Ok(super::RequestForwardingResult::default()))
    }
}

/// Safe local rejection metadata; never contains the rejected request body.
#[derive(Debug, thiserror::Error)]
#[error("abyss-broker: {code}: {reason} (request_id={request_id}, rule_id={rule_id:?})")]
pub struct LocalRejection {
    /// HTTP status for clients that have reached an HTTP boundary.
    pub status: StatusCode,
    /// Stable machine-readable error code.
    pub code: &'static str,
    /// Safe client-facing explanation supplied by the decision maker.
    pub reason: String,
    /// Flow or request identifier for correlation.
    pub request_id: String,
    /// Matched network rule, if any.
    pub rule_id: Option<String>,
}

impl LocalRejection {
    /// Constructs a rejection with a correlation identifier.
    #[must_use]
    pub fn new<R: Into<String>>(
        status: StatusCode,
        code: &'static str,
        reason: R,
        request_id: String,
    ) -> Self {
        Self {
            status,
            code,
            reason: reason.into(),
            request_id,
            rule_id: None,
        }
    }

    /// Sends the local error and closes the HTTP connection.
    ///
    /// # Errors
    /// Returns the client write or shutdown error.
    pub async fn response_error<W: AsyncWrite + Unpin>(
        &self,
        writer: &mut W,
    ) -> Result<(), TransparentFlowError> {
        let body = serde_json::json!({"error": {"source": "abyss-broker", "code": self.code, "message": self.reason, "request_id": self.request_id, "rule_id": self.rule_id}}).to_string();
        let head = format!(
            "HTTP/1.1 {}\r\nServer: abyss-broker\r\nX-Abyss-Blocked: true\r\nCache-Control: no-store\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.status,
            body.len()
        );
        writer
            .write_all(head.as_bytes())
            .await
            .map_err(|source| TransparentFlowError::Io {
                operation: FlowOperation::WriteAgentResponseHead,
                source,
            })?;
        writer
            .write_all(body.as_bytes())
            .await
            .map_err(|source| TransparentFlowError::Io {
                operation: FlowOperation::WriteAgentResponseBody,
                source,
            })?;
        writer
            .shutdown()
            .await
            .map_err(|source| TransparentFlowError::Io {
                operation: FlowOperation::ShutdownAgent,
                source,
            })
    }
}
