//! Internal MITM hook interface.
//!
//! `abyss-mitm` defines hook traits and event types, but it deliberately does
//! not implement product-specific hooks. Callers inject their own hook
//! implementations so higher layers can audit, classify, or upload HTTP
//! exchanges without coupling this crate to LLM provider semantics.

use std::{
    fmt,
    future::{self, Future},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
};

use bytes::Bytes;
use http::{Request, Response, header::HOST};
use parking_lot::Mutex;
use serde_json::Value;
use thiserror::Error;
use tokio::sync::mpsc;

use super::{FlowId, FlowIngress, OriginalDestination, TransparentFlowSource, TransparentProtocol};

const DEFAULT_HOOK_QUEUE_CAPACITY: usize = 1024;

/// Future returned by MITM hook callbacks.
///
/// Hooks are async because future observers may write to disk, send audit
/// events, or call an internal service. The transparent pipeline enqueues
/// complete exchanges and the background hook worker awaits these futures
/// outside the relay path.
pub type HookFuture<'a> = Pin<Box<dyn Future<Output = HookResult> + Send + 'a>>;

/// Result returned by MITM hook callbacks.
pub type HookResult = Result<(), HookError>;

/// Error returned by an injected MITM hook.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum HookError {
    /// Hook failed while processing an HTTP exchange.
    #[error("{message}")]
    Failed {
        /// Human-readable hook failure.
        message: String,
    },
}

impl HookError {
    /// Creates a hook error from a human-readable message.
    #[must_use]
    pub fn failed<T>(message: T) -> Self
    where
        T: Into<String>,
    {
        Self::Failed {
            message: message.into(),
        }
    }
}

/// Stable network metadata attached to a captured HTTP exchange.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct FlowContext {
    /// Stable identity of the physical connection observed by the ingress.
    pub flow_id: FlowId,
    /// Client socket address observed by the broker listener when available.
    pub peer_addr: Option<SocketAddr>,
    /// Local broker listener address for this accepted connection when available.
    pub local_addr: Option<SocketAddr>,
    /// Original remote endpoint captured before platform redirection.
    pub original_destination: OriginalDestination,
    /// Destination hostname recovered before DNS resolution, when available.
    pub destination_host: Option<String>,
    /// Decoded application protocol for this flow.
    pub protocol: TransparentProtocol,
    /// Optional source process metadata supplied by the platform adapter.
    pub source_process: Option<SourceProcess>,
    /// Normalized network ingress and explicit-proxy target, when applicable.
    pub ingress: FlowIngress,
}

impl FlowContext {
    /// Creates hook metadata for one transparent flow.
    #[must_use]
    pub fn new(
        peer_addr: SocketAddr,
        local_addr: SocketAddr,
        original_destination: OriginalDestination,
        protocol: TransparentProtocol,
    ) -> Self {
        Self {
            flow_id: FlowId::generate(),
            peer_addr: Some(peer_addr),
            local_addr: Some(local_addr),
            original_destination,
            destination_host: None,
            protocol,
            source_process: None,
            ingress: FlowIngress::transparent(TransparentFlowSource::Unattributed),
        }
    }

    /// Creates hook metadata from optional platform-observed socket addresses.
    #[must_use]
    pub fn from_optional_addrs(
        peer_addr: Option<SocketAddr>,
        local_addr: Option<SocketAddr>,
        original_destination: OriginalDestination,
        protocol: TransparentProtocol,
        source_process: Option<SourceProcess>,
    ) -> Self {
        Self {
            flow_id: FlowId::generate(),
            peer_addr,
            local_addr,
            original_destination,
            destination_host: None,
            protocol,
            source_process,
            ingress: FlowIngress::transparent(TransparentFlowSource::Unattributed),
        }
    }

    /// Replaces the generated identity with the platform-observed flow identity.
    #[must_use]
    pub const fn with_flow_id(mut self, flow_id: FlowId) -> Self {
        self.flow_id = flow_id;
        self
    }

    /// Attaches source process metadata supplied by the platform adapter.
    #[must_use]
    pub fn with_source_process(mut self, source_process: SourceProcess) -> Self {
        self.source_process = Some(source_process);
        self
    }

    /// Attaches normalized ingress metadata supplied with the accepted flow.
    #[must_use]
    pub fn with_ingress(mut self, ingress: FlowIngress) -> Self {
        self.ingress = ingress;
        self
    }

    /// Attaches the destination hostname recovered by the ingress adapter.
    #[must_use]
    pub fn with_destination_host(mut self, destination_host: Option<String>) -> Self {
        self.destination_host = destination_host;
        self
    }

    /// Returns the source process working directory when the platform captured it.
    #[must_use]
    pub fn source_working_directory(&self) -> Option<&str> {
        self.source_process
            .as_ref()
            .and_then(|source| source.working_directory.as_deref())
    }

    pub(super) fn validate_http_target(
        &self,
        request: &Request<()>,
    ) -> Result<(), super::TransparentFlowError> {
        let Some(target) = self.ingress.proxy_target() else {
            return Ok(());
        };
        if request.uri().scheme().is_some() || request.uri().authority().is_some() {
            return Err(super::TransparentFlowError::ProxyTargetRequestForm {
                target: target.authority(),
            });
        }
        let mut host_values = request.headers().get_all(HOST).iter();
        let Some(host) = host_values.next() else {
            return Err(super::TransparentFlowError::ProxyTargetHostMismatch {
                target: target.authority(),
            });
        };
        if host_values.next().is_some() {
            return Err(super::TransparentFlowError::ProxyTargetHostMismatch {
                target: target.authority(),
            });
        }
        let default_port = match self.protocol {
            TransparentProtocol::PlainHttp => 80,
            TransparentProtocol::TlsHttp { .. } => 443,
        };
        if host
            .to_str()
            .is_ok_and(|host| target.matches_http_authority(host, default_port))
        {
            return Ok(());
        }
        Err(super::TransparentFlowError::ProxyTargetHostMismatch {
            target: target.authority(),
        })
    }
}

/// Source process metadata attached to a redirected flow.
///
/// Platform adapters populate this when the operating system can attribute a
/// redirected connection to a local process. The fields are optional because
/// different interception APIs expose different levels of process identity.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SourceProcess {
    /// Operating-system process identifier.
    pub pid: Option<u32>,
    /// Kernel process incarnation identifier when the platform exposes one.
    pub pid_version: Option<u32>,
    /// Human-readable process name such as `codex`.
    pub name: Option<String>,
    /// Executable path as reported by the platform adapter.
    pub executable_path: Option<String>,
    /// Platform-normalized source application identity when available.
    ///
    /// macOS adapters supply the source bundle or signing identifier. Windows
    /// adapters supply the native application identifier.
    pub application_id: Option<String>,
    /// Best-effort process working directory captured by the platform adapter.
    pub working_directory: Option<String>,
}

impl SourceProcess {
    /// Creates source process metadata from optional platform fields.
    #[must_use]
    pub const fn new(
        pid: Option<u32>,
        name: Option<String>,
        executable_path: Option<String>,
    ) -> Self {
        Self {
            pid,
            pid_version: None,
            name,
            executable_path,
            application_id: None,
            working_directory: None,
        }
    }

    /// Attaches a kernel process incarnation identifier.
    #[must_use]
    pub const fn with_pid_version(mut self, pid_version: Option<u32>) -> Self {
        self.pid_version = pid_version;
        self
    }

    /// Attaches a platform-normalized source application identity.
    #[must_use]
    pub fn with_application_id(mut self, application_id: Option<String>) -> Self {
        self.application_id = application_id;
        self
    }

    /// Attaches a best-effort process working directory.
    #[must_use]
    pub fn with_working_directory(mut self, working_directory: Option<String>) -> Self {
        self.working_directory = working_directory;
        self
    }
}

/// Captured HTTP body made available to hooks.
///
/// The bytes may be a configured-size prefix of the decoded HTTP body when the
/// original message exceeded the relay capture budget. Network relay remains
/// independent from this representation and still forwards the full body.
#[derive(Debug, Clone)]
pub struct CapturedBody {
    /// Decoded HTTP body bytes retained for hooks.
    bytes: Bytes,
    /// Whether the original decoded body exceeded the hook capture budget.
    truncated: bool,
    /// Best-effort structured view for JSON object/array payloads.
    ///
    /// Non-JSON payloads stay available through `bytes`; hooks should treat this
    /// as optional enrichment rather than a replacement for the raw body.
    json: Option<Value>,
}

impl CapturedBody {
    /// Builds a captured body and parses JSON when the bytes represent a JSON
    /// object or array.
    #[must_use]
    pub fn from_bytes(bytes: Bytes) -> Self {
        Self {
            json: parse_json_body(&bytes),
            bytes,
            truncated: false,
        }
    }

    /// Builds a captured body prefix for a message whose full body exceeded the
    /// hook capture budget.
    #[must_use]
    pub fn from_truncated_bytes(bytes: Bytes) -> Self {
        Self {
            json: parse_json_body(&bytes),
            bytes,
            truncated: true,
        }
    }

    /// Raw decoded HTTP body bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Shared raw decoded HTTP body bytes.
    #[must_use]
    pub const fn bytes_ref(&self) -> &Bytes {
        &self.bytes
    }

    /// Parsed JSON body when the payload is a JSON object or array.
    #[must_use]
    pub const fn json(&self) -> Option<&Value> {
        self.json.as_ref()
    }

    /// Whether the captured bytes are only a prefix of the decoded HTTP body.
    #[must_use]
    pub const fn truncated(&self) -> bool {
        self.truncated
    }
}

/// One complete proxied HTTP request/response pair.
///
/// This is the event boundary exposed by `abyss-mitm`: hooks observe network
/// exchanges, not product-specific LLM concepts. Higher-level crates can map
/// these structured HTTP messages into their own domain model.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct HttpExchange {
    /// Network-level flow metadata.
    pub flow: FlowContext,
    /// Captured request with structured HTTP metadata and body.
    pub request: Request<CapturedBody>,
    /// Captured response with structured HTTP metadata and body.
    pub response: Response<CapturedBody>,
}

impl HttpExchange {
    /// Creates one complete HTTP exchange for hook dispatch.
    #[must_use]
    pub const fn new(
        flow: FlowContext,
        request: Request<CapturedBody>,
        response: Response<CapturedBody>,
    ) -> Self {
        Self {
            flow,
            request,
            response,
        }
    }
}

/// Direction of a decoded WebSocket message.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum WebSocketDirection {
    /// Message sent by the local client toward the original upstream.
    ClientToServer,
    /// Message sent by the original upstream back to the local client.
    ServerToClient,
}

/// Decoded WebSocket message observed after an HTTP 101 upgrade.
///
/// WebSocket is a message stream rather than a request/response exchange. The
/// MITM layer exposes each message to hooks and leaves higher-level correlation
/// to product crates such as `abyss-agent-hook`.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct WebSocketMessage {
    /// Network-level flow metadata.
    pub flow: FlowContext,
    /// HTTP request that upgraded this flow to WebSocket.
    ///
    /// The upgraded request supplies host/path/method context for hooks, while
    /// filtering still happens at the flow level through [`MitmHook::matches`].
    pub upgrade_request: Request<()>,
    /// Message direction inside the upgraded WebSocket tunnel.
    pub direction: WebSocketDirection,
    /// Per-flow monotonically increasing message sequence number.
    pub sequence: u64,
    /// Text payload when the frame sequence represents a text message.
    pub text: Option<String>,
    /// Binary payload when the frame sequence represents a binary message.
    pub binary: Option<Bytes>,
}

impl WebSocketMessage {
    /// Creates a decoded WebSocket message event.
    #[must_use]
    pub const fn new(
        flow: FlowContext,
        upgrade_request: Request<()>,
        direction: WebSocketDirection,
        sequence: u64,
        text: Option<String>,
        binary: Option<Bytes>,
    ) -> Self {
        Self {
            flow,
            upgrade_request,
            direction,
            sequence,
            text,
            binary,
        }
    }
}

/// Internal extension point for complete HTTP exchanges.
pub trait MitmHook: Send + Sync {
    /// Returns whether this hook is globally enabled.
    ///
    /// This gate is evaluated before flow-level matching. Product-specific hook
    /// configuration should use this for broad runtime enable/disable switches,
    /// while [`Self::matches`] should stay focused on flow metadata.
    fn enabled(&self) -> bool {
        true
    }

    /// Returns whether this hook wants to observe a flow.
    ///
    /// Filtering is deliberately limited to stable flow metadata: peer/local
    /// addresses, original destination, decoded protocol, SNI, and optional
    /// process attribution. HTTP-path-specific filtering belongs inside the
    /// callback that sees the decoded HTTP message.
    fn matches(&self, _flow: &FlowContext) -> bool {
        true
    }

    /// Observes one complete proxied HTTP exchange.
    ///
    /// The callback is observe-only in the current implementation. Returning an
    /// error is logged by the background hook worker and does not fail or slow
    /// the already-relayed client flow.
    fn on_http_exchange<'a>(&'a self, _exchange: &'a HttpExchange) -> HookFuture<'a> {
        Box::pin(future::ready(Ok(())))
    }

    /// Observes one decoded WebSocket message after a successful HTTP 101.
    ///
    /// The callback is observe-only. Hooks that need request/response semantics
    /// should correlate messages by flow and provider-specific ids.
    fn on_websocket_message<'a>(&'a self, _message: &'a WebSocketMessage) -> HookFuture<'a> {
        Box::pin(future::ready(Ok(())))
    }
}

/// Non-blocking hook event dispatcher.
///
/// The relay path owns the network latency budget, so it only submits owned
/// `HttpExchange` events into a bounded queue. A background worker drains that
/// queue and runs the injected hooks.
pub(super) struct HookDispatcher {
    chain: HookChain,
    sender: std::sync::OnceLock<mpsc::Sender<HookEvent>>,
    queue_capacity: usize,
}

impl Default for HookDispatcher {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_HOOK_QUEUE_CAPACITY)
    }
}

impl HookDispatcher {
    /// Creates a dispatcher with a bounded event queue.
    fn with_capacity(queue_capacity: usize) -> Self {
        Self {
            chain: HookChain::default(),
            sender: std::sync::OnceLock::new(),
            queue_capacity,
        }
    }

    /// Appends one hook to the background chain.
    pub(super) fn push<H>(&self, hook: H)
    where
        H: MitmHook + 'static,
    {
        self.chain.push(hook);
    }

    /// Submits one completed exchange without waiting for hook execution.
    ///
    /// Queue pressure is handled by dropping audit events instead of blocking
    /// traffic. The warning includes enough metadata to diagnose dropped hook
    /// events without retaining the full body payload in logs.
    #[tracing::instrument(level = "trace", skip_all)]
    pub(super) fn submit(&self, exchange: HttpExchange) -> HookDispatchStatus {
        self.submit_event(HookEvent::HttpExchange(exchange))
    }

    /// Submits one WebSocket message without waiting for hook execution.
    #[tracing::instrument(level = "trace", skip_all)]
    pub(super) fn submit_websocket_message(&self, message: WebSocketMessage) -> HookDispatchStatus {
        self.submit_event(HookEvent::WebSocketMessage(message))
    }

    #[tracing::instrument(level = "trace", skip_all)]
    fn submit_event(&self, event: HookEvent) -> HookDispatchStatus {
        if self.chain.is_empty() {
            return HookDispatchStatus::NoHooks;
        }

        // Lazily start the worker only after the first hook is registered and
        // the first exchange arrives. Most tests and deployments without audit
        // hooks then pay no background-task cost.
        let sender = self.sender.get_or_init(|| self.spawn_worker());
        match sender.try_send(event) {
            Ok(()) => HookDispatchStatus::Enqueued,
            Err(mpsc::error::TrySendError::Full(event)) => {
                event.log_drop("MITM hook queue full; dropped hook audit event");
                HookDispatchStatus::Dropped
            }
            Err(mpsc::error::TrySendError::Closed(event)) => {
                event.log_drop("MITM hook worker stopped; dropped hook audit event");
                HookDispatchStatus::Closed
            }
        }
    }

    fn spawn_worker(&self) -> mpsc::Sender<HookEvent> {
        let (sender, receiver) = mpsc::channel(self.queue_capacity);
        let chain = self.chain.clone();
        tokio::spawn(async move {
            run_hook_worker(chain, receiver).await;
        });
        sender
    }
}

impl fmt::Debug for HookDispatcher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HookDispatcher")
            .field("hook_count", &self.chain.hook_count())
            .field("queue_capacity", &self.queue_capacity)
            .field("worker_started", &self.sender.get().is_some())
            .finish()
    }
}

#[tracing::instrument(level = "trace", skip_all)]
async fn run_hook_worker(chain: HookChain, mut receiver: mpsc::Receiver<HookEvent>) {
    while let Some(event) = receiver.recv().await {
        // The worker logs individual hook failures inside `HookChain`. Drop the
        // aggregate result here because relay already completed and hook errors
        // must not feed back into the network path.
        match event {
            HookEvent::HttpExchange(exchange) => {
                drop(chain.on_http_exchange(&exchange).await);
            }
            HookEvent::WebSocketMessage(message) => {
                drop(chain.on_websocket_message(&message).await);
            }
        }
    }
}

#[derive(Debug)]
enum HookEvent {
    HttpExchange(HttpExchange),
    WebSocketMessage(WebSocketMessage),
}

impl HookEvent {
    fn log_drop(&self, message: &'static str) {
        match self {
            Self::HttpExchange(exchange) => {
                tracing::warn!(
                    peer_addr = ?exchange.flow.peer_addr,
                    original_destination = %exchange.flow.original_destination,
                    method = %exchange.request.method(),
                    target_path = %exchange.request.uri().path(),
                    "{message}"
                );
            }
            Self::WebSocketMessage(websocket_message) => {
                tracing::warn!(
                    peer_addr = ?websocket_message.flow.peer_addr,
                    original_destination = %websocket_message.flow.original_destination,
                    direction = ?websocket_message.direction,
                    sequence = websocket_message.sequence,
                    "{message}"
                );
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) enum HookDispatchStatus {
    NoHooks,
    Enqueued,
    Dropped,
    Closed,
}

/// Ordered collection of caller-injected MITM hooks.
#[derive(Clone, Default)]
pub(super) struct HookChain {
    /// Hooks are stored as trait objects so callers can inject implementations
    /// from crates outside `abyss-mitm` while this crate only depends on the
    /// trait contract.
    hooks: Arc<Mutex<Vec<Arc<dyn MitmHook>>>>,
}

impl HookChain {
    /// Appends one hook to the chain.
    pub(super) fn push<H>(&self, hook: H)
    where
        H: MitmHook + 'static,
    {
        self.hooks.lock().push(Arc::new(hook));
    }

    fn is_empty(&self) -> bool {
        self.hook_count() == 0
    }

    fn hook_count(&self) -> usize {
        self.hooks.lock().len()
    }

    fn snapshot(&self) -> Vec<Arc<dyn MitmHook>> {
        // Clone the Arc list and release the mutex before awaiting hooks. This
        // prevents a slow hook from blocking registration of future hooks and
        // avoids holding a synchronous mutex across `.await`.
        self.hooks.lock().clone()
    }

    /// Dispatches a completed HTTP exchange to every injected hook.
    ///
    /// Hook ordering is deterministic and matches insertion order. A failing
    /// hook must not suppress later observers; all hooks run to completion, each
    /// hook failure is logged with exchange context, and the last hook error is
    /// returned so callers can still observe that dispatch was not clean.
    #[tracing::instrument(level = "trace", skip_all)]
    pub(super) async fn on_http_exchange(&self, exchange: &HttpExchange) -> HookResult {
        let mut last_error = None;
        for (hook_index, hook) in self.snapshot().into_iter().enumerate() {
            if !hook.enabled() || !hook.matches(&exchange.flow) {
                continue;
            }

            if let Err(error) = hook.on_http_exchange(exchange).await {
                tracing::warn!(
                    hook_index,
                    peer_addr = ?exchange.flow.peer_addr,
                    original_destination = %exchange.flow.original_destination,
                    method = %exchange.request.method(),
                    target_path = %exchange.request.uri().path(),
                    %error,
                    "MITM hook failed while observing HTTP exchange"
                );
                last_error = Some(error);
            }
        }
        last_error.map_or(Ok(()), Err)
    }

    /// Dispatches a WebSocket message to every injected hook interested in the flow.
    ///
    /// Hook failures are isolated the same way as HTTP exchange failures: later
    /// hooks still run, each error is logged, and the last error is returned to
    /// the background worker for observability.
    #[tracing::instrument(level = "trace", skip_all)]
    pub(super) async fn on_websocket_message(&self, message: &WebSocketMessage) -> HookResult {
        let mut last_error = None;
        for (hook_index, hook) in self.snapshot().into_iter().enumerate() {
            if !hook.enabled() || !hook.matches(&message.flow) {
                continue;
            }

            if let Err(error) = hook.on_websocket_message(message).await {
                tracing::warn!(
                    hook_index,
                    peer_addr = ?message.flow.peer_addr,
                    original_destination = %message.flow.original_destination,
                    direction = ?message.direction,
                    sequence = message.sequence,
                    %error,
                    "MITM hook failed while observing WebSocket message"
                );
                last_error = Some(error);
            }
        }
        last_error.map_or(Ok(()), Err)
    }
}

impl fmt::Debug for HookChain {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HookChain")
            .field("hook_count", &self.hook_count())
            .finish()
    }
}

fn parse_json_body(bytes: &[u8]) -> Option<Value> {
    let trimmed = trim_ascii_whitespace(bytes);
    if !matches!(trimmed.first(), Some(b'{' | b'[')) {
        return None;
    }
    serde_json::from_slice(trimmed).ok()
}

fn trim_ascii_whitespace(bytes: &[u8]) -> &[u8] {
    let leading = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let trailing = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(leading, |index| index.saturating_add(1));
    &bytes[leading..trailing]
}

#[cfg(test)]
mod tests {
    use std::{future, net::SocketAddr};

    use bytes::Bytes;
    use http::{HeaderValue, Request, Response, header::HOST};
    use tokio::sync::mpsc;

    use super::{
        CapturedBody, FlowContext, HookChain, HookDispatchStatus, HookDispatcher, HookFuture,
        HookResult, HttpExchange, MitmHook, SourceProcess, WebSocketDirection, WebSocketMessage,
    };
    use crate::{
        ExplicitRequestDecoder,
        transparent::{FlowIngress, OriginalDestination, TransparentProtocol},
    };

    #[tokio::test]
    async fn explicit_http_target_accepts_matching_host() {
        let tls = explicit_context(
            443,
            TransparentProtocol::TlsHttp {
                server_name: "api.example.test".to_owned(),
            },
        )
        .await;
        let request = Request::builder()
            .uri("/v1/messages")
            .header(HOST, "api.example.test")
            .body(())
            .expect("matching request should build");

        assert!(tls.validate_http_target(&request).is_ok());

        let plain = explicit_context(80, TransparentProtocol::PlainHttp).await;
        assert!(plain.validate_http_target(&request).is_ok());
    }

    #[tokio::test]
    async fn explicit_dns_target_requires_matching_tls_server_name() {
        let context = explicit_context(
            443,
            TransparentProtocol::TlsHttp {
                server_name: "api.example.test".to_owned(),
            },
        )
        .await;

        assert!(
            context
                .ingress
                .validate_tls_server_name(Some("API.EXAMPLE.TEST"))
                .is_ok()
        );
        assert!(matches!(
            context
                .ingress
                .validate_tls_server_name(Some("other.example.test"))
                .expect_err("mismatched SNI should fail"),
            crate::TransparentFlowError::ProxyTargetServerNameMismatch { .. }
        ));
        assert!(matches!(
            context
                .ingress
                .validate_tls_server_name(None)
                .expect_err("missing SNI should fail for a DNS target"),
            crate::TransparentFlowError::MissingSni
        ));
    }

    #[tokio::test]
    async fn explicit_http_target_rejects_mismatched_missing_and_duplicate_host() {
        let context = explicit_context(
            443,
            TransparentProtocol::TlsHttp {
                server_name: "api.example.test".to_owned(),
            },
        )
        .await;
        let mismatch = Request::builder()
            .uri("/v1/messages")
            .header(HOST, "other.example.test")
            .body(())
            .expect("mismatched request should build");
        let missing = Request::builder()
            .uri("/v1/messages")
            .body(())
            .expect("missing-host request should build");
        let mut duplicate = Request::builder()
            .uri("/v1/messages")
            .header(HOST, "api.example.test")
            .body(())
            .expect("duplicate-host request should build");
        duplicate
            .headers_mut()
            .append(HOST, HeaderValue::from_static("api.example.test"));

        for request in [&mismatch, &missing, &duplicate] {
            let error = context
                .validate_http_target(request)
                .expect_err("invalid explicit Host should fail");
            assert!(matches!(
                error,
                crate::TransparentFlowError::ProxyTargetHostMismatch { .. }
            ));
        }

        let absolute = Request::builder()
            .uri("http://other.example.test/v1/messages?api_key=secret")
            .header(HOST, "api.example.test")
            .body(())
            .expect("absolute-form inner request should build");
        assert!(matches!(
            context
                .validate_http_target(&absolute)
                .expect_err("absolute-form request inside CONNECT should fail"),
            crate::TransparentFlowError::ProxyTargetRequestForm { .. }
        ));
    }

    #[test]
    fn transparent_http_target_does_not_apply_explicit_host_rules() {
        let context = FlowContext::new(
            SocketAddr::from(([127, 0, 0, 1], 50000)),
            SocketAddr::from(([127, 0, 0, 1], 18090)),
            OriginalDestination::from(SocketAddr::from(([127, 0, 0, 1], 80))),
            TransparentProtocol::PlainHttp,
        );
        let request = Request::builder()
            .uri("/")
            .body(())
            .expect("transparent request should build");

        assert!(context.validate_http_target(&request).is_ok());
    }

    #[test]
    fn flow_context_exposes_captured_source_working_directory() {
        let context = FlowContext::new(
            SocketAddr::from(([127, 0, 0, 1], 50000)),
            SocketAddr::from(([127, 0, 0, 1], 18090)),
            OriginalDestination::from(SocketAddr::from(([127, 0, 0, 1], 443))),
            TransparentProtocol::TlsHttp {
                server_name: "api.example.test".to_owned(),
            },
        )
        .with_source_process(
            SourceProcess::new(Some(42), Some("codex".to_owned()), None)
                .with_working_directory(Some("/Users/alice/repo".to_owned())),
        );

        assert_eq!(
            context.source_working_directory(),
            Some("/Users/alice/repo")
        );
    }

    #[test]
    fn flow_context_reports_missing_source_working_directory() {
        let context = FlowContext::new(
            SocketAddr::from(([127, 0, 0, 1], 50000)),
            SocketAddr::from(([127, 0, 0, 1], 18090)),
            OriginalDestination::from(SocketAddr::from(([127, 0, 0, 1], 443))),
            TransparentProtocol::PlainHttp,
        );

        assert_eq!(context.source_working_directory(), None);
    }

    #[test]
    fn captured_body_exposes_json_when_payload_is_json() {
        let body = CapturedBody::from_bytes(Bytes::from_static(br#" {"ok": true} "#));

        assert_eq!(
            body.json().and_then(|json| json.get("ok")),
            Some(&true.into())
        );
        assert_eq!(body.bytes(), br#" {"ok": true} "#);
    }

    #[test]
    fn captured_body_keeps_non_json_as_bytes_only() {
        let body = CapturedBody::from_bytes(Bytes::from_static(b"plain text"));

        assert!(body.json().is_none(), "plain text should not parse as JSON");
        assert_eq!(body.bytes(), b"plain text");
    }

    #[test]
    fn dispatcher_skips_work_when_no_hooks_are_registered() {
        assert_eq!(
            HookDispatcher::with_capacity(1).submit(test_exchange("/no-hooks")),
            HookDispatchStatus::NoHooks
        );
    }

    #[tokio::test]
    async fn dispatcher_drops_exchange_when_queue_is_full() {
        let (started, mut started_events) = mpsc::unbounded_channel();
        let dispatcher = HookDispatcher::with_capacity(1);
        dispatcher.push(BlockingHook { started });

        assert_eq!(
            dispatcher.submit(test_exchange("/first")),
            HookDispatchStatus::Enqueued
        );
        started_events
            .recv()
            .await
            .expect("blocking hook should start on first exchange");

        assert_eq!(
            dispatcher.submit(test_exchange("/queued")),
            HookDispatchStatus::Enqueued
        );
        assert_eq!(
            dispatcher.submit(test_exchange("/dropped")),
            HookDispatchStatus::Dropped
        );
    }

    #[tokio::test]
    async fn hook_chain_runs_later_hooks_after_error() {
        let chain = HookChain::default();
        let (observed_sender, mut observed_events) = mpsc::unbounded_channel::<&'static str>();
        chain.push(FailingHook {
            message: "first hook failed",
            observed: Some(observed_sender.clone()),
        });
        chain.push(RecordingHook {
            observed: observed_sender.clone(),
        });
        chain.push(FailingHook {
            message: "last hook failed",
            observed: Some(observed_sender),
        });

        let error = chain
            .on_http_exchange(&test_exchange("/hook-error"))
            .await
            .expect_err("hook chain should return the failing hook error");

        assert!(
            error.to_string().contains("last hook failed"),
            "hook chain should return the last observed hook error"
        );
        assert_eq!(
            observed_events
                .try_recv()
                .expect("first failing hook should run"),
            "first hook failed"
        );
        assert_eq!(
            observed_events
                .try_recv()
                .expect("later successful hook should still observe the exchange"),
            "observed"
        );
        assert_eq!(
            observed_events
                .try_recv()
                .expect("later failing hook should still observe the exchange"),
            "last hook failed"
        );
    }

    #[tokio::test]
    async fn hook_chain_uses_flow_level_matches_before_http_callback() {
        let chain = HookChain::default();
        let (observed_sender, mut observed_events) = mpsc::unbounded_channel::<&'static str>();
        chain.push(MatchingHook {
            should_match: false,
            observed: observed_sender.clone(),
        });
        chain.push(MatchingHook {
            should_match: true,
            observed: observed_sender,
        });

        chain
            .on_http_exchange(&test_exchange("/matched"))
            .await
            .expect("matched hook should succeed");

        assert_eq!(
            observed_events
                .try_recv()
                .expect("only the matching hook should observe the exchange"),
            "matched"
        );
        assert!(
            observed_events.try_recv().is_err(),
            "unmatched hook should not run"
        );
    }

    #[tokio::test]
    async fn hook_chain_skips_disabled_http_hooks_before_matching() {
        let chain = HookChain::default();
        let (observed_sender, mut observed_events) = mpsc::unbounded_channel::<&'static str>();
        chain.push(DisabledHook {
            observed: observed_sender.clone(),
        });
        chain.push(RecordingHook {
            observed: observed_sender,
        });

        chain
            .on_http_exchange(&test_exchange("/disabled-hook"))
            .await
            .expect("enabled hook should succeed");

        assert_eq!(
            observed_events
                .try_recv()
                .expect("enabled hook should still observe the exchange"),
            "observed"
        );
        assert!(
            observed_events.try_recv().is_err(),
            "disabled hook should not run matches or callback"
        );
    }

    #[tokio::test]
    async fn hook_chain_runs_later_websocket_hooks_after_error() {
        let chain = HookChain::default();
        let (observed_sender, mut observed_events) = mpsc::unbounded_channel::<&'static str>();
        chain.push(FailingWebSocketHook {
            message: "first websocket hook failed",
            observed: observed_sender.clone(),
        });
        chain.push(RecordingWebSocketHook {
            observed: observed_sender,
        });

        let error = chain
            .on_websocket_message(&test_websocket_message("hello"))
            .await
            .expect_err("websocket hook chain should return the failing hook error");

        assert!(
            error.to_string().contains("first websocket hook failed"),
            "websocket hook chain should return the observed hook error"
        );
        assert_eq!(
            observed_events
                .try_recv()
                .expect("first failing websocket hook should run"),
            "first websocket hook failed"
        );
        assert_eq!(
            observed_events
                .try_recv()
                .expect("later websocket hook should still observe the message"),
            "websocket observed"
        );
    }

    #[tokio::test]
    async fn hook_chain_skips_disabled_websocket_hooks_before_matching() {
        let chain = HookChain::default();
        let (observed_sender, mut observed_events) = mpsc::unbounded_channel::<&'static str>();
        chain.push(DisabledHook {
            observed: observed_sender.clone(),
        });
        chain.push(RecordingWebSocketHook {
            observed: observed_sender,
        });

        chain
            .on_websocket_message(&test_websocket_message("hello"))
            .await
            .expect("enabled websocket hook should succeed");

        assert_eq!(
            observed_events
                .try_recv()
                .expect("enabled websocket hook should still observe the message"),
            "websocket observed"
        );
        assert!(
            observed_events.try_recv().is_err(),
            "disabled hook should not run matches or callback"
        );
    }

    struct BlockingHook {
        started: mpsc::UnboundedSender<()>,
    }

    impl MitmHook for BlockingHook {
        fn on_http_exchange<'a>(&'a self, _exchange: &'a HttpExchange) -> HookFuture<'a> {
            let _send_result = self.started.send(());
            Box::pin(future::pending::<HookResult>())
        }
    }

    struct FailingHook {
        message: &'static str,
        observed: Option<mpsc::UnboundedSender<&'static str>>,
    }

    impl MitmHook for FailingHook {
        fn on_http_exchange<'a>(&'a self, _exchange: &'a HttpExchange) -> HookFuture<'a> {
            if let Some(observed) = &self.observed {
                let _send_result = observed.send(self.message);
            }
            Box::pin(future::ready(Err(super::HookError::failed(self.message))))
        }
    }

    struct RecordingHook {
        observed: mpsc::UnboundedSender<&'static str>,
    }

    impl MitmHook for RecordingHook {
        fn on_http_exchange<'a>(&'a self, _exchange: &'a HttpExchange) -> HookFuture<'a> {
            let _send_result = self.observed.send("observed");
            Box::pin(future::ready(Ok(())))
        }
    }

    struct DisabledHook {
        observed: mpsc::UnboundedSender<&'static str>,
    }

    impl MitmHook for DisabledHook {
        fn enabled(&self) -> bool {
            false
        }

        fn matches(&self, _flow: &FlowContext) -> bool {
            let _send_result = self.observed.send("disabled matched");
            true
        }

        fn on_http_exchange<'a>(&'a self, _exchange: &'a HttpExchange) -> HookFuture<'a> {
            let _send_result = self.observed.send("disabled http");
            Box::pin(future::ready(Ok(())))
        }

        fn on_websocket_message<'a>(&'a self, _message: &'a WebSocketMessage) -> HookFuture<'a> {
            let _send_result = self.observed.send("disabled websocket");
            Box::pin(future::ready(Ok(())))
        }
    }

    struct MatchingHook {
        should_match: bool,
        observed: mpsc::UnboundedSender<&'static str>,
    }

    impl MitmHook for MatchingHook {
        fn matches(&self, _flow: &FlowContext) -> bool {
            self.should_match
        }

        fn on_http_exchange<'a>(&'a self, _exchange: &'a HttpExchange) -> HookFuture<'a> {
            let _send_result = self.observed.send("matched");
            Box::pin(future::ready(Ok(())))
        }
    }

    struct FailingWebSocketHook {
        message: &'static str,
        observed: mpsc::UnboundedSender<&'static str>,
    }

    impl MitmHook for FailingWebSocketHook {
        fn on_websocket_message<'a>(&'a self, _message: &'a WebSocketMessage) -> HookFuture<'a> {
            let _send_result = self.observed.send(self.message);
            Box::pin(future::ready(Err(super::HookError::failed(self.message))))
        }
    }

    struct RecordingWebSocketHook {
        observed: mpsc::UnboundedSender<&'static str>,
    }

    impl MitmHook for RecordingWebSocketHook {
        fn on_websocket_message<'a>(&'a self, _message: &'a WebSocketMessage) -> HookFuture<'a> {
            let _send_result = self.observed.send("websocket observed");
            Box::pin(future::ready(Ok(())))
        }
    }

    async fn explicit_context(port: u16, protocol: TransparentProtocol) -> FlowContext {
        let request = format!(
            "CONNECT api.example.test:{port} HTTP/1.1\r\nHost: api.example.test:{port}\r\n\r\n"
        );
        let mut input = request.as_bytes();
        let decoded = ExplicitRequestDecoder::default()
            .decode(&mut input)
            .await
            .expect("explicit target fixture should decode");
        let (target, proxy_protocol, _prefix) = decoded.into_parts();
        FlowContext::new(
            SocketAddr::from(([127, 0, 0, 1], 50000)),
            SocketAddr::from(([127, 0, 0, 1], 28999)),
            OriginalDestination::from(SocketAddr::from(([127, 0, 0, 1], port))),
            protocol,
        )
        .with_ingress(FlowIngress::ExplicitProxy {
            protocol: proxy_protocol,
            target,
        })
    }

    fn test_exchange(path: &'static str) -> HttpExchange {
        HttpExchange {
            flow: FlowContext::new(
                SocketAddr::from(([127, 0, 0, 1], 50000)),
                SocketAddr::from(([127, 0, 0, 1], 18090)),
                OriginalDestination::from(SocketAddr::from(([127, 0, 0, 1], 443))),
                TransparentProtocol::PlainHttp,
            ),
            request: Request::builder()
                .method("POST")
                .uri(path)
                .body(CapturedBody::from_bytes(Bytes::from_static(br#"{"n":1}"#)))
                .expect("test request should build"),
            response: Response::builder()
                .status(200)
                .body(CapturedBody::from_bytes(Bytes::from_static(
                    br#"{"ok":true}"#,
                )))
                .expect("test response should build"),
        }
    }

    fn test_websocket_message(text: &'static str) -> WebSocketMessage {
        WebSocketMessage {
            flow: FlowContext::new(
                SocketAddr::from(([127, 0, 0, 1], 50000)),
                SocketAddr::from(([127, 0, 0, 1], 18090)),
                OriginalDestination::from(SocketAddr::from(([127, 0, 0, 1], 443))),
                TransparentProtocol::TlsHttp {
                    server_name: "chatgpt.com".to_owned(),
                },
            ),
            upgrade_request: Request::builder()
                .method("GET")
                .uri("/backend-api/codex/responses")
                .body(())
                .expect("test websocket upgrade request should build"),
            direction: WebSocketDirection::ClientToServer,
            sequence: 1,
            text: Some(text.to_owned()),
            binary: None,
        }
    }
}
