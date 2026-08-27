//! Shared transparent proxy data types.
//!
//! These types are the boundary between platform redirection adapters and the
//! MITM stream pipeline. Platform code supplies duplex byte IO plus the original
//! destination; the pipeline returns decoded HTTP metadata and relay byte
//! counts.

use std::{
    fmt,
    io::ErrorKind,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use http::{Request, Response};
use serde::Serialize;
use thiserror::Error;
use tokio::io;

use crate::{
    ExplicitProxyProtocol, TargetAuthority, TargetHost, http1::Http1Error, tls::TlsMitmError,
};

use super::{decrypt_policy::TlsDecryptionPolicyError, hook::CapturedBody};

/// Original remote endpoint captured before the OS redirected the connection.
#[derive(Debug, Clone)]
pub struct OriginalDestination {
    /// Original remote IP address.
    pub ip: IpAddr,
    /// Original remote TCP port.
    pub port: u16,
}

/// Network ingress that supplied a flow to the shared MITM pipeline.
///
/// Keeping this distinction in the shared core lets hooks and diagnostics
/// retain proxy-request context without depending on any operating-system
/// interception API.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum FlowIngress {
    /// A platform adapter supplied an already redirected connection.
    Transparent {
        /// Typed adapter family that recovered the redirected flow.
        source: TransparentFlowSource,
    },
    /// A local client connected through the broker's explicit HTTP proxy.
    ExplicitProxy {
        /// Explicit proxy request form used to establish the flow.
        protocol: ExplicitProxyProtocol,
        /// Authority requested by the proxy client before DNS resolution.
        target: TargetAuthority,
    },
}

/// Transparent adapter family that supplied a normalized flow.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum TransparentFlowSource {
    /// macOS Network Extension transparent proxy bridge.
    MacosNetworkExtension,
    /// Windows WFP connect-redirection adapter.
    WindowsWfp,
    /// Future Linux transparent interception adapter.
    LinuxTransparent,
    /// Embedded or test caller without a platform attribution.
    Unattributed,
}

/// Side that produced a TLS configuration or validation error.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum TlsErrorSide {
    /// TLS termination between the client Agent and Abyss.
    Client,
    /// TLS establishment between Abyss and the upstream provider.
    Upstream,
}

/// Concrete transport operation that produced a flow error.
///
/// The operation is assigned at the I/O or protocol boundary where the error
/// occurs. It is deliberately more precise than a request/response label: a
/// request can be read from the Agent, written to the provider, or fail while
/// its body is being relayed in either direction.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum FlowOperation {
    /// Read the initial bytes used to detect the Agent protocol.
    ReadAgentProtocol,
    /// Read the Agent TLS `ClientHello`.
    ReadAgentTlsClientHello,
    /// Accept the TLS connection from the Agent.
    AcceptAgentTls,
    /// Read the first HTTP/1 request head from the Agent.
    ReadAgentRequestHead,
    /// Read the Agent HTTP/1 request body.
    ReadAgentRequestBody,
    /// Write the request head to the provider.
    WriteProviderRequestHead,
    /// Write the request body to the provider.
    WriteProviderRequestBody,
    /// Write a locally generated `100 Continue` response to the Agent.
    WriteAgentContinueResponse,
    /// Connect to the provider's TCP endpoint.
    ConnectProviderTcp,
    /// Establish TLS between Abyss and the provider.
    ConnectProviderTls,
    /// Replay an inspected Agent TLS `ClientHello` to the provider.
    WriteProviderTlsClientHello,
    /// Read the first HTTP/1 response head from the provider.
    ReadProviderResponseHead,
    /// Read the provider HTTP/1 response body.
    ReadProviderResponseBody,
    /// Write the response head to the Agent.
    WriteAgentResponseHead,
    /// Write the response body to the Agent.
    WriteAgentResponseBody,
    /// Read WebSocket frames from the Agent.
    ReadAgentWebSocket,
    /// Write WebSocket frames to the provider.
    WriteProviderWebSocket,
    /// Read WebSocket frames from the provider.
    ReadProviderWebSocket,
    /// Write WebSocket frames to the Agent.
    WriteAgentWebSocket,
    /// Relay opaque passthrough bytes in both directions.
    RelayPassthrough,
    /// Shut down the Agent-side stream after a completed exchange.
    ShutdownAgent,
    /// Perform local relay bookkeeping without a network peer operation.
    LocalRelay,
}

impl FlowOperation {
    /// Returns the stable storage and IPC label for this operation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadAgentProtocol => "read_agent_protocol",
            Self::ReadAgentTlsClientHello => "read_agent_tls_client_hello",
            Self::AcceptAgentTls => "accept_agent_tls",
            Self::ReadAgentRequestHead => "read_agent_request_head",
            Self::ReadAgentRequestBody => "read_agent_request_body",
            Self::WriteProviderRequestHead => "write_provider_request_head",
            Self::WriteProviderRequestBody => "write_provider_request_body",
            Self::WriteAgentContinueResponse => "write_agent_continue_response",
            Self::ConnectProviderTcp => "connect_provider_tcp",
            Self::ConnectProviderTls => "connect_provider_tls",
            Self::WriteProviderTlsClientHello => "write_provider_tls_client_hello",
            Self::ReadProviderResponseHead => "read_provider_response_head",
            Self::ReadProviderResponseBody => "read_provider_response_body",
            Self::WriteAgentResponseHead => "write_agent_response_head",
            Self::WriteAgentResponseBody => "write_agent_response_body",
            Self::ReadAgentWebSocket => "read_agent_websocket",
            Self::WriteProviderWebSocket => "write_provider_websocket",
            Self::ReadProviderWebSocket => "read_provider_websocket",
            Self::WriteAgentWebSocket => "write_agent_websocket",
            Self::RelayPassthrough => "relay_passthrough",
            Self::ShutdownAgent => "shutdown_agent",
            Self::LocalRelay => "local_relay",
        }
    }

    /// Parses a stable storage and IPC label.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "read_agent_protocol" => Self::ReadAgentProtocol,
            "read_agent_tls_client_hello" => Self::ReadAgentTlsClientHello,
            "accept_agent_tls" => Self::AcceptAgentTls,
            "read_agent_request_head" => Self::ReadAgentRequestHead,
            "read_agent_request_body" => Self::ReadAgentRequestBody,
            "write_provider_request_head" => Self::WriteProviderRequestHead,
            "write_provider_request_body" => Self::WriteProviderRequestBody,
            "write_agent_continue_response" => Self::WriteAgentContinueResponse,
            "connect_provider_tcp" => Self::ConnectProviderTcp,
            "connect_provider_tls" => Self::ConnectProviderTls,
            "write_provider_tls_client_hello" => Self::WriteProviderTlsClientHello,
            "read_provider_response_head" => Self::ReadProviderResponseHead,
            "read_provider_response_body" => Self::ReadProviderResponseBody,
            "write_agent_response_head" => Self::WriteAgentResponseHead,
            "write_agent_response_body" => Self::WriteAgentResponseBody,
            "read_agent_websocket" => Self::ReadAgentWebSocket,
            "write_provider_websocket" => Self::WriteProviderWebSocket,
            "read_provider_websocket" => Self::ReadProviderWebSocket,
            "write_agent_websocket" => Self::WriteAgentWebSocket,
            "relay_passthrough" => Self::RelayPassthrough,
            "shutdown_agent" => Self::ShutdownAgent,
            "local_relay" => Self::LocalRelay,
            _ => return None,
        })
    }
}

impl fmt::Display for FlowOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FlowIngress {
    /// Creates transparent ingress metadata for a concrete adapter family.
    #[must_use]
    pub const fn transparent(source: TransparentFlowSource) -> Self {
        Self::Transparent { source }
    }

    /// Returns the stable ingress source label used by diagnostics and audit metadata.
    #[must_use]
    pub const fn source_label(&self) -> &'static str {
        match self {
            Self::Transparent {
                source: TransparentFlowSource::MacosNetworkExtension,
            } => "macos_network_extension",
            Self::Transparent {
                source: TransparentFlowSource::WindowsWfp,
            } => "windows_wfp",
            Self::Transparent {
                source: TransparentFlowSource::LinuxTransparent,
            } => "linux_transparent",
            Self::Transparent {
                source: TransparentFlowSource::Unattributed,
            } => "unattributed_transparent",
            Self::ExplicitProxy { .. } => "explicit_proxy",
        }
    }

    /// Returns explicit proxy protocol metadata when this flow used that ingress.
    #[must_use]
    pub const fn proxy_protocol(&self) -> Option<ExplicitProxyProtocol> {
        match self {
            Self::ExplicitProxy { protocol, .. } => Some(*protocol),
            Self::Transparent { .. } => None,
        }
    }

    /// Returns the explicit proxy authority when this flow used that ingress.
    #[must_use]
    pub const fn proxy_target(&self) -> Option<&TargetAuthority> {
        match self {
            Self::ExplicitProxy { target, .. } => Some(target),
            Self::Transparent { .. } => None,
        }
    }

    pub(super) const fn requires_tls_server_name_validation(&self) -> bool {
        matches!(
            self,
            Self::ExplicitProxy {
                target,
                ..
            } if matches!(target.host(), TargetHost::Dns(_))
        )
    }

    pub(super) fn validate_tls_server_name(
        &self,
        server_name: Option<&str>,
    ) -> Result<(), TransparentFlowError> {
        let Self::ExplicitProxy { target, .. } = self else {
            return Ok(());
        };
        let TargetHost::Dns(target_name) = target.host() else {
            return Ok(());
        };
        let server_name = server_name.ok_or(TransparentFlowError::MissingSni)?;
        if target_name
            .trim_end_matches('.')
            .eq_ignore_ascii_case(server_name.trim_end_matches('.'))
        {
            return Ok(());
        }

        Err(TransparentFlowError::ProxyTargetServerNameMismatch {
            target: target.authority(),
            server_name: server_name.to_owned(),
        })
    }
}

/// Protocol selected for the first decoded HTTP request.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum TransparentProtocol {
    /// Plain HTTP over the redirected TCP connection.
    PlainHttp,
    /// HTTP decoded after terminating client TLS.
    TlsHttp {
        /// SNI value used for both client leaf signing and upstream TLS.
        server_name: String,
    },
}

/// Metadata and byte counts returned after an intercepted HTTP flow closes.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct InterceptedHttpOutcome {
    /// Client socket address observed by the broker listener when available.
    pub peer_addr: Option<SocketAddr>,
    /// Local broker listener address for this accepted connection when available.
    pub local_addr: Option<SocketAddr>,
    /// Original remote endpoint captured before platform redirection.
    pub original_destination: OriginalDestination,
    /// Decoded application protocol.
    pub protocol: TransparentProtocol,
    /// First HTTP/1 request observed on the decoded client stream.
    pub first_request: Request<CapturedBody>,
    /// First HTTP/1 response observed on the decoded upstream stream.
    pub first_response: Response<CapturedBody>,
    /// Bytes forwarded from client to upstream, including any buffered preface.
    pub client_to_upstream_bytes: u64,
    /// Bytes forwarded from upstream back to the client.
    pub upstream_to_client_bytes: u64,
}

/// Metadata and byte counts returned after a raw passthrough flow closes.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct TransparentPassthroughOutcome {
    /// Client socket address observed by the broker listener when available.
    pub peer_addr: Option<SocketAddr>,
    /// Local broker listener address for this accepted connection when available.
    pub local_addr: Option<SocketAddr>,
    /// Original remote endpoint captured before platform redirection.
    pub original_destination: OriginalDestination,
    /// Opaque protocol that was relayed without decryption.
    pub protocol: TransparentPassthroughProtocol,
    /// Bytes forwarded from client to upstream.
    pub client_to_upstream_bytes: u64,
    /// Bytes forwarded from upstream back to the client.
    pub upstream_to_client_bytes: u64,
}

/// Protocol metadata for a flow that was intentionally not decrypted.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum TransparentPassthroughProtocol {
    /// TLS was relayed as opaque bytes.
    Tls {
        /// SNI observed from `ClientHello` when available.
        server_name: Option<String>,
    },
}

/// Result of handling one transparent flow.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum TransparentFlowOutcome {
    /// The flow was decrypted and exposed as an HTTP exchange.
    Intercepted(Box<InterceptedHttpOutcome>),
    /// The flow was relayed without decryption.
    Passthrough(TransparentPassthroughOutcome),
}

/// Errors returned while handling a transparent flow.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TransparentFlowError {
    /// The client closed before enough bytes were available to classify.
    #[error("client closed before transparent protocol detection")]
    ClientClosedBeforeProtocol,
    /// The first bytes were neither TLS nor HTTP/1.
    #[error("unsupported transparent protocol")]
    UnsupportedProtocol,
    /// A TLS `ClientHello` did not include SNI.
    #[error("TLS ClientHello did not include SNI")]
    MissingSni,
    /// Client- or upstream-side TLS configuration or validation failed.
    #[error("TLS {side:?} error: {source}")]
    Tls {
        /// Side whose TLS operation produced the error.
        side: TlsErrorSide,
        /// Underlying TLS configuration or validation error.
        #[source]
        source: TlsMitmError,
    },
    /// TLS configuration failed before an accepted flow could be handled.
    #[error("TLS configuration error: {0}")]
    TlsConfiguration(#[source] TlsMitmError),
    /// HTTP/1 decoding failed at a known transport operation.
    #[error("HTTP/1 decode error during {operation}: {source}")]
    Http1 {
        /// Operation whose HTTP/1 decoder produced the error.
        operation: FlowOperation,
        /// Underlying HTTP/1 parsing or framing error.
        #[source]
        source: Http1Error,
    },
    /// WebSocket frame or message relay failed at a known operation.
    #[error("WebSocket relay error during {operation}: {source}")]
    WebSocket {
        /// Operation whose WebSocket relay produced the error.
        operation: FlowOperation,
        /// Underlying WebSocket error.
        #[source]
        source: tokio_tungstenite::tungstenite::Error,
    },
    /// An I/O operation failed.
    #[error("{operation}: {source}")]
    Io {
        /// Operation being performed.
        operation: FlowOperation,
        /// Source I/O error.
        #[source]
        source: io::Error,
    },
    /// An externally controlled operation exceeded its timeout budget.
    #[error("{operation} timed out after {timeout:?}")]
    Timeout {
        /// Operation being performed.
        operation: FlowOperation,
        /// Configured timeout budget.
        timeout: Duration,
    },
    /// Forwarded byte counters overflowed.
    #[error("transparent flow byte counters overflowed")]
    ByteCountOverflow,
    /// A TLS `ClientHello` exceeded the bounded inspection buffer.
    #[error("TLS ClientHello exceeded {limit} byte inspection limit: {size} bytes required")]
    TlsClientHelloTooLarge {
        /// Required bytes reported while parsing.
        size: usize,
        /// Configured inspection limit.
        limit: usize,
    },
    /// TLS `ClientHello` parsing failed before a decryption decision could be made.
    #[error("malformed TLS ClientHello: {0}")]
    MalformedTlsClientHello(&'static str),
    /// A proxy tunnel's TLS SNI does not match its requested DNS authority.
    #[error("TLS ClientHello SNI `{server_name}` does not match proxy target `{target}`")]
    ProxyTargetServerNameMismatch {
        /// Authority requested by the explicit proxy client.
        target: String,
        /// SNI presented inside the established proxy tunnel.
        server_name: String,
    },
    /// The first decoded HTTP request does not identify its explicit proxy target.
    #[error("HTTP Host does not match explicit proxy target `{target}`")]
    ProxyTargetHostMismatch {
        /// Authority declared by the outer explicit proxy request.
        target: String,
    },
    /// The first decoded request inside an explicit proxy flow used proxy or authority form.
    #[error("HTTP request target form is invalid inside explicit proxy target `{target}`")]
    ProxyTargetRequestForm {
        /// Authority declared by the outer explicit proxy request.
        target: String,
    },
    /// TLS decryption policy is invalid.
    #[error("invalid TLS decryption policy: {0}")]
    TlsDecryptionPolicy(#[from] TlsDecryptionPolicyError),
}

impl TransparentFlowError {
    /// Wraps an HTTP/1 error with the operation that produced it.
    #[must_use]
    pub const fn http1(operation: FlowOperation, source: Http1Error) -> Self {
        Self::Http1 { operation, source }
    }

    /// Wraps a WebSocket error with the operation that produced it.
    #[must_use]
    pub const fn websocket(
        operation: FlowOperation,
        source: tokio_tungstenite::tungstenite::Error,
    ) -> Self {
        Self::WebSocket { operation, source }
    }

    /// Returns whether this error only records that the local Agent stopped
    /// using an established response or WebSocket stream.
    #[must_use]
    pub fn is_agent_connection_close(&self) -> bool {
        match self {
            Self::Io { operation, source }
                if is_agent_close_operation(*operation) && is_peer_close_kind(source.kind()) =>
            {
                true
            }
            Self::WebSocket {
                operation: FlowOperation::ReadAgentWebSocket,
                source,
            } => match source {
                tokio_tungstenite::tungstenite::Error::ConnectionClosed => true,
                tokio_tungstenite::tungstenite::Error::Io(source) => {
                    is_peer_close_kind(source.kind())
                }
                _ => false,
            },
            _ => false,
        }
    }
}

const fn is_agent_close_operation(operation: FlowOperation) -> bool {
    matches!(
        operation,
        FlowOperation::WriteAgentContinueResponse
            | FlowOperation::WriteAgentResponseHead
            | FlowOperation::WriteAgentResponseBody
            | FlowOperation::ReadAgentWebSocket
            | FlowOperation::WriteAgentWebSocket
            | FlowOperation::ShutdownAgent
    )
}

const fn is_peer_close_kind(kind: ErrorKind) -> bool {
    matches!(
        kind,
        ErrorKind::BrokenPipe
            | ErrorKind::ConnectionAborted
            | ErrorKind::ConnectionReset
            | ErrorKind::NotConnected
            | ErrorKind::UnexpectedEof
    )
}

impl OriginalDestination {
    /// Converts the original endpoint to a standard socket address.
    #[must_use]
    pub const fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.ip, self.port)
    }
}

impl fmt::Display for OriginalDestination {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.socket_addr().fmt(formatter)
    }
}

impl From<SocketAddr> for OriginalDestination {
    fn from(value: SocketAddr) -> Self {
        Self {
            ip: value.ip(),
            port: value.port(),
        }
    }
}
