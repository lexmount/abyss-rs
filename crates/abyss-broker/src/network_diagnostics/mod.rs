//! Structured technical observations for flows accepted by the Abyss broker.
//!
//! This module deliberately stops at technical facts. It does not decide who
//! is responsible for a failure or generate user-facing guidance. The Host App
//! owns product-facing attribution, while the local storage layer persists the
//! observations without changing their meaning.

mod store;

pub use store::{NetworkObservationStore, NetworkObservationStoreError, database_path};

use std::io::ErrorKind;

use abyss_mitm::{
    FlowIngress, FlowOperation, Http1Error, SourceProcess, TlsErrorSide, TransparentFlowError,
    TransparentFlowOutcome,
};
use serde::Serialize;
use uuid::Uuid;

const MAX_ERROR_DETAIL_CHARS: usize = 1_024;

/// Connection boundary at which a technical observation occurred.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum NetworkHop {
    /// Communication between the Agent and the locally accepted Abyss flow.
    AgentToAbyss,
    /// Communication from Abyss to the model provider.
    AbyssToProvider,
    /// An operation spans both network boundaries and cannot be assigned to one.
    CrossBoundary,
}

impl NetworkHop {
    /// Returns the stable storage and IPC label for this hop.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AgentToAbyss => "agent_to_abyss",
            Self::AbyssToProvider => "abyss_to_provider",
            Self::CrossBoundary => "cross_boundary",
        }
    }

    /// Parses a stable storage and IPC label.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "agent_to_abyss" => Some(Self::AgentToAbyss),
            "abyss_to_provider" => Some(Self::AbyssToProvider),
            "cross_boundary" => Some(Self::CrossBoundary),
            _ => None,
        }
    }
}

/// Byte or local-processing direction for one technical observation.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum NetworkDirection {
    /// Bytes travel from the Agent into Abyss.
    AgentToAbyss,
    /// Bytes travel from Abyss back to the Agent.
    AbyssToAgent,
    /// Bytes travel from Abyss to the model provider.
    AbyssToProvider,
    /// Bytes travel from the model provider back to Abyss.
    ProviderToAbyss,
    /// An opaque relay operation covers both byte directions.
    Bidirectional,
    /// The observation is local processing rather than a network direction.
    Local,
}

impl NetworkDirection {
    /// Returns the stable storage and IPC label for this direction.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AgentToAbyss => "agent_to_abyss",
            Self::AbyssToAgent => "abyss_to_agent",
            Self::AbyssToProvider => "abyss_to_provider",
            Self::ProviderToAbyss => "provider_to_abyss",
            Self::Bidirectional => "bidirectional",
            Self::Local => "local",
        }
    }

    /// Parses a stable storage and IPC label.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "agent_to_abyss" => Self::AgentToAbyss,
            "abyss_to_agent" => Self::AbyssToAgent,
            "abyss_to_provider" => Self::AbyssToProvider,
            "provider_to_abyss" => Self::ProviderToAbyss,
            "bidirectional" => Self::Bidirectional,
            "local" => Self::Local,
            _ => return None,
        })
    }
}

/// Technical stage reached by an accepted flow.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum NetworkStage {
    /// Initial protocol detection on the accepted client stream.
    ProtocolDetection,
    /// TLS handshake at the boundary identified by [`NetworkHop`].
    TlsHandshake,
    /// HTTP request parsing or request forwarding.
    Request,
    /// DNS resolution for an upstream provider target.
    DnsResolution,
    /// TCP connection establishment for an upstream provider target.
    TcpConnect,
    /// HTTP response headers from the upstream provider.
    ResponseHeaders,
    /// Bidirectional response or body streaming.
    Stream,
    /// Local relay or flow shutdown processing.
    LocalRelay,
    /// The flow was accepted but the precise stage is not available.
    Unknown,
}

impl NetworkStage {
    /// Returns the stable storage and IPC label for this stage.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProtocolDetection => "protocol_detection",
            Self::TlsHandshake => "tls_handshake",
            Self::Request => "request",
            Self::DnsResolution => "dns_resolution",
            Self::TcpConnect => "tcp_connect",
            Self::ResponseHeaders => "response_headers",
            Self::Stream => "stream",
            Self::LocalRelay => "local_relay",
            Self::Unknown => "unknown",
        }
    }

    /// Parses a stable storage and IPC label.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "protocol_detection" => Some(Self::ProtocolDetection),
            "tls_handshake" => Some(Self::TlsHandshake),
            "request" => Some(Self::Request),
            "dns_resolution" => Some(Self::DnsResolution),
            "tcp_connect" => Some(Self::TcpConnect),
            "response_headers" => Some(Self::ResponseHeaders),
            "stream" => Some(Self::Stream),
            "local_relay" => Some(Self::LocalRelay),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }
}

/// Technical result of one observed stage.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum NetworkOutcome {
    /// The observed stage completed successfully.
    Succeeded,
    /// The observed stage failed.
    Failed,
    /// The stage started but the exchange ended before completion.
    Interrupted,
    /// The stage was intentionally not inspected or decrypted.
    Skipped,
    /// The result is not known from the available technical evidence.
    Unknown,
}

impl NetworkOutcome {
    /// Returns the stable storage and IPC label for this outcome.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Interrupted => "interrupted",
            Self::Skipped => "skipped",
            Self::Unknown => "unknown",
        }
    }

    /// Parses a stable storage and IPC label.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "succeeded" => Some(Self::Succeeded),
            "failed" => Some(Self::Failed),
            "interrupted" => Some(Self::Interrupted),
            "skipped" => Some(Self::Skipped),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }
}

/// Low-level failure category retained as technical evidence.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum NetworkFailureClass {
    /// The client closed before the expected bytes arrived.
    ClientClosed,
    /// A configured operation exceeded its timeout budget.
    Timeout,
    /// The peer refused a connection.
    ConnectionRefused,
    /// An established connection was reset.
    ConnectionReset,
    /// The upstream peer closed before the expected response arrived.
    UpstreamClosed,
    /// The stream ended at EOF before the expected exchange completed.
    Eof,
    /// TLS parsing, configuration, or handshake failed.
    TlsError,
    /// DNS resolution failed.
    DnsError,
    /// HTTP parsing or an HTTP-level failure occurred.
    HttpError,
    /// A proxy-specific protocol or target validation failed.
    ProxyError,
    /// The protocol or message was not valid for this pipeline.
    InvalidProtocol,
    /// A generic I/O failure without a more specific category.
    IoError,
    /// A local resource or counter could not support the operation.
    ResourceExhausted,
    /// The available error does not fit a known category.
    Unknown,
}

impl NetworkFailureClass {
    /// Returns the stable storage and IPC label for this failure class.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClientClosed => "client_closed",
            Self::Timeout => "timeout",
            Self::ConnectionRefused => "connection_refused",
            Self::ConnectionReset => "connection_reset",
            Self::UpstreamClosed => "upstream_closed",
            Self::Eof => "eof",
            Self::TlsError => "tls_error",
            Self::DnsError => "dns_error",
            Self::HttpError => "http_error",
            Self::ProxyError => "proxy_error",
            Self::InvalidProtocol => "invalid_protocol",
            Self::IoError => "io_error",
            Self::ResourceExhausted => "resource_exhausted",
            Self::Unknown => "unknown",
        }
    }

    /// Parses a stable storage and IPC label.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "client_closed" => Some(Self::ClientClosed),
            "timeout" => Some(Self::Timeout),
            "connection_refused" => Some(Self::ConnectionRefused),
            "connection_reset" => Some(Self::ConnectionReset),
            "upstream_closed" => Some(Self::UpstreamClosed),
            "eof" => Some(Self::Eof),
            "tls_error" => Some(Self::TlsError),
            "dns_error" => Some(Self::DnsError),
            "http_error" => Some(Self::HttpError),
            "proxy_error" => Some(Self::ProxyError),
            "invalid_protocol" => Some(Self::InvalidProtocol),
            "io_error" => Some(Self::IoError),
            "resource_exhausted" => Some(Self::ResourceExhausted),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }
}

/// Stable technical error code emitted by the broker for a failed flow.
///
/// This is deliberately a technical observation, not a user-facing
/// attribution. The Host App maps these codes to localized product copy.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkErrorCode {
    /// The Agent bytes did not match a protocol accepted by Abyss.
    #[serde(rename = "agent_protocol_error")]
    AgentProtocol,
    /// The Agent-side TLS handshake failed.
    #[serde(rename = "agent_tls_error")]
    AgentTls,
    /// The Agent request could not be parsed or prepared.
    #[serde(rename = "agent_request_error")]
    AgentRequest,
    /// The Agent-to-Abyss connection could not be established for a usable exchange.
    #[serde(rename = "agent_connection_error")]
    AgentConnection,
    /// The Agent closed an established connection before the exchange completed.
    #[serde(rename = "agent_connection_closed")]
    AgentConnectionClosed,
    /// Abyss could not relay an otherwise accepted request or response.
    #[serde(rename = "abyss_relay_error")]
    AbyssRelay,
    /// Abyss encountered an internal failure without a more specific code.
    #[serde(rename = "abyss_internal_error")]
    AbyssInternal,
    /// The provider hostname could not be resolved.
    #[serde(rename = "provider_dns_error")]
    ProviderDns,
    /// Abyss could not establish the provider TCP connection.
    #[serde(rename = "provider_tcp_error")]
    ProviderTcp,
    /// The provider-side TLS handshake failed.
    #[serde(rename = "provider_tls_error")]
    ProviderTls,
    /// Abyss could not send or prepare the provider request.
    #[serde(rename = "provider_request_error")]
    ProviderRequest,
    /// The provider response headers could not be received or parsed.
    #[serde(rename = "provider_response_headers_error")]
    ProviderResponseHeaders,
    /// The provider response stream ended or failed unexpectedly.
    #[serde(rename = "provider_stream_error")]
    ProviderStream,
    /// The provider returned an HTTP error response.
    #[serde(rename = "provider_http_error")]
    ProviderHttp,
    /// The provider-side failure did not fit a more specific technical code.
    #[serde(rename = "provider_internal_error")]
    ProviderInternal,
}

impl NetworkErrorCode {
    /// Returns the stable storage and IPC label for this technical error.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AgentProtocol => "agent_protocol_error",
            Self::AgentTls => "agent_tls_error",
            Self::AgentRequest => "agent_request_error",
            Self::AgentConnection => "agent_connection_error",
            Self::AgentConnectionClosed => "agent_connection_closed",
            Self::AbyssRelay => "abyss_relay_error",
            Self::AbyssInternal => "abyss_internal_error",
            Self::ProviderDns => "provider_dns_error",
            Self::ProviderTcp => "provider_tcp_error",
            Self::ProviderTls => "provider_tls_error",
            Self::ProviderRequest => "provider_request_error",
            Self::ProviderResponseHeaders => "provider_response_headers_error",
            Self::ProviderStream => "provider_stream_error",
            Self::ProviderHttp => "provider_http_error",
            Self::ProviderInternal => "provider_internal_error",
        }
    }

    /// Parses a stable storage and IPC label.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "agent_protocol_error" => Some(Self::AgentProtocol),
            "agent_tls_error" => Some(Self::AgentTls),
            "agent_request_error" => Some(Self::AgentRequest),
            "agent_connection_error" => Some(Self::AgentConnection),
            "agent_connection_closed" => Some(Self::AgentConnectionClosed),
            "abyss_relay_error" => Some(Self::AbyssRelay),
            "abyss_internal_error" => Some(Self::AbyssInternal),
            "provider_dns_error" => Some(Self::ProviderDns),
            "provider_tcp_error" => Some(Self::ProviderTcp),
            "provider_tls_error" => Some(Self::ProviderTls),
            "provider_request_error" => Some(Self::ProviderRequest),
            "provider_response_headers_error" => Some(Self::ProviderResponseHeaders),
            "provider_stream_error" => Some(Self::ProviderStream),
            "provider_http_error" => Some(Self::ProviderHttp),
            "provider_internal_error" => Some(Self::ProviderInternal),
            _ => None,
        }
    }

    /// Derives a stable code from the technical fields retained by an observation.
    #[must_use]
    pub fn from_observation(
        hop: NetworkHop,
        stage: NetworkStage,
        outcome: NetworkOutcome,
        failure_class: Option<NetworkFailureClass>,
        http_status: Option<u16>,
    ) -> Option<Self> {
        match hop {
            NetworkHop::AgentToAbyss => {
                if matches!(outcome, NetworkOutcome::Succeeded | NetworkOutcome::Skipped) {
                    return None;
                }

                match stage {
                    NetworkStage::ProtocolDetection => Some(Self::AgentProtocol),
                    NetworkStage::TlsHandshake => Some(Self::AgentTls),
                    NetworkStage::Request => match (failure_class, outcome) {
                        // An incomplete request head means the Agent closed the
                        // connection before Abyss received a request to parse. It
                        // must not be presented as an Abyss request-processing
                        // error.
                        (
                            Some(NetworkFailureClass::Eof | NetworkFailureClass::ClientClosed),
                            NetworkOutcome::Interrupted,
                        ) => Some(Self::AgentConnectionClosed),
                        _ => Some(Self::AgentRequest),
                    },
                    NetworkStage::LocalRelay
                    | NetworkStage::ResponseHeaders
                    | NetworkStage::Stream => match failure_class {
                        Some(NetworkFailureClass::ClientClosed) => {
                            Some(Self::AgentConnectionClosed)
                        }
                        _ => Some(Self::AbyssRelay),
                    },
                    NetworkStage::DnsResolution | NetworkStage::TcpConnect => match failure_class {
                        Some(
                            NetworkFailureClass::ConnectionRefused
                            | NetworkFailureClass::ConnectionReset
                            | NetworkFailureClass::Timeout
                            | NetworkFailureClass::ClientClosed,
                        ) => Some(Self::AgentConnection),
                        _ => Some(Self::AbyssInternal),
                    },
                    NetworkStage::Unknown => match failure_class {
                        Some(
                            NetworkFailureClass::ConnectionRefused
                            | NetworkFailureClass::ConnectionReset
                            | NetworkFailureClass::Timeout
                            | NetworkFailureClass::ClientClosed,
                        ) => Some(Self::AgentConnection),
                        _ => Some(Self::AbyssInternal),
                    },
                }
            }
            NetworkHop::AbyssToProvider => {
                if http_status.is_some_and(|status| status >= 400) {
                    return Some(Self::ProviderHttp);
                }
                if matches!(outcome, NetworkOutcome::Succeeded | NetworkOutcome::Skipped) {
                    return None;
                }

                match stage {
                    NetworkStage::DnsResolution => Some(Self::ProviderDns),
                    NetworkStage::TcpConnect => Some(Self::ProviderTcp),
                    NetworkStage::TlsHandshake => Some(Self::ProviderTls),
                    NetworkStage::Request => Some(Self::ProviderRequest),
                    NetworkStage::ResponseHeaders => Some(Self::ProviderResponseHeaders),
                    NetworkStage::Stream => Some(Self::ProviderStream),
                    NetworkStage::LocalRelay | NetworkStage::Unknown => match failure_class {
                        Some(NetworkFailureClass::DnsError) => Some(Self::ProviderDns),
                        Some(
                            NetworkFailureClass::ConnectionRefused
                            | NetworkFailureClass::ConnectionReset
                            | NetworkFailureClass::Timeout
                            | NetworkFailureClass::IoError,
                        ) => Some(Self::ProviderTcp),
                        Some(NetworkFailureClass::TlsError) => Some(Self::ProviderTls),
                        Some(NetworkFailureClass::HttpError) => Some(Self::ProviderHttp),
                        _ => Some(Self::ProviderInternal),
                    },
                    NetworkStage::ProtocolDetection => Some(Self::ProviderInternal),
                }
            }
            NetworkHop::CrossBoundary => match failure_class {
                Some(NetworkFailureClass::ClientClosed) => Some(Self::AgentConnectionClosed),
                _ => Some(Self::AbyssInternal),
            },
        }
    }
}

/// Wall-clock timing for one completed technical observation.
#[derive(Clone, Serialize)]
pub struct NetworkTiming {
    /// Unix timestamp when the observed stage or flow began.
    #[serde(rename = "started_at_unix_ms")]
    pub started_at: u64,
    /// Unix timestamp when the observed stage or flow ended.
    #[serde(rename = "ended_at_unix_ms")]
    pub ended_at: u64,
    /// Saturating elapsed time in milliseconds between the two timestamps.
    pub elapsed_ms: u64,
}

impl NetworkTiming {
    /// Creates timing from two Unix millisecond timestamps.
    #[must_use]
    pub const fn from_unix_ms(started_at_unix_ms: u64, ended_at_unix_ms: u64) -> Self {
        Self {
            started_at: started_at_unix_ms,
            ended_at: ended_at_unix_ms,
            elapsed_ms: ended_at_unix_ms.saturating_sub(started_at_unix_ms),
        }
    }
}

/// One metadata-only technical observation produced after a flow is accepted.
#[derive(Clone, Serialize)]
pub struct NetworkObservation {
    /// Unique identifier for this observation.
    pub observation_id: Uuid,
    /// Traffic-monitor flow identifier when one is available.
    pub flow_id: Option<Uuid>,
    /// Time at which this observation was finalized.
    pub observed_at_unix_ms: u64,
    /// Ingress that supplied the accepted flow.
    pub ingress_source: String,
    /// Normalized destination host when available.
    pub destination_host: Option<String>,
    /// Operating-system process identifier when the ingress supplied one.
    pub source_pid: Option<u32>,
    /// Process name reported by the platform ingress, such as `claude` or `codex`.
    pub source_process_name: Option<String>,
    /// Executable path reported by the platform ingress.
    pub source_executable_path: Option<String>,
    /// Source bundle or signing identifier when available.
    pub source_bundle_id: Option<String>,
    /// Technical boundary at which the observation occurred.
    pub hop: NetworkHop,
    /// Direction of the bytes or local operation that produced the observation.
    pub direction: Option<NetworkDirection>,
    /// Concrete MITM operation that produced the observation.
    pub operation: Option<FlowOperation>,
    /// Technical stage reached by the flow.
    pub stage: NetworkStage,
    /// Technical result of the observed stage.
    pub outcome: NetworkOutcome,
    /// Low-level failure category, present when the outcome is not successful.
    pub failure_class: Option<NetworkFailureClass>,
    /// Stable technical error code, present for failures and provider HTTP errors.
    pub technical_error_code: Option<NetworkErrorCode>,
    /// Timing for the observed flow or stage.
    pub timing: NetworkTiming,
    /// Provider HTTP status when the response was visible.
    pub http_status: Option<u16>,
    /// HTTP method of the first decoded request when available.
    pub request_method: Option<String>,
    /// Path of the first decoded request without query parameters.
    pub request_path: Option<String>,
    /// Bytes forwarded from the Agent toward the provider.
    pub bytes_up: u64,
    /// Bytes forwarded from the provider toward the Agent.
    pub bytes_down: u64,
    /// Bounded technical error text. This is not user-facing guidance.
    pub error: Option<String>,
}

impl NetworkObservation {
    /// Builds an observation from a completed MITM outcome.
    #[must_use]
    pub fn from_outcome(
        flow_id: Option<Uuid>,
        ingress: &FlowIngress,
        destination_host: Option<&str>,
        source_process: Option<&SourceProcess>,
        started_at_unix_ms: u64,
        ended_at_unix_ms: u64,
        outcome: &TransparentFlowOutcome,
    ) -> Self {
        let (
            hop,
            direction,
            operation,
            stage,
            network_outcome,
            http_status,
            bytes_up,
            bytes_down,
            error,
        ) = match outcome {
            TransparentFlowOutcome::Intercepted(outcome) => (
                NetworkHop::AbyssToProvider,
                None,
                None,
                NetworkStage::Stream,
                NetworkOutcome::Succeeded,
                Some(outcome.first_response.status().as_u16()),
                outcome.client_to_upstream_bytes,
                outcome.upstream_to_client_bytes,
                None,
            ),
            TransparentFlowOutcome::Passthrough(outcome) => (
                NetworkHop::AbyssToProvider,
                None,
                None,
                NetworkStage::Stream,
                NetworkOutcome::Skipped,
                None,
                outcome.client_to_upstream_bytes,
                outcome.upstream_to_client_bytes,
                None,
            ),
            _ => (
                NetworkHop::CrossBoundary,
                Some(NetworkDirection::Local),
                Some(FlowOperation::LocalRelay),
                NetworkStage::LocalRelay,
                NetworkOutcome::Failed,
                None,
                0,
                0,
                Some("unsupported transparent flow outcome".to_owned()),
            ),
        };
        let (request_method, request_path) = match outcome {
            TransparentFlowOutcome::Intercepted(outcome) => (
                Some(outcome.first_request.method().to_string()),
                Some(outcome.first_request.uri().path().to_owned()),
            ),
            _ => (None, None),
        };
        Self {
            observation_id: Uuid::new_v4(),
            flow_id,
            observed_at_unix_ms: ended_at_unix_ms,
            ingress_source: ingress.source_label().to_owned(),
            destination_host: normalized_optional_string(destination_host),
            source_pid: source_process.and_then(|source| source.pid),
            source_process_name: source_process
                .and_then(|source| normalized_optional_string(source.name.as_deref())),
            source_executable_path: source_process
                .and_then(|source| normalized_optional_string(source.executable_path.as_deref())),
            source_bundle_id: source_process
                .and_then(|source| normalized_optional_string(source.application_id.as_deref())),
            hop,
            direction,
            operation,
            stage,
            outcome: network_outcome,
            failure_class: None,
            technical_error_code: NetworkErrorCode::from_observation(
                hop,
                stage,
                network_outcome,
                None,
                http_status,
            ),
            timing: NetworkTiming::from_unix_ms(started_at_unix_ms, ended_at_unix_ms),
            http_status,
            request_method,
            request_path,
            bytes_up,
            bytes_down,
            error,
        }
    }

    /// Builds an observation from a failed accepted flow.
    #[must_use]
    pub fn from_error(
        flow_id: Option<Uuid>,
        ingress: &FlowIngress,
        destination_host: Option<&str>,
        source_process: Option<&SourceProcess>,
        started_at_unix_ms: u64,
        ended_at_unix_ms: u64,
        error: &TransparentFlowError,
    ) -> Self {
        let location = NetworkLocation::from(error);
        let failure_class = NetworkFailureClass::from(error);
        let outcome = outcome_for_error(error);
        Self {
            observation_id: Uuid::new_v4(),
            flow_id,
            observed_at_unix_ms: ended_at_unix_ms,
            ingress_source: ingress.source_label().to_owned(),
            destination_host: normalized_optional_string(destination_host),
            source_pid: source_process.and_then(|source| source.pid),
            source_process_name: source_process
                .and_then(|source| normalized_optional_string(source.name.as_deref())),
            source_executable_path: source_process
                .and_then(|source| normalized_optional_string(source.executable_path.as_deref())),
            source_bundle_id: source_process
                .and_then(|source| normalized_optional_string(source.application_id.as_deref())),
            hop: location.hop,
            direction: Some(location.direction),
            operation: Some(location.operation),
            stage: location.stage,
            outcome,
            failure_class: Some(failure_class),
            technical_error_code: NetworkErrorCode::from_observation(
                location.hop,
                location.stage,
                outcome,
                Some(failure_class),
                None,
            ),
            timing: NetworkTiming::from_unix_ms(started_at_unix_ms, ended_at_unix_ms),
            http_status: None,
            request_method: None,
            request_path: None,
            bytes_up: 0,
            bytes_down: 0,
            error: Some(bounded_error_detail(error)),
        }
    }
}

impl From<&TransparentFlowError> for NetworkFailureClass {
    fn from(error: &TransparentFlowError) -> Self {
        match error {
            _ if error.is_agent_connection_close() => Self::ClientClosed,
            TransparentFlowError::ClientClosedBeforeProtocol => Self::ClientClosed,
            TransparentFlowError::UnsupportedProtocol
            | TransparentFlowError::MalformedTlsClientHello(_)
            | TransparentFlowError::ProxyTargetRequestForm { .. }
            | TransparentFlowError::WebSocket { .. } => Self::InvalidProtocol,
            TransparentFlowError::MissingSni
            | TransparentFlowError::TlsClientHelloTooLarge { .. }
            | TransparentFlowError::Tls { .. }
            | TransparentFlowError::TlsConfiguration(_) => Self::TlsError,
            TransparentFlowError::Http1 { source, .. } => source.into(),
            TransparentFlowError::Io { source, .. } => source.into(),
            TransparentFlowError::Timeout { .. } => Self::Timeout,
            TransparentFlowError::ByteCountOverflow => Self::ResourceExhausted,
            TransparentFlowError::ProxyTargetServerNameMismatch { .. }
            | TransparentFlowError::ProxyTargetHostMismatch { .. } => Self::ProxyError,
            TransparentFlowError::TlsDecryptionPolicy(_) => Self::IoError,
            _ => Self::Unknown,
        }
    }
}

impl From<&Http1Error> for NetworkFailureClass {
    fn from(error: &Http1Error) -> Self {
        match error {
            Http1Error::IncompleteRequest => Self::Eof,
            Http1Error::IncompleteResponse => Self::UpstreamClosed,
            Http1Error::RequestHeadTimeout { .. } | Http1Error::ResponseHeadTimeout { .. } => {
                Self::Timeout
            }
            Http1Error::Io { source } => source.into(),
            Http1Error::HeaderTooLarge
            | Http1Error::BodyTooLarge { .. }
            | Http1Error::InvalidBody(_)
            | Http1Error::UnsupportedBody(_)
            | Http1Error::Parse(_)
            | Http1Error::InvalidRequest(_)
            | Http1Error::InvalidResponse(_)
            | Http1Error::InvalidMethod(_)
            | Http1Error::InvalidUri(_)
            | Http1Error::InvalidStatusCode(_)
            | Http1Error::InvalidHeaderName(_)
            | Http1Error::InvalidHeaderValue(_)
            | Http1Error::BuildMessage(_) => Self::HttpError,
            _ => Self::Unknown,
        }
    }
}

impl From<&std::io::Error> for NetworkFailureClass {
    fn from(error: &std::io::Error) -> Self {
        match error.kind() {
            ErrorKind::ConnectionRefused => Self::ConnectionRefused,
            ErrorKind::ConnectionReset => Self::ConnectionReset,
            ErrorKind::UnexpectedEof => Self::Eof,
            ErrorKind::TimedOut => Self::Timeout,
            _ => Self::IoError,
        }
    }
}

struct NetworkLocation {
    hop: NetworkHop,
    direction: NetworkDirection,
    operation: FlowOperation,
    stage: NetworkStage,
}

impl From<&TransparentFlowError> for NetworkLocation {
    fn from(error: &TransparentFlowError) -> Self {
        let operation = match error {
            TransparentFlowError::ClientClosedBeforeProtocol
            | TransparentFlowError::UnsupportedProtocol => FlowOperation::ReadAgentProtocol,
            TransparentFlowError::MissingSni
            | TransparentFlowError::TlsClientHelloTooLarge { .. }
            | TransparentFlowError::MalformedTlsClientHello(_) => {
                FlowOperation::ReadAgentTlsClientHello
            }
            TransparentFlowError::Tls { side, .. } => match side {
                TlsErrorSide::Client => FlowOperation::AcceptAgentTls,
                TlsErrorSide::Upstream => FlowOperation::ConnectProviderTls,
                _ => FlowOperation::LocalRelay,
            },
            TransparentFlowError::Http1 { operation, .. }
            | TransparentFlowError::WebSocket { operation, .. }
            | TransparentFlowError::Io { operation, .. }
            | TransparentFlowError::Timeout { operation, .. } => *operation,
            _ => FlowOperation::LocalRelay,
        };
        Self::from(operation)
    }
}

impl From<FlowOperation> for NetworkLocation {
    fn from(operation: FlowOperation) -> Self {
        let (hop, direction, stage) = match operation {
            FlowOperation::ReadAgentProtocol => (
                NetworkHop::AgentToAbyss,
                NetworkDirection::AgentToAbyss,
                NetworkStage::ProtocolDetection,
            ),
            FlowOperation::ReadAgentTlsClientHello | FlowOperation::AcceptAgentTls => (
                NetworkHop::AgentToAbyss,
                NetworkDirection::AgentToAbyss,
                NetworkStage::TlsHandshake,
            ),
            FlowOperation::ReadAgentRequestHead | FlowOperation::ReadAgentRequestBody => (
                NetworkHop::AgentToAbyss,
                NetworkDirection::AgentToAbyss,
                NetworkStage::Request,
            ),
            FlowOperation::WriteProviderRequestHead
            | FlowOperation::WriteProviderRequestBody
            | FlowOperation::WriteProviderTlsClientHello
            | FlowOperation::ConnectProviderTcp
            | FlowOperation::ConnectProviderTls => (
                NetworkHop::AbyssToProvider,
                NetworkDirection::AbyssToProvider,
                match operation {
                    FlowOperation::ConnectProviderTcp => NetworkStage::TcpConnect,
                    FlowOperation::ConnectProviderTls
                    | FlowOperation::WriteProviderTlsClientHello => NetworkStage::TlsHandshake,
                    _ => NetworkStage::Request,
                },
            ),
            FlowOperation::ReadProviderResponseHead => (
                NetworkHop::AbyssToProvider,
                NetworkDirection::ProviderToAbyss,
                NetworkStage::ResponseHeaders,
            ),
            FlowOperation::ReadProviderResponseBody | FlowOperation::ReadProviderWebSocket => (
                NetworkHop::AbyssToProvider,
                NetworkDirection::ProviderToAbyss,
                NetworkStage::Stream,
            ),
            FlowOperation::WriteAgentContinueResponse => (
                NetworkHop::AgentToAbyss,
                NetworkDirection::AbyssToAgent,
                NetworkStage::Request,
            ),
            FlowOperation::WriteAgentResponseHead => (
                NetworkHop::AgentToAbyss,
                NetworkDirection::AbyssToAgent,
                NetworkStage::ResponseHeaders,
            ),
            FlowOperation::WriteAgentResponseBody | FlowOperation::WriteAgentWebSocket => (
                NetworkHop::AgentToAbyss,
                NetworkDirection::AbyssToAgent,
                NetworkStage::Stream,
            ),
            FlowOperation::ReadAgentWebSocket => (
                NetworkHop::AgentToAbyss,
                NetworkDirection::AgentToAbyss,
                NetworkStage::Stream,
            ),
            FlowOperation::WriteProviderWebSocket => (
                NetworkHop::AbyssToProvider,
                NetworkDirection::AbyssToProvider,
                NetworkStage::Stream,
            ),
            FlowOperation::RelayPassthrough => (
                NetworkHop::CrossBoundary,
                NetworkDirection::Bidirectional,
                NetworkStage::Stream,
            ),
            FlowOperation::ShutdownAgent => (
                NetworkHop::AgentToAbyss,
                NetworkDirection::AbyssToAgent,
                NetworkStage::LocalRelay,
            ),
            _ => (
                NetworkHop::CrossBoundary,
                NetworkDirection::Local,
                NetworkStage::LocalRelay,
            ),
        };
        Self {
            hop,
            direction,
            operation,
            stage,
        }
    }
}

fn outcome_for_error(error: &TransparentFlowError) -> NetworkOutcome {
    match error {
        _ if error.is_agent_connection_close() => NetworkOutcome::Interrupted,
        TransparentFlowError::ClientClosedBeforeProtocol
        | TransparentFlowError::Http1 {
            source: Http1Error::IncompleteRequest | Http1Error::IncompleteResponse,
            ..
        } => NetworkOutcome::Interrupted,
        _ => NetworkOutcome::Failed,
    }
}

fn normalized_optional_string(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn bounded_error_detail(error: &TransparentFlowError) -> String {
    let error = error.to_string();
    let mut chars = error.chars();
    let mut bounded = chars
        .by_ref()
        .take(MAX_ERROR_DETAIL_CHARS)
        .collect::<String>();
    if chars.next().is_some() {
        bounded.push('…');
    }
    bounded
}

#[cfg(test)]
mod tests {
    use std::{io, time::Duration};

    use super::{
        NetworkDirection, NetworkErrorCode, NetworkFailureClass, NetworkHop, NetworkStage,
        NetworkTiming,
    };
    use abyss_mitm::{
        FlowOperation, Http1Error, SourceProcess, TlsErrorSide, TlsMitmError, TransparentFlowError,
    };

    #[test]
    fn timing_saturates_when_end_precedes_start() {
        let timing = NetworkTiming::from_unix_ms(20, 10);

        assert_eq!(timing.elapsed_ms, 0);
    }

    #[test]
    fn network_location_supports_standard_from_conversions() {
        let provider_tls_location = super::NetworkLocation::from(FlowOperation::ConnectProviderTls);
        assert_eq!(provider_tls_location.hop, NetworkHop::AbyssToProvider);
        assert_eq!(provider_tls_location.stage, NetworkStage::TlsHandshake);

        let client_tls_error = TransparentFlowError::Tls {
            side: TlsErrorSide::Client,
            source: TlsMitmError::InvalidServerName {
                server_name: "agent.example.test".to_owned(),
                details: "invalid test name".to_owned(),
            },
        };
        let agent_location = super::NetworkLocation::from(&client_tls_error);
        assert_eq!(agent_location.hop, NetworkHop::AgentToAbyss);
        assert_eq!(agent_location.stage, NetworkStage::TlsHandshake);
    }

    #[test]
    fn observation_retains_source_process_metadata() {
        let source = SourceProcess::new(
            Some(42),
            Some("claude".to_owned()),
            Some("/usr/local/bin/claude".to_owned()),
        )
        .with_application_id(Some("com.anthropic.claude-code".to_owned()));
        let observation = super::NetworkObservation::from_error(
            None,
            &abyss_mitm::FlowIngress::transparent(
                abyss_mitm::TransparentFlowSource::MacosNetworkExtension,
            ),
            Some("api.anthropic.com"),
            Some(&source),
            100,
            140,
            &TransparentFlowError::MissingSni,
        );

        assert_eq!(observation.source_pid, Some(42));
        assert_eq!(observation.source_process_name.as_deref(), Some("claude"));
        assert_eq!(
            observation.source_executable_path.as_deref(),
            Some("/usr/local/bin/claude")
        );
        assert_eq!(
            observation.source_bundle_id.as_deref(),
            Some("com.anthropic.claude-code")
        );
    }

    #[test]
    fn client_protocol_timeout_maps_to_agent_boundary() {
        let error = TransparentFlowError::Timeout {
            operation: FlowOperation::ReadAgentProtocol,
            timeout: Duration::from_secs(5),
        };

        let observation = super::NetworkObservation::from_error(
            None,
            &abyss_mitm::FlowIngress::transparent(abyss_mitm::TransparentFlowSource::Unattributed),
            Some("api.example.test"),
            None,
            10,
            20,
            &error,
        );

        assert_eq!(observation.hop, NetworkHop::AgentToAbyss);
        assert_eq!(observation.stage, NetworkStage::ProtocolDetection);
        assert_eq!(
            observation.failure_class,
            Some(NetworkFailureClass::Timeout)
        );
        assert_eq!(
            observation.technical_error_code,
            Some(NetworkErrorCode::AgentProtocol)
        );
    }

    #[test]
    fn upstream_connect_error_maps_to_provider_boundary() {
        let error = TransparentFlowError::Io {
            operation: FlowOperation::ConnectProviderTcp,
            source: io::Error::new(io::ErrorKind::ConnectionRefused, "refused"),
        };

        let observation = super::NetworkObservation::from_error(
            None,
            &abyss_mitm::FlowIngress::transparent(abyss_mitm::TransparentFlowSource::Unattributed),
            None,
            None,
            100,
            140,
            &error,
        );

        assert_eq!(observation.hop, NetworkHop::AbyssToProvider);
        assert_eq!(observation.stage, NetworkStage::TcpConnect);
        assert_eq!(
            observation.failure_class,
            Some(NetworkFailureClass::ConnectionRefused)
        );
        assert_eq!(
            observation.technical_error_code,
            Some(NetworkErrorCode::ProviderTcp)
        );
    }

    #[test]
    fn client_tls_error_maps_to_agent_boundary() {
        let error = TransparentFlowError::Tls {
            side: TlsErrorSide::Client,
            source: TlsMitmError::InvalidServerName {
                server_name: "agent.example.test".to_owned(),
                details: "invalid test name".to_owned(),
            },
        };

        let observation = super::NetworkObservation::from_error(
            None,
            &abyss_mitm::FlowIngress::transparent(abyss_mitm::TransparentFlowSource::Unattributed),
            None,
            None,
            100,
            140,
            &error,
        );

        assert_eq!(observation.hop, NetworkHop::AgentToAbyss);
        assert_eq!(observation.stage, NetworkStage::TlsHandshake);
        assert_eq!(
            observation.failure_class,
            Some(NetworkFailureClass::TlsError)
        );
        assert_eq!(
            observation.technical_error_code,
            Some(NetworkErrorCode::AgentTls)
        );
    }

    #[test]
    fn upstream_tls_error_maps_to_provider_boundary() {
        let error = TransparentFlowError::Tls {
            side: TlsErrorSide::Upstream,
            source: TlsMitmError::InvalidServerName {
                server_name: "provider.example.test".to_owned(),
                details: "invalid test name".to_owned(),
            },
        };

        let observation = super::NetworkObservation::from_error(
            None,
            &abyss_mitm::FlowIngress::transparent(abyss_mitm::TransparentFlowSource::Unattributed),
            None,
            None,
            100,
            140,
            &error,
        );

        assert_eq!(observation.hop, NetworkHop::AbyssToProvider);
        assert_eq!(observation.stage, NetworkStage::TlsHandshake);
        assert_eq!(
            observation.failure_class,
            Some(NetworkFailureClass::TlsError)
        );
        assert_eq!(
            observation.technical_error_code,
            Some(NetworkErrorCode::ProviderTls)
        );
    }

    #[test]
    fn relay_direction_maps_to_the_correct_boundary() {
        let request_error = TransparentFlowError::Io {
            operation: FlowOperation::WriteProviderRequestHead,
            source: io::Error::new(io::ErrorKind::BrokenPipe, "provider closed"),
        };
        let response_error = TransparentFlowError::Io {
            operation: FlowOperation::WriteAgentResponseHead,
            source: io::Error::new(io::ErrorKind::BrokenPipe, "agent closed"),
        };

        let ingress =
            abyss_mitm::FlowIngress::transparent(abyss_mitm::TransparentFlowSource::Unattributed);
        let request_observation = super::NetworkObservation::from_error(
            None,
            &ingress,
            None,
            None,
            100,
            140,
            &request_error,
        );
        let response_observation = super::NetworkObservation::from_error(
            None,
            &ingress,
            None,
            None,
            100,
            140,
            &response_error,
        );

        assert_eq!(request_observation.hop, NetworkHop::AbyssToProvider);
        assert_eq!(response_observation.hop, NetworkHop::AgentToAbyss);
        assert_eq!(
            request_observation.direction,
            Some(NetworkDirection::AbyssToProvider)
        );
        assert_eq!(
            request_observation.operation,
            Some(FlowOperation::WriteProviderRequestHead)
        );
        assert_eq!(
            response_observation.direction,
            Some(NetworkDirection::AbyssToAgent)
        );
        assert_eq!(
            response_observation.operation,
            Some(FlowOperation::WriteAgentResponseHead)
        );
        assert_eq!(
            request_observation.technical_error_code,
            Some(NetworkErrorCode::ProviderRequest)
        );
        assert_eq!(
            response_observation.technical_error_code,
            Some(NetworkErrorCode::AgentConnectionClosed)
        );
    }

    #[test]
    fn agent_response_broken_pipe_is_an_agent_connection_interruption() {
        let error = TransparentFlowError::Io {
            operation: FlowOperation::WriteAgentResponseBody,
            source: io::Error::new(io::ErrorKind::BrokenPipe, "agent closed"),
        };
        let ingress =
            abyss_mitm::FlowIngress::transparent(abyss_mitm::TransparentFlowSource::Unattributed);

        let observation = super::NetworkObservation::from_error(
            None,
            &ingress,
            Some("chatgpt.com"),
            None,
            100,
            140,
            &error,
        );

        assert_eq!(observation.hop, NetworkHop::AgentToAbyss);
        assert_eq!(observation.stage, NetworkStage::Stream);
        assert_eq!(observation.outcome, super::NetworkOutcome::Interrupted);
        assert_eq!(
            observation.failure_class,
            Some(NetworkFailureClass::ClientClosed)
        );
        assert_eq!(
            observation.technical_error_code,
            Some(NetworkErrorCode::AgentConnectionClosed)
        );
    }

    #[test]
    fn http1_error_uses_declared_operation_for_boundary() {
        let error = TransparentFlowError::Http1 {
            operation: FlowOperation::ReadProviderResponseHead,
            source: Http1Error::IncompleteResponse,
        };
        let ingress =
            abyss_mitm::FlowIngress::transparent(abyss_mitm::TransparentFlowSource::Unattributed);

        let observation = super::NetworkObservation::from_error(
            None,
            &ingress,
            Some("api.example.test"),
            None,
            100,
            140,
            &error,
        );

        assert_eq!(observation.hop, NetworkHop::AbyssToProvider);
        assert_eq!(
            observation.direction,
            Some(NetworkDirection::ProviderToAbyss)
        );
        assert_eq!(
            observation.operation,
            Some(FlowOperation::ReadProviderResponseHead)
        );
        assert_eq!(observation.stage, NetworkStage::ResponseHeaders);
        assert_eq!(
            observation.failure_class,
            Some(NetworkFailureClass::UpstreamClosed)
        );
        assert_eq!(
            observation.technical_error_code,
            Some(NetworkErrorCode::ProviderResponseHeaders)
        );
    }

    #[test]
    fn incomplete_agent_request_is_an_agent_connection_warning() {
        let error = TransparentFlowError::Http1 {
            operation: FlowOperation::ReadAgentRequestHead,
            source: Http1Error::IncompleteRequest,
        };
        let ingress =
            abyss_mitm::FlowIngress::transparent(abyss_mitm::TransparentFlowSource::Unattributed);

        let observation = super::NetworkObservation::from_error(
            None,
            &ingress,
            Some("www.dmxapi.cn"),
            None,
            100,
            140,
            &error,
        );

        assert_eq!(observation.hop, NetworkHop::AgentToAbyss);
        assert_eq!(observation.stage, NetworkStage::Request);
        assert_eq!(observation.outcome, super::NetworkOutcome::Interrupted);
        assert_eq!(observation.failure_class, Some(NetworkFailureClass::Eof));
        assert_eq!(
            observation.technical_error_code,
            Some(NetworkErrorCode::AgentConnectionClosed)
        );
    }

    #[test]
    fn technical_code_falls_back_to_explicit_internal_errors() {
        assert_eq!(
            NetworkErrorCode::from_observation(
                NetworkHop::AgentToAbyss,
                NetworkStage::Unknown,
                super::NetworkOutcome::Failed,
                Some(NetworkFailureClass::Unknown),
                None,
            ),
            Some(NetworkErrorCode::AbyssInternal)
        );
        assert_eq!(
            NetworkErrorCode::from_observation(
                NetworkHop::AbyssToProvider,
                NetworkStage::Unknown,
                super::NetworkOutcome::Failed,
                Some(NetworkFailureClass::Unknown),
                None,
            ),
            Some(NetworkErrorCode::ProviderInternal)
        );
    }

    #[test]
    fn technical_code_uses_the_stable_error_label_in_ipc() {
        assert_eq!(
            serde_json::to_string(&NetworkErrorCode::ProviderDns)
                .expect("technical code should serialize"),
            "\"provider_dns_error\""
        );
    }
}
