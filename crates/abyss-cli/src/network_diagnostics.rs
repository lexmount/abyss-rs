//! Endpoint network-diagnosis model and terminal presentation.
//!
//! The broker returns technical observations only. This module is the CLI
//! Host App boundary that turns the five most recent observations into
//! user-facing diagnoses and renders them for an interactive terminal.

use serde::Deserialize;
use serde_json::Value;

use crate::error::CliError;

mod terminal;

const RECENT_DIAGNOSIS_LIMIT: usize = 5;

#[derive(Deserialize)]
pub struct NetworkObservationsResponse {
    schema_version: u32,
    observations: Vec<NetworkObservation>,
}

#[derive(Deserialize)]
struct NetworkObservation {
    observed_at_unix_ms: u64,
    destination_host: Option<String>,
    source_process_name: Option<String>,
    hop: NetworkHop,
    stage: NetworkStage,
    outcome: NetworkOutcome,
    failure_class: Option<NetworkFailureClass>,
    technical_error_code: Option<NetworkErrorCode>,
    http_status: Option<u16>,
    operation: Option<String>,
}

#[derive(Deserialize, Clone, Copy, PartialEq)]
#[serde(rename_all = "snake_case")]
enum NetworkHop {
    AgentToAbyss,
    AbyssToProvider,
    CrossBoundary,
    #[serde(other)]
    Unknown,
}

#[derive(Deserialize, Clone, Copy, PartialEq)]
#[serde(rename_all = "snake_case")]
enum NetworkStage {
    ProtocolDetection,
    TlsHandshake,
    Request,
    DnsResolution,
    TcpConnect,
    ResponseHeaders,
    Stream,
    LocalRelay,
    #[serde(other)]
    Unknown,
}

#[derive(Deserialize, Clone, Copy, PartialEq)]
#[serde(rename_all = "snake_case")]
enum NetworkOutcome {
    Succeeded,
    Failed,
    Interrupted,
    Skipped,
    #[serde(other)]
    Unknown,
}

#[derive(Deserialize, Clone, Copy, PartialEq)]
#[serde(rename_all = "snake_case")]
enum NetworkFailureClass {
    ClientClosed,
    Timeout,
    ConnectionRefused,
    ConnectionReset,
    UpstreamClosed,
    Eof,
    TlsError,
    DnsError,
    HttpError,
    ProxyError,
    InvalidProtocol,
    IoError,
    ResourceExhausted,
    #[serde(other)]
    Unknown,
}

#[derive(Deserialize, Clone, Copy, PartialEq)]
#[serde(rename_all = "snake_case")]
enum NetworkErrorCode {
    #[serde(rename = "agent_protocol_error")]
    AgentProtocol,
    #[serde(rename = "agent_tls_error")]
    AgentTls,
    #[serde(rename = "agent_request_error")]
    AgentRequest,
    #[serde(rename = "agent_connection_error")]
    AgentConnection,
    #[serde(rename = "agent_connection_closed")]
    AgentConnectionClosed,
    #[serde(rename = "abyss_relay_error")]
    AbyssRelay,
    #[serde(rename = "abyss_internal_error")]
    AbyssInternal,
    #[serde(rename = "provider_dns_error")]
    ProviderDns,
    #[serde(rename = "provider_tcp_error")]
    ProviderTcp,
    #[serde(rename = "provider_tls_error")]
    ProviderTls,
    #[serde(rename = "provider_request_error")]
    ProviderRequest,
    #[serde(rename = "provider_response_headers_error")]
    ProviderResponseHeaders,
    #[serde(rename = "provider_stream_error")]
    ProviderStream,
    #[serde(rename = "provider_http_error")]
    ProviderHttp,
    #[serde(rename = "provider_internal_error")]
    ProviderInternal,
    #[serde(other)]
    Unknown,
}

#[derive(Clone, Copy, PartialEq)]
enum DiagnosisSeverity {
    Healthy,
    Warning,
    Error,
}

pub struct NetworkDiagnosticsReport {
    diagnoses: Vec<NetworkDiagnosis>,
}

struct NetworkDiagnosis {
    observed_at_unix_ms: u64,
    severity: DiagnosisSeverity,
    message: &'static str,
    guidance: &'static str,
    destination_host: Option<String>,
    source_process_name: Option<String>,
    http_status: Option<u16>,
}

impl NetworkObservationsResponse {
    /// Parses and validates the broker's local observation response.
    pub fn from_value(value: Value) -> Result<Self, CliError> {
        let response: Self = serde_json::from_value(value).map_err(|error| {
            CliError::InvalidConfiguration(format!(
                "broker returned invalid network observations: {error}"
            ))
        })?;
        if response.schema_version != 1 {
            return Err(CliError::InvalidConfiguration(format!(
                "unsupported network observation schema version {}",
                response.schema_version
            )));
        }
        Ok(response)
    }

    /// Diagnoses the five newest observations, newest first.
    #[must_use]
    pub fn diagnose_recent(mut self) -> NetworkDiagnosticsReport {
        self.observations
            .sort_by_key(|observation| std::cmp::Reverse(observation.observed_at_unix_ms));
        let diagnoses = self
            .observations
            .into_iter()
            .filter(|observation| !observation.is_agent_lifecycle_close())
            .take(RECENT_DIAGNOSIS_LIMIT)
            .map(NetworkDiagnosis::from_observation)
            .collect();
        NetworkDiagnosticsReport { diagnoses }
    }
}

impl NetworkObservation {
    fn is_agent_lifecycle_close(&self) -> bool {
        if self.hop != NetworkHop::AgentToAbyss {
            return false;
        }
        if self.failure_class == Some(NetworkFailureClass::ClientClosed)
            || self.technical_error_code == Some(NetworkErrorCode::AgentConnectionClosed)
        {
            return true;
        }
        if self.stage == NetworkStage::Request
            && self.outcome == NetworkOutcome::Interrupted
            && self.failure_class == Some(NetworkFailureClass::Eof)
        {
            return true;
        }

        self.operation.as_deref() == Some("read_agent_websocket")
            && self.failure_class == Some(NetworkFailureClass::Eof)
    }
}

impl NetworkDiagnosis {
    fn from_observation(observation: NetworkObservation) -> Self {
        if Self::is_healthy(&observation) {
            return Self {
                observed_at_unix_ms: observation.observed_at_unix_ms,
                severity: DiagnosisSeverity::Healthy,
                message: "The Agent request completed normally.",
                guidance: "No action needed.",
                destination_host: observation.destination_host,
                source_process_name: observation.source_process_name,
                http_status: observation.http_status,
            };
        }

        let diagnosis = observation
            .technical_error_code
            .or_else(|| Self::technical_error_code_from_legacy_fields(&observation))
            .map_or_else(
                || Self::generic_diagnosis_for_hop(observation.hop),
                |code| Self::diagnosis_for_error_code(code, observation.http_status),
            );
        Self {
            observed_at_unix_ms: observation.observed_at_unix_ms,
            severity: diagnosis.severity,
            message: diagnosis.message,
            guidance: diagnosis.guidance,
            destination_host: observation.destination_host,
            source_process_name: observation.source_process_name,
            http_status: observation.http_status.filter(|status| *status >= 400),
        }
    }

    fn is_healthy(observation: &NetworkObservation) -> bool {
        matches!(
            observation.outcome,
            NetworkOutcome::Succeeded | NetworkOutcome::Skipped
        ) && observation.http_status.is_none_or(|status| status < 400)
    }

    fn technical_error_code_from_legacy_fields(
        observation: &NetworkObservation,
    ) -> Option<NetworkErrorCode> {
        if observation.hop == NetworkHop::AbyssToProvider
            && observation.http_status.is_some_and(|status| status >= 400)
        {
            return Some(NetworkErrorCode::ProviderHttp);
        }
        if Self::is_healthy(observation) {
            return None;
        }

        match observation.hop {
            NetworkHop::AgentToAbyss => match observation.stage {
                NetworkStage::ProtocolDetection => Some(NetworkErrorCode::AgentProtocol),
                NetworkStage::TlsHandshake => Some(NetworkErrorCode::AgentTls),
                NetworkStage::Request => Some(NetworkErrorCode::AgentRequest),
                NetworkStage::LocalRelay | NetworkStage::ResponseHeaders | NetworkStage::Stream => {
                    match observation.failure_class {
                        Some(NetworkFailureClass::ClientClosed) => {
                            Some(NetworkErrorCode::AgentConnectionClosed)
                        }
                        _ => Some(NetworkErrorCode::AbyssRelay),
                    }
                }
                NetworkStage::DnsResolution | NetworkStage::TcpConnect | NetworkStage::Unknown => {
                    match observation.failure_class {
                        Some(
                            NetworkFailureClass::ConnectionRefused
                            | NetworkFailureClass::ConnectionReset
                            | NetworkFailureClass::Timeout
                            | NetworkFailureClass::ClientClosed,
                        ) => Some(NetworkErrorCode::AgentConnection),
                        _ => Some(NetworkErrorCode::AbyssInternal),
                    }
                }
            },
            NetworkHop::AbyssToProvider => match observation.stage {
                NetworkStage::DnsResolution => Some(NetworkErrorCode::ProviderDns),
                NetworkStage::TcpConnect => Some(NetworkErrorCode::ProviderTcp),
                NetworkStage::TlsHandshake => Some(NetworkErrorCode::ProviderTls),
                NetworkStage::Request => Some(NetworkErrorCode::ProviderRequest),
                NetworkStage::ResponseHeaders => Some(NetworkErrorCode::ProviderResponseHeaders),
                NetworkStage::Stream => Some(NetworkErrorCode::ProviderStream),
                NetworkStage::LocalRelay
                | NetworkStage::ProtocolDetection
                | NetworkStage::Unknown => match observation.failure_class {
                    Some(NetworkFailureClass::DnsError) => Some(NetworkErrorCode::ProviderDns),
                    Some(
                        NetworkFailureClass::ConnectionRefused
                        | NetworkFailureClass::ConnectionReset
                        | NetworkFailureClass::Timeout
                        | NetworkFailureClass::IoError,
                    ) => Some(NetworkErrorCode::ProviderTcp),
                    Some(NetworkFailureClass::TlsError) => Some(NetworkErrorCode::ProviderTls),
                    Some(NetworkFailureClass::HttpError) => Some(NetworkErrorCode::ProviderHttp),
                    _ => Some(NetworkErrorCode::ProviderInternal),
                },
            },
            NetworkHop::CrossBoundary => match observation.failure_class {
                Some(NetworkFailureClass::ClientClosed) => {
                    Some(NetworkErrorCode::AgentConnectionClosed)
                }
                _ => Some(NetworkErrorCode::AbyssInternal),
            },
            NetworkHop::Unknown => Some(NetworkErrorCode::Unknown),
        }
    }

    const fn diagnosis_for_error_code(
        code: NetworkErrorCode,
        http_status: Option<u16>,
    ) -> DiagnosisCopy {
        match code {
            NetworkErrorCode::AgentConnectionClosed => DiagnosisCopy::warning(
                "The Agent connection was interrupted.",
                "Confirm whether normal Agent use is affected; if it is, contact the Abyss developer or support team.",
            ),
            NetworkErrorCode::AgentProtocol => DiagnosisCopy::error(
                "Abyss proxy error: the Agent request format could not be recognized.",
                "Contact the Abyss developer or support team.",
            ),
            NetworkErrorCode::AgentTls => DiagnosisCopy::error(
                "Abyss proxy error: the Agent could not establish a secure connection to Abyss.",
                "Contact the Abyss developer or support team.",
            ),
            NetworkErrorCode::AgentRequest => DiagnosisCopy::error(
                "Abyss proxy error: the Agent request could not be processed.",
                "Contact the Abyss developer or support team.",
            ),
            NetworkErrorCode::AgentConnection => DiagnosisCopy::error(
                "Abyss proxy error: could not establish a connection with the Agent.",
                "Contact the Abyss developer or support team.",
            ),
            NetworkErrorCode::AbyssRelay => DiagnosisCopy::error(
                "Abyss proxy error: the request could not be relayed.",
                "Contact the Abyss developer or support team.",
            ),
            NetworkErrorCode::AbyssInternal => DiagnosisCopy::error(
                "Abyss proxy error: the request could not be processed.",
                "Contact the Abyss developer or support team.",
            ),
            NetworkErrorCode::ProviderDns => DiagnosisCopy::error(
                "Could not find the model provider address.",
                "Check the computer's DNS, VPN, or network settings, then try again.",
            ),
            NetworkErrorCode::ProviderTcp => DiagnosisCopy::error(
                "Could not connect to the model provider.",
                "Check the computer's network, VPN, or firewall, then try again.",
            ),
            NetworkErrorCode::ProviderTls => DiagnosisCopy::error(
                "Could not establish a secure connection to the model provider.",
                "Check the system time, certificates, VPN, or network interception, then try again.",
            ),
            NetworkErrorCode::ProviderRequest => DiagnosisCopy::error(
                "The model provider request could not be sent.",
                "Check the Agent or API configuration, then try again.",
            ),
            NetworkErrorCode::ProviderResponseHeaders => DiagnosisCopy::error(
                "The model provider did not return response headers.",
                "Check the computer's network or VPN, then try again.",
            ),
            NetworkErrorCode::ProviderStream => DiagnosisCopy::error(
                "The connection to the model provider was interrupted.",
                "Check the computer's network or VPN, then try again.",
            ),
            NetworkErrorCode::ProviderHttp => {
                DiagnosisCopy::error(http_message(http_status), http_guidance(http_status))
            }
            NetworkErrorCode::ProviderInternal => DiagnosisCopy::error(
                "The model provider request could not be processed.",
                "Check the Agent or API configuration, then try again.",
            ),
            NetworkErrorCode::Unknown => DiagnosisCopy::error(
                "Abyss could not complete the request.",
                "Contact the Abyss developer or support team.",
            ),
        }
    }

    const fn generic_diagnosis_for_hop(hop: NetworkHop) -> DiagnosisCopy {
        match hop {
            NetworkHop::AgentToAbyss => DiagnosisCopy::error(
                "Abyss proxy error: the request could not be classified.",
                "Contact the Abyss developer or support team.",
            ),
            NetworkHop::AbyssToProvider => DiagnosisCopy::error(
                "The request to the model provider could not be classified.",
                "Contact the Abyss developer or support team.",
            ),
            NetworkHop::CrossBoundary | NetworkHop::Unknown => DiagnosisCopy::error(
                "Abyss could not complete the request.",
                "Contact the Abyss developer or support team.",
            ),
        }
    }
}

struct DiagnosisCopy {
    severity: DiagnosisSeverity,
    message: &'static str,
    guidance: &'static str,
}

impl DiagnosisCopy {
    const fn error(message: &'static str, guidance: &'static str) -> Self {
        Self {
            severity: DiagnosisSeverity::Error,
            message,
            guidance,
        }
    }

    const fn warning(message: &'static str, guidance: &'static str) -> Self {
        Self {
            severity: DiagnosisSeverity::Warning,
            message,
            guidance,
        }
    }
}

const fn http_message(status: Option<u16>) -> &'static str {
    match status {
        Some(401 | 403) => {
            "The model provider rejected the request (authentication or permission error)."
        }
        Some(429) => "The model provider rate-limited the request.",
        Some(500..=599) => "The model provider returned a server error.",
        _ => "The model provider returned an HTTP error.",
    }
}

const fn http_guidance(status: Option<u16>) -> &'static str {
    match status {
        Some(401 | 403) => "Check the Agent login or API configuration, then try again.",
        Some(429) => "Wait a moment and try again, or check the provider quota and rate limits.",
        Some(500..=599) => "The model provider may be temporarily unavailable; try again later.",
        _ => "Check the Agent or API configuration, then try again.",
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{DiagnosisSeverity, NetworkObservationsResponse, RECENT_DIAGNOSIS_LIMIT};

    #[test]
    fn classifies_and_orders_the_five_most_recent_observations() {
        let observations = (1_u64..=7).map(|observed_at| {
            json!({
                "observed_at_unix_ms": observed_at,
                "destination_host": format!("api-{observed_at}.example.test"),
                "source_process_name": "claude",
                "hop": "abyss_to_provider",
                "stage": "dns_resolution",
                "outcome": "failed",
                "failure_class": "dns_error",
                "technical_error_code": "provider_dns_error",
                "http_status": null
            })
        });
        let response = NetworkObservationsResponse::from_value(json!({
            "schema_version": 1_i32,
            "observations": observations.collect::<Vec<_>>()
        }))
        .expect("response should parse");

        let report = response.diagnose_recent();

        assert_eq!(report.diagnoses.len(), RECENT_DIAGNOSIS_LIMIT);
        assert_eq!(report.diagnoses[0].observed_at_unix_ms, 7);
        assert_eq!(report.diagnoses[4].observed_at_unix_ms, 3);
        assert!(report.diagnoses.iter().all(|diagnosis| {
            diagnosis.severity == DiagnosisSeverity::Error
                && diagnosis.message == "Could not find the model provider address."
        }));
    }

    #[test]
    fn broker_error_code_takes_precedence_over_legacy_fields() {
        let response = NetworkObservationsResponse::from_value(json!({
            "schema_version": 1_i32,
            "observations": [{
                "observed_at_unix_ms": 100_i32,
                "destination_host": "api.example.test",
                "hop": "abyss_to_provider",
                "stage": "tcp_connect",
                "outcome": "failed",
                "failure_class": "timeout",
                "technical_error_code": "provider_dns_error",
                "http_status": null
            }]
        }))
        .expect("response should parse");

        let report = response.diagnose_recent();

        assert_eq!(
            report.diagnoses[0].message,
            "Could not find the model provider address."
        );
    }

    #[test]
    fn renders_error_warning_and_healthy_summary_without_ansi_for_piped_output() {
        let response = NetworkObservationsResponse::from_value(json!({
            "schema_version": 1_i32,
            "observations": [
                {
                    "observed_at_unix_ms": 3_i32,
                    "destination_host": "api.example.test",
                    "source_process_name": "codex",
                    "hop": "abyss_to_provider",
                    "stage": "request",
                    "outcome": "failed",
                    "failure_class": "http_error",
                    "technical_error_code": "provider_http_error",
                    "http_status": 429_i32
                },
                {
                    "observed_at_unix_ms": 2_i32,
                    "destination_host": "api.example.test",
                    "source_process_name": "codex",
                    "hop": "agent_to_abyss",
                    "stage": "stream",
                    "outcome": "interrupted",
                    "failure_class": "client_closed",
                    "technical_error_code": "agent_connection_closed",
                    "http_status": null
                },
                {
                    "observed_at_unix_ms": 1_i32,
                    "destination_host": "api.example.test",
                    "source_process_name": "codex",
                    "hop": "abyss_to_provider",
                    "stage": "stream",
                    "outcome": "succeeded",
                    "failure_class": null,
                    "technical_error_code": null,
                    "http_status": 200_i32
                }
            ]
        }))
        .expect("response should parse");

        let output = response.diagnose_recent().render(false);

        assert!(output.contains("2 most recent Agent network events"));
        assert!(output.contains("Errors 1  Warnings 0  Normal 1"));
        assert!(output.contains("ERROR"));
        assert!(!output.contains("WARNING"));
        assert!(output.contains("NORMAL"));
        assert!(output.contains("HTTP status  429"));
        assert!(!output.contains("\u{1b}["));
    }

    #[test]
    fn agent_lifecycle_closes_are_not_rendered_as_network_diagnoses() {
        let response = NetworkObservationsResponse::from_value(json!({
            "schema_version": 1_i32,
            "observations": [{
                "observed_at_unix_ms": 100_i32,
                "destination_host": "chatgpt.com",
                "source_process_name": "codex",
                "hop": "agent_to_abyss",
                "stage": "stream",
                "outcome": "interrupted",
                "failure_class": "client_closed",
                "technical_error_code": "agent_connection_closed",
                "http_status": null
            }]
        }))
        .expect("response should parse");

        let output = response.diagnose_recent().render(false);

        assert!(output.contains("No Agent request has been observed."));
        assert!(!output.contains("WARNING"));
    }

    #[test]
    fn request_and_websocket_eof_are_not_rendered_as_network_diagnoses() {
        let response = NetworkObservationsResponse::from_value(json!({
            "schema_version": 1_i32,
            "observations": [
                {
                    "observed_at_unix_ms": 101_i32,
                    "destination_host": "chatgpt.com",
                    "source_process_name": "codex",
                    "hop": "agent_to_abyss",
                    "stage": "request",
                    "outcome": "interrupted",
                    "failure_class": "eof",
                    "technical_error_code": "agent_request_error",
                    "http_status": null
                },
                {
                    "observed_at_unix_ms": 100_i32,
                    "destination_host": "chatgpt.com",
                    "source_process_name": "codex",
                    "hop": "agent_to_abyss",
                    "stage": "stream",
                    "outcome": "failed",
                    "failure_class": "eof",
                    "technical_error_code": "abyss_relay_error",
                    "operation": "read_agent_websocket",
                    "http_status": null
                }
            ]
        }))
        .expect("response should parse");

        let output = response.diagnose_recent().render(false);

        assert!(output.contains("No Agent request has been observed."));
    }

    #[test]
    fn websocket_protocol_errors_are_not_suppressed_by_error_text() {
        let response = NetworkObservationsResponse::from_value(json!({
            "schema_version": 1_i32,
            "observations": [{
                "observed_at_unix_ms": 100_i32,
                "destination_host": "chatgpt.com",
                "source_process_name": "codex",
                "hop": "agent_to_abyss",
                "stage": "stream",
                "outcome": "failed",
                "failure_class": "invalid_protocol",
                "technical_error_code": "abyss_relay_error",
                "operation": "read_agent_websocket",
                "error": "server rejected TLS close_notify",
                "http_status": null
            }]
        }))
        .expect("response should parse");

        let report = response.diagnose_recent();

        assert_eq!(report.diagnoses.len(), 1);
        assert!(report.diagnoses[0].severity == DiagnosisSeverity::Error);
    }

    #[test]
    fn renders_clear_no_data_guidance() {
        let response = NetworkObservationsResponse::from_value(json!({
            "schema_version": 1_i32,
            "observations": []
        }))
        .expect("response should parse");

        let output = response.diagnose_recent().render(false);

        assert!(output.contains("No Agent request has been observed."));
        assert!(output.contains("traffic is routed through Abyss"));
    }

    #[test]
    fn accepts_unknown_future_values_with_generic_diagnosis() {
        let response = NetworkObservationsResponse::from_value(json!({
            "schema_version": 1_i32,
            "observations": [{
                "observed_at_unix_ms": 100_i32,
                "destination_host": null,
                "hop": "future_hop",
                "stage": "future_stage",
                "outcome": "future_outcome",
                "failure_class": "future_failure",
                "technical_error_code": "future_error",
                "http_status": null
            }]
        }))
        .expect("future network values should be accepted");

        let report = response.diagnose_recent();

        assert_eq!(report.diagnoses.len(), 1);
        assert_eq!(
            report.diagnoses[0].message,
            "Abyss could not complete the request."
        );
    }
}
