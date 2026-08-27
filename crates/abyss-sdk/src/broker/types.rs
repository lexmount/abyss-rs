//! Stable request and response types published by the broker REST contract.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Successful broker liveness response.
#[derive(Debug, Deserialize)]
pub struct HealthResponse {
    /// Stable local service identity.
    pub service: String,
    /// Current liveness state.
    pub status: String,
}

/// Proxy lifecycle exposed by the broker.
#[derive(Clone, Copy, Debug, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum ProxyLifecycle {
    /// One ingress is accepting traffic.
    Running,
    /// No ingress is accepting traffic.
    Stopped,
}

/// Active proxy mode.
#[derive(Clone, Copy, Debug, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum ProxyMode {
    /// Loopback HTTP explicit proxy.
    Explicit,
    /// Platform transparent interception.
    Transparent,
}

/// Concrete platform ingress identity.
#[derive(Clone, Copy, Debug, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum IngressSource {
    /// Loopback HTTP explicit proxy.
    ExplicitHttp,
    /// macOS Network Extension framed-flow bridge.
    MacosNetworkExtension,
    /// Windows WFP redirected TCP ingress.
    WindowsWfp,
}

/// One bound ingress returned by the status API.
#[derive(Debug, Deserialize)]
pub struct IngressStatus {
    /// Concrete ingress implementation.
    pub source: IngressSource,
    /// Bound TCP address for TCP-based ingresses.
    pub listen_addr: Option<String>,
    /// Bound Unix socket for filesystem-based ingresses.
    #[serde(default)]
    pub socket_path: Option<String>,
}

/// Current local proxy status.
#[derive(Debug, Deserialize)]
pub struct ProxyStatus {
    /// Running or stopped lifecycle.
    pub lifecycle: ProxyLifecycle,
    /// Broker process identifier.
    pub process_id: u32,
    /// Active mode when running.
    pub mode: Option<ProxyMode>,
    /// Active ingress; version 1 returns zero or one item.
    pub ingresses: Vec<IngressStatus>,
    /// Compatibility projection of the active TCP address.
    pub listen_addr: Option<String>,
    /// Compatibility projection of the active Unix socket.
    #[serde(default)]
    pub socket_path: Option<String>,
}

/// REST representation of dynamic MITM behavior.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MitmConfig {
    /// TLS decryption policy evaluated for new flows.
    pub tls_decryption: TlsDecryptionPolicy,
}

/// Source- and destination-aware TLS decryption policy.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TlsDecryptionPolicy {
    /// Action used when no enabled rule matches.
    pub default_action: TlsDecryptionAction,
    /// Action used for a `ClientHello` without SNI.
    pub missing_sni_action: Option<TlsDecryptionAction>,
    /// Ordered matching rules.
    pub rules: Vec<TlsDecryptionRule>,
}

/// Action selected by TLS decryption policy.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum TlsDecryptionAction {
    /// Decrypt and inspect matching TLS traffic.
    Intercept,
    /// Relay matching TLS traffic without decryption.
    Passthrough,
}

/// One ordered TLS decryption rule.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TlsDecryptionRule {
    /// Stable operator-facing rule identifier.
    pub id: String,
    /// Whether the rule participates in matching.
    pub enabled: bool,
    /// Action applied after a match.
    pub action: TlsDecryptionAction,
    /// Exact process-name selectors.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub process_names: Vec<String>,
    /// Exact application-identity selectors.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub application_ids: Vec<String>,
    /// Exact hosts and leading-wildcard suffixes.
    pub destination_hosts: Vec<String>,
}

/// Dynamic configuration for all compiled-in hooks.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HooksConfig {
    /// Harness usage producer policy.
    pub harness_usage: HarnessUsageHookConfig,
}

/// Common envelope for the Harness usage hook.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HarnessUsageHookConfig {
    /// Whether the hook emits events.
    pub enabled: bool,
    /// Hook-owned behavior policy.
    pub config: HarnessUsageConfig,
}

/// Default and per-Harness usage behavior.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HarnessUsageConfig {
    /// Default content retention controls.
    pub content: HarnessUsageContentConfig,
    /// Built-in overrides and custom Harness definitions keyed by Harness id.
    pub harnesses: BTreeMap<String, HarnessConfig>,
}

/// Optional per-Harness behavior override.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HarnessConfig {
    /// Optional producer enablement override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Optional content retention override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<HarnessUsageContentConfig>,
    /// Source matchers for a custom Harness.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matchers: Vec<HarnessMatcherConfig>,
}

/// One custom Harness source matcher.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HarnessMatcherConfig {
    /// Exact process names accepted by the matcher.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub process_names: Vec<String>,
    /// Exact platform-neutral application identities accepted by the matcher.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub application_ids: Vec<String>,
}

/// Independent content retention controls.
#[derive(Debug, Deserialize, Serialize)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "the broker REST contract intentionally exposes four independent retention switches"
)]
#[serde(deny_unknown_fields)]
pub struct HarnessUsageContentConfig {
    /// Retain token usage counters.
    pub token_usage: bool,
    /// Retain conversation request and response text.
    pub conversation_text: bool,
    /// Retain tool call and result content.
    pub tool_calls: bool,
    /// Retain image metadata and content.
    pub images: bool,
}

/// Bounded support-log collection request.
#[derive(Debug, Default, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerLogRequest {
    /// Maximum tail bytes retained for each broker-owned log file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_bytes_per_file: Option<u64>,
}

/// Broker-owned support-log response.
#[derive(Debug, Deserialize)]
pub struct BrokerLogResponse {
    /// Successfully collected files.
    pub files: Vec<BrokerLogFile>,
    /// Per-file collection errors.
    pub errors: Vec<BrokerLogError>,
}

/// One collected broker log file.
#[derive(Debug, Deserialize)]
pub struct BrokerLogFile {
    /// Stable broker-owned log name.
    pub name: String,
    /// UTF-8-lossy tail content.
    pub content: String,
    /// Whether older content was omitted.
    pub truncated: bool,
    /// Complete file size before truncation.
    pub original_size: u64,
}

/// One broker log collection error.
#[derive(Debug, Deserialize)]
pub struct BrokerLogError {
    /// Stable broker-owned log name.
    pub name: String,
    /// Diagnostic error text.
    pub error: String,
}

/// Metadata-only live traffic snapshot.
#[derive(Debug, Deserialize)]
pub struct TrafficSnapshot {
    /// Unix time at which the snapshot was produced.
    pub sampled_at_unix_ms: u64,
    /// Recent client-to-upstream throughput.
    pub upload_bytes_per_second: u64,
    /// Recent upstream-to-client throughput.
    pub download_bytes_per_second: u64,
    /// Total upload bytes since broker startup.
    pub total_upload_bytes: u64,
    /// Total download bytes since broker startup.
    pub total_download_bytes: u64,
    /// Bounded active-flow list.
    pub active_flows: Vec<ActiveFlow>,
}

/// One currently active flow.
#[derive(Debug, Deserialize)]
pub struct ActiveFlow {
    /// Opaque process-local flow identifier.
    pub id: String,
    /// Destination host or address.
    pub host: String,
    /// Source process name when available.
    #[serde(default)]
    pub process: Option<String>,
    /// Source process identifier when available.
    #[serde(default)]
    pub pid: Option<u32>,
    /// Client-to-upstream bytes observed for this flow.
    pub upload_bytes: u64,
    /// Upstream-to-client bytes observed for this flow.
    pub download_bytes: u64,
}
