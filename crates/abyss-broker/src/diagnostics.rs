//! Runtime diagnostics captured by the broker for support bundles.
//!
//! This module keeps diagnostics metadata-only. It records flow decisions,
//! endpoint/process labels, byte counts, and broker runtime state, but never
//! stores HTTP bodies, prompts, responses, cookies, or authorization headers.
//! Completed technical observations are handed to the broker's local
//! Diesel-backed store; this module still does not perform attribution or
//! produce user-facing guidance.

use std::{
    collections::{BTreeMap, VecDeque},
    net::SocketAddr,
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use abyss_mitm::{
    ExplicitProxyProtocol, FlowIngress, SourceProcess, TransparentFlowError,
    TransparentFlowOutcome, TransparentPassthroughProtocol, TransparentProtocol,
};
use serde::Serialize;

use crate::{
    connection::{DestinationAddressRange, OriginalDestination},
    network_diagnostics::NetworkObservation,
    network_diagnostics::NetworkObservationStore,
    proxy::ProxyStatus,
};

const MAX_RECENT_FLOWS: usize = 100;
const MAX_RECENT_ACCEPT_ERRORS: usize = 25;
const MAX_AGGREGATE_KEYS: usize = 100;
const OTHER_KEY: &str = "<other>";
const UNKNOWN_KEY: &str = "<unknown>";

/// Shared recorder for traffic hit/miss diagnostics.
#[derive(Clone)]
pub struct FlowDiagnostics {
    inner: Arc<Mutex<FlowDiagnosticsState>>,
    network_observations: Arc<NetworkObservationStore>,
}

/// Records diagnostics for a flow result without changing the result value.
pub trait RecordFlowDiagnostics: Sized {
    /// Records and traces the completed flow, then returns the original result.
    fn record(self, diagnostics: &FlowDiagnostics, context: FlowDiagnosticContext<'_>) -> Self;
}

/// Borrowed flow metadata shared by diagnostics success and failure paths.
#[derive(Clone)]
pub struct FlowDiagnosticContext<'a> {
    ingress: &'a FlowIngress,
    peer_addr: Option<SocketAddr>,
    local_addr: Option<SocketAddr>,
    original_destination: &'a OriginalDestination,
    destination_host: Option<&'a str>,
    source_process: Option<&'a SourceProcess>,
    flow_id: Option<uuid::Uuid>,
    started_at_unix_ms: Option<u64>,
}

/// Snapshot builder for broker runtime status.
#[derive(Clone)]
pub struct BrokerDiagnosticsService {
    started_at_unix_ms: u64,
    started_at_instant: Instant,
    api_addr: SocketAddr,
    proxy_endpoint: String,
    executable_path: Option<String>,
    flow: FlowDiagnostics,
}

#[derive(Default)]
struct FlowDiagnosticsState {
    accepted_total: u64,
    completed_total: u64,
    in_flight: u64,
    accept_errors_total: u64,
    by_decision: BTreeMap<String, u64>,
    by_ingress: BTreeMap<String, u64>,
    by_host: BTreeMap<String, u64>,
    by_process: BTreeMap<String, u64>,
    by_bundle_id: BTreeMap<String, u64>,
    by_miss_reason: BTreeMap<String, u64>,
    by_destination_address_class: BTreeMap<String, u64>,
    by_fake_ip_host: BTreeMap<String, u64>,
    by_fake_ip_process: BTreeMap<String, u64>,
    recent_flows: VecDeque<FlowRecord>,
    recent_observations: VecDeque<NetworkObservation>,
    recent_accept_errors: VecDeque<AcceptErrorRecord>,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum FlowDecision {
    Intercepted,
    Passthrough,
    Failed,
    Unknown,
}

#[derive(Serialize)]
pub struct BrokerDiagnosticsSnapshot {
    schema_version: u8,
    collected_at_unix_ms: u64,
    broker: BrokerProcessSnapshot,
    proxy: ProxyStatus,
    flow: FlowDiagnosticsSnapshot,
}

#[derive(Serialize)]
struct BrokerProcessSnapshot {
    package_name: &'static str,
    package_version: &'static str,
    process_id: u32,
    executable_path: Option<String>,
    started_at_unix_ms: u64,
    uptime_ms: u64,
    api_addr: String,
    proxy_endpoint: String,
    platform: &'static str,
    arch: &'static str,
}

#[derive(Serialize)]
pub struct FlowDiagnosticsSnapshot {
    totals: FlowTotalsSnapshot,
    aggregates: FlowAggregatesSnapshot,
    recent_flows: Vec<FlowRecord>,
    recent_observations: Vec<NetworkObservation>,
    recent_accept_errors: Vec<AcceptErrorRecord>,
}

#[derive(Serialize)]
struct FlowTotalsSnapshot {
    accepted: u64,
    completed: u64,
    in_flight: u64,
    accept_errors: u64,
}

#[derive(Serialize)]
struct FlowAggregatesSnapshot {
    #[serde(rename = "by_decision")]
    decision: BTreeMap<String, u64>,
    #[serde(rename = "by_ingress")]
    ingress: BTreeMap<String, u64>,
    #[serde(rename = "by_host")]
    host: BTreeMap<String, u64>,
    #[serde(rename = "by_process")]
    process: BTreeMap<String, u64>,
    #[serde(rename = "by_bundle_id")]
    bundle_id: BTreeMap<String, u64>,
    #[serde(rename = "by_miss_reason")]
    miss_reason: BTreeMap<String, u64>,
    #[serde(rename = "by_destination_address_class")]
    destination_address_class: BTreeMap<String, u64>,
    #[serde(rename = "by_fake_ip_host")]
    fake_ip_host: BTreeMap<String, u64>,
    #[serde(rename = "by_fake_ip_process")]
    fake_ip_process: BTreeMap<String, u64>,
}

#[derive(Clone, Serialize)]
struct FlowRecord {
    observed_at_unix_ms: u64,
    ingress: IngressSnapshot,
    decision: FlowDecision,
    miss_reason: Option<String>,
    peer_addr: Option<String>,
    local_addr: Option<String>,
    original_destination: String,
    platform_destination_host: Option<String>,
    fake_ip: Option<FakeIpSnapshot>,
    protocol: Option<String>,
    server_name: Option<String>,
    host: String,
    source_process: SourceProcessSnapshot,
    http: Option<HttpSnapshot>,
    bytes: Option<ByteCountSnapshot>,
}

#[derive(Clone, Serialize)]
struct IngressSnapshot {
    source: &'static str,
    proxy_protocol: Option<&'static str>,
    target: Option<String>,
}

#[derive(Clone, Serialize)]
struct FakeIpSnapshot {
    candidate: bool,
    class: &'static str,
    cidr: &'static str,
    reason: &'static str,
}

#[derive(Clone, Serialize)]
struct AcceptErrorRecord {
    observed_at_unix_ms: u64,
    error: String,
}

#[derive(Clone, Serialize)]
struct SourceProcessSnapshot {
    pid: Option<u32>,
    name: Option<String>,
    executable_path: Option<String>,
    /// Best-effort working directory captured for the source process.
    working_directory: Option<String>,
    bundle_id: Option<String>,
    label: String,
}

#[derive(Clone, Serialize)]
struct HttpSnapshot {
    method: String,
    path: String,
    status: u16,
}

#[derive(Clone, Serialize)]
struct ByteCountSnapshot {
    client_to_upstream: u64,
    upstream_to_client: u64,
}

impl FlowRecord {
    fn from_outcome(
        context: &FlowDiagnosticContext<'_>,
        outcome: &TransparentFlowOutcome,
        observed_at_unix_ms: u64,
    ) -> Self {
        let FlowDiagnosticContext {
            ingress,
            peer_addr,
            local_addr,
            original_destination,
            destination_host,
            source_process,
            ..
        } = context;
        let platform_destination_host = normalized_optional_string(*destination_host);
        let fake_ip = FakeIpSnapshot::from_destination(original_destination);

        match outcome {
            TransparentFlowOutcome::Intercepted(outcome) => {
                let (protocol, server_name) = transparent_protocol_snapshot(&outcome.protocol);
                let host = outcome
                    .first_request
                    .headers()
                    .get("host")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned)
                    .or_else(|| server_name.clone())
                    .or_else(|| platform_destination_host.clone())
                    .unwrap_or_else(|| original_destination.to_string());
                Self {
                    observed_at_unix_ms,
                    ingress: IngressSnapshot::from_ingress(ingress),
                    decision: FlowDecision::Intercepted,
                    miss_reason: None,
                    peer_addr: outcome.peer_addr.map(|addr| addr.to_string()),
                    local_addr: outcome.local_addr.map(|addr| addr.to_string()),
                    original_destination: original_destination.to_string(),
                    platform_destination_host,
                    fake_ip,
                    protocol: Some(protocol),
                    server_name,
                    host,
                    source_process: SourceProcessSnapshot::from_source(*source_process),
                    http: Some(HttpSnapshot {
                        method: outcome.first_request.method().to_string(),
                        path: outcome.first_request.uri().path().to_owned(),
                        status: outcome.first_response.status().as_u16(),
                    }),
                    bytes: Some(ByteCountSnapshot {
                        client_to_upstream: outcome.client_to_upstream_bytes,
                        upstream_to_client: outcome.upstream_to_client_bytes,
                    }),
                }
            }
            TransparentFlowOutcome::Passthrough(outcome) => {
                let (protocol, server_name) = passthrough_protocol_snapshot(&outcome.protocol);
                let host = server_name
                    .clone()
                    .or_else(|| platform_destination_host.clone())
                    .unwrap_or_else(|| original_destination.to_string());
                Self {
                    observed_at_unix_ms,
                    ingress: IngressSnapshot::from_ingress(ingress),
                    decision: FlowDecision::Passthrough,
                    miss_reason: Some("tls_decryption_policy_passthrough".to_owned()),
                    peer_addr: outcome.peer_addr.map(|addr| addr.to_string()),
                    local_addr: outcome.local_addr.map(|addr| addr.to_string()),
                    original_destination: original_destination.to_string(),
                    platform_destination_host,
                    fake_ip,
                    protocol: Some(protocol),
                    server_name,
                    host,
                    source_process: SourceProcessSnapshot::from_source(*source_process),
                    http: None,
                    bytes: Some(ByteCountSnapshot {
                        client_to_upstream: outcome.client_to_upstream_bytes,
                        upstream_to_client: outcome.upstream_to_client_bytes,
                    }),
                }
            }
            _ => {
                let host = platform_destination_host
                    .clone()
                    .unwrap_or_else(|| original_destination.to_string());
                Self {
                    observed_at_unix_ms,
                    ingress: IngressSnapshot::from_ingress(ingress),
                    decision: FlowDecision::Unknown,
                    miss_reason: Some("unknown_outcome".to_owned()),
                    peer_addr: peer_addr.map(|addr| addr.to_string()),
                    local_addr: local_addr.map(|addr| addr.to_string()),
                    original_destination: original_destination.to_string(),
                    platform_destination_host,
                    fake_ip,
                    protocol: None,
                    server_name: None,
                    host,
                    source_process: SourceProcessSnapshot::from_source(*source_process),
                    http: None,
                    bytes: None,
                }
            }
        }
    }

    fn from_failure(
        context: &FlowDiagnosticContext<'_>,
        error: &TransparentFlowError,
        observed_at_unix_ms: u64,
    ) -> Self {
        let FlowDiagnosticContext {
            ingress,
            peer_addr,
            local_addr,
            original_destination,
            destination_host,
            source_process,
            ..
        } = context;
        let platform_destination_host = normalized_optional_string(*destination_host);
        Self {
            observed_at_unix_ms,
            ingress: IngressSnapshot::from_ingress(ingress),
            decision: FlowDecision::Failed,
            miss_reason: Some(flow_error_reason(error).to_owned()),
            peer_addr: peer_addr.map(|addr| addr.to_string()),
            local_addr: local_addr.map(|addr| addr.to_string()),
            original_destination: original_destination.to_string(),
            platform_destination_host: platform_destination_host.clone(),
            fake_ip: FakeIpSnapshot::from_destination(original_destination),
            protocol: None,
            server_name: None,
            host: platform_destination_host.unwrap_or_else(|| original_destination.to_string()),
            source_process: SourceProcessSnapshot::from_source(*source_process),
            http: None,
            bytes: None,
        }
    }
}

impl<'a> FlowDiagnosticContext<'a> {
    /// Creates a borrowed diagnostics context for one normalized flow.
    #[must_use]
    pub const fn new(
        ingress: &'a FlowIngress,
        peer_addr: Option<SocketAddr>,
        local_addr: Option<SocketAddr>,
        original_destination: &'a OriginalDestination,
        destination_host: Option<&'a str>,
        source_process: Option<&'a SourceProcess>,
    ) -> Self {
        Self {
            ingress,
            peer_addr,
            local_addr,
            original_destination,
            destination_host,
            source_process,
            flow_id: None,
            started_at_unix_ms: None,
        }
    }

    /// Adds the broker flow identity and start timestamp to this context.
    #[must_use]
    pub const fn with_flow(mut self, flow_id: uuid::Uuid, started_at_unix_ms: u64) -> Self {
        self.flow_id = Some(flow_id);
        self.started_at_unix_ms = Some(started_at_unix_ms);
        self
    }

    fn trace_outcome(&self, outcome: &TransparentFlowOutcome) {
        match outcome {
            TransparentFlowOutcome::Intercepted(outcome) => {
                let fake_ip_range = mitm_original_destination_range(&outcome.original_destination);
                tracing::info!(
                    peer_addr = ?self.peer_addr,
                    local_addr = ?self.local_addr,
                    original_destination = %outcome.original_destination,
                    destination_host = ?self.destination_host,
                    fake_ip_candidate = fake_ip_range.is_some(),
                    fake_ip_cidr = fake_ip_range.map(DestinationAddressRange::cidr),
                    ingress_source = self.ingress.source_label(),
                    proxy_protocol = ?self.ingress.proxy_protocol(),
                    proxy_target = ?self.ingress.proxy_target().map(abyss_mitm::TargetAuthority::authority),
                    protocol = ?outcome.protocol,
                    method = %outcome.first_request.method(),
                    target_path = %outcome.first_request.uri().path(),
                    host = ?outcome.first_request.headers().get("host").and_then(|value| value.to_str().ok()),
                    client_to_upstream_bytes = outcome.client_to_upstream_bytes,
                    upstream_to_client_bytes = outcome.upstream_to_client_bytes,
                    "broker proxy intercepted flow closed"
                );
            }
            TransparentFlowOutcome::Passthrough(outcome) => {
                let fake_ip_range = mitm_original_destination_range(&outcome.original_destination);
                tracing::info!(
                    peer_addr = ?self.peer_addr,
                    local_addr = ?self.local_addr,
                    original_destination = %outcome.original_destination,
                    destination_host = ?self.destination_host,
                    fake_ip_candidate = fake_ip_range.is_some(),
                    fake_ip_cidr = fake_ip_range.map(DestinationAddressRange::cidr),
                    ingress_source = self.ingress.source_label(),
                    proxy_protocol = ?self.ingress.proxy_protocol(),
                    proxy_target = ?self.ingress.proxy_target().map(abyss_mitm::TargetAuthority::authority),
                    protocol = ?outcome.protocol,
                    client_to_upstream_bytes = outcome.client_to_upstream_bytes,
                    upstream_to_client_bytes = outcome.upstream_to_client_bytes,
                    "broker proxy passthrough flow closed"
                );
            }
            outcome => {
                tracing::warn!(
                    peer_addr = ?self.peer_addr,
                    local_addr = ?self.local_addr,
                    ingress_source = self.ingress.source_label(),
                    outcome = ?outcome,
                    "broker proxy received unknown flow outcome"
                );
            }
        }
    }

    fn trace_failure(&self, error: &TransparentFlowError) {
        let fake_ip_range = self.original_destination.special_address_range();
        tracing::warn!(
            peer_addr = ?self.peer_addr,
            local_addr = ?self.local_addr,
            original_destination = %self.original_destination,
            destination_host = ?self.destination_host,
            fake_ip_candidate = fake_ip_range.is_some(),
            fake_ip_cidr = fake_ip_range.map(DestinationAddressRange::cidr),
            ingress_source = self.ingress.source_label(),
            proxy_protocol = ?self.ingress.proxy_protocol(),
            proxy_target = ?self.ingress.proxy_target().map(abyss_mitm::TargetAuthority::authority),
            %error,
            "broker proxy flow failed"
        );
    }
}

impl RecordFlowDiagnostics for Result<TransparentFlowOutcome, TransparentFlowError> {
    fn record(self, diagnostics: &FlowDiagnostics, context: FlowDiagnosticContext<'_>) -> Self {
        match &self {
            Ok(outcome) => diagnostics.record_outcome(&context, outcome),
            Err(error) => diagnostics.record_failure(&context, error),
        }
        self
    }
}

impl FlowDiagnostics {
    /// Creates an empty flow diagnostics recorder with an in-memory store.
    #[must_use]
    #[cfg(test)]
    pub fn new() -> Self {
        let store = NetworkObservationStore::open(":memory:")
            .expect("in-memory network observation store should open");
        Self::with_network_observation_store(Arc::new(store))
    }

    /// Creates a recorder that persists completed observations locally.
    #[must_use]
    pub fn with_network_observation_store(store: Arc<NetworkObservationStore>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(FlowDiagnosticsState::default())),
            network_observations: store,
        }
    }

    /// Records that the broker accepted a platform flow.
    pub fn record_accepted(&self) {
        self.with_state(|state| {
            state.accepted_total = state.accepted_total.saturating_add(1);
            state.in_flight = state.in_flight.saturating_add(1);
        });
    }

    /// Records an ingress accept error.
    pub fn record_accept_error(&self, error: String) {
        self.with_state(|state| {
            state.accept_errors_total = state.accept_errors_total.saturating_add(1);
            push_bounded(
                &mut state.recent_accept_errors,
                AcceptErrorRecord {
                    observed_at_unix_ms: current_unix_ms(),
                    error,
                },
                MAX_RECENT_ACCEPT_ERRORS,
            );
        });
    }

    /// Records the final decision for one handled proxy flow.
    pub fn record_outcome(
        &self,
        context: &FlowDiagnosticContext<'_>,
        outcome: &TransparentFlowOutcome,
    ) {
        let flow_id = context.flow_id;
        let started_at_unix_ms = context.started_at_unix_ms;
        let ended_at_unix_ms = current_unix_ms();
        let observation = NetworkObservation::from_outcome(
            flow_id,
            context.ingress,
            context.destination_host,
            context.source_process,
            started_at_unix_ms.unwrap_or(ended_at_unix_ms),
            ended_at_unix_ms,
            outcome,
        );
        let record = FlowRecord::from_outcome(context, outcome, ended_at_unix_ms);
        self.record_completed(record, observation);
        context.trace_outcome(outcome);
    }

    /// Records a proxy flow failure with a compact miss reason.
    pub fn record_failure(
        &self,
        context: &FlowDiagnosticContext<'_>,
        error: &TransparentFlowError,
    ) {
        let flow_id = context.flow_id;
        let started_at_unix_ms = context.started_at_unix_ms;
        let ended_at_unix_ms = current_unix_ms();
        let observation = NetworkObservation::from_error(
            flow_id,
            context.ingress,
            context.destination_host,
            context.source_process,
            started_at_unix_ms.unwrap_or(ended_at_unix_ms),
            ended_at_unix_ms,
            error,
        );
        let record = FlowRecord::from_failure(context, error, ended_at_unix_ms);
        self.record_completed(record, observation);
        context.trace_failure(error);
    }

    /// Returns a JSON-serializable snapshot of current flow diagnostics.
    #[must_use]
    pub fn snapshot(&self) -> FlowDiagnosticsSnapshot {
        self.with_state(|state| FlowDiagnosticsSnapshot {
            totals: FlowTotalsSnapshot {
                accepted: state.accepted_total,
                completed: state.completed_total,
                in_flight: state.in_flight,
                accept_errors: state.accept_errors_total,
            },
            aggregates: FlowAggregatesSnapshot {
                decision: state.by_decision.clone(),
                ingress: state.by_ingress.clone(),
                host: state.by_host.clone(),
                process: state.by_process.clone(),
                bundle_id: state.by_bundle_id.clone(),
                miss_reason: state.by_miss_reason.clone(),
                destination_address_class: state.by_destination_address_class.clone(),
                fake_ip_host: state.by_fake_ip_host.clone(),
                fake_ip_process: state.by_fake_ip_process.clone(),
            },
            recent_flows: state.recent_flows.iter().cloned().collect(),
            recent_observations: state.recent_observations.iter().cloned().collect(),
            recent_accept_errors: state.recent_accept_errors.iter().cloned().collect(),
        })
    }

    fn record_completed(&self, record: FlowRecord, observation: NetworkObservation) {
        let persisted_observation = observation.clone();
        self.with_state(|state| {
            state.completed_total = state.completed_total.saturating_add(1);
            state.in_flight = state.in_flight.saturating_sub(1);
            increment_bounded(&mut state.by_decision, record.decision.name());
            increment_bounded(&mut state.by_ingress, record.ingress.source);
            increment_bounded(&mut state.by_host, &record.host);
            increment_bounded(&mut state.by_process, &record.source_process.label);
            if let Some(bundle_id) = &record.source_process.bundle_id {
                increment_bounded(&mut state.by_bundle_id, bundle_id);
            }
            if let Some(reason) = &record.miss_reason {
                increment_bounded(&mut state.by_miss_reason, reason);
            }
            let destination_class = record
                .fake_ip
                .as_ref()
                .map_or("ordinary", |fake_ip| fake_ip.class);
            increment_bounded(&mut state.by_destination_address_class, destination_class);
            if record.fake_ip.is_some() {
                increment_bounded(&mut state.by_fake_ip_host, &record.host);
                increment_bounded(&mut state.by_fake_ip_process, &record.source_process.label);
            }
            push_bounded(&mut state.recent_flows, record, MAX_RECENT_FLOWS);
            push_bounded(
                &mut state.recent_observations,
                observation,
                MAX_RECENT_FLOWS,
            );
        });
        let store = Arc::clone(&self.network_observations);
        let persist = move || {
            if let Err(error) = store.insert(&persisted_observation) {
                tracing::error!(%error, "failed to persist network observation");
            }
        };
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                drop(handle.spawn_blocking(persist));
            }
            Err(_) => persist(),
        }
    }

    fn with_state<R, F>(&self, function: F) -> R
    where
        F: FnOnce(&mut FlowDiagnosticsState) -> R,
    {
        let mut guard = match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        function(&mut guard)
    }
}

impl BrokerDiagnosticsService {
    /// Creates a broker diagnostics snapshotter.
    #[must_use]
    pub async fn new(api_addr: SocketAddr, proxy_endpoint: String, flow: FlowDiagnostics) -> Self {
        let executable_path = match tokio::task::spawn_blocking(current_executable_path).await {
            Ok(path) => path,
            Err(error) => {
                tracing::warn!(%error, "failed to query broker executable path");
                None
            }
        };
        Self {
            started_at_unix_ms: current_unix_ms(),
            started_at_instant: Instant::now(),
            api_addr,
            proxy_endpoint,
            executable_path,
            flow,
        }
    }

    /// Returns the Unix timestamp at which this broker diagnostics session began.
    #[must_use]
    pub const fn started_at_unix_ms(&self) -> u64 {
        self.started_at_unix_ms
    }

    /// Captures broker status and flow diagnostics.
    #[must_use]
    pub fn snapshot(&self, proxy: ProxyStatus) -> BrokerDiagnosticsSnapshot {
        BrokerDiagnosticsSnapshot {
            schema_version: 1,
            collected_at_unix_ms: current_unix_ms(),
            broker: BrokerProcessSnapshot {
                package_name: env!("CARGO_PKG_NAME"),
                package_version: env!("CARGO_PKG_VERSION"),
                process_id: std::process::id(),
                executable_path: self.executable_path.clone(),
                started_at_unix_ms: self.started_at_unix_ms,
                uptime_ms: duration_millis(self.started_at_instant.elapsed()),
                api_addr: self.api_addr.to_string(),
                proxy_endpoint: self.proxy_endpoint.clone(),
                platform: std::env::consts::OS,
                arch: std::env::consts::ARCH,
            },
            proxy,
            flow: self.flow.snapshot(),
        }
    }
}

impl FlowDecision {
    const fn name(self) -> &'static str {
        match self {
            Self::Intercepted => "intercepted",
            Self::Passthrough => "passthrough",
            Self::Failed => "failed",
            Self::Unknown => "unknown",
        }
    }
}

impl IngressSnapshot {
    fn from_ingress(ingress: &FlowIngress) -> Self {
        Self {
            source: ingress.source_label(),
            proxy_protocol: ingress.proxy_protocol().map(explicit_proxy_protocol_label),
            target: ingress
                .proxy_target()
                .map(abyss_mitm::TargetAuthority::authority),
        }
    }
}

impl SourceProcessSnapshot {
    fn from_source(source: Option<&SourceProcess>) -> Self {
        let Some(source) = source else {
            return Self {
                pid: None,
                name: None,
                executable_path: None,
                working_directory: None,
                bundle_id: None,
                label: UNKNOWN_KEY.to_owned(),
            };
        };
        let label = source_process_label(source);
        Self {
            pid: source.pid,
            name: source.name.clone(),
            executable_path: source.executable_path.clone(),
            working_directory: source.working_directory.clone(),
            bundle_id: source.application_id.clone(),
            label,
        }
    }
}

impl FakeIpSnapshot {
    fn from_destination(destination: &OriginalDestination) -> Option<Self> {
        destination
            .special_address_range()
            .map(Self::from_address_range)
    }

    const fn from_address_range(range: DestinationAddressRange) -> Self {
        Self {
            candidate: true,
            class: range.name(),
            cidr: range.cidr(),
            reason: range.reason(),
        }
    }
}

const fn mitm_original_destination_range(
    destination: &abyss_mitm::OriginalDestination,
) -> Option<DestinationAddressRange> {
    OriginalDestination {
        ip: destination.ip,
        port: destination.port,
    }
    .special_address_range()
}

fn increment_bounded(map: &mut BTreeMap<String, u64>, key: &str) {
    let target = if map.contains_key(key) || map.len() < MAX_AGGREGATE_KEYS {
        key
    } else {
        OTHER_KEY
    };
    let count = map.entry(target.to_owned()).or_insert(0);
    *count = count.saturating_add(1);
}

fn push_bounded<T>(records: &mut VecDeque<T>, record: T, max_records: usize) {
    records.push_back(record);
    while records.len() > max_records {
        let _removed = records.pop_front();
    }
}

fn transparent_protocol_snapshot(protocol: &TransparentProtocol) -> (String, Option<String>) {
    match protocol {
        TransparentProtocol::PlainHttp => ("plain_http".to_owned(), None),
        TransparentProtocol::TlsHttp { server_name } => {
            ("tls_http".to_owned(), Some(server_name.clone()))
        }
        _ => ("unknown".to_owned(), None),
    }
}

fn passthrough_protocol_snapshot(
    protocol: &TransparentPassthroughProtocol,
) -> (String, Option<String>) {
    match protocol {
        TransparentPassthroughProtocol::Tls { server_name } => {
            ("tls_passthrough".to_owned(), server_name.clone())
        }
        _ => ("unknown_passthrough".to_owned(), None),
    }
}

const fn explicit_proxy_protocol_label(protocol: ExplicitProxyProtocol) -> &'static str {
    match protocol {
        ExplicitProxyProtocol::HttpConnect => "http_connect",
        ExplicitProxyProtocol::HttpAbsoluteForm => "http_absolute_form",
        _ => "unknown",
    }
}

const fn flow_error_reason(error: &TransparentFlowError) -> &'static str {
    match error {
        TransparentFlowError::ClientClosedBeforeProtocol => "client_closed_before_protocol",
        TransparentFlowError::UnsupportedProtocol => "unsupported_protocol",
        TransparentFlowError::MissingSni => "missing_sni",
        TransparentFlowError::Tls { .. } => "tls_error",
        TransparentFlowError::Http1 { .. } => "http1_decode_error",
        TransparentFlowError::WebSocket { .. } => "websocket_error",
        TransparentFlowError::Io { .. } => "io_error",
        TransparentFlowError::Timeout { .. } => "timeout",
        TransparentFlowError::ByteCountOverflow => "byte_count_overflow",
        TransparentFlowError::TlsClientHelloTooLarge { .. } => "tls_client_hello_too_large",
        TransparentFlowError::MalformedTlsClientHello(_) => "malformed_tls_client_hello",
        TransparentFlowError::ProxyTargetServerNameMismatch { .. } => {
            "proxy_target_server_name_mismatch"
        }
        TransparentFlowError::ProxyTargetHostMismatch { .. } => "proxy_target_host_mismatch",
        TransparentFlowError::ProxyTargetRequestForm { .. } => "proxy_target_request_form",
        TransparentFlowError::TlsConfiguration(_) => "tls_configuration_error",
        TransparentFlowError::TlsDecryptionPolicy(_) => "invalid_tls_decryption_policy",
        _ => "unknown_error",
    }
}

fn normalized_optional_string(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn source_process_label(source: &SourceProcess) -> String {
    source
        .application_id
        .clone()
        .or_else(|| source.name.clone())
        .or_else(|| executable_file_name(source.executable_path.as_deref()))
        .unwrap_or_else(|| UNKNOWN_KEY.to_owned())
}

fn executable_file_name(path: Option<&str>) -> Option<String> {
    let path = path?;
    Path::new(path)
        .file_name()
        .and_then(|value| value.to_str())
        .map(str::to_owned)
}

fn current_executable_path() -> Option<String> {
    std::env::current_exe()
        .ok()
        .map(|path| path.display().to_string())
}

fn current_unix_ms() -> u64 {
    system_time_ms(SystemTime::now()).unwrap_or(0)
}

fn system_time_ms(time: SystemTime) -> Option<u64> {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use crate::network_diagnostics::{NetworkFailureClass, NetworkHop, NetworkStage};

    use super::*;

    #[test]
    fn record_flow_diagnostics_returns_and_records_failure() {
        let diagnostics = FlowDiagnostics::new();
        let ingress = test_ingress();
        let original_destination = OriginalDestination {
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 443,
        };
        diagnostics.record_accepted();
        let result: Result<TransparentFlowOutcome, TransparentFlowError> =
            Err(TransparentFlowError::MissingSni);

        let recorded = result.record(
            &diagnostics,
            FlowDiagnosticContext::new(&ingress, None, None, &original_destination, None, None),
        );

        assert!(matches!(recorded, Err(TransparentFlowError::MissingSni)));
        let snapshot = diagnostics.snapshot();
        assert_eq!(snapshot.totals.accepted, 1);
        assert_eq!(snapshot.totals.completed, 1);
        assert_eq!(snapshot.totals.in_flight, 0);
        assert_eq!(snapshot.aggregates.decision["failed"], 1);
        assert_eq!(snapshot.aggregates.miss_reason["missing_sni"], 1);
    }

    #[test]
    fn flow_diagnostics_records_process_and_failure_aggregates() {
        let diagnostics = FlowDiagnostics::new();
        let source_process = SourceProcess::new(
            Some(42),
            Some("Claude".to_owned()),
            Some("/Applications/Claude.app/Contents/MacOS/Claude".to_owned()),
        );
        diagnostics.record_accepted();
        diagnostics.record_failure(
            &FlowDiagnosticContext::new(
                &test_ingress(),
                None,
                None,
                &OriginalDestination {
                    ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                    port: 443,
                },
                None,
                Some(&source_process),
            ),
            &TransparentFlowError::UnsupportedProtocol,
        );

        let snapshot = diagnostics.snapshot();

        assert_eq!(snapshot.totals.accepted, 1);
        assert_eq!(snapshot.totals.completed, 1);
        assert_eq!(snapshot.totals.in_flight, 0);
        assert_eq!(snapshot.aggregates.decision["failed"], 1);
        assert_eq!(snapshot.aggregates.miss_reason["unsupported_protocol"], 1);
        assert_eq!(snapshot.aggregates.host["1.1.1.1:443"], 1);
        assert_eq!(snapshot.aggregates.process["Claude"], 1);
        assert_eq!(snapshot.recent_flows.len(), 1);
        assert_eq!(snapshot.recent_observations.len(), 1);
        assert_eq!(
            snapshot.recent_observations[0].failure_class,
            Some(NetworkFailureClass::InvalidProtocol)
        );
        assert_eq!(
            snapshot.recent_observations[0].hop,
            NetworkHop::AgentToAbyss
        );
        assert_eq!(
            snapshot.recent_observations[0].stage,
            NetworkStage::ProtocolDetection
        );
    }

    #[test]
    fn flow_diagnostics_serializes_source_working_directory() {
        let diagnostics = FlowDiagnostics::new();
        let source_process = SourceProcess::new(
            Some(42),
            Some("codex".to_owned()),
            Some("/usr/local/bin/codex".to_owned()),
        )
        .with_working_directory(Some("/Users/alice/repo".to_owned()));
        diagnostics.record_failure(
            &FlowDiagnosticContext::new(
                &test_ingress(),
                None,
                None,
                &OriginalDestination {
                    ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    port: 443,
                },
                Some("api.openai.com"),
                Some(&source_process),
            ),
            &TransparentFlowError::UnsupportedProtocol,
        );

        let snapshot = diagnostics.snapshot();
        let serialized =
            serde_json::to_value(&snapshot).expect("flow diagnostics snapshot should serialize");

        assert_eq!(
            serialized["recent_flows"][0]["source_process"]["working_directory"],
            "/Users/alice/repo"
        );
    }

    #[test]
    fn flow_diagnostics_records_failures() {
        let diagnostics = FlowDiagnostics::new();
        diagnostics.record_accepted();
        diagnostics.record_failure(
            &FlowDiagnosticContext::new(
                &test_ingress(),
                None,
                None,
                &OriginalDestination {
                    ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    port: 8443,
                },
                None,
                None,
            ),
            &TransparentFlowError::MissingSni,
        );

        let snapshot = diagnostics.snapshot();

        assert_eq!(snapshot.totals.accepted, 1);
        assert_eq!(snapshot.totals.completed, 1);
        assert_eq!(snapshot.aggregates.decision["failed"], 1);
        assert_eq!(snapshot.aggregates.miss_reason["missing_sni"], 1);
        assert_eq!(snapshot.recent_flows[0].host, "127.0.0.1:8443");
        assert_eq!(
            snapshot.recent_flows[0].ingress.source,
            "unattributed_transparent"
        );
        assert_eq!(snapshot.recent_flows[0].ingress.proxy_protocol, None);
        assert_eq!(snapshot.recent_observations.len(), 1);
        assert_eq!(
            snapshot.recent_observations[0].failure_class,
            Some(NetworkFailureClass::TlsError)
        );
        assert_eq!(
            snapshot.recent_observations[0].hop,
            NetworkHop::AgentToAbyss
        );
        assert_eq!(
            snapshot.recent_observations[0].stage,
            NetworkStage::TlsHandshake
        );
    }

    #[test]
    fn flow_diagnostics_records_fake_ip_candidates() {
        let diagnostics = FlowDiagnostics::new();
        let source_process = SourceProcess::new(
            Some(123),
            Some("codex".to_owned()),
            Some("/usr/local/bin/codex".to_owned()),
        )
        .with_application_id(Some("codex".to_owned()));
        diagnostics.record_accepted();
        diagnostics.record_failure(
            &FlowDiagnosticContext::new(
                &test_ingress(),
                None,
                None,
                &OriginalDestination {
                    ip: IpAddr::V4(Ipv4Addr::new(198, 19, 0, 2)),
                    port: 443,
                },
                Some("chatgpt.com"),
                Some(&source_process),
            ),
            &TransparentFlowError::Timeout {
                operation: abyss_mitm::FlowOperation::ConnectProviderTcp,
                timeout: Duration::from_secs(10),
            },
        );

        let snapshot = diagnostics.snapshot();
        let flow = &snapshot.recent_flows[0];
        let fake_ip = flow
            .fake_ip
            .as_ref()
            .expect("fake-IP candidate should be annotated");

        assert_eq!(flow.host, "chatgpt.com");
        assert_eq!(
            flow.platform_destination_host.as_deref(),
            Some("chatgpt.com")
        );
        assert!(fake_ip.candidate);
        assert_eq!(fake_ip.class, "fake_ip_candidate");
        assert_eq!(fake_ip.cidr, "198.18.0.0/15");
        assert_eq!(
            fake_ip.reason,
            "destination_ip_in_ipv4_benchmark_net_commonly_used_for_proxy_fake_ip"
        );
        assert_eq!(
            snapshot.aggregates.destination_address_class["fake_ip_candidate"],
            1
        );
        assert_eq!(snapshot.aggregates.fake_ip_host["chatgpt.com"], 1);
        assert_eq!(snapshot.aggregates.fake_ip_process["codex"], 1);
        assert_eq!(snapshot.recent_observations.len(), 1);
        assert_eq!(
            snapshot.recent_observations[0].failure_class,
            Some(NetworkFailureClass::Timeout)
        );
        assert_eq!(
            snapshot.recent_observations[0].hop,
            NetworkHop::AbyssToProvider
        );
        assert_eq!(
            snapshot.recent_observations[0].stage,
            NetworkStage::TcpConnect
        );
    }

    #[test]
    fn flow_accept_errors_are_not_network_observations() {
        let diagnostics = FlowDiagnostics::new();

        diagnostics.record_accept_error("platform accept failed".to_owned());

        let snapshot = diagnostics.snapshot();

        assert_eq!(snapshot.totals.accept_errors, 1);
        assert!(snapshot.recent_observations.is_empty());
        assert_eq!(snapshot.recent_accept_errors.len(), 1);
    }

    #[test]
    fn completed_observations_are_persisted_when_store_is_configured() {
        let store = Arc::new(
            NetworkObservationStore::open(":memory:")
                .expect("in-memory network observation store should open"),
        );
        let diagnostics = FlowDiagnostics::with_network_observation_store(store.clone());
        diagnostics.record_accepted();
        diagnostics.record_failure(
            &FlowDiagnosticContext::new(
                &test_ingress(),
                None,
                None,
                &OriginalDestination {
                    ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    port: 443,
                },
                Some("api.example.test"),
                None,
            ),
            &TransparentFlowError::Timeout {
                operation: abyss_mitm::FlowOperation::ConnectProviderTcp,
                timeout: Duration::from_secs(5),
            },
        );

        let observations = store
            .latest(10)
            .expect("persisted observations should be queryable");
        assert_eq!(observations.len(), 1);
        assert_eq!(
            observations[0].destination_host.as_deref(),
            Some("api.example.test")
        );
        assert_eq!(observations[0].hop, NetworkHop::AbyssToProvider);
        assert_eq!(observations[0].stage, NetworkStage::TcpConnect);
    }

    fn test_ingress() -> FlowIngress {
        FlowIngress::transparent(abyss_mitm::TransparentFlowSource::Unattributed)
    }
}
