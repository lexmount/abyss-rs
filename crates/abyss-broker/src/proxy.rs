//! Local proxy listeners controlled by the broker REST API.
//!
//! Each concrete ingress is monomorphized into its own worker. Lifecycle state
//! retains only one task control handle and its common status snapshot, keeping
//! dynamic dispatch out of the connection path.

use std::{net::SocketAddr, path::Path, sync::Arc};

use serde::Serialize;
use tokio::{
    sync::{Mutex, oneshot},
    task::{JoinError, JoinHandle, JoinSet},
};

use crate::{
    diagnostics::{FlowDiagnosticContext, FlowDiagnostics, RecordFlowDiagnostics},
    error::BrokerError,
    ingress::{
        Ingress, IngressConnection, IngressFactory, IngressRuntimeStatus, PlatformFlow, ProxyMode,
        ProxyPlan, StartedIngress,
    },
    traffic::{TrafficFlowHandle, TrafficMonitor},
};

const MAX_CONCURRENT_PROXY_CONNECTIONS: usize = 256;
const PROXY_SHUTDOWN_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

struct TrafficFlowFinishGuard(TrafficFlowHandle);

impl Drop for TrafficFlowFinishGuard {
    fn drop(&mut self) {
        self.0.finish();
    }
}

/// Proxy lifecycle reported by the REST API and CLI.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyLifecycle {
    Running,
    Stopped,
}

/// Proxy status returned by `abyss-broker`.
///
/// Runtime status is modeled as distinct states. State-dependent optional
/// fields exist only in the compatibility JSON projection implemented below.
#[derive(Debug)]
pub enum ProxyStatus {
    /// The proxy owns a bound ingress worker.
    Started(StartedProxyStatus),
    /// The proxy owns no ingress resources.
    Stopped(StoppedProxyStatus),
}

/// Status fields that always exist while the proxy is started.
#[derive(Debug)]
pub struct StartedProxyStatus {
    process_id: u32,
    mode: ProxyMode,
    ingress: IngressRuntimeStatus,
}

/// Status fields that always exist while the proxy is stopped.
#[derive(Debug)]
pub struct StoppedProxyStatus {
    process_id: u32,
}

impl ProxyStatus {
    /// Returns the stable lifecycle label exposed by the REST API.
    #[must_use]
    pub const fn lifecycle(&self) -> ProxyLifecycle {
        match self {
            Self::Started(_) => ProxyLifecycle::Running,
            Self::Stopped(_) => ProxyLifecycle::Stopped,
        }
    }

    /// Returns the broker process that owns this proxy state.
    #[must_use]
    pub const fn process_id(&self) -> u32 {
        match self {
            Self::Started(status) => status.process_id,
            Self::Stopped(status) => status.process_id,
        }
    }

    /// Returns the started state when the proxy owns an ingress worker.
    #[must_use]
    pub const fn started(&self) -> Option<&StartedProxyStatus> {
        match self {
            Self::Started(status) => Some(status),
            Self::Stopped(_) => None,
        }
    }
}

impl StartedProxyStatus {
    /// Returns the active proxy mode.
    #[must_use]
    pub const fn mode(&self) -> ProxyMode {
        self.mode
    }

    /// Returns the active bound ingress.
    #[must_use]
    pub const fn ingress(&self) -> &IngressRuntimeStatus {
        &self.ingress
    }
}

impl Serialize for ProxyStatus {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        struct ProxyStatusResponse<'a> {
            lifecycle: ProxyLifecycle,
            process_id: u32,
            mode: Option<ProxyMode>,
            ingresses: &'a [IngressRuntimeStatus],
            listen_addr: Option<SocketAddr>,
            #[serde(skip_serializing_if = "Option::is_none")]
            socket_path: Option<&'a Path>,
        }

        let started = self.started();
        let ingress = started.map(StartedProxyStatus::ingress);
        ProxyStatusResponse {
            lifecycle: self.lifecycle(),
            process_id: self.process_id(),
            mode: started.map(StartedProxyStatus::mode),
            ingresses: ingress.map_or(&[], std::slice::from_ref),
            listen_addr: ingress.and_then(IngressRuntimeStatus::listen_addr),
            socket_path: ingress.and_then(IngressRuntimeStatus::socket_path),
        }
        .serialize(serializer)
    }
}

/// Shared proxy service handle used by REST handlers.
#[derive(Clone)]
pub struct ProxyService {
    state: Arc<Mutex<ProxyRuntimeState>>,
    worker_services: ProxyWorkerServices,
}

#[derive(Clone)]
struct ProxyWorkerServices {
    mitm: Arc<abyss_mitm::MitmEngine>,
    diagnostics: FlowDiagnostics,
    traffic: TrafficMonitor,
}

enum ProxyRuntimeState {
    Stopped(StoppedProxyRuntime),
    Started(StartedProxyRuntime),
}

struct StoppedProxyRuntime {
    process_id: u32,
}

struct StartedProxyRuntime {
    process_id: u32,
    requested_plan: ProxyPlan,
    task: IngressTask,
}

struct IngressTask {
    status: IngressRuntimeStatus,
    shutdown: oneshot::Sender<()>,
    join_handle: JoinHandle<()>,
}

impl ProxyService {
    /// Creates a proxy service backed by the shared MITM engine.
    #[must_use]
    pub fn new(
        mitm: Arc<abyss_mitm::MitmEngine>,
        diagnostics: FlowDiagnostics,
        traffic: TrafficMonitor,
    ) -> Self {
        Self {
            state: Arc::new(Mutex::new(ProxyRuntimeState::stopped())),
            worker_services: ProxyWorkerServices {
                mitm,
                diagnostics,
                traffic,
            },
        }
    }

    /// Starts the requested proxy ingress plan when it is not already running.
    ///
    /// # Errors
    ///
    /// Returns an error when binding fails or a proxy is already running on a
    /// different endpoint.
    #[tracing::instrument(level = "trace", skip_all)]
    pub async fn start(&self, plan: ProxyPlan) -> Result<ProxyStatus, BrokerError> {
        let mut state = self.state.lock().await;
        if let ProxyRuntimeState::Started(runtime) = &*state {
            if runtime.matches_plan(&plan) {
                return Ok(ProxyStatus::Started(runtime.status()));
            }
            return Err(BrokerError::ProxyAlreadyRunning {
                current: runtime.endpoint_label(),
                requested: plan.endpoint_label(),
            });
        }

        let previous = std::mem::replace(&mut *state, ProxyRuntimeState::stopped());
        let ProxyRuntimeState::Stopped(stopped) = previous else {
            unreachable!("started proxy state was handled before transition");
        };
        let started = stopped.start(plan, self.worker_services.clone()).await?;
        let started_status = started.status();
        let listen_addr = started_status.ingress().listen_addr();
        let socket_path = started_status.ingress().socket_path();
        let mode = started_status.mode();
        *state = ProxyRuntimeState::Started(started);
        drop(state);
        tracing::info!(
            ?mode,
            ingress_count = 1_usize,
            ?listen_addr,
            ?socket_path,
            "broker proxy started"
        );
        Ok(ProxyStatus::Started(started_status))
    }

    /// Stops the proxy listener when it is running.
    ///
    /// # Errors
    ///
    /// Returns an error when the listener task cannot be joined cleanly.
    #[tracing::instrument(level = "trace", skip_all)]
    pub async fn stop(&self) -> Result<ProxyStatus, BrokerError> {
        let mut state = self.state.lock().await;
        if let ProxyRuntimeState::Stopped(stopped) = &*state {
            return Ok(ProxyStatus::Stopped(stopped.status()));
        }

        let previous = std::mem::replace(&mut *state, ProxyRuntimeState::stopped());
        let ProxyRuntimeState::Started(started) = previous else {
            unreachable!("stopped proxy state was handled before transition");
        };
        let endpoint = started.endpoint_label();
        let stopped = started.stop().await?;
        let stopped_status = stopped.status();
        *state = ProxyRuntimeState::Stopped(stopped);
        drop(state);
        tracing::info!(%endpoint, "broker proxy stopped");
        Ok(ProxyStatus::Stopped(stopped_status))
    }

    /// Returns the current proxy status.
    pub async fn status(&self) -> ProxyStatus {
        let state = self.state.lock().await;
        state.status()
    }
}

impl ProxyRuntimeState {
    fn stopped() -> Self {
        Self::Stopped(StoppedProxyRuntime::new())
    }

    fn status(&self) -> ProxyStatus {
        match self {
            Self::Stopped(stopped) => ProxyStatus::Stopped(stopped.status()),
            Self::Started(started) => ProxyStatus::Started(started.status()),
        }
    }
}

impl StoppedProxyRuntime {
    fn new() -> Self {
        Self {
            process_id: std::process::id(),
        }
    }

    async fn start(
        self,
        plan: ProxyPlan,
        services: ProxyWorkerServices,
    ) -> Result<StartedProxyRuntime, BrokerError> {
        let requested_plan = plan.clone();
        let task = match plan {
            ProxyPlan::Explicit { explicit } => {
                let started = Self::bind_factory(explicit.into_factory()).await?;
                Self::spawn_started(started, services)
            }
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            ProxyPlan::Transparent { transparent } => {
                let started = Self::bind_factory(transparent.into_factory()).await?;
                Self::spawn_started(started, services)
            }
        };
        Ok(StartedProxyRuntime {
            process_id: self.process_id,
            requested_plan,
            task,
        })
    }

    async fn bind_factory<F>(factory: F) -> Result<StartedIngress<F::Ingress>, BrokerError>
    where
        F: IngressFactory,
    {
        Ok(factory.start().await?)
    }

    fn spawn_started<I>(started: StartedIngress<I>, services: ProxyWorkerServices) -> IngressTask
    where
        I: Ingress + 'static,
    {
        let (ingress, status) = started.into_parts();
        let (shutdown, shutdown_rx) = oneshot::channel();
        let join_handle = tokio::spawn(
            ProxyWorker::new(
                ingress,
                services.mitm,
                services.diagnostics,
                services.traffic,
            )
            .run(shutdown_rx),
        );
        IngressTask {
            status,
            shutdown,
            join_handle,
        }
    }

    const fn status(&self) -> StoppedProxyStatus {
        StoppedProxyStatus {
            process_id: self.process_id,
        }
    }
}

impl StartedProxyRuntime {
    fn matches_plan(&self, plan: &ProxyPlan) -> bool {
        self.requested_plan == *plan
    }

    fn endpoint_label(&self) -> String {
        self.requested_plan.endpoint_label()
    }

    fn status(&self) -> StartedProxyStatus {
        StartedProxyStatus {
            process_id: self.process_id,
            mode: self.requested_plan.mode(),
            ingress: self.task.status.clone(),
        }
    }

    async fn stop(self) -> Result<StoppedProxyRuntime, BrokerError> {
        self.task.stop().await?;
        Ok(StoppedProxyRuntime {
            process_id: self.process_id,
        })
    }
}

impl IngressTask {
    async fn stop(self) -> Result<(), BrokerError> {
        let endpoint = self.status.endpoint_label();
        let _sent = self.shutdown.send(());
        self.join_handle
            .await
            .map_err(|source| BrokerError::task("stop proxy listener", source))?;
        tracing::info!(%endpoint, "broker ingress stopped");
        Ok(())
    }
}

struct ProxyWorker<I> {
    ingress: I,
    mitm: Arc<abyss_mitm::MitmEngine>,
    diagnostics: FlowDiagnostics,
    traffic: TrafficMonitor,
    connections: JoinSet<()>,
    shutdown_drain_timeout: std::time::Duration,
}

impl<I> ProxyWorker<I>
where
    I: Ingress + 'static,
{
    fn new(
        ingress: I,
        mitm: Arc<abyss_mitm::MitmEngine>,
        diagnostics: FlowDiagnostics,
        traffic: TrafficMonitor,
    ) -> Self {
        Self {
            ingress,
            mitm,
            diagnostics,
            traffic,
            connections: JoinSet::new(),
            shutdown_drain_timeout: PROXY_SHUTDOWN_DRAIN_TIMEOUT,
        }
    }

    #[cfg(all(test, unix))]
    const fn with_shutdown_drain_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.shutdown_drain_timeout = timeout;
        self
    }

    #[expect(
        clippy::integer_division_remainder_used,
        reason = "tokio::select! expands through runtime code that uses remainder internally."
    )]
    async fn run(mut self, mut shutdown: oneshot::Receiver<()>) {
        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    break;
                }
                accepted = self.ingress.accept(), if self.connections.len() < MAX_CONCURRENT_PROXY_CONNECTIONS => {
                    match accepted {
                        Ok(connection) => {
                            self.spawn_connection(connection);
                        }
                        Err(error) => {
                            self.diagnostics.record_accept_error(error.to_string());
                            tracing::warn!(%error, "broker ingress accept failed");
                        }
                    }
                }
                completed = self.connections.join_next(), if !self.connections.is_empty() => {
                    Self::log_connection_task_result(completed);
                }
            }
        }
        self.drain_connections().await;
        self.ingress.shutdown().await;
    }

    fn spawn_connection(&mut self, connection: I::Accepted) {
        self.connections.spawn(
            ProxyConnection::new(
                connection,
                self.mitm.clone(),
                self.diagnostics.clone(),
                self.traffic.clone(),
            )
            .run(),
        );
        if self.connections.len() == MAX_CONCURRENT_PROXY_CONNECTIONS {
            tracing::warn!(
                connection_limit = MAX_CONCURRENT_PROXY_CONNECTIONS,
                "broker proxy reached its concurrent connection limit"
            );
        }
    }

    /// Gracefully shuts down the connection tasks after the accept loop stops.
    ///
    /// Existing connections may finish naturally until the drain timeout expires. Any tasks
    /// still running after that deadline are aborted and joined so cancellation completes before
    /// the worker returns. This is an explicit async shutdown step rather than `Drop` cleanup
    /// because waiting for tasks requires `.await`; if the worker is dropped unexpectedly, the
    /// [`JoinSet`] destructor still aborts its remaining tasks as a last-resort fallback.
    async fn drain_connections(&mut self) {
        let connection_count = self.connections.len();
        if connection_count > 0 {
            tracing::info!(
                connection_count,
                "broker proxy draining in-flight connections"
            );
        }
        let drain_timeout = self.shutdown_drain_timeout;
        let drain = async {
            while let Some(result) = self.connections.join_next().await {
                Self::log_connection_join_result(result);
            }
        };
        if tokio::time::timeout(drain_timeout, drain).await.is_err() {
            let remaining_connections = self.connections.len();
            tracing::warn!(
                remaining_connections,
                timeout = ?drain_timeout,
                "broker proxy aborting connections after shutdown drain timeout"
            );
            self.connections.abort_all();
            while let Some(result) = self.connections.join_next().await {
                Self::log_connection_join_result(result);
            }
        }
    }

    fn log_connection_task_result(result: Option<Result<(), JoinError>>) {
        if let Some(result) = result {
            Self::log_connection_join_result(result);
        }
    }

    fn log_connection_join_result(result: Result<(), JoinError>) {
        if let Err(error) = result {
            tracing::warn!(%error, "broker proxy connection task failed");
        }
    }
}

struct ProxyConnection<C> {
    connection: C,
    mitm: Arc<abyss_mitm::MitmEngine>,
    diagnostics: FlowDiagnostics,
    traffic: TrafficMonitor,
}

impl<C> ProxyConnection<C>
where
    C: IngressConnection,
{
    const fn new(
        connection: C,
        mitm: Arc<abyss_mitm::MitmEngine>,
        diagnostics: FlowDiagnostics,
        traffic: TrafficMonitor,
    ) -> Self {
        Self {
            connection,
            mitm,
            diagnostics,
            traffic,
        }
    }

    #[tracing::instrument(level = "trace", skip_all)]
    async fn run(self) {
        let Self {
            connection,
            mitm,
            diagnostics,
            traffic,
        } = self;
        let flow = match connection.into_flow().await {
            Ok(flow) => flow,
            Err(error) => {
                diagnostics.record_accept_error(error.to_string());
                tracing::warn!(%error, "broker ingress connection preparation failed");
                return;
            }
        };
        diagnostics.record_accepted();
        Self::run_flow(flow, mitm, diagnostics, traffic).await;
    }

    async fn run_flow(
        flow: PlatformFlow,
        mitm: Arc<abyss_mitm::MitmEngine>,
        diagnostics: FlowDiagnostics,
        traffic: TrafficMonitor,
    ) {
        let peer_addr = flow.peer_addr();
        let local_addr = flow.local_addr();
        let original_destination = flow.original_destination().clone();
        let destination_host = flow.destination_host().map(str::to_owned);
        let source_process = flow.source_process().cloned();
        let ingress = flow.ingress().clone();
        let traffic_flow = traffic.start_flow(
            crate::traffic::TrafficFlowMetadata::from_platform_flow(&flow),
        );
        let flow_id = traffic_flow.id();
        let flow_started_at_unix_ms = traffic_flow.started_at_unix_ms();
        let traffic_finish_guard = TrafficFlowFinishGuard(traffic_flow.clone());
        let diagnostic_context = FlowDiagnosticContext::new(
            &ingress,
            peer_addr,
            local_addr,
            &original_destination,
            destination_host.as_deref(),
            source_process.as_ref(),
        )
        .with_flow(flow_id, flow_started_at_unix_ms);
        let mitm_flow = flow
            .into_mitm_flow()
            .with_traffic_observer(traffic_flow.observer());
        let result = mitm.handle_flow(mitm_flow).await;
        traffic_flow.finish();
        drop(traffic_finish_guard);
        let _recorded_result = result.record(&diagnostics, diagnostic_context);
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::{
        fs,
        net::SocketAddr,
        path::Path,
        sync::Arc,
        time::{SystemTime, UNIX_EPOCH},
    };

    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
        KeyUsagePurpose,
    };
    use tokio::{
        sync::oneshot,
        time::{Duration, timeout},
    };

    use crate::{
        connection::OriginalDestination,
        diagnostics::FlowDiagnostics,
        ingress::{
            Ingress, IngressError, PlatformFlow, PlatformFlowMetadata, ProxyMode, ProxyPlan,
            explicit::ExplicitIngressEndpoint,
        },
        traffic::TrafficMonitor,
    };

    use super::{ProxyLifecycle, ProxyService, ProxyWorker};

    #[tokio::test]
    async fn proxy_start_and_stop_updates_status() {
        let service = test_proxy_service().await;

        let running = service
            .start(test_plan())
            .await
            .expect("proxy should start on a free test endpoint");
        assert_eq!(running.lifecycle(), ProxyLifecycle::Running);
        assert_eq!(running.process_id(), std::process::id());
        let started = running
            .started()
            .expect("started proxy status should expose started-only fields");
        assert_eq!(started.mode(), ProxyMode::Explicit);
        assert_ne!(
            started.ingress().listen_addr(),
            Some(loopback_ephemeral_addr())
        );
        let running_json = serde_json::to_value(&running)
            .expect("started proxy status should serialize for the REST API");
        assert_eq!(running_json["lifecycle"], "running");
        assert_eq!(running_json["process_id"], std::process::id());
        assert_eq!(running_json["mode"], "explicit");
        assert_eq!(
            running_json["ingresses"]
                .as_array()
                .expect("started ingress projection should be an array")
                .len(),
            1
        );
        assert!(running_json["listen_addr"].is_string());

        let stopped = service.stop().await.expect("proxy should stop cleanly");
        assert_eq!(stopped.lifecycle(), ProxyLifecycle::Stopped);
        assert!(stopped.started().is_none());
        let stopped_json = serde_json::to_value(&stopped)
            .expect("stopped proxy status should serialize for the REST API");
        assert_eq!(stopped_json["lifecycle"], "stopped");
        assert_eq!(stopped_json["process_id"], std::process::id());
        assert!(stopped_json["mode"].is_null());
        assert_eq!(
            stopped_json["ingresses"]
                .as_array()
                .expect("stopped ingress projection should be an array")
                .len(),
            0
        );
        assert!(stopped_json["listen_addr"].is_null());
        assert!(stopped_json.get("socket_path").is_none());
    }

    #[tokio::test]
    async fn proxy_rejects_second_running_address() {
        let service = test_proxy_service().await;

        service
            .start(test_plan())
            .await
            .expect("first proxy start should succeed");
        let error = service
            .start(different_plan())
            .await
            .expect_err("second address should be rejected while proxy runs");

        assert!(
            error.to_string().contains("already running"),
            "error should explain that a proxy is already running"
        );
    }

    #[tokio::test]
    async fn same_bound_address_start_returns_running_status() {
        let service = test_proxy_service().await;
        let plan = test_plan();

        let first = service
            .start(plan.clone())
            .await
            .expect("first start should succeed");
        let second = service
            .start(plan)
            .await
            .expect("same endpoint start should reuse running proxy");

        assert_eq!(first.lifecycle(), ProxyLifecycle::Running);
        assert_eq!(second.lifecycle(), ProxyLifecycle::Running);
        let first = first
            .started()
            .expect("first status should contain a started proxy");
        let second = second
            .started()
            .expect("second status should contain a started proxy");
        assert_eq!(
            first.ingress().listen_addr(),
            second.ingress().listen_addr()
        );
        assert_eq!(
            first.ingress().socket_path(),
            second.ingress().socket_path()
        );
    }

    #[tokio::test]
    async fn proxy_worker_drains_in_flight_connections_on_shutdown() {
        let (mitm, diagnostics) = test_proxy_dependencies().await;
        let (client, server) = tokio::io::duplex(64);
        let (accepted_tx, accepted_rx) = oneshot::channel();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let ingress = SingleFlowIngress::new(test_platform_flow(server), accepted_tx);
        let mut worker = tokio::spawn(
            ProxyWorker::new(ingress, Arc::new(mitm), diagnostics, TrafficMonitor::new())
                .run(shutdown_rx),
        );

        accepted_rx
            .await
            .expect("test ingress should hand one flow to the worker");
        shutdown_tx
            .send(())
            .expect("worker should still be waiting for shutdown");

        let early_stop = timeout(Duration::from_millis(100), &mut worker).await;
        assert!(
            early_stop.is_err(),
            "proxy worker should wait for in-flight connections before stopping"
        );

        drop(client);
        worker
            .await
            .expect("worker should finish after in-flight connection closes");
    }

    #[tokio::test]
    async fn proxy_worker_aborts_stuck_connections_after_drain_timeout() {
        let (mitm, diagnostics) = test_proxy_dependencies().await;
        let (client, server) = tokio::io::duplex(64);
        let (accepted_tx, accepted_rx) = oneshot::channel();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let ingress = SingleFlowIngress::new(test_platform_flow(server), accepted_tx);
        let worker = tokio::spawn(
            ProxyWorker::new(ingress, Arc::new(mitm), diagnostics, TrafficMonitor::new())
                .with_shutdown_drain_timeout(Duration::from_millis(250))
                .run(shutdown_rx),
        );

        accepted_rx
            .await
            .expect("test ingress should hand one flow to the worker");
        shutdown_tx
            .send(())
            .expect("worker should still be waiting for shutdown");
        timeout(Duration::from_secs(1), worker)
            .await
            .expect("stuck flow should be aborted within the drain budget")
            .expect("worker task should join");

        drop(client);
    }

    struct SingleFlowIngress {
        flow: Option<PlatformFlow>,
        accepted: Option<oneshot::Sender<()>>,
    }

    impl SingleFlowIngress {
        const fn new(flow: PlatformFlow, accepted: oneshot::Sender<()>) -> Self {
            Self {
                flow: Some(flow),
                accepted: Some(accepted),
            }
        }
    }

    impl Ingress for SingleFlowIngress {
        type Accepted = PlatformFlow;

        fn accept(
            &mut self,
        ) -> impl std::future::Future<Output = Result<Self::Accepted, IngressError>> + Send
        {
            let flow = self.flow.take();
            let accepted = self.accepted.take();
            async move {
                if let Some(flow) = flow {
                    if let Some(accepted) = accepted {
                        let _sent = accepted.send(());
                    }
                    return Ok(flow);
                }
                std::future::pending::<Result<PlatformFlow, IngressError>>().await
            }
        }
    }

    fn loopback_ephemeral_addr() -> SocketAddr {
        "127.0.0.1:0"
            .parse()
            .expect("loopback ephemeral address should parse")
    }

    fn test_plan() -> ProxyPlan {
        ProxyPlan::explicit(ExplicitIngressEndpoint::new(loopback_ephemeral_addr()))
    }

    fn different_plan() -> ProxyPlan {
        ProxyPlan::explicit(ExplicitIngressEndpoint::new(SocketAddr::from((
            [127, 0, 0, 1],
            1,
        ))))
    }

    fn test_platform_flow(io: tokio::io::DuplexStream) -> PlatformFlow {
        let peer_addr = SocketAddr::from(([127, 0, 0, 1], 49_152));
        let local_addr = SocketAddr::from(([127, 0, 0, 1], 18_190));
        let original_destination =
            OriginalDestination::from(SocketAddr::from(([127, 0, 0, 1], 443)));
        PlatformFlow::new(
            io,
            PlatformFlowMetadata::from_parts(
                Some(peer_addr),
                Some(local_addr),
                original_destination,
                None,
                None,
            ),
        )
    }

    async fn test_proxy_service() -> ProxyService {
        let (mitm, diagnostics) = test_proxy_dependencies().await;
        ProxyService::new(Arc::new(mitm), diagnostics, TrafficMonitor::new())
    }

    async fn test_proxy_dependencies() -> (abyss_mitm::MitmEngine, FlowDiagnostics) {
        tokio::task::spawn_blocking(|| (test_mitm_engine_blocking(), FlowDiagnostics::new()))
            .await
            .expect("test proxy dependencies should initialize")
    }

    fn test_mitm_engine_blocking() -> abyss_mitm::MitmEngine {
        let ca_dir = unique_test_dir();
        write_ca_fixture(&ca_dir);
        let ca = abyss_mitm::CaStore::at(&ca_dir)
            .load_required()
            .expect("test CA fixture should load");
        let mitm = abyss_mitm::MitmEngine::from_ca(&ca).expect("test MITM engine should build");
        drop(fs::remove_dir_all(ca_dir));
        mitm
    }

    fn unique_test_dir() -> std::path::PathBuf {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after Unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "abyss-broker-proxy-ca-{}-{timestamp}-{}",
            std::process::id(),
            rand::random::<u64>()
        ))
    }

    fn write_ca_fixture(directory: &Path) {
        fs::create_dir_all(directory).expect("test CA directory should be created");
        // The test fixture generates CA material directly instead of using
        // CaStore, so install the rustls provider before rcgen key generation.
        abyss_mitm::install_default_crypto_provider();
        let key_pair = KeyPair::generate().expect("test CA key should generate");
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, "Abyss Broker Test Root CA");
        let mut params = CertificateParams::default();
        params.distinguished_name = distinguished_name;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::CrlSign,
        ];
        let certificate = params
            .self_signed(&key_pair)
            .expect("test root CA should self-sign");
        fs::write(directory.join("abyss-root-ca.der"), certificate.der())
            .expect("test DER certificate should be written");
        fs::write(directory.join("abyss-root-ca.pem"), certificate.pem())
            .expect("test PEM certificate should be written");
        fs::write(
            directory.join("abyss-root-ca-key.pem"),
            key_pair.serialize_pem(),
        )
        .expect("test private key should be written");
    }
}
