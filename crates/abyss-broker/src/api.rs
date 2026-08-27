//! REST API for controlling the broker proxy service.

use std::{future::Future, io, net::SocketAddr, path::PathBuf, sync::Arc};

use abyss_agent_hook::{HooksConfig, HooksRuntimeConfig};
use axum::{
    Json, Router,
    extract::{Request, State},
    http::{HeaderMap, header::AUTHORIZATION},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
};
use subtle::ConstantTimeEq;
#[cfg(unix)]
use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio::{
    net::TcpListener,
    sync::{Mutex, oneshot, watch},
};

use crate::{
    diagnostics::{BrokerDiagnosticsService, BrokerDiagnosticsSnapshot, FlowDiagnostics},
    error::BrokerError,
    ingress::ProxyPlan,
    plugin::PluginServer,
    proxy::{ProxyService, ProxyStatus},
    runtime_config::{MitmConfig, RuntimeConfigService},
    startup_info::StartupInfo,
    support_logs::{BrokerLogCollector, BrokerLogRequest, BrokerLogResponse},
};

#[derive(Clone)]
struct AppState {
    proxy: ProxyService,
    runtime_config: RuntimeConfigService,
    diagnostics: BrokerDiagnosticsService,
    network_observations: Arc<crate::network_diagnostics::NetworkObservationStore>,
    traffic: crate::traffic::TrafficMonitor,
    shutdown: ShutdownHandle,
    auth: AuthState,
    broker_logs: Arc<BrokerLogCollector>,
}

#[derive(Clone)]
struct ShutdownHandle {
    sender: Arc<Mutex<Option<oneshot::Sender<()>>>>,
}

#[derive(Clone)]
struct AuthState {
    bearer_token: Arc<str>,
}

/// Runtime services owned by the broker REST process.
pub struct RuntimeServices {
    /// Shared MITM engine that handles redirected traffic.
    pub mitm: abyss_mitm::MitmEngine,
    /// Dynamic hook behavior policy.
    pub hooks: HooksRuntimeConfig,
    /// Durable file backing REST-managed MITM and Hook policy.
    pub runtime_policy_path: PathBuf,
    /// Collector for broker-owned support log files.
    pub broker_logs: BrokerLogCollector,
    /// Local Diesel-backed technical network observation store.
    pub network_observations: Arc<crate::network_diagnostics::NetworkObservationStore>,
    /// Bound local plugin listener and live Agent event source.
    pub plugin_server: PluginServer,
}

/// Runs the broker REST server until an operating-system signal or REST shutdown.
///
/// # Errors
///
/// Returns an error when the API listener cannot bind or the HTTP server fails.
#[tracing::instrument(level = "trace", skip_all)]
pub async fn serve(
    api_addr: SocketAddr,
    proxy_plan: ProxyPlan,
    auth_token_file: PathBuf,
    startup_info_file: Option<PathBuf>,
    bearer_token: String,
    runtime: RuntimeServices,
) -> Result<(), BrokerError> {
    #[cfg(unix)]
    let termination_signal = signal(SignalKind::terminate())
        .map_err(|source| BrokerError::io("register SIGTERM listener", source))?;
    let proxy_endpoint_label = proxy_plan.endpoint_label();
    tracing::info!(
        %api_addr,
        proxy_endpoint = %proxy_endpoint_label,
        "abyss-broker REST API and proxy services starting"
    );
    let RuntimeServices {
        mitm,
        hooks,
        runtime_policy_path,
        broker_logs,
        network_observations,
        plugin_server,
    } = runtime;
    let plugin_endpoint = plugin_server.endpoint_label();
    let mitm = Arc::new(mitm);
    let listener = TcpListener::bind(api_addr)
        .await
        .map_err(|source| BrokerError::io("bind broker REST API", source))?;
    let actual_addr = listener
        .local_addr()
        .map_err(|source| BrokerError::io("read broker REST API address", source))?;
    let flow_diagnostics =
        FlowDiagnostics::with_network_observation_store(network_observations.clone());
    let traffic = crate::traffic::TrafficMonitor::new();
    let proxy = ProxyService::new(mitm.clone(), flow_diagnostics.clone(), traffic.clone());
    let diagnostics =
        BrokerDiagnosticsService::new(actual_addr, proxy_endpoint_label, flow_diagnostics).await;
    let _proxy_status = proxy.start(proxy_plan).await?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let shutdown_handle = ShutdownHandle {
        sender: Arc::new(Mutex::new(Some(shutdown_tx))),
    };
    let state = AppState {
        proxy: proxy.clone(),
        runtime_config: RuntimeConfigService::new(mitm, hooks, runtime_policy_path),
        diagnostics,
        network_observations,
        traffic,
        shutdown: shutdown_handle.clone(),
        auth: AuthState {
            bearer_token: Arc::from(bearer_token),
        },
        broker_logs: Arc::new(broker_logs),
    };

    tracing::info!(api_addr = %actual_addr, "abyss-broker REST API listening");
    if let Some(startup_info_file) = startup_info_file {
        StartupInfo::new(actual_addr, auth_token_file, plugin_endpoint)
            .write_to(&startup_info_file)
            .await?;
        tracing::info!(
            path = %startup_info_file.display(),
            "abyss-broker startup info written"
        );
    }
    let (plugin_shutdown_tx, plugin_shutdown_rx) = watch::channel(false);
    let plugin_shutdown_on_signal = plugin_shutdown_tx.clone();
    #[cfg(unix)]
    let shutdown = async move {
        shutdown_signal(shutdown_rx, termination_signal).await;
        let _plugin_shutdown_sent = plugin_shutdown_on_signal.send(true);
    };
    #[cfg(not(unix))]
    let shutdown = async move {
        shutdown_signal(shutdown_rx).await;
        let _plugin_shutdown_sent = plugin_shutdown_on_signal.send(true);
    };
    let http_server = async move {
        axum::serve(listener, router(state))
            .with_graceful_shutdown(shutdown)
            .await
    };
    let plugin_service = plugin_server.run(plugin_shutdown_rx);
    let service_result = coordinate_servers(
        http_server,
        plugin_service,
        plugin_shutdown_tx,
        shutdown_handle,
    )
    .await;
    let proxy_result = proxy.stop().await;
    service_result?;
    proxy_result.map(|_status| ())
}

#[expect(
    clippy::integer_division_remainder_used,
    reason = "tokio::select! expands through runtime code that uses remainder internally"
)]
async fn coordinate_servers<H, P>(
    http_server: H,
    plugin_service: P,
    plugin_shutdown_tx: watch::Sender<bool>,
    shutdown_handle: ShutdownHandle,
) -> Result<(), BrokerError>
where
    H: Future<Output = Result<(), io::Error>>,
    P: Future<Output = Result<(), crate::plugin::PluginServerError>>,
{
    tokio::pin!(http_server);
    tokio::pin!(plugin_service);
    tokio::select! {
        http_result = &mut http_server => {
            let _plugin_shutdown_sent = plugin_shutdown_tx.send(true);
            let plugin_result = plugin_service.await;
            http_result.map_err(|source| BrokerError::io("serve broker REST API", source))?;
            plugin_result.map_err(BrokerError::from)
        }
        plugin_result = &mut plugin_service => {
            if !*plugin_shutdown_tx.borrow() {
                tracing::error!("broker plugin listener stopped before broker shutdown");
                shutdown_handle.request().await;
            }
            let http_result = http_server.await;
            plugin_result.map_err(BrokerError::from)?;
            http_result.map_err(|source| BrokerError::io("serve broker REST API", source))
        }
    }
}

fn router(state: AppState) -> Router {
    let auth = state.auth.clone();
    let protected_routes = Router::new()
        .route("/v1/mitm/config", get(mitm_config).put(update_mitm_config))
        .route(
            "/v1/hooks/config",
            get(hooks_config).put(update_hooks_config),
        )
        .route("/v1/support/logs/broker", post(broker_logs))
        .route("/v1/support/diagnostics", get(broker_diagnostics))
        .route("/v1/network/observations", get(network_observations))
        .route("/v1/traffic/snapshot", get(traffic_snapshot))
        .route("/v1/broker/shutdown", post(shutdown_broker))
        .route_layer(middleware::from_fn_with_state(auth, authorize_request));

    Router::new()
        .route("/healthz", get(health))
        .route("/v1/proxy/status", get(proxy_status))
        .merge(protected_routes)
        .with_state(state)
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        service: "abyss-broker",
        status: "ok",
    })
}

#[tracing::instrument(level = "trace", skip_all)]
async fn proxy_status(State(state): State<AppState>) -> Json<ProxyStatus> {
    Json(state.proxy.status().await)
}

async fn authorize_request(
    State(auth): State<AuthState>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response, BrokerError> {
    auth.authorize(&headers)?;
    Ok(next.run(request).await)
}

async fn mitm_config(State(state): State<AppState>) -> Result<Json<MitmConfig>, BrokerError> {
    Ok(Json(state.runtime_config.mitm_config()))
}

#[tracing::instrument(level = "trace", skip_all)]
async fn update_mitm_config(
    State(state): State<AppState>,
    Json(config): Json<MitmConfig>,
) -> Result<Json<MitmConfig>, BrokerError> {
    let updated = state.runtime_config.update_mitm_config(config).await?;
    Ok(Json(updated))
}

async fn hooks_config(State(state): State<AppState>) -> Result<Json<HooksConfig>, BrokerError> {
    Ok(Json(state.runtime_config.hooks_config()))
}

async fn update_hooks_config(
    State(state): State<AppState>,
    Json(config): Json<HooksConfig>,
) -> Result<Json<HooksConfig>, BrokerError> {
    let updated = state.runtime_config.update_hooks_config(config).await?;
    Ok(Json(updated))
}

async fn broker_logs(
    State(state): State<AppState>,
    Json(request): Json<BrokerLogRequest>,
) -> Result<Json<BrokerLogResponse>, BrokerError> {
    let response = state
        .broker_logs
        .collect(&request)
        .await
        .map_err(|error| BrokerError::invalid_arguments(error.to_string()))?;
    Ok(Json(response))
}

async fn broker_diagnostics(State(state): State<AppState>) -> Json<BrokerDiagnosticsSnapshot> {
    let proxy = state.proxy.status().await;
    Json(state.diagnostics.snapshot(proxy))
}

#[derive(serde::Deserialize)]
struct NetworkObservationQuery {
    limit: Option<usize>,
}

#[derive(serde::Serialize)]
struct NetworkObservationsResponse {
    schema_version: u8,
    broker_started_at_unix_ms: u64,
    observations: Vec<crate::network_diagnostics::NetworkObservation>,
}

async fn network_observations(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<NetworkObservationQuery>,
) -> Result<Json<NetworkObservationsResponse>, BrokerError> {
    const DEFAULT_LIMIT: usize = 100;
    const MAX_LIMIT: usize = 1_000;
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT);
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err(BrokerError::invalid_arguments(format!(
            "network observation limit must be between 1 and {MAX_LIMIT}"
        )));
    }
    let store = state.network_observations.clone();
    let observations = tokio::task::spawn_blocking(move || store.latest(limit))
        .await
        .map_err(|source| BrokerError::task("query network observations", source))??;
    Ok(Json(NetworkObservationsResponse {
        schema_version: 1,
        broker_started_at_unix_ms: state.diagnostics.started_at_unix_ms(),
        observations,
    }))
}

async fn traffic_snapshot(State(state): State<AppState>) -> Json<crate::traffic::TrafficSnapshot> {
    Json(state.traffic.snapshot())
}

async fn shutdown_broker(State(state): State<AppState>) -> Result<Json<ProxyStatus>, BrokerError> {
    let status = state.proxy.stop().await?;
    state.shutdown.request().await;
    Ok(Json(status))
}

#[expect(
    clippy::integer_division_remainder_used,
    reason = "tokio::select! expands through runtime code that uses remainder internally."
)]
#[cfg(unix)]
async fn shutdown_signal(shutdown_rx: oneshot::Receiver<()>, mut termination_signal: Signal) {
    tokio::select! {
        _ = shutdown_rx => {}
        result = tokio::signal::ctrl_c() => {
            if let Err(error) = result {
                tracing::warn!(%error, "failed to listen for Ctrl+C");
            }
        }
        received = termination_signal.recv() => {
            if received.is_none() {
                tracing::warn!("SIGTERM signal stream closed");
            }
        }
    }
}

#[expect(
    clippy::integer_division_remainder_used,
    reason = "tokio::select! expands through runtime code that uses remainder internally."
)]
#[cfg(not(unix))]
async fn shutdown_signal(shutdown_rx: oneshot::Receiver<()>) {
    tokio::select! {
        _ = shutdown_rx => {}
        result = tokio::signal::ctrl_c() => {
            if let Err(error) = result {
                tracing::warn!(%error, "failed to listen for Ctrl+C");
            }
        }
    }
}

impl ShutdownHandle {
    async fn request(&self) {
        let sender = self.sender.lock().await.take();
        if let Some(sender) = sender {
            let _sent = sender.send(());
        }
    }
}

impl AuthState {
    fn authorize(&self, headers: &HeaderMap) -> Result<(), BrokerError> {
        let Some(header) = headers.get(AUTHORIZATION) else {
            return Err(BrokerError::unauthorized());
        };
        let Ok(value) = header.to_str() else {
            return Err(BrokerError::unauthorized());
        };
        let Some(token) = value.strip_prefix("Bearer ") else {
            return Err(BrokerError::unauthorized());
        };
        if token
            .as_bytes()
            .ct_eq(self.bearer_token.as_bytes())
            .unwrap_u8()
            != 1
        {
            return Err(BrokerError::unauthorized());
        }
        Ok(())
    }
}

#[derive(serde::Serialize)]
struct HealthResponse {
    service: &'static str,
    status: &'static str,
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue};

    use super::AuthState;

    #[test]
    fn authorizes_exact_bearer_token() {
        let auth = AuthState {
            bearer_token: "secret-token".into(),
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer secret-token"),
        );

        assert!(auth.authorize(&headers).is_ok());
    }

    #[test]
    fn rejects_bearer_tokens_with_different_length_or_content() {
        let auth = AuthState {
            bearer_token: "secret-token".into(),
        };
        for value in ["Bearer secret", "Bearer secret-tokeu"] {
            let mut headers = HeaderMap::new();
            headers.insert(
                "authorization",
                HeaderValue::try_from(value).expect("test authorization value should be valid"),
            );

            assert!(auth.authorize(&headers).is_err());
        }
    }
}
