//! Local broker REST client.

mod endpoint;

use std::{
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};

use abyss_agent_hook::HooksConfig;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

use crate::{error::CliError, local_config::LocalMitmConfig};

pub use endpoint::{BrokerConnection, BrokerEndpoint};
const BROKER_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const BROKER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(15);

/// Structured proxy state returned by `/v1/proxy/status`.
#[derive(Deserialize, Serialize)]
pub struct ProxyStatusResponse {
    /// Current proxy lifecycle.
    pub lifecycle: ProxyLifecycle,
    /// Process serving the broker REST API and proxy.
    pub process_id: u32,
    /// Active proxy mode, or `None` while stopped.
    pub mode: Option<ProxyMode>,
    /// Bound ingress endpoints.
    pub ingresses: Vec<IngressStatus>,
    /// Compatibility projection of the active TCP ingress.
    pub listen_addr: Option<SocketAddr>,
    /// Compatibility projection of the active Unix-socket ingress.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socket_path: Option<PathBuf>,
}

impl ProxyStatusResponse {
    /// Returns an address local clients can use to reach the explicit listener.
    fn connect_addr(&self) -> Result<SocketAddr, CliError> {
        let mode = self.mode.as_ref();
        if !matches!(mode, Some(ProxyMode::Explicit)) {
            return Err(CliError::InvalidConfiguration(format!(
                "broker endpoint is not an explicit proxy (mode={})",
                mode.map_or("unknown", ProxyMode::as_str)
            )));
        }
        let mut address = self.listen_addr.ok_or_else(|| {
            CliError::InvalidConfiguration(
                "broker proxy is running without a TCP listener".to_owned(),
            )
        })?;
        // Wildcard addresses describe binding scope, not a client destination.
        let connect_ip = match address.ip() {
            IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some_and(|ip| ip.is_unspecified()) => {
                IpAddr::V4(Ipv4Addr::LOCALHOST)
            }
            ip => ip,
        };
        address.set_ip(connect_ip);
        Ok(address)
    }
}

/// Proxy lifecycle values exposed by the broker REST API.
#[derive(Deserialize, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum ProxyLifecycle {
    /// The proxy owns a running ingress.
    Running,
    /// The proxy owns no ingress resources.
    Stopped,
}

/// Proxy modes exposed by the broker REST API.
#[derive(Deserialize, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum ProxyMode {
    /// Explicit HTTP proxy mode.
    Explicit,
    /// Platform transparent interception mode.
    Transparent,
}

/// One bound ingress endpoint in a proxy status response.
#[derive(Deserialize, Serialize)]
pub struct IngressStatus {
    /// Ingress implementation identity.
    pub source: IngressSource,
    /// Bound TCP address for TCP-based ingresses.
    pub listen_addr: Option<SocketAddr>,
    /// Bound Unix socket for filesystem-based ingresses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socket_path: Option<PathBuf>,
}

/// Ingress identities exposed by the broker REST API.
#[derive(Deserialize, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum IngressSource {
    /// Local explicit HTTP proxy listener.
    ExplicitHttp,
    /// macOS Network Extension flow ingress.
    MacosNetworkExtension,
    /// Windows WFP redirected-flow ingress.
    WindowsWfp,
}

/// Structured broker health response.
#[derive(Deserialize)]
pub struct HealthResponse {
    #[serde(rename = "service")]
    _service: String,
    #[serde(rename = "status")]
    _status: HealthStatus,
}

/// Health states exposed by the broker REST API.
#[derive(Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    /// The broker is healthy.
    Ok,
}

/// Structured response containing broker-owned support logs.
#[derive(Deserialize)]
pub struct BrokerLogResponse {
    /// Collected broker log files.
    pub files: Vec<BrokerLogFile>,
    /// Per-file collection failures.
    pub errors: Vec<BrokerLogError>,
}

/// One broker-owned log file returned for a support bundle.
#[derive(Deserialize)]
pub struct BrokerLogFile {
    /// Stable log file name.
    pub name: String,
    /// Bounded log content.
    pub content: String,
    #[serde(rename = "truncated")]
    _truncated: bool,
    #[serde(rename = "original_size")]
    _original_size: u64,
}

/// One broker log collection failure.
#[derive(Deserialize)]
pub struct BrokerLogError {
    /// Stable log file name.
    pub name: String,
    /// Collection failure description.
    pub error: String,
}

impl ProxyMode {
    /// Returns the stable broker API label.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Explicit => "explicit",
            Self::Transparent => "transparent",
        }
    }
}

/// Blocking client for the local broker REST surface.
pub struct BrokerClient {
    client: Client,
    base_url: String,
    token: Option<String>,
}

impl BrokerClient {
    /// Creates a client for a typed loopback endpoint and token file.
    pub fn from_addr_and_token(api_addr: SocketAddr, token_file: &Path) -> Result<Self, CliError> {
        let token = fs::read_to_string(token_file)
            .map_err(|source| CliError::filesystem("read broker token", token_file, source))?
            .trim()
            .to_owned();
        if token.is_empty() {
            return Err(CliError::InvalidConfiguration(
                "broker token file is empty".to_owned(),
            ));
        }
        Self::new(api_addr, Some(token))
    }

    /// Creates a client for a typed public loopback endpoint.
    pub fn from_addr(api_addr: SocketAddr) -> Result<Self, CliError> {
        Self::new(api_addr, None)
    }

    /// Returns the current broker proxy status.
    pub fn proxy_status(&self) -> Result<ProxyStatusResponse, CliError> {
        self.request_json("GET", "/v1/proxy/status", None)
    }

    /// Returns a usable local client endpoint for the explicit proxy.
    pub fn proxy_connect_addr(&self) -> Result<SocketAddr, CliError> {
        self.proxy_status()?.connect_addr()
    }

    /// Returns the effective broker MITM configuration.
    pub fn mitm_config(&self) -> Result<LocalMitmConfig, CliError> {
        self.request_json("GET", "/v1/mitm/config", None)
    }

    /// Returns the broker health response.
    pub fn health(&self) -> Result<HealthResponse, CliError> {
        self.request_json("GET", "/healthz", None)
    }

    /// Returns the broker's persisted/runtime hook policy.
    pub fn hooks_config(&self) -> Result<HooksConfig, CliError> {
        self.request_json("GET", "/v1/hooks/config", None)
    }

    /// Replaces the broker's hook policy for future flows.
    pub fn set_hooks_config(&self, config: &HooksConfig) -> Result<(), CliError> {
        let _response: Value = self.request_json(
            "PUT",
            "/v1/hooks/config",
            Some(serde_json::to_value(config).map_err(CliError::Json)?),
        )?;
        Ok(())
    }

    /// Returns metadata-only broker diagnostics.
    pub fn diagnostics(&self) -> Result<Value, CliError> {
        self.request_json("GET", "/v1/support/diagnostics", None)
    }

    /// Returns the five latest technical network observations.
    pub fn network_observations(&self) -> Result<Value, CliError> {
        self.request_json("GET", "/v1/network/observations?limit=5", None)
    }

    /// Collects bounded broker-owned logs for a support bundle.
    pub fn broker_logs(&self, max_bytes_per_file: u64) -> Result<BrokerLogResponse, CliError> {
        self.request_json(
            "POST",
            "/v1/support/logs/broker",
            Some(json!({"max_bytes_per_file": max_bytes_per_file})),
        )
    }

    /// Requests graceful shutdown through the existing authenticated API.
    pub fn shutdown(&self) -> Result<(), CliError> {
        if self.token.is_none() {
            return Err(CliError::InvalidConfiguration(
                "broker shutdown requires a broker token".to_owned(),
            ));
        }
        let _response: ProxyStatusResponse = self.request_json_with_timeout(
            "POST",
            "/v1/broker/shutdown",
            None,
            BROKER_SHUTDOWN_TIMEOUT,
        )?;
        Ok(())
    }

    pub(crate) fn parse_api_addr(api: &str) -> Result<SocketAddr, CliError> {
        let address = api.parse::<SocketAddr>().map_err(|error| {
            CliError::InvalidConfiguration(format!("invalid broker address `{api}`: {error}"))
        })?;
        if !address.ip().is_loopback() {
            return Err(CliError::InvalidConfiguration(
                "broker API must use a loopback address".to_owned(),
            ));
        }
        if address.port() == 0 {
            return Err(CliError::InvalidConfiguration(
                "broker API must use a concrete non-zero port".to_owned(),
            ));
        }
        Ok(address)
    }

    fn new(address: SocketAddr, token: Option<String>) -> Result<Self, CliError> {
        Ok(Self {
            client: Client::builder()
                .no_proxy()
                .build()
                .map_err(CliError::BrokerRequest)?,
            base_url: format!("http://{address}"),
            token,
        })
    }

    fn request_json<T>(
        &self,
        method: &str,
        path: &'static str,
        body: Option<Value>,
    ) -> Result<T, CliError>
    where
        T: DeserializeOwned,
    {
        self.request_json_with_timeout(method, path, body, BROKER_REQUEST_TIMEOUT)
    }

    fn request_json_with_timeout<T>(
        &self,
        method: &str,
        path: &'static str,
        body: Option<Value>,
        timeout: Duration,
    ) -> Result<T, CliError>
    where
        T: DeserializeOwned,
    {
        let url = format!("{}{path}", self.base_url);
        let mut request = match method {
            "GET" => self.client.get(url),
            "POST" => self.client.post(url),
            "PUT" => self.client.put(url),
            _ => {
                return Err(CliError::InvalidConfiguration(format!(
                    "unsupported broker HTTP method `{method}`"
                )));
            }
        }
        .timeout(timeout);
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().map_err(CliError::BrokerRequest)?;
        let status = response.status();
        let body = response.text().map_err(CliError::BrokerRequest)?;
        if !status.is_success() {
            return Err(CliError::BrokerStatus {
                operation: path,
                status,
                body,
            });
        }
        if body.trim().is_empty() {
            return serde_json::from_value(Value::Null).map_err(CliError::Json);
        }
        serde_json::from_str(&body).map_err(CliError::Json)
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use serde_json::json;

    use super::{
        BrokerLogResponse, HealthResponse, ProxyLifecycle, ProxyMode, ProxyStatusResponse,
    };
    use crate::local_config::LocalMitmConfig;

    #[test]
    fn proxy_status_uses_the_complete_broker_response_schema() {
        let value = json!({
            "lifecycle": "running",
            "process_id": 42_u32,
            "mode": "explicit",
            "ingresses": [{
                "source": "explicit_http",
                "listen_addr": "127.0.0.1:18191"
            }],
            "listen_addr": "127.0.0.1:18191"
        });
        let status: ProxyStatusResponse =
            serde_json::from_value(value.clone()).expect("proxy status should deserialize");

        assert!(matches!(&status.lifecycle, ProxyLifecycle::Running));
        assert!(matches!(status.mode.as_ref(), Some(ProxyMode::Explicit)));
        assert_eq!(status.process_id, 42);
        assert_eq!(
            status.listen_addr,
            Some(
                "127.0.0.1:18191"
                    .parse::<SocketAddr>()
                    .expect("test listener should parse")
            )
        );
        assert_eq!(
            serde_json::to_value(status).expect("proxy status should serialize"),
            value
        );
    }

    #[test]
    fn proxy_connection_address_supports_wildcard_and_interface_listeners() {
        for (listener, expected) in [
            ("0.0.0.0:8080", "127.0.0.1:8080"),
            ("[::]:8080", "[::1]:8080"),
            ("[::ffff:0.0.0.0]:8080", "127.0.0.1:8080"),
            ("192.168.1.10:8080", "192.168.1.10:8080"),
            ("[2001:db8::1]:8080", "[2001:db8::1]:8080"),
        ] {
            let status: ProxyStatusResponse = serde_json::from_value(json!({
                "lifecycle": "running", "process_id": 42_u32, "mode": "explicit",
                "ingresses": [], "listen_addr": listener,
            }))
            .expect("proxy status");
            assert_eq!(
                status.connect_addr().expect("connect address").to_string(),
                expected
            );
            assert_eq!(
                status.listen_addr.expect("bound address").to_string(),
                listener
            );
        }
    }

    #[test]
    fn broker_endpoints_deserialize_into_their_response_types() {
        let _health: HealthResponse = serde_json::from_value(json!({
            "service": "abyss-broker",
            "status": "ok"
        }))
        .expect("health response should deserialize");

        let mitm: LocalMitmConfig = serde_json::from_value(json!({
            "tls_decryption": {
                "default_action": "passthrough",
                "missing_sni_action": "passthrough",
                "rules": []
            }
        }))
        .expect("MITM response should deserialize");
        assert!(mitm.tls_decryption.rules.is_empty());

        let logs: BrokerLogResponse = serde_json::from_value(json!({
            "files": [{
                "name": "abyss-broker.log",
                "content": "broker log",
                "truncated": false,
                "original_size": 10_u64
            }],
            "errors": [{
                "name": "abyss-broker-trace.log",
                "error": "not found"
            }]
        }))
        .expect("broker log response should deserialize");
        assert_eq!(logs.files[0].name, "abyss-broker.log");
        assert_eq!(logs.errors[0].name, "abyss-broker-trace.log");
    }
}
