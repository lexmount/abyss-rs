//! Async HTTP implementation of the broker REST management contract.

use std::{path::Path, time::Duration};

use reqwest::{Method, RequestBuilder, Url};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;

use super::{
    error::BrokerClientError,
    types::{
        BrokerLogRequest, BrokerLogResponse, HealthResponse, HooksConfig, MitmConfig, ProxyStatus,
        TrafficSnapshot,
    },
};

const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_ERROR_BODY_BYTES: usize = 16 * 1024;

/// Async client for the loopback `abyss-broker` REST API.
pub struct BrokerClient {
    base_url: Url,
    bearer_token: Option<String>,
    http: reqwest::Client,
}

#[derive(Deserialize)]
struct StartupInfo {
    api_addr: String,
    auth_token_file: String,
}

#[derive(Deserialize)]
struct ErrorResponse {
    error: String,
}

impl BrokerClient {
    /// Creates a client for an explicit broker HTTP base URL.
    ///
    /// # Errors
    ///
    /// Returns an error when the URL is malformed or the HTTP client cannot be built.
    pub fn new(base_url: &str) -> Result<Self, BrokerClientError> {
        let normalized = format!("{}/", base_url.trim().trim_end_matches('/'));
        let base_url =
            Url::parse(&normalized).map_err(|error| BrokerClientError::InvalidBaseUrl {
                base_url: base_url.to_owned(),
                reason: error.to_string(),
            })?;
        if base_url.scheme() != "http" || !is_loopback_host(&base_url) {
            return Err(BrokerClientError::NonLoopbackBaseUrl(base_url.to_string()));
        }
        let http = reqwest::Client::builder()
            .no_proxy()
            .timeout(DEFAULT_REQUEST_TIMEOUT)
            .build()?;
        Ok(Self {
            base_url,
            bearer_token: None,
            http,
        })
    }

    /// Adds the per-process local bearer token used by protected routes.
    #[must_use]
    pub fn with_bearer_token<T>(mut self, bearer_token: T) -> Self
    where
        T: Into<String>,
    {
        self.bearer_token = Some(bearer_token.into());
        self
    }

    /// Discovers the REST endpoint and bearer token from broker startup information.
    ///
    /// # Errors
    ///
    /// Returns an error when either discovery file is unreadable, startup JSON
    /// is invalid, or the advertised URL is malformed.
    pub async fn from_startup_info(path: &Path) -> Result<Self, BrokerClientError> {
        let body =
            tokio::fs::read(path)
                .await
                .map_err(|source| BrokerClientError::DiscoveryIo {
                    path: path.to_path_buf(),
                    source,
                })?;
        let startup: StartupInfo =
            serde_json::from_slice(&body).map_err(|source| BrokerClientError::StartupInfoJson {
                path: path.to_path_buf(),
                source,
            })?;
        let token_path = std::path::PathBuf::from(startup.auth_token_file);
        let token = tokio::fs::read_to_string(&token_path)
            .await
            .map_err(|source| BrokerClientError::DiscoveryIo {
                path: token_path,
                source,
            })?;
        Self::new(&format!("http://{}", startup.api_addr))
            .map(|client| client.with_bearer_token(token.trim().to_owned()))
    }

    /// Returns broker process liveness.
    ///
    /// # Errors
    ///
    /// Returns an error when transport or response decoding fails.
    pub async fn health(&self) -> Result<HealthResponse, BrokerClientError> {
        self.send_json(Method::GET, "healthz", false, Option::<&()>::None)
            .await
    }

    /// Returns current proxy lifecycle and ingress status.
    ///
    /// # Errors
    ///
    /// Returns an error when transport or response decoding fails.
    pub async fn proxy_status(&self) -> Result<ProxyStatus, BrokerClientError> {
        self.send_json(Method::GET, "v1/proxy/status", false, Option::<&()>::None)
            .await
    }

    /// Returns the current TLS decryption policy.
    ///
    /// # Errors
    ///
    /// Returns an error for failed authentication, transport, or decoding.
    pub async fn mitm_config(&self) -> Result<MitmConfig, BrokerClientError> {
        self.send_json(Method::GET, "v1/mitm/config", true, Option::<&()>::None)
            .await
    }

    /// Durably replaces the TLS decryption policy.
    ///
    /// # Errors
    ///
    /// Returns an error when policy validation, persistence, transport, or decoding fails.
    pub async fn update_mitm_config(
        &self,
        config: &MitmConfig,
    ) -> Result<MitmConfig, BrokerClientError> {
        self.send_json(Method::PUT, "v1/mitm/config", true, Some(config))
            .await
    }

    /// Returns the current Harness usage policy.
    ///
    /// # Errors
    ///
    /// Returns an error for failed authentication, transport, or decoding.
    pub async fn hooks_config(&self) -> Result<HooksConfig, BrokerClientError> {
        self.send_json(Method::GET, "v1/hooks/config", true, Option::<&()>::None)
            .await
    }

    /// Durably replaces the Harness usage policy.
    ///
    /// # Errors
    ///
    /// Returns an error when persistence, transport, or decoding fails.
    pub async fn update_hooks_config(
        &self,
        config: &HooksConfig,
    ) -> Result<HooksConfig, BrokerClientError> {
        self.send_json(Method::PUT, "v1/hooks/config", true, Some(config))
            .await
    }

    /// Collects bounded broker-owned support logs.
    ///
    /// # Errors
    ///
    /// Returns an error when the request is invalid or the broker cannot collect logs.
    pub async fn collect_broker_logs(
        &self,
        request: &BrokerLogRequest,
    ) -> Result<BrokerLogResponse, BrokerClientError> {
        self.send_json(Method::POST, "v1/support/logs/broker", true, Some(request))
            .await
    }

    /// Returns the versioned metadata-only diagnostics snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error for failed authentication, transport, or decoding.
    pub async fn diagnostics(&self) -> Result<Value, BrokerClientError> {
        self.send_json(
            Method::GET,
            "v1/support/diagnostics",
            true,
            Option::<&()>::None,
        )
        .await
    }

    /// Returns the newest durable technical network observations.
    ///
    /// # Errors
    ///
    /// Returns an error when `limit` is outside 1 through 1000 or the request fails.
    pub async fn network_observations(
        &self,
        limit: Option<u16>,
    ) -> Result<Value, BrokerClientError> {
        if let Some(limit) = limit
            && !(1..=1_000).contains(&limit)
        {
            return Err(BrokerClientError::InvalidArgument(
                "network observation limit must be between 1 and 1000".to_owned(),
            ));
        }
        let path = limit.map_or_else(
            || "v1/network/observations".to_owned(),
            |limit| format!("v1/network/observations?limit={limit}"),
        );
        self.send_json(Method::GET, &path, true, Option::<&()>::None)
            .await
    }

    /// Returns ephemeral metadata-only live traffic.
    ///
    /// # Errors
    ///
    /// Returns an error for failed authentication, transport, or decoding.
    pub async fn traffic_snapshot(&self) -> Result<TrafficSnapshot, BrokerClientError> {
        self.send_json(
            Method::GET,
            "v1/traffic/snapshot",
            true,
            Option::<&()>::None,
        )
        .await
    }

    /// Stops the proxy and requests orderly broker process shutdown.
    ///
    /// # Errors
    ///
    /// Returns an error for failed authentication, transport, or decoding.
    pub async fn shutdown(&self) -> Result<ProxyStatus, BrokerClientError> {
        self.send_json(
            Method::POST,
            "v1/broker/shutdown",
            true,
            Option::<&()>::None,
        )
        .await
    }

    async fn send_json<R, B>(
        &self,
        method: Method,
        path: &str,
        protected: bool,
        body: Option<&B>,
    ) -> Result<R, BrokerClientError>
    where
        R: DeserializeOwned,
        B: Serialize + Sync + ?Sized,
    {
        let url =
            self.base_url
                .join(path)
                .map_err(|error| BrokerClientError::InvalidRequestPath {
                    path: path.to_owned(),
                    reason: error.to_string(),
                })?;
        let mut request = self.http.request(method, url);
        if protected && let Some(token) = &self.bearer_token {
            request = request.bearer_auth(token);
        }
        if let Some(body) = body {
            request = request.json(body);
        }
        self.decode_response(request).await
    }

    async fn decode_response<R>(&self, request: RequestBuilder) -> Result<R, BrokerClientError>
    where
        R: DeserializeOwned,
    {
        let response = request.send().await?;
        let status = response.status();
        if status.is_success() {
            return response.json().await.map_err(BrokerClientError::from);
        }
        let bytes = response.bytes().await?;
        let bounded = &bytes[..bytes.len().min(MAX_ERROR_BODY_BYTES)];
        let message = serde_json::from_slice::<ErrorResponse>(bounded).map_or_else(
            |_error| String::from_utf8_lossy(bounded).into_owned(),
            |body| body.error,
        );
        Err(BrokerClientError::Api { status, message })
    }
}

fn is_loopback_host(url: &Url) -> bool {
    url.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    })
}

#[cfg(test)]
mod tests {
    use super::BrokerClient;
    use crate::broker::BrokerClientError;

    #[test]
    fn rejects_non_loopback_or_encrypted_remote_base_urls() {
        for base_url in ["http://example.com:18190", "https://127.0.0.1:18190"] {
            let result = BrokerClient::new(base_url);
            assert!(
                matches!(result, Err(BrokerClientError::NonLoopbackBaseUrl(_))),
                "broker REST clients must remain on the loopback HTTP boundary: {base_url}"
            );
        }
    }
}
