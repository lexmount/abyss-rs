//! Resolves runtime-configured broker endpoints before constructing an SDK client.
//!
//! Delivery only consumes events, so it does not load the broker REST token.
//! Environment-based discovery belongs to this executable, not to SDK plugins.

use std::path::PathBuf;

use abyss_delivery_plugin::DeliveryPluginConfig;
use abyss_sdk::{BrokerClient, broker::BrokerClientError};
use serde::Deserialize;

pub struct DeliveryBroker {
    api_url: Option<String>,
    plugin_endpoint: Option<String>,
    startup_info: Option<PathBuf>,
}

#[derive(Deserialize)]
struct StartupInfo {
    api_addr: String,
    plugin_endpoint: String,
}

impl DeliveryBroker {
    pub(super) fn from_config(config: &DeliveryPluginConfig) -> Self {
        Self {
            api_url: config.broker_api_url.clone(),
            plugin_endpoint: config
                .broker_endpoint
                .clone()
                .or_else(|| Self::non_empty_env("ABYSS_BROKER_PLUGIN_ENDPOINT")),
            startup_info: Self::non_empty_env("ABYSS_BROKER_STARTUP_INFO")
                .map(PathBuf::from)
                .or_else(|| {
                    Self::non_empty_env("ABYSS_HOME")
                        .map(|root| PathBuf::from(root).join("runtime/startup-info.json"))
                }),
        }
    }

    pub(super) async fn into_client(self) -> Result<BrokerClient, BrokerClientError> {
        let Self {
            api_url,
            plugin_endpoint,
            startup_info,
        } = self;
        let (api_url, plugin_endpoint) = match (api_url, plugin_endpoint) {
            (Some(api_url), Some(plugin_endpoint)) => (api_url, plugin_endpoint),
            (api_url, plugin_endpoint) => {
                let path = startup_info.ok_or_else(|| BrokerClientError::InvalidArgument(
                    "configure broker_api_url and broker_endpoint, or set ABYSS_BROKER_STARTUP_INFO or ABYSS_HOME".to_owned(),
                ))?;
                let body = tokio::fs::read(&path).await.map_err(|source| {
                    BrokerClientError::DiscoveryIo {
                        path: path.clone(),
                        source,
                    }
                })?;
                let startup: StartupInfo = serde_json::from_slice(&body)
                    .map_err(|source| BrokerClientError::StartupInfoJson { path, source })?;
                (
                    api_url.unwrap_or_else(|| format!("http://{}", startup.api_addr)),
                    plugin_endpoint.unwrap_or(startup.plugin_endpoint),
                )
            }
        };
        BrokerClient::new(&api_url, &plugin_endpoint)
    }

    fn non_empty_env(name: &str) -> Option<String> {
        std::env::var(name)
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::DeliveryBroker;
    use abyss_sdk::broker::BrokerClientError;

    #[tokio::test]
    async fn explicit_endpoints_do_not_read_startup_info() {
        let broker = DeliveryBroker {
            api_url: Some("http://127.0.0.1:1".to_owned()),
            plugin_endpoint: Some("/not/listening.sock".to_owned()),
            startup_info: Some("/missing/startup.json".into()),
        };
        assert!(broker.into_client().await.is_ok());
    }

    #[tokio::test]
    async fn startup_discovery_needs_no_rest_token() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("startup.json");
        tokio::fs::write(
            &path,
            br#"{"api_addr":"127.0.0.1:1","plugin_endpoint":"/not/listening.sock"}"#,
        )
        .await
        .unwrap();
        for (api_url, plugin_endpoint) in [
            (None, None),
            (Some("http://127.0.0.1:2".to_owned()), None),
            (None, Some("/override.sock".to_owned())),
        ] {
            let broker = DeliveryBroker {
                api_url,
                plugin_endpoint,
                startup_info: Some(path.clone()),
            };
            assert!(broker.into_client().await.is_ok());
        }
    }

    #[tokio::test]
    async fn incomplete_manual_configuration_requires_startup_info() {
        let broker = DeliveryBroker {
            api_url: None,
            plugin_endpoint: Some("/not/listening.sock".to_owned()),
            startup_info: None,
        };
        assert!(matches!(
            broker.into_client().await,
            Err(BrokerClientError::InvalidArgument(_))
        ));
    }
}
