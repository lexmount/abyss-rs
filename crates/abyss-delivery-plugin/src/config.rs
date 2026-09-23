//! Product-owned configuration for the official Agent event delivery plugin.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::DeliveryPluginError;

const PRODUCT_CONFIG_SCHEMA_VERSION: u32 = 1;
const DEFAULT_PLUGIN_ID: &str = "lexmount.abyss.delivery";
const DEFAULT_DELIVERY_ENDPOINT: &str = "http://127.0.0.1:8080/v1/agent-usage/events";

/// Complete configuration for the official delivery plugin.
#[derive(Deserialize)]
#[serde(default)]
pub struct DeliveryPluginConfig {
    /// Stable identity presented to the broker during the handshake.
    pub plugin_id: String,
    /// Optional concrete broker endpoint; normal SDK discovery is used when absent.
    pub broker_endpoint: Option<String>,
    /// Destination and failed-delivery persistence settings.
    pub delivery: DeliveryConfig,
    /// Destination authentication mode.
    pub authentication: AuthenticationConfig,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProductConfigFile {
    schema_version: u32,
    #[serde(rename = "product")]
    _product: serde_json::Value,
    #[serde(default, rename = "adapter")]
    _adapter: Option<serde_json::Value>,
    delivery_worker: DeliveryPluginConfig,
}

/// Remote delivery settings owned by the plugin rather than the broker.
#[derive(Deserialize)]
#[serde(default)]
pub struct DeliveryConfig {
    /// Backend ingest URL. The default points at a local Abyss backend.
    pub endpoint: String,
    /// Whether a failed request is appended to the plugin's JSONL spool.
    pub spool_enabled: bool,
    /// Optional spool path. A product-local default is used when absent.
    pub spool_path: Option<PathBuf>,
}

/// Authentication applied by the official delivery plugin.
#[derive(Default, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuthenticationConfig {
    /// Send events without authentication.
    #[default]
    None,
    /// Read the complete `Authorization` header value from a separate file.
    AuthorizationHeaderFile {
        /// Credential file path, relative to the config file when not absolute.
        path: PathBuf,
    },
    /// Read the complete `Cookie` header value from a separate file.
    CookieHeaderFile {
        /// Credential file path, relative to the config file when not absolute.
        path: PathBuf,
    },
    /// Accept a product-managed bearer credential through the local control API.
    ManagedBearer,
}

/// Resolved authentication material loaded once at plugin startup.
#[derive(Clone)]
pub struct DeliveryAuthentication {
    authorization_header: Option<String>,
    cookie_header: Option<String>,
}

impl DeliveryPluginConfig {
    /// Loads the delivery section from a product JSON file, or uses local defaults.
    ///
    /// # Errors
    ///
    /// Returns an error when the selected file cannot be read or decoded.
    pub async fn load(path: Option<&Path>) -> Result<Self, DeliveryPluginError> {
        let Some(path) = path else {
            return Ok(Self::default());
        };
        let body =
            tokio::fs::read(path)
                .await
                .map_err(|source| DeliveryPluginError::ReadConfig {
                    path: path.to_owned(),
                    source,
                })?;
        let file = serde_json::from_slice::<ProductConfigFile>(&body).map_err(|source| {
            DeliveryPluginError::DecodeConfig {
                path: path.to_owned(),
                source,
            }
        })?;
        if file.schema_version != PRODUCT_CONFIG_SCHEMA_VERSION {
            return Err(DeliveryPluginError::UnsupportedProductConfigSchema {
                path: path.to_owned(),
                actual: file.schema_version,
                expected: PRODUCT_CONFIG_SCHEMA_VERSION,
            });
        }
        let mut config = file.delivery_worker;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        config.resolve_relative_paths(base);
        Ok(config)
    }

    /// Loads the authentication value selected by the configuration.
    ///
    /// # Errors
    ///
    /// Returns an error when the configured credential file cannot be read.
    pub async fn load_authentication(&self) -> Result<DeliveryAuthentication, DeliveryPluginError> {
        match &self.authentication {
            AuthenticationConfig::None | AuthenticationConfig::ManagedBearer => {
                Ok(DeliveryAuthentication::none())
            }
            AuthenticationConfig::AuthorizationHeaderFile { path } => {
                let value = Self::read_credential(path).await?;
                Ok(DeliveryAuthentication {
                    authorization_header: Some(value),
                    cookie_header: None,
                })
            }
            AuthenticationConfig::CookieHeaderFile { path } => {
                let value = Self::read_credential(path).await?;
                Ok(DeliveryAuthentication {
                    authorization_header: None,
                    cookie_header: Some(value),
                })
            }
        }
    }

    /// Returns the configured spool path or the plugin-owned product default.
    #[must_use]
    pub fn spool_path(&self) -> PathBuf {
        self.delivery.spool_path.clone().unwrap_or_else(|| {
            std::env::var_os("ABYSS_HOME")
                .map_or_else(|| PathBuf::from(".abyss"), PathBuf::from)
                .join("delivery")
                .join("failed-events.jsonl")
        })
    }

    fn resolve_relative_paths(&mut self, base: &Path) {
        if let Some(path) = &mut self.delivery.spool_path {
            Self::resolve_path(path, base);
        }
        match &mut self.authentication {
            AuthenticationConfig::None | AuthenticationConfig::ManagedBearer => {}
            AuthenticationConfig::AuthorizationHeaderFile { path }
            | AuthenticationConfig::CookieHeaderFile { path } => Self::resolve_path(path, base),
        }
    }

    fn resolve_path(path: &mut PathBuf, base: &Path) {
        if path.is_relative() {
            *path = base.join(&*path);
        }
    }

    async fn read_credential(path: &Path) -> Result<String, DeliveryPluginError> {
        let value = tokio::fs::read_to_string(path).await.map_err(|source| {
            DeliveryPluginError::ReadCredential {
                path: path.to_owned(),
                source,
            }
        })?;
        Ok(value.trim().to_owned())
    }
}

impl Default for DeliveryPluginConfig {
    fn default() -> Self {
        Self {
            plugin_id: DEFAULT_PLUGIN_ID.to_owned(),
            broker_endpoint: None,
            delivery: DeliveryConfig::default(),
            authentication: AuthenticationConfig::None,
        }
    }
}

impl Default for DeliveryConfig {
    fn default() -> Self {
        Self {
            endpoint: DEFAULT_DELIVERY_ENDPOINT.to_owned(),
            spool_enabled: true,
            spool_path: None,
        }
    }
}

impl DeliveryAuthentication {
    pub(crate) const fn none() -> Self {
        Self {
            authorization_header: None,
            cookie_header: None,
        }
    }

    /// Builds a complete Authorization header from an opaque bearer token.
    #[must_use]
    pub(crate) fn from_bearer(token: &str) -> Self {
        Self {
            authorization_header: Some(format!("Bearer {token}")),
            cookie_header: None,
        }
    }

    /// Returns the configured `Authorization` header value.
    #[must_use]
    pub fn authorization_header(&self) -> Option<&str> {
        self.authorization_header.as_deref()
    }

    /// Returns the configured `Cookie` header value.
    #[must_use]
    pub fn cookie_header(&self) -> Option<&str> {
        self.cookie_header.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::{AuthenticationConfig, DeliveryPluginConfig};

    #[tokio::test]
    async fn defaults_to_local_delivery_without_authentication() {
        let config = DeliveryPluginConfig::load(None)
            .await
            .expect("default config should load");
        let auth = config
            .load_authentication()
            .await
            .expect("default auth should load");

        assert_eq!(
            config.delivery.endpoint,
            "http://127.0.0.1:8080/v1/agent-usage/events"
        );
        assert!(auth.authorization_header().is_none());
        assert!(auth.cookie_header().is_none());
    }

    #[tokio::test]
    async fn resolves_credential_and_spool_paths_from_config_directory() {
        let directory = tempdir().expect("temporary directory should exist");
        tokio::fs::write(directory.path().join("token"), "Bearer private-token\n")
            .await
            .expect("credential should be written");
        let config_path = directory.path().join("product-config.json");
        tokio::fs::write(
            &config_path,
            r#"{
                "schema_version": 1,
                "product": {"kind": "cli"},
                "delivery_worker": {
                    "delivery": {"spool_path": "spool/events.jsonl"},
                    "authentication": {
                        "mode": "authorization_header_file",
                        "path": "token"
                    }
                }
            }"#,
        )
        .await
        .expect("config should be written");

        let config = DeliveryPluginConfig::load(Some(&config_path))
            .await
            .expect("configured delivery should load");
        let auth = config
            .load_authentication()
            .await
            .expect("credential should load");

        assert_eq!(
            config.spool_path(),
            directory.path().join("spool/events.jsonl")
        );
        assert_eq!(auth.authorization_header(), Some("Bearer private-token"));
    }

    #[tokio::test]
    async fn deployment_profile_selects_its_delivery_worker() {
        let directory = tempdir().expect("temporary directory should exist");
        let config_path = directory.path().join("product-config.json");
        tokio::fs::write(
            &config_path,
            r#"{
                "schema_version": 1,
                "product": {"kind": "cli"},
                "delivery_worker": {
                    "plugin_id": "example.delivery",
                    "delivery": {
                        "endpoint": "https://events.example.test/v1/events"
                    },
                    "authentication": {"mode": "managed_bearer"}
                }
            }"#,
        )
        .await
        .expect("deployment product configuration should write");
        let config = DeliveryPluginConfig::load(Some(&config_path))
            .await
            .expect("deployment product configuration should decode");

        assert_eq!(
            config.delivery.endpoint,
            "https://events.example.test/v1/events"
        );
        assert!(matches!(
            config.authentication,
            AuthenticationConfig::ManagedBearer
        ));
    }
}
