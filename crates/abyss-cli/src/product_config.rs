//! Product-level configuration shared by the CLI and its delivery worker.

use std::{fs, path::Path};

use abyss_delivery_plugin::{AuthenticationConfig, DeliveryPluginConfig};
use serde::Deserialize;

use crate::error::CliError;

const PRODUCT_CONFIG_SCHEMA_VERSION: u32 = 1;

/// Product settings required by the user-facing CLI.
#[derive(Debug)]
pub struct CliProductConfig {
    control_plane_url: Option<String>,
    requires_terminal_login: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProductConfigFile {
    schema_version: u32,
    product: ProductSettings,
    #[serde(default)]
    adapter: Option<serde_json::Value>,
    delivery_worker: DeliveryPluginConfig,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProductSettings {
    kind: ProductKind,
    #[serde(default)]
    control_plane: Option<ControlPlaneSettings>,
    #[serde(default)]
    dashboard: Option<serde_json::Value>,
    #[serde(default)]
    sso: Option<serde_json::Value>,
    #[serde(default)]
    updates: Option<serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum ProductKind {
    Cli,
    Host,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlPlaneSettings {
    url: String,
    #[serde(default)]
    auth_path_prefix: Option<String>,
}

impl CliProductConfig {
    /// Returns the configured control-plane base URL when this deployment has one.
    #[must_use]
    pub fn control_plane_url(&self) -> Option<&str> {
        self.control_plane_url.as_deref()
    }

    /// Returns whether endpoint commands require a valid terminal credential.
    #[must_use]
    pub const fn requires_terminal_login(&self) -> bool {
        self.requires_terminal_login
    }

    /// Loads and validates the deployment-supplied CLI product configuration.
    pub fn load(path: &Path) -> Result<Self, CliError> {
        match fs::read_to_string(path) {
            Ok(contents) => Self::decode(&contents),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Err(CliError::InvalidConfiguration(format!(
                    "deployment-supplied product configuration is required at {}",
                    path.display()
                )))
            }
            Err(source) => Err(CliError::filesystem(
                "read product configuration",
                path,
                source,
            )),
        }
    }

    fn decode(contents: &str) -> Result<Self, CliError> {
        let file = serde_json::from_str::<ProductConfigFile>(contents)?;
        if file.schema_version != PRODUCT_CONFIG_SCHEMA_VERSION {
            return Err(CliError::InvalidConfiguration(format!(
                "unsupported product schema_version {}; expected {PRODUCT_CONFIG_SCHEMA_VERSION}",
                file.schema_version
            )));
        }
        if !matches!(file.product.kind, ProductKind::Cli) {
            return Err(CliError::InvalidConfiguration(
                "the Abyss CLI requires product.kind=cli".to_owned(),
            ));
        }
        if file.adapter.is_some() {
            return Err(CliError::InvalidConfiguration(
                "the Abyss CLI product configuration must not define an adapter".to_owned(),
            ));
        }
        let requires_terminal_login = !matches!(
            &file.delivery_worker.authentication,
            AuthenticationConfig::None
        );
        let control_plane_url = file
            .product
            .control_plane
            .as_ref()
            .map(Self::validate_control_plane_url)
            .transpose()?;
        if requires_terminal_login && control_plane_url.is_none() {
            return Err(CliError::InvalidConfiguration(
                "product.control_plane is required when delivery_worker.authentication.mode is not \"none\""
                    .to_owned(),
            ));
        }
        drop((
            file.delivery_worker,
            file.product.dashboard,
            file.product.sso,
            file.product.updates,
            file.product
                .control_plane
                .and_then(|settings| settings.auth_path_prefix),
        ));
        Ok(Self {
            control_plane_url,
            requires_terminal_login,
        })
    }

    fn validate_control_plane_url(
        control_plane: &ControlPlaneSettings,
    ) -> Result<String, CliError> {
        let control_plane_url = control_plane.url.trim().to_owned();
        let parsed = reqwest::Url::parse(&control_plane_url).map_err(|error| {
            CliError::InvalidConfiguration(format!("invalid product.control_plane.url: {error}"))
        })?;
        if parsed.host_str().is_none()
            || !matches!(parsed.scheme(), "http" | "https")
            || parsed.username() != ""
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(CliError::InvalidConfiguration(
                "product.control_plane.url must be an absolute HTTP(S) URL without credentials, query, or fragment"
                    .to_owned(),
            ));
        }
        Ok(control_plane_url)
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf, time::SystemTime};

    use super::CliProductConfig;

    #[test]
    fn deployment_supplied_cli_profile_is_valid() {
        let config = CliProductConfig::decode(valid_product_config())
            .expect("deployment product configuration should decode");

        assert_eq!(
            config.control_plane_url(),
            Some("https://control.example.test/api")
        );
        assert!(config.requires_terminal_login());
    }

    #[test]
    fn unauthenticated_delivery_does_not_require_a_control_plane() {
        for product in [
            r#"{"kind":"cli"}"#,
            r#"{"kind":"cli","control_plane":null}"#,
        ] {
            let config = CliProductConfig::decode(&format!(
                r#"{{
                    "schema_version": 1,
                    "product": {product},
                    "delivery_worker": {{
                        "delivery": {{"endpoint": "https://events.example.test/v1/events"}},
                        "authentication": {{"mode": "none"}}
                    }}
                }}"#
            ))
            .expect("unauthenticated delivery should not require a control plane");

            assert_eq!(config.control_plane_url(), None);
            assert!(!config.requires_terminal_login());
        }
    }

    #[test]
    fn authenticated_delivery_requires_a_control_plane() {
        for authentication in [
            r#"{"mode":"managed_bearer"}"#,
            r#"{"mode":"authorization_header_file","path":"token"}"#,
            r#"{"mode":"cookie_header_file","path":"cookie"}"#,
        ] {
            let error = CliProductConfig::decode(&format!(
                r#"{{
                    "schema_version": 1,
                    "product": {{"kind": "cli"}},
                    "delivery_worker": {{"authentication": {authentication}}}
                }}"#
            ))
            .expect_err("authenticated delivery must require a control plane");

            assert!(error.to_string().contains(
                "product.control_plane is required when delivery_worker.authentication.mode is not \"none\""
            ));
        }
    }

    #[test]
    fn cli_profile_rejects_a_platform_adapter() {
        let error = CliProductConfig::decode(
            r#"{
                "schema_version": 1,
                "product": {
                    "kind": "cli",
                    "control_plane": {"url": "https://example.test/api"}
                },
                "adapter": {"kind": "windows_wfp"},
                "delivery_worker": {}
            }"#,
        )
        .expect_err("CLI configuration must not include an adapter");

        assert!(error.to_string().contains("must not define an adapter"));
    }

    #[test]
    fn missing_product_config_is_not_seeded_from_a_product_profile() {
        let path = test_path();

        let error = CliProductConfig::load(&path)
            .expect_err("a deployment must provide its product configuration");

        assert!(error.to_string().contains("deployment-supplied"));
        assert!(!path.exists());
        drop(fs::remove_dir_all(
            path.parent().expect("test path should have a parent"),
        ));
    }

    fn valid_product_config() -> &'static str {
        r#"{
            "schema_version": 1,
            "product": {
                "kind": "cli",
                "control_plane": {"url": "https://control.example.test/api"}
            },
            "delivery_worker": {
                "plugin_id": "example.delivery",
                "delivery": {"endpoint": "https://events.example.test/v1/events"},
                "authentication": {"mode": "managed_bearer"}
            }
        }"#
    }

    fn test_path() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("test clock should be after the Unix epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "abyss-cli-product-config-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).expect("test directory should create");
        directory.join("product-config.json")
    }
}
