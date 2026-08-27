//! Endpoint CLI runtime orchestration.
//!
//! This boundary keeps CA trust and platform lifecycle operations out of the
//! public command handlers. The user-facing CLI owns the product lifecycle;
//! the broker remains the long-running MITM process.

use std::{net::SocketAddr, thread, time::Duration};

use abyss_terminal_auth::CredentialStore as _;
use chrono::Utc;

use crate::{
    broker::BrokerEndpoint,
    credential::CliCredentialStore,
    delivery::{DeliveryConnection, DeliveryWorker},
    error::CliError,
    local_config::{LocalConfig, LocalRuntimePolicy},
    paths::CliPaths,
    platform::platform_adapter,
    product_config::CliProductConfig,
};
use abyss_mitm::CaStore;

/// A verified CLI-owned broker and its explicit ingress listener.
pub struct RunningBroker {
    endpoint: BrokerEndpoint,
    proxy_addr: SocketAddr,
}

impl RunningBroker {
    /// Returns the concrete REST endpoint published by the broker.
    #[must_use]
    pub const fn endpoint(&self) -> &BrokerEndpoint {
        &self.endpoint
    }

    /// Returns the concrete explicit ingress listener.
    #[must_use]
    pub const fn proxy_addr(&self) -> SocketAddr {
        self.proxy_addr
    }
}

/// Starts the complete explicit-ingress runtime required by agent commands.
pub fn ensure_started(
    paths: &CliPaths,
    user: Option<&str>,
    requested_port: Option<u16>,
) -> Result<RunningBroker, CliError> {
    ensure_config(paths)?;
    let mut config = LocalConfig::load(&paths.config_file())?;
    config.require_explicit_mode()?;
    let config_changed = requested_port.is_some_and(|port| config.set_explicit_proxy_port(port));
    if config_changed {
        config.write(&paths.config_file())?;
    }
    let platform = platform_adapter();
    let ca_path = config.ca_path(&paths.config_file())?;
    let store = CaStore::at(ca_path);
    store.load_or_generate_with(platform.ca_material_persistence())?;
    platform.install_ca_trust(store.directory())?;
    let endpoint =
        platform.start_broker(paths, user, requested_port.is_some() && config_changed)?;
    let proxy_addr = wait_for_broker(&endpoint)?;
    let delivery = DeliveryWorker::ensure_running(paths, &endpoint)?;
    sync_delivery_credential(paths, &delivery)?;
    Ok(RunningBroker {
        endpoint,
        proxy_addr,
    })
}

/// Synchronizes the authoritative CLI credential into one running worker.
fn sync_delivery_credential(
    paths: &CliPaths,
    delivery: &DeliveryConnection,
) -> Result<(), CliError> {
    if !paths.credential_file().exists() {
        return delivery.clear_bearer_if_managed();
    }
    let credential = CliCredentialStore::from_paths(paths)?.read()?;
    if credential.expires_at <= Utc::now() {
        return delivery.clear_bearer_if_managed();
    }
    delivery.set_bearer_if_managed(&credential.token, &credential.control_plane)
}

/// Loads, validates, and seeds the CLI-owned configuration files.
pub fn ensure_config(paths: &CliPaths) -> Result<(), CliError> {
    let config_path = paths.config_file();
    let config = LocalConfig::load(&config_path)?;
    config.require_explicit_mode()?;
    let policy_path = paths.runtime_policy_file();
    let policy = LocalRuntimePolicy::load(&policy_path)?;
    CliProductConfig::load(&paths.product_config_file())?;
    if !config_path.exists() {
        config.write(&config_path)?;
    }
    if !policy_path.exists() {
        policy.write(&policy_path)?;
    }
    Ok(())
}

fn wait_for_broker(endpoint: &BrokerEndpoint) -> Result<SocketAddr, CliError> {
    for _ in 0_u8..50_u8 {
        if let Ok(broker) = endpoint.require_owned_explicit()
            && let Ok(proxy_addr) = broker.proxy_listen_addr()
        {
            return Ok(proxy_addr);
        }
        thread::sleep(Duration::from_millis(100));
    }
    Err(CliError::InvalidConfiguration(
        "abyss-broker did not become healthy in explicit ingress mode".to_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf, time::SystemTime};

    use super::ensure_config;
    use crate::{local_config::LocalConfig, paths::CliPaths};

    const PRODUCT_CONFIG: &str = r#"{
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
    }"#;

    fn test_root(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("test clock should be after the Unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "abyss-cli-runtime-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn missing_open_configuration_is_seeded_without_rewriting_product_config() {
        let root = test_root("seed");
        let paths = CliPaths::at(root.clone());
        fs::create_dir_all(&root).expect("test state root should create");
        fs::write(paths.product_config_file(), PRODUCT_CONFIG)
            .expect("product configuration should write");

        ensure_config(&paths).expect("missing open configuration should be seeded");
        let config = LocalConfig::load(&paths.config_file())
            .expect("seeded startup configuration should load");
        config
            .require_explicit_mode()
            .expect("seeded configuration must stay explicit");
        assert!(paths.runtime_policy_file().is_file());
        assert!(paths.product_config_file().is_file());

        let config_bytes = fs::read(paths.config_file()).expect("seeded config should read");
        let policy_bytes =
            fs::read(paths.runtime_policy_file()).expect("seeded policy should read");
        let product_bytes =
            fs::read(paths.product_config_file()).expect("seeded product config should read");
        ensure_config(&paths).expect("existing CLI configuration should remain valid");
        assert_eq!(
            fs::read(paths.config_file()).expect("preserved config should read"),
            config_bytes
        );
        assert_eq!(
            fs::read(paths.runtime_policy_file()).expect("preserved policy should read"),
            policy_bytes
        );
        assert_eq!(
            fs::read(paths.product_config_file()).expect("preserved product config should read"),
            product_bytes
        );
        drop(fs::remove_dir_all(root));
    }

    #[test]
    fn missing_product_configuration_is_rejected_without_partial_seeding() {
        let root = test_root("missing-product");
        let paths = CliPaths::at(root.clone());

        let error = ensure_config(&paths)
            .expect_err("the open CLI must not invent deployment configuration");

        assert!(error.to_string().contains("deployment-supplied"));
        assert!(!paths.config_file().exists());
        assert!(!paths.runtime_policy_file().exists());
        assert!(!paths.product_config_file().exists());
        drop(fs::remove_dir_all(root));
    }

    #[test]
    fn transparent_proxy_configuration_is_rejected_without_rewriting_it() {
        let root = test_root("transparent");
        let paths = CliPaths::at(root.clone());
        fs::create_dir_all(&root).expect("test state root should create");
        let contents = b"schema_version = 1\n[proxy]\nmode = \"windows_wfp\"\n";
        fs::write(paths.config_file(), contents).expect("test config should write");

        let error =
            ensure_config(&paths).expect_err("the CLI must never accept a transparent proxy mode");
        assert!(error.to_string().contains("proxy.mode=explicit"));
        assert_eq!(
            fs::read(paths.config_file()).expect("rejected config should remain readable"),
            contents
        );
        assert!(!paths.runtime_policy_file().exists());
        assert!(!paths.product_config_file().exists());
        drop(fs::remove_dir_all(root));
    }
}
