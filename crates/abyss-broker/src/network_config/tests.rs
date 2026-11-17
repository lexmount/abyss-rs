//! Route-manager ownership across reloads, retained snapshots and independent runtimes.

use std::path::PathBuf;

use abyss_mitm::outbound::{UpstreamProxyConfig, UpstreamProxyProtocol};
use serde_json::json;

use super::{NetworkConfig, NetworkRuntime};

struct WireguardFile {
    path: PathBuf,
}

impl WireguardFile {
    fn new() -> Self {
        let file = Self {
            path: std::env::temp_dir().join(format!("abyss-wg-{}.json", uuid::Uuid::new_v4())),
        };
        file.write(1280);
        file
    }

    fn write(&self, mtu: u16) {
        // Fixed, test-only keys make independent runtimes exercise the same identity.
        std::fs::write(
            &self.path,
            json!({
                "private_key": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
                "public_key": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
                "addresses": ["10.77.0.2"],
                "allowed_ips": ["10.77.0.0/24"],
                "mtu": mtu
            })
            .to_string(),
        )
        .unwrap();
    }

    fn config(&self) -> NetworkConfig {
        NetworkConfig {
            upstream: Some(UpstreamProxyConfig {
                protocol: UpstreamProxyProtocol::Wireguard,
                endpoint: "wireguard://127.0.0.1:51820".to_owned(),
                wireguard_file: Some(self.path.clone()),
                ca_file: None,
                credentials_file: None,
                connect_timeout_ms: 500,
                handshake_timeout_ms: 500,
            }),
        }
    }
}

impl Drop for WireguardFile {
    fn drop(&mut self) {
        std::fs::remove_file(&self.path).unwrap();
    }
}

#[test]
fn cloned_manager_preserves_identity_until_old_snapshots_drain() {
    let file = WireguardFile::new();
    let runtime = NetworkRuntime::new(file.config().upstream, None).unwrap();
    let old_flow = runtime.snapshot();
    let updater = runtime.clone();
    updater.publish(updater.validate(file.config()).unwrap());
    updater.publish(updater.validate(NetworkConfig::default()).unwrap());
    assert!(
        runtime.snapshot().proxy().is_none(),
        "direct route was published"
    );
    assert!(old_flow.proxy().is_some(), "the old flow retains its route");
    file.write(1300);
    assert!(
        updater.validate(file.config()).is_err(),
        "a shared manager must protect identities held only by old flows"
    );
    drop(old_flow);
    assert!(
        updater.validate(file.config()).is_ok(),
        "weak registration must allow reconfiguration after the last owner drains"
    );
}

#[test]
fn independent_managers_have_independent_identity_ownership() {
    let file = WireguardFile::new();
    let first = NetworkRuntime::new(file.config().upstream, None).unwrap();
    file.write(1300);
    let second = NetworkRuntime::new(file.config().upstream, None).unwrap();
    assert!(
        second.snapshot().proxy().is_some(),
        "independent manager can load its route"
    );
    assert!(
        first.validate(file.config()).is_err(),
        "an independent manager must not replace the first manager's identity"
    );
}
