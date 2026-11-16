//! `WireGuard` configuration, identity ownership and deadline regression tests.

use std::{sync::Arc, time::Duration};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use boringtun::x25519::{PublicKey, StaticSecret};
use serde_json::{Value, json};

use super::{WireguardRoute, config::Settings};
use crate::{
    TargetAuthority,
    outbound::{UpstreamProxy, UpstreamProxyConfig, UpstreamProxyProtocol},
};

fn material() -> Value {
    let mut private = [0; 32];
    private[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    private[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    json!({
        "private_key": STANDARD.encode(private),
        "public_key": STANDARD.encode(PublicKey::from(&StaticSecret::from([7; 32])).as_bytes()),
        "preshared_key": STANDARD.encode([9; 32]),
        "addresses": ["10.77.0.2", "fd77::2"],
        "allowed_ips": ["10.77.0.0/24", "fd77::/64"],
        "dns_servers": ["10.77.0.1"],
        "persistent_keepalive_secs": 25
    })
}

fn config(file: &tempfile::NamedTempFile) -> UpstreamProxyConfig {
    UpstreamProxyConfig {
        protocol: UpstreamProxyProtocol::Wireguard,
        endpoint: "wireguard://127.0.0.1:51820".to_owned(),
        wireguard_file: Some(file.path().to_owned()),
        ca_file: None,
        credentials_file: None,
        connect_timeout_ms: 500,
        handshake_timeout_ms: 100,
    }
}

#[test]
fn strict_material_validation_never_exposes_keys() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let valid = material();
    std::fs::write(file.path(), valid.to_string()).unwrap();
    let settings = Settings::load(file.path()).unwrap();
    for (address, allowed) in [
        ("10.77.0.1", true),
        ("fd77::1", true),
        ("10.77.0.2", false),
        ("10.78.0.1", false),
        ("127.0.0.1", false),
    ] {
        assert_eq!(settings.allows(address.parse().unwrap()), allowed);
    }
    for (field, value) in [
        ("private_key", json!("secret-not-a-key")),
        ("public_key", json!(STANDARD.encode([0; 32]))),
        ("preshared_key", json!(STANDARD.encode([0; 32]))),
        ("addresses", json!([])),
        ("addresses", json!(["10.77.0.2", "10.77.0.3"])),
        ("addresses", json!(["::ffff:10.77.0.2"])),
        ("allowed_ips", json!([])),
        ("dns_servers", json!(["1.1.1.1"])),
        ("mtu", json!(100_u16)),
        ("persistent_keepalive_secs", json!(0_u16)),
        ("unexpected_secret", json!("private-value")),
    ] {
        let mut candidate = valid.clone();
        candidate[field] = value;
        std::fs::write(file.path(), candidate.to_string()).unwrap();
        let error = Settings::load(file.path())
            .err()
            .expect("invalid configuration")
            .to_string();
        for secret in [
            valid["private_key"].as_str().unwrap(),
            "secret-not-a-key",
            "private-value",
        ] {
            assert!(
                !error.contains(secret),
                "configuration errors must redact material"
            );
        }
    }
    std::fs::write(file.path(), vec![b' '; 0x0001_0001]).unwrap();
    assert!(
        Settings::load(file.path()).is_err(),
        "oversized files are rejected"
    );
}

#[test]
fn route_round_trips_paths_and_validates_protocol_fields() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let mut route = config(&file);
    route.validate().unwrap();
    let encoded = serde_json::to_string(&route).unwrap();
    assert_eq!(
        serde_json::from_str::<UpstreamProxyConfig>(&encoded).unwrap(),
        route
    );
    for endpoint in [
        "http://peer:51820",
        "wireguard://user:secret@peer:51820",
        "wireguard://peer:0",
        "wireguard://peer:51820/path",
    ] {
        route.endpoint = endpoint.to_owned();
        assert!(
            route.validate().is_err(),
            "endpoint must match protocol and authority syntax"
        );
    }
    route = config(&file);
    route.credentials_file = Some(file.path().to_owned());
    assert!(
        route.validate().is_err(),
        "proxy credentials cannot configure WireGuard"
    );
    route = config(&file);
    route.wireguard_file = Some("relative.json".into());
    assert!(
        route.validate().is_err(),
        "material path must be broker-local and absolute"
    );
    route = config(&file);
    route.protocol = UpstreamProxyProtocol::Socks5;
    route.endpoint = "socks5://peer:1080".to_owned();
    assert!(
        route.validate().is_err(),
        "other protocols reject WireGuard material"
    );
}

#[test]
fn repeated_snapshots_share_identity_until_the_last_owner_is_dropped() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let mut value = material();
    std::fs::write(file.path(), value.to_string()).unwrap();
    let config = config(&file);
    let first = WireguardRoute::load(&config).unwrap();
    let second = WireguardRoute::load(&config).unwrap();
    assert!(
        Arc::ptr_eq(&first, &second),
        "reapply must not cause endpoint roaming"
    );
    value["mtu"] = json!(1300_u16);
    std::fs::write(file.path(), value.to_string()).unwrap();
    assert!(
        WireguardRoute::load(&config).is_err(),
        "active identity conflicts are rejected"
    );
    drop(first);
    drop(second);
    assert!(
        WireguardRoute::load(&config).is_ok(),
        "drained identities can be reconfigured"
    );
}

#[tokio::test]
async fn unreachable_peer_is_bounded_and_never_connects_to_the_target_directly() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let value = material();
    std::fs::write(file.path(), value.to_string()).unwrap();
    let mut config = config(&file);
    config.endpoint = format!("wireguard://{}", udp.local_addr().unwrap());
    let proxy = UpstreamProxy::new(&config).unwrap();
    let target = TargetAuthority::parse("10.77.0.1:80").unwrap();
    let result = tokio::time::timeout(Duration::from_secs(2), proxy.connect_tunnel(&target, &[]))
        .await
        .unwrap();
    assert!(
        result.err().unwrap().is_timeout(),
        "silent peer must respect handshake deadline"
    );
    let mut packet = [0; 512];
    let size = udp.recv(&mut packet).await.unwrap();
    assert_eq!(size, 148, "actual WireGuard handshake was emitted");
    assert_eq!(
        &packet[..4],
        &[1, 0, 0, 0],
        "WireGuard handshake initiation"
    );
}
