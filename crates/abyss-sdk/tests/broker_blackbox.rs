//! Black-box SDK test against an independently running real broker process.

use std::path::PathBuf;

use abyss_sdk::{
    BrokerClient,
    broker::{
        BrokerClientError, BrokerLogRequest, HarnessConfig, HarnessMatcherConfig, ProxyLifecycle,
    },
    plugin::AbyssPlugin,
};
use futures_util::StreamExt as _;

#[tokio::test]
#[ignore = "requires ABYSS_BROKER_STARTUP_INFO pointing to a real broker"]
async fn real_broker_supports_rest_and_plugin_sdk() {
    let startup_info = PathBuf::from(
        std::env::var_os("ABYSS_BROKER_STARTUP_INFO")
            .expect("black-box runner must set ABYSS_BROKER_STARTUP_INFO"),
    );
    let client = BrokerClient::from_startup_info(&startup_info)
        .await
        .expect("Rust SDK should discover the real broker REST API");
    let startup_json: serde_json::Value = serde_json::from_slice(
        &tokio::fs::read(&startup_info)
            .await
            .expect("startup info should remain readable"),
    )
    .expect("startup info should remain valid JSON");
    let unauthenticated = BrokerClient::new(&format!(
        "http://{}",
        startup_json["api_addr"]
            .as_str()
            .expect("startup info should advertise api_addr")
    ))
    .expect("public real-broker URL should be accepted");
    let mut events = AbyssPlugin::new("blackbox.rust-sdk")
        .connect()
        .await
        .expect("Rust SDK should complete a real broker plugin handshake");

    let health = client.health().await.expect("health should succeed");
    assert_eq!(health.service, "abyss-broker");
    assert_eq!(health.status, "ok");
    assert!(matches!(
        unauthenticated.mitm_config().await,
        Err(BrokerClientError::Api { status, .. }) if status.as_u16() == 401
    ));

    let status = client
        .proxy_status()
        .await
        .expect("proxy status should succeed");
    assert!(matches!(status.lifecycle, ProxyLifecycle::Running));

    let mitm = client.mitm_config().await.expect("MITM config should read");
    client
        .update_mitm_config(&mitm)
        .await
        .expect("MITM config should round-trip through the real broker");
    let mut hooks = client
        .hooks_config()
        .await
        .expect("Hook config should read");
    hooks.harness_usage.config.harnesses.insert(
        "rust-sdk-custom".to_owned(),
        HarnessConfig {
            enabled: Some(true),
            content: None,
            matchers: vec![HarnessMatcherConfig {
                process_names: vec!["rust-sdk-custom".to_owned()],
                application_ids: Vec::new(),
            }],
        },
    );
    let updated_hooks = client
        .update_hooks_config(&hooks)
        .await
        .expect("Hook config should round-trip through the real broker");
    assert!(
        updated_hooks
            .harness_usage
            .config
            .harnesses
            .contains_key("rust-sdk-custom")
    );
    client
        .collect_broker_logs(&BrokerLogRequest {
            max_bytes_per_file: Some(4_096),
        })
        .await
        .expect("broker support logs should collect");
    let diagnostics = client.diagnostics().await.expect("diagnostics should read");
    assert_eq!(diagnostics["schema_version"], 1_u64);
    let observations = client
        .network_observations(Some(10))
        .await
        .expect("network observations should read");
    assert_eq!(observations["schema_version"], 1_u64);
    client
        .traffic_snapshot()
        .await
        .expect("traffic snapshot should read");

    let stopped = client.shutdown().await.expect("broker should shut down");
    assert!(matches!(stopped.lifecycle, ProxyLifecycle::Stopped));
    assert!(events.next().await.is_none());
    let close = events
        .take_close()
        .expect("real broker should send a deliberate close frame");
    assert_eq!(close.code, 100_u32);
}
