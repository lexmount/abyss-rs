//! Public SDK factory and endpoint ownership tests over local protocol peers.

#![cfg(unix)]

use std::{
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use abyss_sdk::{BrokerClient, broker::BrokerClientError, plugin::BrokerClose};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{UnixListener, UnixStream},
    task::JoinHandle,
};

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("sdk-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    async fn startup(&self, endpoint: &str) -> PathBuf {
        let token = self.path("token");
        tokio::fs::write(&token, "local-token\n").await.unwrap();
        let path = self.path("startup.json");
        tokio::fs::write(
            &path,
            serde_json::to_vec(&json!({
                "api_addr": "127.0.0.1:1",
                "auth_token_file": token,
                "plugin_endpoint": endpoint,
            }))
            .unwrap(),
        )
        .await
        .unwrap();
        path
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _removed = std::fs::remove_dir_all(&self.0);
    }
}

struct BrokerPeer;

impl BrokerPeer {
    fn start(path: &Path, event_id: &'static str, count: usize) -> JoinHandle<Vec<String>> {
        let listener = UnixListener::bind(path).unwrap();
        tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(5), async {
                let mut identities = Vec::new();
                for _ in 0..count {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let size = stream.read_u32().await.unwrap();
                    let mut payload = vec![0; usize::try_from(size).unwrap()];
                    stream.read_exact(&mut payload).await.unwrap();
                    let hello: Value = serde_json::from_slice(&payload).unwrap();
                    assert_eq!(hello["protocol_version"], 1_u32, "SDK must use protocol v1");
                    identities.push(hello["plugin_id"].as_str().unwrap().to_owned());
                    let mut event: Value = serde_json::from_str(include_str!(
                        "../../../specs/broker-plugin-protocol/v1/fixtures/agent-event.json"
                    ))
                    .unwrap();
                    event["event_id"] = json!(event_id);
                    Self::write(&mut stream, json!({"protocol_version": 1_u32})).await;
                    Self::write(&mut stream, event).await;
                    Self::write(&mut stream, json!({"code": 100_u32, "reason": "complete"})).await;
                }
                identities
            })
            .await
            .expect("clients should complete their handshakes")
        })
    }

    async fn write(stream: &mut UnixStream, value: Value) {
        let bytes = serde_json::to_vec(&value).unwrap();
        stream
            .write_u32(u32::try_from(bytes.len()).unwrap())
            .await
            .unwrap();
        stream.write_all(&bytes).await.unwrap();
    }
}

#[tokio::test]
async fn plugins_keep_client_endpoints_and_independent_lifecycles() {
    let directory = TestDirectory::new();
    let first_path = directory.path("first.sock");
    let second_path = directory.path("second.sock");
    let first_client =
        BrokerClient::new("http://127.0.0.1:1", first_path.to_str().unwrap()).unwrap();
    let first_plugin = first_client.plugin("first.consumer");
    // Configuration is lazy: neither listener exists until after plugin creation.
    let first_peer = BrokerPeer::start(&first_path, "first-event", 2);
    let second_peer = BrokerPeer::start(&second_path, "second-event", 1);
    let path = directory.startup(second_path.to_str().unwrap()).await;
    let second_client = BrokerClient::from_startup_info(&path).await.unwrap();
    tokio::fs::write(&path, b"{}").await.unwrap();
    let second_plugin = second_client.plugin("second.consumer");
    drop(second_client);
    let first = first_plugin.run(|event| async move {
        assert_eq!(event.event_id, "first-event");
        Ok::<(), std::convert::Infallible>(())
    });
    let another = first_client
        .plugin("another.consumer")
        .run(|event| async move {
            assert_eq!(event.event_id, "first-event");
            Ok::<(), std::convert::Infallible>(())
        });
    let second = second_plugin.run(|event| async move {
        assert_eq!(event.event_id, "second-event");
        Ok::<(), std::convert::Infallible>(())
    });
    let closes = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::try_join!(first, another, second).unwrap()
    })
    .await
    .unwrap();
    for BrokerClose { code, .. } in <[BrokerClose; 3]>::from(closes) {
        assert_eq!(code, 100);
    }
    let mut identities = first_peer.await.unwrap();
    identities.sort();
    assert_eq!(identities, ["another.consumer", "first.consumer"]);
    assert_eq!(second_peer.await.unwrap(), ["second.consumer"]);
}

#[tokio::test]
async fn startup_info_requires_a_usable_plugin_endpoint() {
    let directory = TestDirectory::new();
    for endpoint in ["", " ", "bad\0socket"] {
        let path = directory.startup(endpoint).await;
        assert!(matches!(
            BrokerClient::from_startup_info(&path).await,
            Err(BrokerClientError::InvalidPluginEndpoint)
        ));
    }
    let path = directory.startup("/tmp/valid.sock").await;
    let mut startup: Value =
        serde_json::from_slice(&tokio::fs::read(&path).await.unwrap()).unwrap();
    startup.as_object_mut().unwrap().remove("plugin_endpoint");
    tokio::fs::write(&path, serde_json::to_vec(&startup).unwrap())
        .await
        .unwrap();
    assert!(matches!(
        BrokerClient::from_startup_info(&path).await,
        Err(BrokerClientError::StartupInfoJson { .. })
    ));
}

#[test]
fn manual_client_rejects_unusable_plugin_endpoints() {
    for endpoint in ["", " \n", "bad\0socket"] {
        assert!(matches!(
            BrokerClient::new("http://127.0.0.1:1", endpoint),
            Err(BrokerClientError::InvalidPluginEndpoint)
        ));
    }
}
