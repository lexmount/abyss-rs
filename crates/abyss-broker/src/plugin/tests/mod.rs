//! `PluginServer` tests using real local plugin connections.

mod inspection;

use std::path::PathBuf;

use abyss_agent_hook::AgentEventSink as _;
use abyss_plugin_protocol::{
    event::AgentEvent,
    message::{BrokerClose, BrokerHello, PluginHello, PluginMessage},
};
use tokio::net::UnixStream;

use super::{
    PluginServer,
    codec::{read_payload, write_json},
};

#[tokio::test]
async fn one_real_listener_broadcasts_the_same_event_to_two_plugins() {
    let root = test_root();
    let server = PluginServer::bind(&root)
        .await
        .expect("plugin server should bind");
    let endpoint = PathBuf::from(server.endpoint_label());
    let sink = server.client();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server_task = tokio::spawn(server.run(shutdown_rx));

    let mut first = connect_plugin(&endpoint, "first-plugin").await;
    let mut second = connect_plugin(&endpoint, "second-plugin").await;
    let event: AgentEvent = serde_json::from_str(include_str!("../fixtures/agent-event.json"))
        .expect("published AgentEvent fixture should decode");
    sink.publish(event)
        .await
        .expect("broker event sink should accept the event");

    // Both plugins negotiate v1, whose frames are not `AgentEvent`s.
    let first_event: serde_json::Value = read_json(&mut first).await;
    let second_event: serde_json::Value = read_json(&mut second).await;
    assert_eq!(first_event["event_id"], "evt-123");
    assert_eq!(second_event, first_event);

    shutdown_tx
        .send(true)
        .expect("server should retain shutdown receiver");
    let first_close: BrokerClose = read_json(&mut first).await;
    let second_close: BrokerClose = read_json(&mut second).await;
    assert_eq!(first_close.code, 100_u32);
    assert_eq!(second_close.code, 100_u32);
    server_task
        .await
        .expect("plugin server task should finish")
        .expect("plugin server should stop cleanly");
    assert!(
        !endpoint.exists(),
        "orderly shutdown should remove the Unix socket"
    );
    if tokio::fs::try_exists(&root)
        .await
        .expect("plugin server test root should be queryable")
    {
        tokio::fs::remove_dir_all(root)
            .await
            .expect("plugin server test root should remove");
    }
}

async fn connect_plugin(endpoint: &std::path::Path, plugin_id: &str) -> UnixStream {
    connect_capabilities(
        endpoint,
        plugin_id,
        vec![abyss_plugin_protocol::inspection::PluginCapability::AgentEvents],
    )
    .await
}

async fn connect_capabilities(
    endpoint: &std::path::Path,
    plugin_id: &str,
    capabilities: Vec<abyss_plugin_protocol::inspection::PluginCapability>,
) -> UnixStream {
    let mut hello = PluginHello::new(plugin_id.to_owned());
    hello.capabilities = capabilities;
    let mut stream = UnixStream::connect(endpoint)
        .await
        .expect("plugin should connect to the Unix socket");
    write_json(&mut stream, &PluginMessage::PluginHello(hello))
        .await
        .expect("PluginHello should write");
    let hello: BrokerHello = read_json(&mut stream).await;
    assert_eq!(
        hello.protocol_version.wire_value(),
        1_u16,
        "broker should negotiate plugin protocol version 1"
    );
    stream
}

async fn read_json<T>(stream: &mut UnixStream) -> T
where
    T: serde::de::DeserializeOwned,
{
    let payload = read_payload(stream)
        .await
        .expect("plugin frame should read")
        .expect("plugin frame should be present");
    decode_payload(&payload)
}

fn test_root() -> PathBuf {
    std::env::temp_dir().join(format!(
        "abyss-plugin-server-test-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ))
}
fn decode_payload<T: serde::de::DeserializeOwned>(payload: &[u8]) -> T {
    let mut frame: serde_json::Value = serde_json::from_slice(payload).unwrap();
    assert!(frame["type"].is_string(), "session frames are tagged");
    let payload = if frame["type"] == "agent_event" {
        frame["event"].take()
    } else {
        frame.as_object_mut().unwrap().remove("type");
        frame
    };
    serde_json::from_value(payload).unwrap()
}
