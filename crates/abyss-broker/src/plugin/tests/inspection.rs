//! Real server command routing, concurrent decisions and connection snapshots.

use std::sync::Arc;

use abyss_agent_hook::AgentEventSink as _;
use abyss_plugin_protocol::{
    inspection::{AgentRequestContext, InspectResponse, PluginCapability},
    message::{BrokerMessage, PluginMessage},
};
use tokio::{net::UnixStream, sync::watch, task::JoinHandle};

use super::{connect_capabilities, read_json, test_root};
use crate::plugin::{
    InspectionDecision, InspectionError, PluginClient, PluginServer,
    codec::{read_payload, write_json},
};

struct Server {
    root: std::path::PathBuf,
    endpoint: std::path::PathBuf,
    client: PluginClient,
    shutdown: watch::Sender<bool>,
    task: JoinHandle<Result<(), crate::plugin::PluginServerError>>,
}

impl Server {
    async fn start() -> Self {
        let root = test_root();
        tokio::fs::create_dir_all(&root).await.unwrap();
        let server = PluginServer::bind(&root).await.unwrap();
        let endpoint = server.endpoint_label().into();
        let client = server.client();
        let (shutdown, receiver) = watch::channel(false);
        let task = tokio::spawn(server.run(receiver));
        Self {
            root,
            endpoint,
            client,
            shutdown,
            task,
        }
    }

    async fn stop(self) {
        self.shutdown.send(true).unwrap();
        self.task.await.unwrap().unwrap();
        tokio::fs::remove_dir_all(self.root).await.unwrap();
    }

    fn inspect(&self, id: &str) -> JoinHandle<Result<InspectionDecision, InspectionError>> {
        let client = self.client.clone();
        let plan = client.inspection_plan().expect("inspector connected");
        let context = context(id);
        tokio::spawn(async move {
            for participant in plan.participants() {
                let decision = client.inspect(participant, context.clone()).await?;
                if !matches!(decision, InspectionDecision::Allow) {
                    return Ok(decision);
                }
            }
            Ok(InspectionDecision::Allow)
        })
    }
}

fn context(id: &str) -> Arc<AgentRequestContext> {
    let message: BrokerMessage = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../specs/broker-plugin-protocol/v1/fixtures/inspect-request.json"
    )))
    .unwrap();
    let BrokerMessage::InspectRequest { mut context } = message else {
        panic!("fixture");
    };
    id.clone_into(&mut Arc::get_mut(&mut context).unwrap().request_id);
    context
}

async fn receive_request(stream: &mut UnixStream) -> Arc<AgentRequestContext> {
    let payload = read_payload(stream).await.unwrap().unwrap();
    let message: BrokerMessage = serde_json::from_slice(&payload).unwrap();
    let BrokerMessage::InspectRequest { context } = message else {
        panic!("expected inspection");
    };
    context
}

async fn reply(stream: &mut UnixStream, id: &str, allow: bool) {
    write_json(
        stream,
        &PluginMessage::InspectResponse(InspectResponse {
            request_id: id.to_owned(),
            decision: if allow {
                InspectionDecision::Allow
            } else {
                InspectionDecision::Block("Test policy".to_owned())
            },
        }),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn waiting_inspections_do_not_block_events_new_connections_or_other_decisions() {
    let server = Server::start().await;
    assert!(server.client.inspection_plan().is_none());
    let mut sink = super::connect_plugin(&server.endpoint, "sink").await;
    assert!(
        server.client.inspection_plan().is_none(),
        "sink is not inspector"
    );
    let mut plugin = connect_capabilities(
        &server.endpoint,
        "both",
        vec![
            PluginCapability::AgentRequest,
            PluginCapability::AgentEvents,
        ],
    )
    .await;

    let first = server.inspect("first");
    assert_eq!(
        serde_json::to_value(receive_request(&mut plugin).await).unwrap(),
        serde_json::to_value(context("first")).unwrap()
    );
    assert!(
        !first.is_finished(),
        "caller must await the plugin response"
    );
    let second = server.inspect("second");
    assert_eq!(receive_request(&mut plugin).await.request_id, "second");

    // The server keeps accepting and publishing while both decisions are pending.
    let mut later = connect_capabilities(
        &server.endpoint,
        "later",
        vec![PluginCapability::AgentRequest],
    )
    .await;
    let event = serde_json::from_str(include_str!("../fixtures/agent-event.json")).unwrap();
    server.client.publish(event).await.unwrap();
    let received: serde_json::Value = read_json(&mut plugin).await;
    let sink_event: serde_json::Value = read_json(&mut sink).await;
    assert_eq!(received, sink_event);
    assert_eq!(received["event_id"], "evt-123");

    // Out-of-order replies still resolve only their corresponding request.
    reply(&mut plugin, "second", false).await;
    assert_eq!(
        second.await.unwrap(),
        Ok(InspectionDecision::Block("Test policy".to_owned()))
    );
    assert!(!first.is_finished());
    reply(&mut plugin, "first", true).await;
    assert_eq!(first.await.unwrap(), Ok(InspectionDecision::Allow));

    let third = server.inspect("third");
    assert_eq!(receive_request(&mut plugin).await.request_id, "third");
    reply(&mut plugin, "third", true).await;
    // The new connection participates in subsequent plans, not previous requests.
    assert_eq!(receive_request(&mut later).await.request_id, "third");
    assert!(!third.is_finished());
    reply(&mut later, "third", true).await;
    assert_eq!(third.await.unwrap(), Ok(InspectionDecision::Allow));
    server.stop().await;
}

#[tokio::test]
async fn reconnect_cannot_replace_a_selected_session_and_shutdown_wakes_callers() {
    let server = Server::start().await;
    let plugin = connect_capabilities(
        &server.endpoint,
        "same-id",
        vec![PluginCapability::AgentRequest],
    )
    .await;
    let plan = server.client.inspection_plan().unwrap();
    drop(plugin);
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while server.client.inspection_plan().is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let mut reconnected = connect_capabilities(
        &server.endpoint,
        "same-id",
        vec![PluginCapability::AgentRequest],
    )
    .await;
    assert_eq!(
        server
            .client
            .inspect(plan.participants().next().unwrap(), context("stale"))
            .await,
        Err(InspectionError::Unavailable)
    );
    let pending = server.inspect("current");
    assert_eq!(
        receive_request(&mut reconnected).await.request_id,
        "current"
    );
    let client = server.client.clone();
    server.stop().await;
    assert_eq!(pending.await.unwrap(), Err(InspectionError::Unavailable));
    assert!(client.inspection_plan().is_none());
}

#[tokio::test]
async fn capacity_rejects_excess_inspections_and_recovers_after_decisions() {
    let server = Server::start().await;
    let mut plugin = connect_capabilities(
        &server.endpoint,
        "capacity",
        vec![PluginCapability::AgentRequest],
    )
    .await;
    let mut pending = Vec::new();
    for index in 0..crate::plugin::COMMAND_CAPACITY {
        let id = index.to_string();
        let request = server.inspect(&id);
        assert_eq!(receive_request(&mut plugin).await.request_id, id);
        pending.push(request);
    }
    assert_eq!(
        server.inspect("excess").await.unwrap(),
        Err(InspectionError::Unavailable)
    );
    for index in 0..crate::plugin::COMMAND_CAPACITY {
        reply(&mut plugin, &index.to_string(), true).await;
    }
    for request in pending {
        assert_eq!(request.await.unwrap(), Ok(InspectionDecision::Allow));
    }
    let recovered = server.inspect("recovered");
    assert_eq!(receive_request(&mut plugin).await.request_id, "recovered");
    reply(&mut plugin, "recovered", true).await;
    assert_eq!(recovered.await.unwrap(), Ok(InspectionDecision::Allow));
    server.stop().await;
}
