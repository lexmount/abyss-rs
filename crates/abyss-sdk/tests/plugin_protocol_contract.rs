//! Black-box compatibility tests for the published broker plugin contract.

use std::{fs, path::PathBuf};

use abyss_sdk::{
    event::AgentEvent,
    plugin::{BrokerClose, BrokerError, BrokerHello, MessageRole, PluginHello},
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;

const EVENT_SCHEMA_ID: &str =
    "https://schemas.lexmount.net/abyss/broker-plugin/v1/agent-event.schema.json";

struct PublishedContract {
    root: PathBuf,
}

#[test]
fn v2_conversation_and_handshakes_round_trip_without_changing_v1() {
    let contract = PublishedContract::load_version("v2");
    contract.assert_fixture_round_trip::<AgentEvent>("agent-event.json");
    contract.assert_fixture_round_trip::<PluginHello>("plugin-hello.json");
    contract.assert_fixture_round_trip::<BrokerHello>("broker-hello.json");
    let fixture = contract.json("fixtures/agent-event.json");
    assert!(fixture["conversation"]["messages"][0]["text"].is_string());
    let schema = contract.json("agent-event.schema.json");
    assert!(schema["properties"].get("conversation").is_some());
    assert!(schema["properties"].get("raw_body").is_none());
    let messages = contract.json("messages.schema.json");
    for name in ["pluginHello", "brokerHello"] {
        assert_eq!(
            messages["$defs"][name]["properties"]["protocol_version"]["const"],
            2_u16
        );
    }
    let mut obsolete = fixture;
    obsolete["raw_body"] = serde_json::json!({"parts": []});
    assert!(serde_json::from_value::<AgentEvent>(obsolete).is_err());

    let mut counted = contract.json("fixtures/agent-event.json");
    counted["turn_index"] = 1_u32.into();
    assert!(
        serde_json::from_value::<AgentEvent>(counted).is_err(),
        "v2 has no collector-counted turn_index"
    );
    assert!(schema["properties"].get("turn_index").is_none());

    assert!(
        PublishedContract::load().json("agent-event.schema.json")["properties"]
            .get("conversation")
            .is_none()
    );
}

#[test]
fn v2_conversation_carries_only_role_aware_messages() {
    let contract = PublishedContract::load_version("v2");
    let schema = contract.json("agent-event.schema.json");
    let conversation = &schema["$defs"]["conversation"];
    let message = &schema["$defs"]["conversationMessage"];
    assert_eq!(
        conversation["required"],
        serde_json::json!([
            "messages",
            "previous_response_id",
            "thread_source",
            "instructions_present",
            "completeness",
            "policy_omitted"
        ]),
        "conversation fields should match the public Rust contract"
    );
    assert!(
        conversation["properties"].get("payloads").is_none()
            && message["properties"].get("blocks").is_none(),
        "v2 must not carry raw provider documents or original content blocks"
    );
    assert_eq!(
        message["required"],
        serde_json::json!(["id", "role", "text"])
    );
    assert_eq!(
        message["properties"]["role"]["enum"],
        serde_json::json!([
            "system",
            "developer",
            "user",
            "assistant",
            "reasoning",
            "tool",
            "unknown"
        ]),
        "message roles should be a closed published set"
    );

    let fixture = contract.json("fixtures/agent-event.json");
    let event: AgentEvent =
        serde_json::from_value(fixture.clone()).expect("the v2 fixture should decode");
    let roles = event
        .conversation
        .expect("the v2 fixture should carry a conversation")
        .messages
        .into_iter()
        .map(|message| message.role)
        .collect::<Vec<_>>();
    assert_eq!(
        roles,
        [
            MessageRole::Reasoning,
            MessageRole::Assistant,
            MessageRole::Tool
        ]
    );

    let mut payloads = fixture.clone();
    payloads["conversation"]["payloads"] = serde_json::json!([]);
    assert!(
        serde_json::from_value::<AgentEvent>(payloads).is_err(),
        "decoded provider documents are not part of the v2 contract"
    );
    let mut blocks = fixture.clone();
    blocks["conversation"]["messages"][0]["blocks"] = serde_json::json!([]);
    assert!(
        serde_json::from_value::<AgentEvent>(blocks).is_err(),
        "original content blocks are not part of the v2 contract"
    );
    let mut placeholder = fixture;
    placeholder["conversation"]["messages"][0]["role"] = "request".into();
    assert!(
        serde_json::from_value::<AgentEvent>(placeholder).is_err(),
        "an undeclared role should use `unknown`, not a placeholder"
    );
}

#[test]
fn packaged_v2_contract_matches_the_public_specification() {
    let specification =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../specs/broker-plugin-protocol/v2");
    if !specification.is_dir() {
        // A packaged crate carries only its copy of the contract.
        return;
    }
    let packaged = PublishedContract::load_version("v2").root;
    for relative in [
        "README.md",
        "agent-event.schema.json",
        "messages.schema.json",
        "fixtures/agent-event.json",
        "fixtures/broker-close.json",
        "fixtures/broker-error.json",
        "fixtures/broker-hello.json",
        "fixtures/plugin-hello.json",
    ] {
        assert_eq!(
            fs::read(packaged.join(relative)).expect("packaged contract file should exist"),
            fs::read(specification.join(relative)).expect("specification file should exist"),
            "SDK's packaged v2 {relative} must match the public specification"
        );
    }
}

impl PublishedContract {
    fn load() -> Self {
        Self::load_version("v1")
    }

    fn load_version(version: &str) -> Self {
        Self {
            root: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/broker-plugin-protocol")
                .join(version),
        }
    }

    fn json(&self, relative_path: &str) -> Value {
        let path = self.root.join(relative_path);
        let bytes = fs::read(&path).unwrap_or_else(|error| {
            panic!(
                "failed to read published contract {}: {error}",
                path.display()
            )
        });
        serde_json::from_slice(&bytes).unwrap_or_else(|error| {
            panic!(
                "published contract {} is not valid JSON: {error}",
                path.display()
            )
        })
    }

    fn assert_fixture_round_trip<T>(&self, fixture_name: &str)
    where
        T: DeserializeOwned + Serialize,
    {
        let relative_path = format!("fixtures/{fixture_name}");
        let fixture = self.json(&relative_path);
        let decoded: T = serde_json::from_value(fixture.clone()).unwrap_or_else(|error| {
            panic!("fixture {relative_path} does not match the public Rust contract: {error}")
        });
        let encoded = serde_json::to_value(decoded).unwrap_or_else(|error| {
            panic!("public Rust contract could not re-encode {relative_path}: {error}")
        });

        assert_eq!(
            encoded, fixture,
            "fixture {relative_path} must round-trip without changing its wire representation"
        );
    }
}

#[test]
fn published_agent_event_fixture_matches_the_public_sdk() {
    let contract = PublishedContract::load();
    let event = contract.json("fixtures/agent-event.json");

    assert!(
        event.get("schema_version").is_none(),
        "AgentEvent must not define a version separate from the plugin protocol"
    );
    assert!(
        event.get("type").is_none() && event.get("event").is_none(),
        "an Agent event frame should contain the event directly without a message wrapper"
    );
    assert!(
        event.get("event_type").is_none()
            && event.get("payload").is_none()
            && event.get("metadata").is_none(),
        "the only version 1 Agent event should be flat and contain no unstructured metadata"
    );
    assert_eq!(
        event["tool_calls"][0]["name"], "exec",
        "tool activity should use the public structured contract"
    );
    // The SDK speaks v2, which carries `turn_id` instead of the
    // collector-counted `turn_index` of the unchanged v1 contract.
    assert!(event["turn_index"].is_u64());
    assert!(serde_json::from_value::<AgentEvent>(event).is_err());
    PublishedContract::load_version("v2")
        .assert_fixture_round_trip::<AgentEvent>("agent-event.json");
}

#[test]
fn published_handshake_fixtures_match_the_public_sdk() {
    let contract = PublishedContract::load();

    contract.assert_fixture_round_trip::<PluginHello>("plugin-hello.json");
    contract.assert_fixture_round_trip::<BrokerHello>("broker-hello.json");
    contract.assert_fixture_round_trip::<BrokerError>("broker-error.json");
    contract.assert_fixture_round_trip::<BrokerClose>("broker-close.json");
}

#[test]
fn published_event_schema_defines_the_flat_typed_contract() {
    let contract = PublishedContract::load();
    let event_schema = contract.json("agent-event.schema.json");

    assert_eq!(
        event_schema["$schema"], "https://json-schema.org/draft/2020-12/schema",
        "Agent event schema should declare JSON Schema draft 2020-12"
    );
    assert_eq!(
        event_schema["$id"], EVENT_SCHEMA_ID,
        "Agent event schema id should remain scoped to plugin protocol v1"
    );
    let event_properties = event_schema["properties"]
        .as_object()
        .expect("Agent event schema should define root properties");
    assert!(
        event_properties.get("schema_version").is_none()
            && event_properties.get("event_type").is_none()
            && event_properties.get("payload").is_none(),
        "the event contract should use a flat shape versioned by the plugin handshake"
    );
    assert!(
        event_properties.get("metadata").is_none(),
        "the public event schema should not expose an arbitrary metadata object"
    );
    assert_eq!(
        event_properties["tool_calls"]["items"]["$ref"], "#/$defs/toolCall",
        "tool calls should reference their structured public schema"
    );
    assert_eq!(
        event_properties["tool_results"]["items"]["$ref"], "#/$defs/toolResult",
        "tool results should reference their structured public schema"
    );
    assert_eq!(
        event_schema["additionalProperties"], false,
        "the public event should reject undeclared fields"
    );
}

#[test]
fn published_message_schema_defines_handshake_and_control_contracts() {
    let contract = PublishedContract::load();
    let message_schema = contract.json("messages.schema.json");

    assert_eq!(
        message_schema["$schema"], "https://json-schema.org/draft/2020-12/schema",
        "message schema should declare JSON Schema draft 2020-12"
    );
    assert_eq!(
        message_schema["$id"],
        "https://schemas.lexmount.net/abyss/broker-plugin/v1/messages.schema.json",
        "message schema id should remain versioned"
    );
    assert_eq!(
        message_schema["oneOf"][3]["$ref"], "agent-event.schema.json",
        "the live frame should directly reference the version 1 Agent event schema"
    );
    assert_eq!(
        message_schema["oneOf"][2]["$ref"], "#/$defs/brokerError",
        "the first-response error should be a published frame payload"
    );
    assert_eq!(
        message_schema["oneOf"][4]["$ref"], "#/$defs/brokerClose",
        "the deliberate close should be a published final frame payload"
    );
    assert_eq!(
        message_schema["oneOf"].as_array().map(Vec::len),
        Some(5),
        "version 1 should publish handshakes, broker control, and direct Agent events"
    );
    assert!(
        message_schema["$defs"]
            .as_object()
            .map(serde_json::Map::len)
            == Some(4)
            && message_schema["$defs"].get("pluginHello").is_some()
            && message_schema["$defs"].get("brokerHello").is_some()
            && message_schema["$defs"].get("brokerError").is_some()
            && message_schema["$defs"].get("brokerClose").is_some()
            && message_schema["$defs"].get("pullEvents").is_none()
            && message_schema["$defs"].get("eventBatch").is_none()
            && message_schema["$defs"].get("ackEvents").is_none(),
        "version 1 should not publish event wrappers, pull, batch, or acknowledgement messages"
    );
    assert_eq!(
        message_schema["$defs"]["brokerError"]["properties"]["code"]["enum"],
        serde_json::json!([1_u32, 2_u32, 3_u32]),
        "handshake rejection codes should use the documented namespace"
    );
    assert_eq!(
        message_schema["$defs"]["brokerClose"]["properties"]["code"]["enum"],
        serde_json::json!([100_u32, 101_u32]),
        "deliberate close codes should not overlap handshake errors"
    );
    assert_eq!(
        message_schema["$defs"]["pluginHello"]["properties"]["plugin_id"]["minLength"], 1_u32,
        "plugin id should not be empty"
    );
    assert_eq!(
        message_schema["$defs"]["pluginHello"]["properties"]["plugin_id"]["maxLength"], 128_u32,
        "plugin id should have a stable upper bound"
    );
    assert_eq!(
        message_schema["$defs"]["pluginHello"]["properties"]["plugin_id"]["pattern"],
        "^[a-zA-Z0-9._-]+$",
        "plugin id should use the documented portable character set"
    );
    assert!(
        message_schema["$defs"]["pluginHello"]["properties"]
            .get("type")
            .is_none()
            && message_schema["$defs"]["brokerHello"]["properties"]
                .get("type")
                .is_none()
            && message_schema["$defs"]["brokerError"]["properties"]
                .get("type")
                .is_none()
            && message_schema["$defs"]["brokerClose"]["properties"]
                .get("type")
                .is_none(),
        "session phase should identify handshake and control payloads without a discriminator"
    );
    assert!(
        contract.root.join("agent-event.schema.json").is_file(),
        "the direct Agent event schema reference should resolve on disk"
    );
}
