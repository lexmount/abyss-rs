//! Client attribution exercised through the public MITM hook API.
//! Synthetic wire documents reproduce the installed clients' identity contracts.

use std::{convert::Infallible, future::Future, net::SocketAddr, sync::Arc};

use abyss_agent_hook::{
    AgentEventSink, DeviceIdentity, HarnessUsageHook, HarnessUsageHookConfig, HooksConfig,
    HooksRuntimeConfig,
};
use abyss_mitm::{
    CapturedBody, FlowContext, HttpExchange, MitmHook, OriginalDestination, SourceProcess,
    TransparentProtocol, WebSocketDirection, WebSocketMessage,
};
use abyss_plugin_protocol::event::AgentEvent;
use http::{Request, Response};
use parking_lot::Mutex;
use serde_json::{Value, json};

#[derive(Debug, Default)]
struct RecordingSink(Mutex<Vec<AgentEvent>>);

impl AgentEventSink for RecordingSink {
    type Error = Infallible;

    fn publish(&self, event: AgentEvent) -> impl Future<Output = Result<(), Self::Error>> + Send {
        self.0.lock().push(event);
        std::future::ready(Ok(()))
    }
}

struct Scenario {
    sink: Arc<RecordingSink>,
    hook: HarnessUsageHook<Arc<RecordingSink>>,
}

#[tokio::test]
async fn opencode_native_sessions_and_declared_turns_survive_protocol_changes() {
    let scenario = Scenario::new(json!({}));
    for path in ["/v1/responses", "/v1/chat/completions", "/v1/messages"] {
        for (session, turn, response) in [
            ("session-a", "message-1", "response-1"),
            ("session-a", "message-1", "tool-followup"),
            ("session-a", "message-2", "resumed-turn"),
            ("session-b", "message-3", "independent-session"),
        ] {
            scenario
                .http(
                    &[
                        ("user-agent", "opencode/latest/1.19.4/cli"),
                        ("x-opencode-session-id", session),
                        ("x-opencode-session", "gateway-alias"),
                        ("x-session-id", "generic-alias"),
                        ("x-opencode-parent-session-id", "parent-is-not-this-session"),
                        ("x-opencode-request", turn),
                    ],
                    path,
                    response,
                )
                .await;
        }
    }
    let events = scenario.sink.0.lock();
    assert_eq!(events.len(), 24);
    for (pair, (session, turn)) in events.as_chunks::<2>().0.iter().zip(
        [
            ("session-a", "message-1"),
            ("session-a", "message-1"),
            ("session-a", "message-2"),
            ("session-b", "message-3"),
        ]
        .into_iter()
        .cycle(),
    ) {
        for event in pair {
            assert_eq!(event.agent.name, "opencode");
            assert_eq!(event.agent.version.as_deref(), Some("1.19.4"));
            assert_eq!(event.session_id, session);
            assert_eq!(event.turn_id.as_deref(), Some(turn));
            assert_eq!(event.llm.provider.wire_name(), "openai");
        }
    }
}

#[tokio::test]
async fn opencode_session_aliases_do_not_invent_a_user_turn() {
    for path in ["/v1/responses", "/v1/chat/completions", "/v1/messages"] {
        for session_header in [
            "x-opencode-session-id",
            "x-opencode-session",
            "x-session-id",
        ] {
            let scenario = Scenario::new(json!({}));
            scenario
                .http(
                    &[
                        ("user-agent", "opencode/1.1.50"),
                        (session_header, " session-a "),
                        ("x-opencode-request", "  "),
                        ("x-request-id", "provider-request"),
                    ],
                    path,
                    "reply",
                )
                .await;
            let events = scenario.sink.0.lock();
            assert_eq!(events.len(), 2);
            for event in events.iter() {
                assert_eq!(event.session_id, "session-a");
                assert!(event.turn_id.is_none());
                assert_eq!(event.agent.version.as_deref(), Some("1.1.50"));
            }
        }
    }
}

#[tokio::test]
async fn opencode_headers_and_gateway_routes_alone_do_not_identify_the_client() {
    for user_agent in ["ai-sdk/5.0", "OpenAI/Python 2.0", "other-opencode/1.0"] {
        let scenario = Scenario::new(json!({}));
        scenario
            .http(
                &[
                    ("user-agent", user_agent),
                    ("x-opencode-session-id", "session-a"),
                    ("x-opencode-session", "session-a"),
                    ("x-opencode-request", "message-a"),
                    ("x-opencode-client", "cli"),
                ],
                "/zen/v1/chat/completions",
                "reply",
            )
            .await;
        assert!(scenario.sink.0.lock().is_empty());
    }
    let scenario = Scenario::new(json!({}));
    for path in ["/v1/responses", "/v1/messages"] {
        scenario
            .http(
                &[
                    ("user-agent", "deepseek-harness/0.2.0"),
                    ("x-session-id", "not-an-opencode-session"),
                    ("x-opencode-request", "not-a-deepseek-turn"),
                ],
                path,
                "reply",
            )
            .await;
    }
    let events = scenario.sink.0.lock();
    assert_eq!(events.len(), 4);
    for event in events.iter() {
        assert_ne!(event.session_id, "not-an-opencode-session");
        assert!(event.turn_id.is_none());
    }
}

#[tokio::test]
async fn opencode_obeys_harness_and_content_policy() {
    for enabled in [true, false] {
        let scenario = Scenario::new(json!({"harness_usage": {"config": {
            "harnesses": {"opencode": {"enabled": enabled,
                "content": {"conversation_text": false, "tool_calls": false, "images": false}}}
        }}}));
        scenario
            .http(
                &[
                    ("user-agent", "opencode/latest/1.19.4/cli"),
                    ("x-opencode-session-id", "session-a"),
                ],
                "/v1/chat/completions",
                "reply",
            )
            .await;
        let events = scenario.sink.0.lock();
        if !enabled {
            assert!(events.is_empty());
            continue;
        }
        assert_eq!(events.len(), 2);
        for event in events.iter() {
            assert!(event.text.is_none());
            let conversation = event.conversation.as_ref().unwrap();
            assert!(conversation.policy_omitted);
            assert!(conversation.messages.is_empty());
            assert_eq!(event.session_id, "session-a");
            assert!(event.token_usage.total_tokens > 0);
        }
    }
}

#[tokio::test]
async fn opencode_websocket_upgrade_does_not_pin_future_turns() {
    let scenario = Scenario::new(json!({}));
    scenario
        .websocket(
            &[
                ("user-agent", "opencode/latest/1.19.4/cli"),
                ("x-opencode-session-id", "session-a"),
                ("x-opencode-request", "upgrade-message"),
            ],
            &[
                json!({"type": "response.create", "model": "test-model", "input": [
                    {"role": "user", "content": "hello"}
                ]}),
            ],
        )
        .await;
    let events = scenario.sink.0.lock();
    assert_eq!(events.len(), 2);
    for event in events.iter() {
        assert_eq!(event.agent.name, "opencode");
        assert_eq!(event.session_id, "session-a");
        assert!(event.turn_id.is_none());
    }
}

impl Scenario {
    fn new(policy: Value) -> Self {
        let sink = Arc::new(RecordingSink::default());
        let hook = HarnessUsageHook::with_runtime_config_and_event_sink(
            HarnessUsageHookConfig::new(DeviceIdentity::new()),
            HooksRuntimeConfig::new(serde_json::from_value::<HooksConfig>(policy).unwrap()),
            Arc::clone(&sink),
        );
        Self { sink, hook }
    }

    fn flow() -> FlowContext {
        FlowContext::from_optional_addrs(
            None,
            None,
            OriginalDestination::from(SocketAddr::from(([127, 0, 0, 1], 443))),
            TransparentProtocol::PlainHttp,
            None,
        )
    }

    fn response(id: &str) -> Value {
        json!({"id": id, "model": "test-model",
            "output": [{"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "hi"}]}],
            "usage": {"input_tokens": 3_i32, "output_tokens": 2_i32, "total_tokens": 5_i32}})
    }

    async fn http(&self, headers: &[(&str, &str)], path: &str, id: &str) {
        self.http_from_source(headers, path, id, None).await;
    }

    async fn http_from_source(
        &self,
        headers: &[(&str, &str)],
        path: &str,
        id: &str,
        source: Option<SourceProcess>,
    ) {
        let mut flow = Self::flow();
        flow.source_process = source;
        let messages = json!([{"role": "user", "content": "hello"}]);
        let (request, response) = match path {
            "/v1/messages" => (
                json!({"model": "test-model", "messages": messages}),
                json!({"id": id, "model": "test-model", "content": [{"type": "text", "text": "hi"}],
                    "usage": {"input_tokens": 3_i32, "output_tokens": 2_i32}}),
            ),
            "/v1/chat/completions" => (
                json!({"model": "test-model", "messages": messages}),
                json!({"id": id, "model": "test-model", "choices": [{"message": {"role": "assistant", "content": "hi"}}],
                    "usage": {"prompt_tokens": 3_i32, "completion_tokens": 2_i32, "total_tokens": 5_i32}}),
            ),
            _ => (
                json!({"model": "test-model", "input": messages, "prompt_cache_key": "not-a-session"}),
                Self::response(id),
            ),
        };
        let mut builder = Request::builder()
            .method("POST")
            .uri(path)
            .header("host", "chatgpt.com");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        self.hook
            .on_http_exchange(&HttpExchange::new(
                flow,
                builder
                    .body(CapturedBody::from_bytes(request.to_string().into()))
                    .unwrap(),
                Response::builder()
                    .header("content-type", "application/json")
                    .body(CapturedBody::from_bytes(response.to_string().into()))
                    .unwrap(),
            ))
            .await
            .unwrap();
    }

    async fn websocket(&self, headers: &[(&str, &str)], requests: &[Value]) {
        let flow = Self::flow();
        let mut builder = Request::builder()
            .uri("/backend-api/codex/responses")
            .header("host", "chatgpt.com");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let upgrade = builder.body(()).unwrap();
        for (index, request) in requests.iter().enumerate() {
            let mut response = Self::response(&format!("resp-{index}"));
            // Server metadata must not be accepted as a client declaration.
            response["metadata"] = json!({"session_id": "server-spoof"});
            for (direction, body) in [
                (WebSocketDirection::ClientToServer, request.clone()),
                (
                    WebSocketDirection::ServerToClient,
                    json!({"type": "response.completed", "response": response}),
                ),
            ] {
                self.hook
                    .on_websocket_message(&WebSocketMessage::new(
                        flow.clone(),
                        upgrade.clone(),
                        direction,
                        u64::try_from(index).unwrap(),
                        Some(body.to_string()),
                        None,
                    ))
                    .await
                    .unwrap();
            }
        }
    }
}

#[tokio::test]
async fn client_sessions_and_optional_user_turns_reach_all_protocol_events() {
    for (harness, headers, turn) in [
        (
            "cursor",
            vec![
                ("user-agent", "Cursor-CLI/2026.10.19-6bbf2c4 (darwin arm64)"),
                ("x-agent-id", "client-session"),
                ("x-request-id", "user-turn"),
            ],
            Some("user-turn"),
        ),
        (
            "hermes",
            vec![
                ("x-hermes-session-id", "client-session"),
                ("x-hermes-turn-id", "user-turn"),
            ],
            Some("user-turn"),
        ),
        (
            "hermes",
            vec![
                ("user-agent", "HermesAgent/0.22.0"),
                ("session_id", "client-session"),
            ],
            None,
        ),
    ] {
        let scenario = Scenario::new(json!({}));
        for path in [
            "/backend-api/codex/responses",
            "/v1/chat/completions",
            "/v1/messages",
        ] {
            scenario.http(&headers, path, "resp-1").await;
            scenario.http(&headers, path, "resp-2").await;
        }
        let events = scenario.sink.0.lock();
        assert_eq!(events.len(), 12, "{harness} {headers:?}");
        for (event, response_id) in events
            .iter()
            .zip(["resp-1", "resp-1", "resp-2", "resp-2"].into_iter().cycle())
        {
            assert_eq!(event.agent.name, harness);
            assert_eq!(event.session_id, "client-session");
            assert_eq!(event.turn_id.as_deref(), turn);
            assert_eq!(event.response_id.as_deref(), Some(response_id));
        }
    }
}

#[tokio::test]
async fn cursor_local_correlates_tool_followups_user_turns_and_separate_sessions() {
    let scenario = Scenario::new(json!({}));
    let calls = [
        ("session-a", "turn-1", "response-1"),
        ("session-a", "turn-1", "response-2"),
        ("session-a", "turn-2", "response-3"),
        ("session-b", "turn-3", "response-4"),
    ];
    for (session, turn, response) in calls {
        scenario
            .http(
                &[
                    ("user-agent", "Cursor-CLI/2026.10.19-6bbf2c4 (darwin arm64)"),
                    ("x-agent-id", session),
                    ("x-request-id", turn),
                ],
                "/v1/chat/completions",
                response,
            )
            .await;
    }
    let events = scenario.sink.0.lock();
    assert_eq!(events.len(), 8);
    for (pair, (session, turn, response)) in events.as_chunks::<2>().0.iter().zip(calls) {
        for event in pair {
            assert_eq!(event.agent.name, "cursor");
            assert_eq!(event.session_id, session);
            assert_eq!(event.turn_id.as_deref(), Some(turn));
            assert_eq!(event.response_id.as_deref(), Some(response));
        }
    }
}

#[tokio::test]
async fn cursor_headers_are_scoped_to_local_identity_and_follow_existing_session_rules() {
    for path in ["/v1/chat/completions", "/v1/responses", "/v1/messages"] {
        let scenario = Scenario::new(json!({}));
        // These generic headers must not identify an arbitrary client as Cursor.
        scenario
            .http(
                &[("x-agent-id", "agent"), ("x-request-id", "request")],
                path,
                "ignored",
            )
            .await;
        assert!(scenario.sink.0.lock().is_empty());

        // X-Agent-Id has no session semantics for a different harness.
        scenario
            .http(
                &[
                    ("user-agent", "HermesAgent/0.22.0"),
                    ("x-agent-id", "agent"),
                    ("x-request-id", "request"),
                ],
                path,
                "hermes",
            )
            .await;
        {
            let events = scenario.sink.0.lock();
            assert_eq!(events.len(), 2);
            for event in events.iter() {
                assert_ne!(event.session_id, "agent");
                assert!(event.turn_id.is_none());
            }
        }

        // Existing canonical session headers retain precedence; turn is optional.
        scenario
            .http(
                &[
                    ("user-agent", "Cursor-CLI/2026.10.19-6bbf2c4"),
                    ("x-agent-id", "cursor-session"),
                    ("session-id", "canonical"),
                    ("x-request-id", " "),
                ],
                path,
                "cursor",
            )
            .await;
        let events = scenario.sink.0.lock();
        assert_eq!(events.len(), 4);
        for event in &events[2..] {
            assert_eq!(event.agent.name, "cursor");
            assert_eq!(event.session_id, "canonical");
            assert!(event.turn_id.is_none());
        }
    }
}

#[tokio::test]
async fn cursor_observation_can_be_disabled_and_cloud_headers_are_not_local_identity() {
    let scenario = Scenario::new(json!({"harness_usage": {"config": {"harnesses": {
        "cursor": {"enabled": false}
    }}}}));
    scenario
        .http(
            &[
                ("user-agent", "Cursor-CLI/2026.10.19-6bbf2c4"),
                ("x-agent-id", "session"),
            ],
            "/v1/chat/completions",
            "ignored",
        )
        .await;
    assert!(scenario.sink.0.lock().is_empty());

    let scenario = Scenario::new(json!({}));
    scenario
        .http(
            &[
                ("user-agent", "connect-es/1.6.1"),
                ("x-cursor-client-type", "cli"),
                ("x-cursor-client-version", "cli-2026.10.19-6bbf2c4"),
            ],
            "/v1/chat/completions",
            "ignored",
        )
        .await;
    assert!(scenario.sink.0.lock().is_empty());
}

#[tokio::test]
async fn header_detection_uses_protocol_fallback_and_respects_policy() {
    let harness = "hermes";
    let missing_session = Scenario::new(json!({}));
    let identity = [("user-agent", "HermesAgent/0.22.0")];
    missing_session
        .http(&identity, "/v1/responses", "resp-http")
        .await;
    missing_session.websocket(&identity, &[
        json!({"type": "response.create", "model": "test", "input": "hello", "prompt_cache_key": "not-session"}),
    ]).await;
    {
        let events = missing_session.sink.0.lock();
        assert_eq!(events.len(), 4);
        for event in events.iter() {
            assert_eq!(event.agent.name, harness);
            assert!(event.session_id.starts_with("flow-"));
        }
    }

    for enabled in [true, false] {
        let scenario = Scenario::new(json!({"harness_usage": {"config": {"harnesses": {
            harness: {"enabled": enabled, "content": {"conversation_text": false}}
        }}}}));
        // Hermes request markers win over transport compatibility headers.
        let headers = [
            ("user-agent", "codex_cli_rs/1.0"),
            ("originator", "hermes-agent"),
            ("session_id", "session"),
        ];
        scenario
            .http(&headers, "/backend-api/codex/responses", "resp-http")
            .await;
        scenario
            .websocket(
                &headers,
                &[json!({"type": "response.create", "model": "test", "input": "hello"})],
            )
            .await;
        let events = scenario.sink.0.lock();
        assert_eq!(events.len(), if enabled { 4 } else { 0 });
        for event in events.iter() {
            assert_eq!(event.agent.name, harness);
            assert!(event.text.is_none());
        }
    }
}

#[tokio::test]
async fn missing_or_blank_session_uses_each_protocols_existing_fallback() {
    let scenario = Scenario::new(json!({}));
    for headers in [
        vec![("user-agent", "HermesAgent/0.22.0")],
        vec![
            ("user-agent", "HermesAgent/0.22.0"),
            ("x-hermes-session-id", " "),
        ],
    ] {
        for path in ["/v1/responses", "/v1/chat/completions", "/v1/messages"] {
            scenario.http(&headers, path, "resp-1").await;
        }
    }
    let events = scenario.sink.0.lock();
    assert_eq!(events.len(), 12);
    for (pair, messages) in events
        .as_chunks::<2>()
        .0
        .iter()
        .zip([false, false, true].into_iter().cycle())
    {
        assert_eq!(pair[0].session_id, pair[1].session_id);
        for event in pair {
            assert_eq!(event.agent.name, "hermes");
            if messages {
                assert_eq!(event.session_id, "anthropic-unattributed-chatgpt-com");
            } else {
                assert!(event.session_id.starts_with("flow-"));
            }
        }
    }
}

#[tokio::test]
async fn compatibility_identity_and_policy_cannot_relabel_a_client() {
    for (harness, headers) in [
        (
            "hermes",
            vec![
                ("user-agent", "codex_cli_rs/0.0.0 (Hermes Agent)"),
                ("originator", "codex_cli_rs"),
                ("session_id", "session-1"),
            ],
        ),
        (
            "hermes",
            vec![
                ("user-agent", "claude-code/1.0 (external, cli)"),
                ("x-hermes-session-id", "session-1"),
            ],
        ),
    ] {
        for enabled in [true, false] {
            let scenario = Scenario::new(json!({"harness_usage": {"config": {"harnesses": {
                harness: {"enabled": enabled, "content": {"conversation_text": false}}
            }}}}));
            scenario
                .http(&headers, "/backend-api/codex/responses", "resp-1")
                .await;
            let events = scenario.sink.0.lock();
            assert_eq!(events.len(), if enabled { 2 } else { 0 });
            for event in events.iter() {
                assert_eq!(event.agent.name, harness);
                assert!(event.text.is_none());
            }
        }
    }
    let ambiguous = Scenario::new(json!({}));
    ambiguous
        .http(
            &[
                ("x-hermes-session-id", "h"),
                ("user-agent", "deepseek-harness/0.2.0"),
            ],
            "/v1/responses",
            "resp-1",
        )
        .await;
    assert!(ambiguous.sink.0.lock().is_empty());
}

#[tokio::test]
async fn websocket_retains_session_and_never_reuses_upgrade_turns() {
    let scenario = Scenario::new(json!({}));
    scenario.websocket(&[
        ("x-hermes-session-id", "hermes-session"),
        ("x-hermes-turn-id", "stale"),
    ], &[
        json!({"type": "response.create", "model": "test", "input": "hello"}),
        json!({"type": "response.create", "response": {"model": "test", "input": "again", "previous_response_id": "resp-0"}}),
    ]).await;
    scenario
        .websocket(
            &[("user-agent", "HermesAgent/0.22.0")],
            &[json!({"type": "response.create", "model": "test", "input": "no session"})],
        )
        .await;
    let events = scenario.sink.0.lock();
    assert_eq!(events.len(), 6);
    for event in &events[..4] {
        assert_eq!(event.session_id, "hermes-session");
        assert!(event.turn_id.is_none());
        assert!(event.response_id.is_some());
    }
    assert_eq!(events[2].previous_response_id.as_deref(), Some("resp-0"));
    for event in &events[4..] {
        assert!(event.session_id.starts_with("flow-"));
        assert!(event.turn_id.is_none());
    }
}

#[tokio::test]
async fn successive_user_turns_preserve_native_session_and_turn_ids() {
    let scenario = Scenario::new(json!({}));
    for path in ["/v1/responses", "/v1/chat/completions", "/v1/messages"] {
        for (session, turn) in [
            ("a", "turn-1"),
            ("b", "turn-1"),
            ("a", "turn-2"),
            ("a", "turn-3"),
        ] {
            scenario
                .http(
                    &[("x-hermes-session-id", session), ("x-hermes-turn-id", turn)],
                    path,
                    turn,
                )
                .await;
        }
    }
    let events = scenario.sink.0.lock();
    assert_eq!(events.len(), 24);
    for (pair, (session, turn)) in events.as_chunks::<2>().0.iter().zip(
        [
            ("a", "turn-1"),
            ("b", "turn-1"),
            ("a", "turn-2"),
            ("a", "turn-3"),
        ]
        .into_iter()
        .cycle(),
    ) {
        for event in pair {
            assert_eq!(event.session_id, session);
            assert_eq!(event.turn_id.as_deref(), Some(turn));
        }
    }
}

#[tokio::test]
async fn hermes_managed_python_is_identified_without_product_headers() {
    let source = SourceProcess::new(
        Some(42),
        Some("python3.14".to_owned()),
        Some("/Users/test/.hermes/tools/python/bin/python3.14".to_owned()),
    )
    .with_application_id(Some("com.nousresearch.hermes.managed-python".to_owned()));
    let scenario = Scenario::new(json!({}));
    for path in ["/v1/responses", "/v1/chat/completions", "/v1/messages"] {
        scenario
            .http_from_source(
                &[("user-agent", "OpenAI/Python 2.24.0")],
                path,
                "response-1",
                Some(source.clone()),
            )
            .await;
    }
    let events = scenario.sink.0.lock();
    assert_eq!(events.len(), 6);
    assert!(events.iter().all(|event| event.agent.name == "hermes"));
    drop(events);
}

#[tokio::test]
async fn hermes_source_matching_remains_exact_and_respects_policy() {
    for identity in [
        None,
        Some("com.nousresearch.hermes.managed-python.other"),
        Some("other.com.nousresearch.hermes.managed-python"),
    ] {
        let source = SourceProcess::new(
            None,
            Some("python3.14".to_owned()),
            Some("/Users/test/.hermes/tools/python/bin/python3.14".to_owned()),
        )
        .with_application_id(identity.map(str::to_owned));
        let scenario = Scenario::new(json!({}));
        scenario
            .http_from_source(
                &[("user-agent", "OpenAI/Python 2.24.0")],
                "/v1/responses",
                "response-1",
                Some(source),
            )
            .await;
        assert!(scenario.sink.0.lock().is_empty());
    }
    let source = SourceProcess::new(None, Some("python3.14".to_owned()), None)
        .with_application_id(Some("com.nousresearch.hermes.managed-python".to_owned()));
    for policy in [
        json!({"harnesses": {"hermes": {"enabled": false}}}),
        json!({"harnesses": {"another-agent": {"matchers": [{"application_ids": ["com.nousresearch.hermes.managed-python"]}]}}}),
    ] {
        let scenario = Scenario::new(json!({"harness_usage": {"config": policy}}));
        scenario
            .http_from_source(
                &[("user-agent", "codex_cli_rs/1.0")],
                "/v1/responses",
                "response-1",
                Some(source.clone()),
            )
            .await;
        assert!(scenario.sink.0.lock().is_empty());
    }
}
