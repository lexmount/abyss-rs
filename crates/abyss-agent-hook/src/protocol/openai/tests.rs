//! Cross-dialect exchange regression cases.

use std::net::SocketAddr;

use abyss_mitm::{
    CapturedBody, FlowContext, HttpExchange, OriginalDestination, TransparentProtocol,
    WebSocketDirection, WebSocketMessage,
};
use http::{Request, Response};
use serde_json::{Value, json};

use crate::protocol::model::tool::ParsedToolEvent;
use crate::protocol::openai::{
    parse_openai_websocket_message, responses::websocket::OpenAiWebSocketFrame,
};

#[test]
fn parses_responses_json_without_harness_assumptions() {
    let exchange = json_exchange(
        "/v1/responses",
        &json!({
            "model": "gpt-5",
            "input": [{"role": "user", "content": "hello"}]
        }),
        &json!({
            "id": "resp-1",
            "model": "gpt-5",
            "output": [{"content": [{"type": "output_text", "text": "hi"}]}],
            "usage": {
                "input_tokens": 3_i32,
                "output_tokens": 4_i32,
                "total_tokens": 7_i32
            }
        }),
    );

    let parsed = parse_openai_exchange(&exchange).expect("OpenAI exchange");

    assert_eq!(parsed.host, "gateway.example");
    assert_eq!(parsed.session_id, "session-1");
    assert_eq!(parsed.request_texts, vec!["hello"]);
    assert_eq!(parsed.response_texts, vec!["hi"]);
    assert_eq!(parsed.response_id.as_deref(), Some("resp-1"));
    assert_eq!(parsed.model.as_deref(), Some("gpt-5"));
    assert_eq!(parsed.usage.total_tokens, 7);
}

#[test]
fn parses_chat_completions_shape() {
    let exchange = json_exchange(
        "/v1/chat/completions",
        &json!({
            "model": "compatible-model",
            "messages": [{"role": "user", "content": "hello gateway"}]
        }),
        &json!({
            "id": "chatcmpl-1",
            "model": "compatible-model",
            "choices": [{"message": {"role": "assistant", "content": "hello user"}}],
            "usage": {
                "prompt_tokens": 2_i32,
                "completion_tokens": 3_i32,
                "total_tokens": 5_i32
            }
        }),
    );

    let parsed = parse_openai_exchange(&exchange).expect("chat completions exchange");

    assert_eq!(parsed.request_texts, vec!["hello gateway"]);
    assert_eq!(parsed.response_texts, vec!["hello user"]);
    assert_eq!(parsed.usage.input_tokens, 2);
    assert_eq!(parsed.usage.output_tokens, 3);
}

#[test]
fn correlates_http_requests_with_underscore_session_header() {
    for (path, messages_field) in [
        ("/v1/responses", "input"),
        ("/v1/chat/completions", "messages"),
    ] {
        let mut hashes = Vec::new();
        for text in ["first request", "second request"] {
            let mut request = json!({"model": "compatible-model"});
            request[messages_field] = json!([{"role": "user", "content": text}]);
            let mut exchange = json_exchange(path, &request, &json!({}));
            let headers = exchange.request.headers_mut();
            headers.remove("session-id");
            headers.insert("session_id", " shared-session ".parse().unwrap());

            let parsed = parse_openai_exchange(&exchange).expect("OpenAI exchange");

            assert_eq!(parsed.session_id, "shared-session");
            hashes.push(parsed.request_hash);
        }
        assert_ne!(hashes[0], hashes[1]);
    }
}

#[test]
fn session_header_alias_preserves_precedence_and_ignores_blank_values() {
    for (session, alias, thread, expected) in [
        ("canonical", "alias", "thread", "canonical"),
        (" ", "alias", "thread", "alias"),
        (" ", " ", "thread", "thread"),
    ] {
        let mut exchange = json_exchange("/v1/responses", &json!({"input": "hi"}), &json!({}));
        let headers = exchange.request.headers_mut();
        headers.insert("session-id", session.parse().unwrap());
        headers.insert("session_id", alias.parse().unwrap());
        headers.insert("thread-id", thread.parse().unwrap());

        let parsed = parse_openai_exchange(&exchange).expect("OpenAI exchange");

        assert_eq!(parsed.session_id, expected);
    }
}

#[test]
fn dsh_session_header_correlates_compatible_protocols_without_overriding_existing_ids() {
    for path in [
        "/api/paas/v4/chat/completions",
        "/api/coding/paas/v4/chat/completions",
        "/v1/responses",
    ] {
        let mut exchange = json_exchange(
            path,
            &json!({"input": "hi", "messages": [{"role": "user", "content": "hi"}]}),
            &json!({}),
        );
        exchange.request.headers_mut().insert(
            "x-deepseek-harness-session-id",
            " dsh-session ".parse().unwrap(),
        );
        assert_eq!(
            parse_openai_exchange(&exchange).unwrap().session_id,
            "session-1"
        );
        exchange.request.headers_mut().remove("session-id");
        assert_eq!(
            parse_openai_exchange(&exchange).unwrap().session_id,
            "dsh-session"
        );
        exchange
            .request
            .headers_mut()
            .insert("x-deepseek-harness-session-id", " ".parse().unwrap());
        assert!(
            parse_openai_exchange(&exchange)
                .unwrap()
                .session_id
                .starts_with("flow-")
        );
    }
}

#[test]
fn hermes_session_header_uses_existing_http_precedence_and_fallbacks() {
    for path in ["/v1/responses", "/v1/chat/completions"] {
        for (canonical, hermes, expected) in [
            ("canonical", "hermes-session", Some("canonical")),
            (" ", " hermes-session ", Some("hermes-session")),
            (" ", " ", None),
        ] {
            let mut exchange = json_exchange(
                path,
                &json!({"input": "hi", "messages": [{"role": "user", "content": "hi"}]}),
                &json!({}),
            );
            let headers = exchange.request.headers_mut();
            headers.insert("session-id", canonical.parse().unwrap());
            headers.insert("x-hermes-session-id", hermes.parse().unwrap());
            let parsed = parse_openai_exchange(&exchange).unwrap();
            match expected {
                Some(session) => assert_eq!(parsed.session_id, session),
                None => assert!(parsed.session_id.starts_with("flow-")),
            }
        }
    }
}

#[test]
fn removes_cached_tokens_from_input() {
    let exchange = json_exchange(
        "/v1/responses",
        &json!({
            "model": "gpt-5",
            "input": [{"role": "user", "content": "hello"}]
        }),
        &json!({
            "id": "resp-2",
            "model": "gpt-5",
            "output": [{"content": [{"type": "output_text", "text": "hi"}]}],
            "usage": {
                "input_tokens": 1000_i32,
                "input_tokens_details": {"cached_tokens": 900_i32},
                "output_tokens": 50_i32,
                "output_tokens_details": {"reasoning_tokens": 20_i32},
                "total_tokens": 1050_i32
            }
        }),
    );

    let parsed = parse_openai_exchange(&exchange).expect("OpenAI exchange");

    assert_eq!(parsed.usage.input_tokens, 100);
    assert_eq!(parsed.usage.cache_read_tokens, 900);
    assert_eq!(parsed.usage.output_tokens, 50);
    assert_eq!(parsed.usage.reasoning_tokens, 20);
    assert_eq!(parsed.usage.total_tokens, 1050);
}

#[test]
fn chat_stream_assembles_parallel_tools_by_choice_and_tool_index() {
    let documents = [
        json!({"id":"chat-1","choices":[
            {"index":1_i32,"delta":{"tool_calls":[{"index":0_i32,"id":"c3","type":"function","function":{"name":"clock","arguments":"{}"}}]}},
            {"index":0_i32,"delta":{"content":"Reading files.","tool_calls":[
                {"index":1_i32,"id":"c2","type":"function","function":{"name":"read","arguments":""}},
                {"index":0_i32,"id":"c1","type":"function","function":{"name":"read","arguments":"{\"path\":"}}
            ]}}
        ]}),
        json!({"id":"chat-1","choices":[{"index":0_i32,"delta":{"tool_calls":[
            {"index":1_i32,"function":{"arguments":"{\"path\":\"b\"}"}},
            {"index":0_i32,"function":{"arguments":"\"a\"}"}}
        ]}}]}),
        json!({"id":"chat-1","choices":[{"index":0_i32,"delta":{},"finish_reason":"tool_calls"}]}),
        json!({"id":"chat-1","choices":[],"usage":{"prompt_tokens":5_i32,"completion_tokens":7_i32,"total_tokens":12_i32}}),
    ];
    let mut body = String::new();
    for document in documents {
        body.push_str("data: ");
        body.push_str(&document.to_string());
        body.push_str("\n\n");
    }
    body.push_str("data: [DONE]\n\n");
    let mut exchange = exchange(
        "/v1/chat/completions",
        &json!({"messages":[{"role":"user","content":"Read both files"}],"stream":true}),
        "text/event-stream",
        body.into_bytes(),
    );
    exchange.request.headers_mut().remove("session-id");
    let parsed = parse_openai_exchange(&exchange).unwrap();

    assert_eq!(parsed.response_id.as_deref(), Some("chat-1"));
    assert_eq!(parsed.response_texts, ["Reading files."]);
    assert_eq!(parsed.usage.total_tokens, 12);
    assert_eq!(
        parsed.response_tool_events,
        vec![
            ParsedToolEvent::ToolCall {
                item_id: None,
                call_id: Some("c1".into()),
                name: Some("read".into()),
                input: r#"{"path":"a"}"#.into()
            },
            ParsedToolEvent::ToolCall {
                item_id: None,
                call_id: Some("c2".into()),
                name: Some("read".into()),
                input: r#"{"path":"b"}"#.into()
            },
            ParsedToolEvent::ToolCall {
                item_id: None,
                call_id: Some("c3".into()),
                name: Some("clock".into()),
                input: "{}".into()
            },
        ]
    );
}

#[test]
fn chat_nonstream_tool_only_exchange_retains_calls_without_text_or_usage() {
    let parsed = parse_openai_exchange(&json_exchange(
            "/v1/chat/completions",
            &json!({"messages":[]}),
            &json!({"id":"chat-2","choices":[{"index":0_i32,"message":{"role":"assistant","content":null,"tool_calls":[
                {"id":"c1","type":"function","function":{"name":"clock","arguments":"{}"}},
                {"id":"c2","type":"custom","custom":{"name":"patch","input":"  keep whitespace\n"}},
                {"id":"c3","type":"custom","custom":{"name":"empty","input":""}}
            ]}}]}),
        )).expect("tool-only Chat response");

    assert_eq!(parsed.response_texts, Vec::<String>::new());
    assert_eq!(
        parsed.response_tool_events,
        vec![
            ParsedToolEvent::ToolCall {
                item_id: None,
                call_id: Some("c1".into()),
                name: Some("clock".into()),
                input: "{}".into()
            },
            ParsedToolEvent::ToolCall {
                item_id: None,
                call_id: Some("c2".into()),
                name: Some("patch".into()),
                input: "  keep whitespace\n".into()
            },
            ParsedToolEvent::ToolCall {
                item_id: None,
                call_id: Some("c3".into()),
                name: Some("empty".into()),
                input: String::new()
            },
        ]
    );
}

#[test]
fn chat_request_results_preserve_history_in_every_observed_request() {
    let mut request = json!({"messages":[
        {"role":"assistant","tool_calls":[{"id":"old","type":"function","function":{"name":"read","arguments":"{}"}}]},
        {"role":"tool","tool_call_id":"old","content":"old output"},
        {"role":"assistant","content":"Previous answer"},
        {"role":"user","content":"Read again"},
        {"role":"assistant","tool_calls":[{"id":"new","type":"function","function":{"name":"read","arguments":"{}"}}]},
        {"role":"tool","tool_call_id":"new","content":[{"type":"text","text":"line 1"},{"type":"text","text":"line 2"}]},
        {"role":"tool","tool_call_id":"empty","content":""}
    ]});
    let response = json!({"choices":[{"message":{"role":"assistant","content":"Done"}}]});
    let parsed =
        parse_openai_exchange(&json_exchange("/chat/completions", &request, &response)).unwrap();
    assert_eq!(
        parsed.request_tool_events,
        vec![
            ParsedToolEvent::ToolResult {
                call_id: Some("old".into()),
                output: "old output".into()
            },
            ParsedToolEvent::ToolResult {
                call_id: Some("new".into()),
                output: "line 1\nline 2".into()
            },
            ParsedToolEvent::ToolResult {
                call_id: Some("empty".into()),
                output: String::new()
            },
        ]
    );
    assert_eq!(parsed.request_texts, ["Read again"]);
    assert_eq!(parsed.response_tool_events, Vec::<ParsedToolEvent>::new());

    request["messages"]
        .as_array_mut()
        .unwrap()
        .push(json!({"role":"user","content":"Next turn"}));
    let replay =
        parse_openai_exchange(&json_exchange("/chat/completions", &request, &response)).unwrap();
    assert_eq!(replay.request_tool_events, parsed.request_tool_events);
}

#[test]
fn chat_request_results_survive_a_following_image_message() {
    let output =
        "<type>image</type>\n<content>image/jpeg image, 1086x724 px, 94815 bytes</content>";
    let parsed = parse_openai_exchange(&json_exchange(
            "/chat/completions",
            &json!({"messages":[
                {"role":"assistant","tool_calls":[{"id":"image-call","type":"function","function":{"name":"read_image","arguments":"{}"}}]},
                {"role":"tool","tool_call_id":"image-call","content":output},
                {"role":"user","content":[
                    {"type":"text","text":"Attached image(s) from tool result:"},
                    {"type":"image_url","image_url":{"url":"data:image/jpeg;base64,/9j/dGVzdA=="}}
                ]}
            ]}),
            &json!({"choices":[{"message":{"role":"assistant","content":"Image description"}}]}),
        )).unwrap();

    assert_eq!(
        parsed.request_tool_events,
        vec![ParsedToolEvent::ToolResult {
            call_id: Some("image-call".into()),
            output: output.into(),
        }]
    );
    assert_eq!(parsed.request_images.len(), 1);
}

#[test]
fn chat_request_results_keep_repeated_occurrences_and_only_tool_roles() {
    let parsed = parse_openai_exchange(&json_exchange(
        "/chat/completions",
        &json!({"messages":[
            {"role":"tool","tool_call_id":"same-call","content":"  original output\n"},
            {"role":"user","tool_call_id":"not-a-tool","content":"user text"},
            {"role":"tool","tool_call_id":"same-call","content":"  original output\n"},
            {"role":"assistant","content":"Answer"}
        ]}),
        &json!({"choices":[{"message":{"role":"assistant","content":"Next answer"}}]}),
    ))
    .unwrap();

    let result = ParsedToolEvent::ToolResult {
        call_id: Some("same-call".into()),
        output: "  original output\n".into(),
    };
    assert_eq!(parsed.request_tool_events, vec![result.clone(), result]);
}

#[test]
fn chat_tool_declarations_and_nested_user_content_do_not_create_tool_events() {
    let parsed = parse_openai_exchange(&json_exchange(
            "/chat/completions",
            &json!({
                "tools":[{"type":"function","function":{"name":"read","parameters":{"type":"object"}}}],
                "messages":[{"role":"user","content":[{"type":"text","text":"Hello","extra":{"type":"function_call_output","call_id":"fake","output":"not a tool result"}}]}]
            }),
            &json!({"choices":[{"message":{"role":"assistant","content":"Hello"}}]}),
        )).unwrap();
    assert_eq!(parsed.request_tool_events, Vec::<ParsedToolEvent>::new());
    assert_eq!(parsed.response_tool_events, Vec::<ParsedToolEvent>::new());
}

#[test]
fn parses_responses_sse_and_tool_call() {
    let request = json!({
        "model": "gpt-test",
        "input": [{"role": "user", "content": "run pwd"}]
    });
    let response = concat!(
        "data: {\"type\":\"response.output_item.done\",\"item\":",
        "{\"type\":\"function_call\",\"id\":\"item-1\",\"call_id\":\"call-1\",",
        "\"name\":\"shell\",\"arguments\":\"{\\\"command\\\":\\\"pwd\\\"}\"}}\n\n",
        "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp-2\",",
        "\"usage\":{\"input_tokens\":4,\"output_tokens\":2,\"total_tokens\":6}}}\n\n"
    );
    let exchange = exchange(
        "/v1/responses",
        &request,
        "text/event-stream",
        response.as_bytes().to_vec(),
    );

    let parsed = parse_openai_exchange(&exchange).expect("SSE exchange");

    assert_eq!(parsed.response_id.as_deref(), Some("resp-2"));
    assert_eq!(parsed.response_tool_events.len(), 1);
    assert_eq!(parsed.usage.total_tokens, 6);
    assert!(
        parsed
            .event_types
            .iter()
            .any(|event_type| event_type == "response.completed")
    );
}

#[test]
fn truncated_exchange_is_retained_without_parseable_content() {
    let request = Request::builder()
        .method("POST")
        .uri("/v1/responses")
        .header("host", "gateway.example")
        .body(CapturedBody::from_truncated_bytes(
            b"{\"input\":".to_vec().into(),
        ))
        .unwrap();
    let response = Response::new(CapturedBody::from_bytes(Vec::new().into()));
    let exchange = HttpExchange::new(flow(), request, response);

    let parsed = parse_openai_exchange(&exchange).expect("truncated exchange");

    assert_eq!(parsed.request_texts, Vec::<String>::new());
    assert_eq!(parsed.response_texts, Vec::<String>::new());
}

#[test]
fn parses_responses_websocket_message() {
    let message = WebSocketMessage::new(
        flow(),
        Request::builder()
            .method("GET")
            .uri("/v1/responses")
            .header("host", "gateway.example")
            .header("session-id", "session-1")
            .body(())
            .unwrap(),
        WebSocketDirection::ClientToServer,
        1,
        Some(
            json!({
                "type": "response.create",
                "response": {
                    "model": "gpt-test",
                    "input": [{"role": "user", "content": "hello websocket"}]
                }
            })
            .to_string(),
        ),
        None,
    );

    let OpenAiWebSocketFrame::Request(parsed) = parse_openai_websocket_message(&message) else {
        panic!("WebSocket request message");
    };

    assert_eq!(parsed.session_id, "session-1");
    assert_eq!(parsed.request_texts, vec!["hello websocket"]);
}

#[test]
fn correlates_websocket_frames_with_underscore_session_header() {
    for (sequence, text) in [(1, "first request"), (2, "second request")] {
        let message = WebSocketMessage::new(
            flow(),
            Request::builder()
                .method("GET")
                .uri("/v1/responses")
                .header("host", "gateway.example")
                .header("session_id", "shared-session")
                .body(())
                .unwrap(),
            WebSocketDirection::ClientToServer,
            sequence,
            Some(json!({"type": "response.create", "input": text}).to_string()),
            None,
        );

        let OpenAiWebSocketFrame::Request(parsed) = parse_openai_websocket_message(&message) else {
            panic!("WebSocket request message");
        };

        assert_eq!(parsed.session_id, "shared-session");
        assert_eq!(parsed.request_texts, vec![text]);
    }
}

#[test]
fn hermes_websocket_session_header_preserves_existing_header_precedence() {
    for (canonical, hermes, expected) in [
        ("canonical", "hermes-session", "canonical"),
        (" ", " hermes-session ", "hermes-session"),
        ("canonical", " ", "canonical"),
    ] {
        let message = WebSocketMessage::new(
            flow(),
            Request::builder()
                .uri("/v1/responses")
                .header("host", "gateway.example")
                .header("session-id", canonical)
                .header("x-hermes-session-id", hermes)
                .body(())
                .unwrap(),
            WebSocketDirection::ClientToServer,
            1,
            Some(json!({"type": "response.create", "input": "hello"}).to_string()),
            None,
        );
        let OpenAiWebSocketFrame::Request(parsed) = parse_openai_websocket_message(&message) else {
            panic!("WebSocket request message");
        };
        assert_eq!(parsed.session_id, expected);
    }
}

#[test]
fn request_carries_its_client_metadata_and_continuation() {
    let client_metadata = json!({"x-codex-turn-metadata": "{\"thread_id\":\"session-1\"}"});
    let exchange = json_exchange(
        "/v1/responses",
        &json!({"input": "hello", "previous_response_id": "resp-0",
                "client_metadata": client_metadata}),
        &json!({"id": "resp-1", "output": [{"content": [{"type": "output_text", "text": "hi"}]}]}),
    );

    let parsed = parse_openai_exchange(&exchange).expect("OpenAI exchange");

    assert_eq!(parsed.client_metadata.as_ref(), Some(&client_metadata));
    assert_eq!(parsed.previous_response_id.as_deref(), Some("resp-0"));
    assert_eq!(parsed.response_id.as_deref(), Some("resp-1"));
}

#[test]
fn websocket_request_carries_the_frame_client_metadata() {
    let client_metadata = json!({"x-codex-turn-metadata": "{\"thread_id\":\"thread-g\"}"});
    let message = WebSocketMessage::new(
        flow(),
        Request::builder()
            .method("GET")
            .uri("/v1/responses")
            .header("host", "gateway.example")
            .header("session-id", "session-1")
            .body(())
            .unwrap(),
        WebSocketDirection::ClientToServer,
        1,
        Some(
            json!({"type": "response.create", "response": {
                "previous_response_id": "resp-0",
                "input": "hello",
                "client_metadata": client_metadata
            }})
            .to_string(),
        ),
        None,
    );

    let OpenAiWebSocketFrame::Request(parsed) = parse_openai_websocket_message(&message) else {
        panic!("WebSocket request message");
    };

    assert_eq!(parsed.client_metadata.as_ref(), Some(&client_metadata));
    assert_eq!(parsed.previous_response_id.as_deref(), Some("resp-0"));
}

#[test]
fn websocket_frames_distinguish_undecodable_from_irrelevant() {
    let frame = |direction, body: &str| {
        parse_openai_websocket_message(&WebSocketMessage::new(
            flow(),
            Request::builder()
                .method("GET")
                .uri("/v1/responses")
                .header("host", "gateway.example")
                .body(())
                .unwrap(),
            direction,
            1,
            Some(body.to_owned()),
            None,
        ))
    };

    assert!(matches!(
        frame(WebSocketDirection::ServerToClient, "{broken"),
        OpenAiWebSocketFrame::Undecodable(WebSocketDirection::ServerToClient)
    ));
    assert!(matches!(
        frame(
            WebSocketDirection::ServerToClient,
            r#"{"type":"response.created","response":{"id":"resp_1"}}"#
        ),
        OpenAiWebSocketFrame::Irrelevant
    ));
    assert!(matches!(
        frame(
            WebSocketDirection::ServerToClient,
            r#"{"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":"hi"}"#
        ),
        OpenAiWebSocketFrame::Response(_)
    ));
    assert!(matches!(
        frame(
            WebSocketDirection::ClientToServer,
            r#"{"type":"response.cancel"}"#
        ),
        OpenAiWebSocketFrame::Irrelevant
    ));
}

#[test]
fn streaming_response_text_is_not_repeated_by_terminal_events() {
    // The Responses stream republishes one completed answer through several
    // terminal events. The parser must report the answer once.
    let exchange = sse_exchange(&[
        r#"{"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":"Hello "}"#,
        r#"{"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":"world"}"#,
        r#"{"type":"response.output_text.done","output_index":0,"content_index":0,"text":"Hello world"}"#,
        r#"{"type":"response.content_part.done","output_index":0,"content_index":0,"part":{"type":"output_text","text":"Hello world"}}"#,
        r#"{"type":"response.output_item.done","output_index":0,"item":{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"output_text","text":"Hello world"}]}}"#,
        r#"{"type":"response.completed","response":{"id":"resp_1","model":"gpt-5","output":[{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"output_text","text":"Hello world"}]}],"usage":{"input_tokens":1,"output_tokens":2,"total_tokens":3}}}"#,
    ]);

    let parsed = parse_openai_exchange(&exchange).expect("streaming exchange");

    assert_eq!(parsed.response_texts, vec!["Hello world"]);
    assert_eq!(parsed.usage.total_tokens, 3);
}

#[test]
fn streaming_response_keeps_accumulated_text_without_terminal_events() {
    // A response body truncated by the capture budget keeps its deltas but
    // loses every terminal event.
    let exchange = sse_exchange(&[
        r#"{"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":"partial "}"#,
        r#"{"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":"answer"}"#,
    ]);

    let parsed = parse_openai_exchange(&exchange).expect("truncated streaming exchange");

    assert_eq!(parsed.response_texts, vec!["partial answer"]);
}

#[test]
fn streaming_response_recovers_text_lost_from_deltas() {
    // A terminal snapshot extends an incomplete accumulation instead of
    // replacing or duplicating it.
    let exchange = sse_exchange(&[
        r#"{"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":"Hello "}"#,
        r#"{"type":"response.output_text.done","output_index":0,"content_index":0,"text":"Hello world"}"#,
    ]);

    let parsed = parse_openai_exchange(&exchange).expect("streaming exchange");

    assert_eq!(parsed.response_texts, vec!["Hello world"]);
}

#[test]
fn streaming_response_prefers_the_provider_snapshot_when_it_diverges() {
    let exchange = sse_exchange(&[
        r#"{"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":"draft"}"#,
        r#"{"type":"response.output_text.done","output_index":0,"content_index":0,"text":"final"}"#,
    ]);

    let parsed = parse_openai_exchange(&exchange).expect("streaming exchange");

    assert_eq!(parsed.response_texts, vec!["final"]);
}

#[test]
fn streaming_response_keeps_reasoning_summary_and_message_order() {
    let exchange = sse_exchange(&[
        r#"{"type":"response.reasoning_summary_text.delta","output_index":0,"summary_index":0,"delta":"thinking"}"#,
        r#"{"type":"response.output_text.delta","output_index":1,"content_index":0,"delta":"answer"}"#,
        r#"{"type":"response.completed","response":{"id":"resp_1","model":"gpt-5","output":[{"id":"rs_1","type":"reasoning","summary":[{"type":"summary_text","text":"thinking"}]},{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"output_text","text":"answer"}]}]}}"#,
    ]);

    let parsed = parse_openai_exchange(&exchange).expect("streaming exchange");

    assert_eq!(parsed.response_texts, vec!["thinking", "answer"]);
}

#[test]
fn streaming_response_keeps_parallel_message_parts_separate() {
    let exchange = sse_exchange(&[
        r#"{"type":"response.output_text.delta","output_index":0,"content_index":1,"delta":"second"}"#,
        r#"{"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":"first"}"#,
    ]);

    let parsed = parse_openai_exchange(&exchange).expect("streaming exchange");

    assert_eq!(parsed.response_texts, vec!["first", "second"]);
}

#[test]
fn streaming_response_ignores_tool_call_items() {
    let exchange = sse_exchange(&[
        r#"{"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":"answer"}"#,
        r#"{"type":"response.output_item.done","output_index":1,"item":{"id":"fc_1","type":"function_call","name":"read_file","arguments":"{}"}}"#,
    ]);

    let parsed = parse_openai_exchange(&exchange).expect("streaming exchange");

    assert_eq!(parsed.response_texts, vec!["answer"]);
}

#[test]
fn a_streamed_tool_call_item_yields_one_tool_call() {
    // Codex streams each output item when it is added and done, then
    // republishes the whole output in `response.completed`.
    let call = r#"{"type":"function_call","id":"fc_1","call_id":"call_1","name":"exec_command","arguments":"{\"cmd\":\"pwd\"}"}"#;
    let parallel = r#"{"type":"function_call","id":"fc_2","call_id":"call_2","name":"exec_command","arguments":"{\"cmd\":\"ls\"}"}"#;
    let added = r#"{"type":"response.output_item.added","output_index":0,"item":{"type":"function_call","id":"fc_1","call_id":"call_1","name":"exec_command","arguments":""}}"#;
    let delta = r#"{"type":"response.function_call_arguments.delta","output_index":0,"item_id":"fc_1","delta":"{\"cmd\""}"#;
    let done = format!(r#"{{"type":"response.output_item.done","output_index":0,"item":{call}}}"#);
    let done_parallel =
        format!(r#"{{"type":"response.output_item.done","output_index":1,"item":{parallel}}}"#);
    let completed = format!(
        r#"{{"type":"response.completed","response":{{"id":"resp_1","output":[{call},{parallel}]}}}}"#
    );
    let parsed = parse_openai_exchange(&sse_exchange(&[
        added,
        delta,
        &done,
        &done_parallel,
        &completed,
    ]))
    .expect("SSE exchange");

    assert_eq!(
        parsed.response_tool_events,
        [
            ParsedToolEvent::ToolCall {
                item_id: Some("fc_1".to_owned()),
                call_id: Some("call_1".to_owned()),
                name: Some("exec_command".to_owned()),
                input: r#"{"cmd":"pwd"}"#.to_owned(),
            },
            ParsedToolEvent::ToolCall {
                item_id: Some("fc_2".to_owned()),
                call_id: Some("call_2".to_owned()),
                name: Some("exec_command".to_owned()),
                input: r#"{"cmd":"ls"}"#.to_owned(),
            },
        ]
    );
}

#[test]
fn response_id_is_read_where_the_protocol_puts_it() {
    // A stream names the response in `response.id`, whatever its format.
    let streamed = parse_openai_exchange(&sse_exchange(&[
            r#"{"type":"response.created","response":{"id":"r1"}}"#,
            r#"{"type":"response.output_item.done","output_index":0,"item":{"id":"resp_item","type":"message","role":"assistant","content":[{"type":"output_text","text":"hi"}]}}"#,
            r#"{"type":"response.completed","response":{"id":"r1"}}"#,
        ]))
        .expect("SSE exchange");
    assert_eq!(streamed.response_id.as_deref(), Some("r1"));

    // A whole Chat Completions document names it in its top-level `id`.
    let chat = parse_openai_exchange(&json_exchange(
            "/v1/chat/completions",
            &json!({"messages": [{"role": "user", "content": "hello"}]}),
            &json!({"id": "chatcmpl-1", "choices": [{"message": {"role": "assistant", "content": "hi"}}]}),
        ))
        .expect("chat exchange");
    assert_eq!(chat.response_id.as_deref(), Some("chatcmpl-1"));

    // Ids elsewhere, such as an output item's or the request's, are not it.
    let unnamed = parse_openai_exchange(&sse_exchange(&[
            r#"{"type":"response.output_item.done","output_index":0,"item":{"id":"resp_item","type":"message","role":"assistant","content":[{"type":"output_text","text":"hi"}]}}"#,
        ]))
        .expect("SSE exchange");
    assert_eq!(unnamed.response_id, None);
}

fn sse_exchange(events: &[&str]) -> HttpExchange {
    let mut body = String::new();
    for event in events {
        body.push_str("data: ");
        body.push_str(event);
        body.push_str("\n\n");
    }
    body.push_str("data: [DONE]\n\n");
    exchange(
        "/v1/responses",
        &json!({"model": "gpt-5", "input": [{"role": "user", "content": "hi"}], "stream": true}),
        "text/event-stream",
        body.into_bytes(),
    )
}

fn json_exchange(path: &str, request: &Value, response: &Value) -> HttpExchange {
    exchange(
        path,
        request,
        "application/json",
        serde_json::to_vec(response).unwrap(),
    )
}

fn exchange(
    path: &str,
    request_body: &Value,
    response_content_type: &str,
    response_body: Vec<u8>,
) -> HttpExchange {
    let request = Request::builder()
        .method("POST")
        .uri(path)
        .header("host", "gateway.example")
        .header("session-id", "session-1")
        .header("content-type", "application/json")
        .body(CapturedBody::from_bytes(
            serde_json::to_vec(request_body).unwrap().into(),
        ))
        .unwrap();
    let response = Response::builder()
        .header("content-type", response_content_type)
        .body(CapturedBody::from_bytes(response_body.into()))
        .unwrap();
    HttpExchange::new(flow(), request, response)
}

fn flow() -> FlowContext {
    FlowContext::new(
        SocketAddr::from(([127, 0, 0, 1], 50000)),
        SocketAddr::from(([127, 0, 0, 1], 18090)),
        OriginalDestination::from(SocketAddr::from(([127, 0, 0, 1], 443))),
        TransparentProtocol::TlsHttp {
            server_name: "gateway.example".to_owned(),
        },
    )
}

fn parse_openai_exchange(exchange: &HttpExchange) -> Option<super::ParsedOpenAiExchange> {
    let crate::protocol::LlmProtocol::OpenAi(protocol) =
        crate::protocol::ProtocolDetector::detect_http(exchange)?
    else {
        return None;
    };
    super::parse_openai_exchange(exchange, protocol)
}

#[test]
fn routes_select_only_their_own_request_and_response_shapes() {
    let request = json!({"input":[{"role":"user","content":"Responses input"}],"messages":[{"role":"user","content":"Chat input"}]});
    let response = json!({"id":"r1","output":[{"role":"assistant","content":"Responses output"}],"choices":[{"message":{"role":"assistant","content":"Chat output"}}]});
    for (path, input, output) in [
        ("/v1/responses", "Responses input", "Responses output"),
        ("/v1/chat/completions", "Chat input", "Chat output"),
    ] {
        let parsed = parse_openai_exchange(&json_exchange(path, &request, &response))
            .expect("protocol exchange");
        assert_eq!(parsed.request_texts, [input]);
        assert_eq!(parsed.response_texts, [output]);
        assert_eq!(parsed.request_conversation.messages.len(), 1);
        assert_eq!(parsed.response_conversation.messages.len(), 1);
    }
}

#[test]
fn chat_conversation_preserves_system_assistant_and_repeated_user_history() {
    let parsed = parse_openai_exchange(&json_exchange(
        "/v1/chat/completions",
        &json!({"messages":[
            {"role":"system","content":"rules"},
            {"role":"user","content":"repeat"},
            {"role":"assistant","content":"answer"},
            {"role":"user","content":"repeat"},
            {"role":"tool","tool_call_id":"call-1","content":"result"}
        ]}),
        &json!({"choices":[{"message":{"content":"done"}}]}),
    ))
    .expect("chat exchange");
    assert_eq!(
        parsed
            .request_conversation
            .messages
            .iter()
            .map(|m| m.text.as_str())
            .collect::<Vec<_>>(),
        ["rules", "repeat", "answer", "repeat", ""]
    );
    assert_eq!(
        parsed.request_tool_events,
        vec![ParsedToolEvent::ToolResult {
            call_id: Some("call-1".into()),
            output: "result".into()
        }]
    );
}

#[test]
fn conversation_header_uses_the_existing_http_session_chain() {
    for (path, messages_field) in [
        ("/v2/chat/completions", "messages"),
        ("/v1/responses", "input"),
    ] {
        for (session, text) in [
            ("conversation-1", "first request"),
            ("conversation-1", "tool continuation"),
            ("conversation-2", "new conversation"),
        ] {
            let mut body = json!({"model": "compatible-model"});
            body[messages_field] = json!([{"role": "user", "content": text}]);
            let mut exchange = json_exchange(path, &body, &json!({}));
            exchange.request.headers_mut().insert(
                http::HeaderName::from_bytes(b"X-Conversation-ID").unwrap(),
                format!(" {session} ").parse().unwrap(),
            );
            // Existing session sources retain their precedence.
            assert_eq!(
                parse_openai_exchange(&exchange).unwrap().session_id,
                "session-1"
            );
            exchange.request.headers_mut().remove("session-id");
            let parsed = parse_openai_exchange(&exchange).unwrap();
            assert_eq!(parsed.session_id, session);
            assert_eq!(parsed.request_texts, vec![text]);
            exchange
                .request
                .headers_mut()
                .insert("x-conversation-id", " \t".parse().unwrap());
            assert!(
                parse_openai_exchange(&exchange)
                    .unwrap()
                    .session_id
                    .starts_with("flow-")
            );
        }
    }
}


#[test]
fn conversation_header_does_not_override_existing_session_metadata() {
    for (name, value, expected) in [
        ("session_id", "alias-session", "alias-session"),
        ("thread-id", "thread-session", "thread-session"),
        (
            "x-codex-turn-metadata",
            r#"{"session_id":"codex-session"}"#,
            "codex-session",
        ),
        (
            "x-codex-turn-metadata",
            r#"{"thread_id":"codex-thread"}"#,
            "codex-thread",
        ),
        (
            "x-deepseek-harness-session-id",
            "dsh-session",
            "dsh-session",
        ),
    ] {
        let mut exchange = json_exchange("/v1/responses", &json!({"input": "hi"}), &json!({}));
        let headers = exchange.request.headers_mut();
        headers.remove("session-id");
        headers.insert("x-conversation-id", "conversation-1".parse().unwrap());
        headers.insert(name, value.parse().unwrap());
        assert_eq!(
            parse_openai_exchange(&exchange).unwrap().session_id,
            expected
        );
    }
}


#[test]
fn conversation_header_uses_the_existing_websocket_session_chain() {
    for (sequence, text) in [(1, "first request"), (2, "second request")] {
        let message = WebSocketMessage::new(
            flow(),
            Request::builder()
                .method("GET")
                .uri("/v1/responses")
                .header("host", "gateway.example")
                .header("X-Conversation-ID", " shared-conversation ")
                .body(())
                .unwrap(),
            WebSocketDirection::ClientToServer,
            sequence,
            Some(json!({"type": "response.create", "input": text}).to_string()),
            None,
        );
        let OpenAiWebSocketFrame::Request(parsed) = parse_openai_websocket_message(&message) else {
            panic!("WebSocket request message");
        };
        assert_eq!(parsed.session_id, "shared-conversation");
        assert_eq!(parsed.request_texts, vec![text]);
    }
}

