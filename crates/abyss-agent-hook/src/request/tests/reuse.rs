//! Prepared request ownership and event parity through the production parsing stages.

use std::{
    convert::Infallible,
    sync::{Arc, Mutex},
};

use abyss_mitm::{
    CapturedBody, FlowContext, HttpExchange, MitmHook, OriginalDestination, RequestTransport,
    RequestView, TransparentProtocol, WebSocketDirection, WebSocketMessage,
};
use abyss_plugin_protocol::event::AgentEvent;
use http::{Request, Response};
use serde_json::{Value, json};

use crate::{
    AgentEventSink, AgentRequestParser, DeviceIdentity, HarnessUsageConfig, HarnessUsageHook,
    HarnessUsageHookConfig, HooksRuntimeConfig,
    protocol::{
        AnthropicProtocol, LlmProtocol, OpenAiProtocol,
        anthropic::{claude_web::ClaudeWebParser, messages::MessagesParser},
        openai::{
            chat_completions::ChatCompletionsParser,
            parse_openai_websocket_message,
            responses::{
                ResponsesParser,
                websocket::{OpenAiWebSocketAccumulator, OpenAiWebSocketFrame},
            },
        },
        parser::request_content,
    },
};

#[derive(Debug, Default)]
struct Events(Mutex<Vec<AgentEvent>>);

impl AgentEventSink for Events {
    type Error = Infallible;
    fn publish(
        &self,
        event: AgentEvent,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        self.0.lock().unwrap().push(event);
        std::future::ready(Ok(()))
    }
}

impl Events {
    fn normalized(&self) -> Vec<Value> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .map(|event| {
                let mut event = serde_json::to_value(event).unwrap();
                event.as_object_mut().unwrap().remove("observed_at");
                event
            })
            .collect()
    }
}

fn flow() -> FlowContext {
    FlowContext::from_optional_addrs(
        None,
        None,
        OriginalDestination::from("127.0.0.1:443".parse::<std::net::SocketAddr>().unwrap()),
        TransparentProtocol::PlainHttp,
        None,
    )
}

fn head(path: &str) -> Request<()> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header("host", "gateway.example")
        .header("originator", "codex_cli_rs")
        .header("session-id", "session-1")
        .body(())
        .unwrap()
}

fn body(value: &Value) -> CapturedBody {
    CapturedBody::from_bytes(serde_json::to_vec(value).unwrap().into())
}

fn hook(sink: Arc<Events>) -> HarnessUsageHook<Arc<Events>> {
    HarnessUsageHook::with_runtime_config_and_event_sink(
        HarnessUsageHookConfig::new(DeviceIdentity::new()),
        HooksRuntimeConfig::default_enabled(),
        sink,
    )
}

#[tokio::test]
async fn http_prepared_requests_reuse_the_same_projection_and_emit_identical_events() {
    for (path, request, response) in [
        (
            "/v1/responses",
            json!({"model":" requested ","input":"hello","previous_response_id":" prior ","tools":[{"type":"function","name":"lookup"}]}),
            json!({"id":"response-1","model":"actual","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"answer"}]}],"usage":{"input_tokens":3_i32,"output_tokens":2_i32}}),
        ),
        (
            "/v1/chat/completions",
            json!({"model":" requested ","messages":[{"role":"user","content":"hello"}],"previous_response_id":" prior "}),
            json!({"id":"response-1","model":"actual","choices":[{"message":{"role":"assistant","content":"answer"}}],"usage":{"prompt_tokens":3_i32,"completion_tokens":2_i32}}),
        ),
        (
            "/v1/messages",
            json!({"model":" requested ","messages":[{"role":"user","content":"hello"}],"thread":{"type":" continue ","previous_message_id":" prior "}}),
            json!({"id":"response-1","model":"actual","content":[{"type":"text","text":"answer"}],"usage":{"input_tokens":3_i32,"output_tokens":2_i32}}),
        ),
        (
            "/api/organizations/org/chat_conversations/conversation-1/completion",
            json!({"model":" requested ","prompt":"hello","turn_message_uuids":{"assistant_message_uuid":"assistant-1"}}),
            json!({"id":"response-1","model":"actual","content":[{"type":"text","text":"answer"}],"usage":{"input_tokens":3_i32,"output_tokens":2_i32}}),
        ),
    ] {
        let flow = flow();
        let head = head(path);
        let mut request_body = body(&request);
        let plain = HttpExchange::new(
            flow.clone(),
            head.clone().map(|()| request_body.clone()),
            Response::new(body(&response)),
        );
        let view = RequestView {
            flow: &flow,
            head: &head,
            body: &request_body,
            transport: RequestTransport::Http,
        };
        let prepared = AgentRequestParser::prepare(&view);
        let projected = prepared.projection.as_ref().unwrap().1.clone();
        let context = AgentRequestParser::parse_prepared(
            &prepared,
            &view,
            &HarnessUsageConfig::default(),
            "checked".to_owned(),
        );
        assert_eq!(context.agent.unwrap().model.as_deref(), Some("requested"));
        let protocol = prepared.projection.as_ref().unwrap().0;
        request_body.extensions_mut().insert(prepared);
        let observed = match protocol {
            LlmProtocol::OpenAi(OpenAiProtocol::Responses) => {
                request_content::<ResponsesParser>(&request_body)
            }
            LlmProtocol::OpenAi(OpenAiProtocol::ChatCompletions) => {
                request_content::<ChatCompletionsParser>(&request_body)
            }
            LlmProtocol::Anthropic(AnthropicProtocol::Messages) => {
                request_content::<MessagesParser>(&request_body)
            }
            LlmProtocol::Anthropic(AnthropicProtocol::ClaudeWeb(_)) => {
                request_content::<ClaudeWebParser>(&request_body)
            }
        };
        assert!(
            std::ptr::eq(projected.as_ref(), observed.as_ref()),
            "{path}: observation must retain the inspection result, not reconstruct it"
        );
        let inspected = HttpExchange::new(
            flow,
            head.map(|()| request_body),
            Response::new(body(&response)),
        );
        let plain_events = Arc::new(Events::default());
        let inspected_events = Arc::new(Events::default());
        hook(plain_events.clone())
            .on_http_exchange(&plain)
            .await
            .unwrap();
        hook(inspected_events.clone())
            .on_http_exchange(&inspected)
            .await
            .unwrap();
        let plain_events = plain_events.normalized();
        assert_eq!(plain_events.len(), 2, "{path}: request and response events");
        assert_eq!(plain_events, inspected_events.normalized(), "{path}");
    }
}

#[test]
fn websocket_messages_retain_their_own_request_result_through_terminal_assembly() {
    let flow = flow();
    let upgrade = head("/v1/responses");
    let inspected = OpenAiWebSocketAccumulator::default();
    let streaming = OpenAiWebSocketAccumulator::default();
    for (sequence, text, model) in [(1, "first", "model-1"), (3, "second", "model-2")] {
        let payload = json!({"type":"response.create","response":{"model":model,"input":text,"previous_response_id":"prior","client_metadata":{"turn":"current"}}});
        let mut captured = body(&payload);
        let prepared = AgentRequestParser::prepare(&RequestView {
            flow: &flow,
            head: &upgrade,
            body: &captured,
            transport: RequestTransport::WebSocketText { sequence },
        });
        let original = prepared.projection.as_ref().unwrap().1.clone();
        captured.extensions_mut().insert(prepared);
        assert!(std::ptr::eq(
            original.as_ref(),
            request_content::<ResponsesParser>(&captured).as_ref()
        ));
        let ordinary = WebSocketMessage::new(
            flow.clone(),
            upgrade.clone(),
            Response::new(()),
            WebSocketDirection::ClientToServer,
            sequence,
            Some(payload.to_string()),
            None,
        );
        let mut checked = ordinary.clone();
        checked.captured_body = Some(captured);
        assert!(
            streaming
                .push(&flow.flow_id, parse_openai_websocket_message(&ordinary))
                .is_none()
        );
        let parsed = parse_openai_websocket_message(&checked);
        let OpenAiWebSocketFrame::Request(request) = &parsed else {
            panic!("client request")
        };
        assert_eq!(request.model.as_deref(), Some(model));
        assert_eq!(request.request_conversation.entries[0].text, text);
        assert!(inspected.push(&flow.flow_id, parsed).is_none());
        let response = json!({"type":"response.completed","response":{"id":format!("response-{sequence}"),"output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"answer"}]}],"usage":{"input_tokens":3_i32,"output_tokens":2_i32}}});
        let server = WebSocketMessage::new(
            flow.clone(),
            upgrade.clone(),
            Response::new(()),
            WebSocketDirection::ServerToClient,
            sequence + 1,
            Some(response.to_string()),
            None,
        );
        let plain = streaming
            .push(&flow.flow_id, parse_openai_websocket_message(&server))
            .unwrap();
        let checked = inspected
            .push(&flow.flow_id, parse_openai_websocket_message(&server))
            .unwrap();
        assert_eq!(format!("{plain:?}"), format!("{checked:?}"));
    }
}
