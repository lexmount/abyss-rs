//! Decodes the Claude Desktop Code session stream into individual model calls.

use std::{
    collections::VecDeque,
    time::{Duration, SystemTime},
};

use abyss_mitm::{DEFAULT_MAX_HTTP1_BODY_BYTES, FlowContext};
use abyss_plugin_protocol::event::Conversation;
use http::Request;
use serde_json::{Map, Value};

use crate::protocol::{
    model::{image::ParsedImageAttachment, usage::TokenUsage},
    shared::http::{flow_server_name, request_host},
};

use super::shared::{
    conversation::{AnthropicRequest, AnthropicResponse},
    images::extract_anthropic_request_images,
    usage::UsageCounters,
};

pub fn matches_request<B>(flow: &FlowContext, request: &Request<B>) -> bool {
    session_segment(request).is_some()
        && matches!(
            request_host(request.headers(), request.uri())
                .or_else(|| flow_server_name(flow))
                .as_deref(),
            Some("claude.ai")
        )
}

pub fn session_segment<B>(request: &Request<B>) -> Option<&str> {
    request
        .uri()
        .path()
        .strip_prefix("/v1/code/sessions/")?
        .strip_suffix("/events/stream")
}

pub struct ParsedClaudeCodeCall {
    pub session_id: String,
    pub message_id: String,
    pub model: Option<String>,
    pub request_conversation: Conversation,
    pub request_images: Vec<ParsedImageAttachment>,
    pub response_conversation: Conversation,
    pub usage: TokenUsage,
    pub request_at: SystemTime,
    pub response_at: SystemTime,
}

/// A session stream holds the observed inputs since its last completed call
/// and the in-progress Messages responses. Dropping the stream drops both.
pub struct ClaudeCodeSession {
    session_id: String,
    requests: Documents,
    responses: VecDeque<PendingResponse>,
}

impl ClaudeCodeSession {
    pub fn new(session: &str) -> Self {
        Self {
            session_id: session
                .strip_prefix("cse_")
                .map_or_else(|| session.to_owned(), |suffix| format!("session_{suffix}")),
            requests: Documents::default(),
            responses: VecDeque::new(),
        }
    }

    pub fn reset(&mut self) {
        self.requests = Documents::default();
        self.responses.clear();
    }

    pub fn push(&mut self, data: &str, at: SystemTime) -> Option<ParsedClaudeCodeCall> {
        let mut document: Value = serde_json::from_str(data).ok()?;
        let payload = document.get_mut("payload")?;
        match payload["type"].as_str()? {
            "user" => {
                let message = payload.get_mut("message")?;
                self.requests.push(message.take(), data.len());
                None
            }
            "stream_event" => {
                let event = payload.get_mut("event")?.take();
                let message_id = payload["api_message_id"].as_str()?;
                self.push_response(
                    message_id,
                    event,
                    data.len(),
                    at,
                    payload["ttft_ms"].as_u64(),
                )
            }
            _ => None,
        }
    }

    fn push_response(
        &mut self,
        message_id: &str,
        event: Value,
        bytes: usize,
        at: SystemTime,
        ttft_ms: Option<u64>,
    ) -> Option<ParsedClaudeCodeCall> {
        let kind = event["type"].as_str()?;
        if kind == "message_start" {
            let request_at = ttft_ms.and_then(|ms| at.checked_sub(Duration::from_millis(ms)));
            self.start_response(message_id, event, bytes, request_at);
            return None;
        }
        let index = self
            .responses
            .iter()
            .position(|response| response.message_id == message_id)?;
        match kind {
            "content_block_start" | "content_block_delta" => {
                self.responses[index].documents.push(event, bytes);
            }
            "message_delta" => {
                self.responses[index].usage.merge_fields(&event["usage"]);
            }
            "message_stop" => {
                return Some(self.responses.remove(index)?.finish(
                    &self.session_id,
                    std::mem::take(&mut self.requests),
                    at,
                ));
            }
            _ => {}
        }
        None
    }

    fn start_response(
        &mut self,
        message_id: &str,
        event: Value,
        bytes: usize,
        request_at: Option<SystemTime>,
    ) {
        let message = &event["message"];
        let model = message["model"].as_str().map(str::to_owned);
        let mut usage = UsageCounters::default();
        usage.merge_fields(&message["usage"]);
        let mut documents = Documents::default();
        documents.push(event, bytes);
        self.responses.push_back(PendingResponse {
            documents,
            message_id: message_id.to_owned(),
            model,
            usage,
            request_at,
        });
    }
}

struct PendingResponse {
    documents: Documents,
    message_id: String,
    model: Option<String>,
    usage: UsageCounters,
    request_at: Option<SystemTime>,
}

impl PendingResponse {
    fn finish(
        self,
        session_id: &str,
        requests: Documents,
        response_at: SystemTime,
    ) -> ParsedClaudeCodeCall {
        let request = Value::Object(Map::from_iter([(
            "messages".to_owned(),
            Value::Array(requests.values),
        )]));
        let response =
            AnthropicResponse::assemble(&self.documents.values, self.documents.truncated);
        ParsedClaudeCodeCall {
            session_id: session_id.to_owned(),
            message_id: self.message_id,
            model: self.model,
            request_conversation: AnthropicRequest::parse(&request, requests.truncated)
                .conversation(),
            request_images: extract_anthropic_request_images(&request),
            response_conversation: response.conversation(),
            usage: self.usage.into_usage(),
            request_at: self.request_at.unwrap_or(response_at),
            response_at,
        }
    }
}

/// Once a side reaches its budget, preserve only the observed prefix.
#[derive(Default)]
struct Documents {
    values: Vec<Value>,
    bytes: usize,
    truncated: bool,
}

impl Documents {
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "The remaining-budget check keeps the retained byte count within the limit."
    )]
    fn push(&mut self, value: Value, bytes: usize) {
        if self.truncated || bytes > DEFAULT_MAX_HTTP1_BODY_BYTES - self.bytes {
            self.truncated = true;
            return;
        }
        self.bytes += bytes;
        self.values.push(value);
    }
}

#[cfg(test)]
mod tests {
    use abyss_plugin_protocol::event::ContentCompleteness;
    use serde_json::json;

    use super::*;

    #[test]
    fn session_id_rewrites_only_the_cse_prefix() {
        for (segment, id) in [
            ("cse_test", "session_test"),
            ("session_test", "session_test"),
            ("other_test", "other_test"),
        ] {
            assert_eq!(ClaudeCodeSession::new(segment).session_id, id);
        }
    }

    #[test]
    fn request_entries_become_partial_when_capture_reaches_its_budget() {
        let mut stream = ClaudeCodeSession::new("session_test");
        let input = json!({"role":"user","content":"retained"});
        stream
            .requests
            .push(input.clone(), DEFAULT_MAX_HTTP1_BODY_BYTES);
        stream.requests.push(input, 1);
        stream.start_response("msg_test", json!({"message":{"id":"msg_test"}}), 1, None);
        let call = stream
            .push_response(
                "msg_test",
                json!({"type":"message_stop"}),
                1,
                SystemTime::UNIX_EPOCH,
                None,
            )
            .unwrap();
        assert_eq!(
            call.request_conversation.completeness,
            ContentCompleteness::Partial
        );
        assert_eq!(call.request_conversation.entries.len(), 1);
    }
}
