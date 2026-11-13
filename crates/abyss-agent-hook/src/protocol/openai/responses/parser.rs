//! Responses request and response projections, independent of transport and observation.

use super::{request::ResponsesRequest, response::ResponsesResponse};
use crate::protocol::{
    LlmProtocol, OpenAiProtocol,
    model::{
        request::{RequestContent, RequestMetadata},
        response::ResponseContent,
    },
    openai::shared::{
        images::extract_openai_request_images,
        metadata::{first_model, response_id},
        usage::best_usage,
    },
    parser::ProtocolParser,
    shared::{json::event_types, sse::ResponseDocuments},
};
use serde_json::Value;

pub struct ResponsesParser;

impl ProtocolParser for ResponsesParser {
    const PROTOCOL: LlmProtocol = LlmProtocol::OpenAi(OpenAiProtocol::Responses);

    fn parse_request(payload: Option<&Value>, truncated: bool) -> RequestContent {
        let parsed = ResponsesRequest::parse(payload, truncated);
        let conversation = parsed.conversation();
        RequestContent {
            carries_messages: !parsed.is_empty(),
            conversation,
            images: payload.map_or_else(Vec::new, extract_openai_request_images),
            metadata: RequestMetadata::parse(payload),
            usage: payload.and_then(|value| best_usage(std::slice::from_ref(value))),
            file_uuids: Vec::new(),
            assistant_message_uuid: None,
        }
    }

    fn parse_response(values: &[Value], incomplete: bool) -> ResponseContent {
        let parsed = ResponsesResponse::assemble(values, incomplete);
        ResponseContent {
            has_content: !parsed.is_empty(),
            conversation: parsed.conversation(),
            usage: best_usage(values),
            model: first_model(values),
            response_id: response_id(values),
            event_types: values.iter().flat_map(event_types).collect(),
        }
    }

    fn parse_http_response(documents: &ResponseDocuments) -> ResponseContent {
        // Codex can cancel HTTP/2 after the terminal SSE snapshot, before the
        // origin sends END_STREAM. Keep raw capture truncation, but distinguish
        // it from missing conversation content. Malformed events remain partial.
        let complete_snapshot = documents.values.last().is_some_and(|value| {
            matches!(
                value["type"].as_str(),
                Some("response.completed" | "response.done")
            ) && value
                .pointer("/response/output")
                .is_some_and(Value::is_array)
                && value
                    .pointer("/response/status")
                    .is_none_or(|status| status == "completed")
        });
        let incomplete = documents.incomplete && (documents.malformed || !complete_snapshot);
        Self::parse_response(&documents.values, incomplete)
    }
}

#[cfg(test)]
mod tests {
    use abyss_mitm::CapturedBody;
    use abyss_plugin_protocol::event::ContentCompleteness;
    use serde_json::json;

    use super::*;

    fn completeness(bytes: String) -> ContentCompleteness {
        let body = CapturedBody::from_truncated_bytes(bytes.into_bytes().into());
        let documents = ResponseDocuments::decode(&body);
        ResponsesParser::parse_http_response(&documents)
            .conversation
            .completeness
    }

    #[test]
    fn terminal_output_snapshots_complete_http_content_after_transport_cancellation() {
        for kind in ["response.completed", "response.done"] {
            for status in [Some("completed"), None] {
                let mut event = json!({"type":kind,"response":{"output":[]}});
                if let Some(status) = status {
                    event["response"]["status"] = status.into();
                }
                assert_eq!(
                    completeness(format!("data: {event}\n\n")),
                    ContentCompleteness::Complete
                );
            }
        }
    }

    #[test]
    fn missing_snapshots_and_malformed_events_remain_partial() {
        let terminal = json!({"type":"response.completed","response":{"output":[]}});
        let delta = json!({"type":"response.output_text.delta","delta":"prefix"});
        for bytes in [
            format!("data: {delta}\n\n"),
            "data: {\"type\":\"response.completed\",\"response\":{}}\n\n".to_owned(),
            "data: {\"type\":\"response.completed\",\"response\":{\"output\":[],\"status\":\"incomplete\"}}\n\n".to_owned(),
            format!("data: {terminal}\n\ndata: {delta}\n\n"),
            format!("data: {{broken\n\ndata: {terminal}\n\n"),
            format!("data: {terminal}\n\ndata: {{broken\n\n"),
            "{\"output\":[]}".to_owned(),
        ] {
            assert_eq!(completeness(bytes.clone()), ContentCompleteness::Partial, "{bytes}");
        }
    }
}
