//! Responses WebSocket frame decoding; accumulation is handled by websocket.

use std::borrow::Cow;

use abyss_mitm::{WebSocketDirection, WebSocketMessage};
use serde_json::Value;

use super::{
    parser::ResponsesParser,
    websocket::{OpenAiWebSocketFrame, OpenAiWebSocketResponse, is_terminal_event},
};
use crate::protocol::{
    model::conversation::ConversationProjection,
    openai::shared::{exchange::ParsedOpenAiExchange, metadata::response_id},
    parser::{ProtocolParser, prepared_request},
    shared::{
        digest::sha256_hex,
        http::{flow_server_name, header, opencode_session_id, request_host},
        json::{collect_string_field, string_field},
    },
};

/// Decodes one OpenAI Responses WebSocket frame after a successful HTTP 101.
///
/// A frame whose payload is not JSON is reported as undecodable so the turn
/// side it belongs to is marked partial. A decodable frame that carries no
/// request content, response content, tools, usage, or terminal state, such as
/// `response.created`, is irrelevant and leaves the pending turn untouched.
/// Server frames keep their decoded document because the turn's response is
/// assembled from the complete stream when the terminal event arrives.
#[must_use]
pub fn parse_openai_websocket_message(message: &WebSocketMessage) -> OpenAiWebSocketFrame {
    let Some(payload) = websocket_json_payload(message) else {
        return OpenAiWebSocketFrame::Undecodable(message.direction);
    };
    // A frame that cannot be attributed to a host is not a content failure.
    let Some(host) = request_host(
        message.upgrade_request.headers(),
        message.upgrade_request.uri(),
    )
    .or_else(|| flow_server_name(&message.flow)) else {
        return OpenAiWebSocketFrame::Irrelevant;
    };
    let path = message.upgrade_request.uri().path();
    let is_client_message = matches!(message.direction, WebSocketDirection::ClientToServer);
    let request_payload = payload.get("response").unwrap_or(&payload);
    let request = is_client_message.then(|| {
        message
            .captured_body
            .as_ref()
            .and_then(prepared_request::<ResponsesParser>)
            .map_or_else(
                || Cow::Owned(ResponsesParser::parse_request(Some(request_payload), false)),
                Cow::Borrowed,
            )
    });
    let response = (!is_client_message)
        .then(|| ResponsesParser::parse_response(std::slice::from_ref(payload.as_ref()), false));
    let relevant = request.as_ref().is_some_and(|request| !request.is_empty())
        || response.as_ref().is_some_and(|response| {
            response.has_content
                || response
                    .usage
                    .as_ref()
                    .is_some_and(|usage| !usage.is_empty())
                || string_field(&payload, "type").is_some_and(is_terminal_event)
        });
    if !relevant {
        return OpenAiWebSocketFrame::Irrelevant;
    }

    let Ok(payload_text) = serde_json::to_string(&payload) else {
        return OpenAiWebSocketFrame::Undecodable(message.direction);
    };
    let request_hash = sha256_hex(&format!(
        "{:?}\0{}\0{}\0{}\0{}",
        message.direction, host, path, message.sequence, payload_text
    ));
    let exchange = ParsedOpenAiExchange {
        generates_output: is_client_message.then(|| {
            string_field(&payload, "type") != Some("response.create")
                || request_payload.get("generate").and_then(Value::as_bool) != Some(false)
        }),
        session_id: websocket_session_id(message, &payload),
        request_hash,
        request_conversation: request
            .as_ref()
            .map_or_else(ConversationProjection::empty, |request| {
                request.conversation.clone()
            }),
        // The accumulator assembles the response once the turn terminates.
        response_conversation: ConversationProjection::empty(),
        request_images: request
            .as_ref()
            .map_or_else(Vec::new, |request| request.images.clone()),
        usage: response
            .as_ref()
            .and_then(|response| response.usage.clone())
            .unwrap_or_default(),
        response_id: response
            .as_ref()
            .and_then(|response| response.response_id.clone()),
        previous_response_id: request
            .as_ref()
            .and_then(|request| request.metadata.previous_response_id.clone()),
        client_metadata: request
            .as_ref()
            .and_then(|request| request.metadata.client_metadata.clone()),
        model: request
            .as_ref()
            .and_then(|request| request.metadata.model.clone())
            .or_else(|| {
                response
                    .as_ref()
                    .and_then(|response| response.model.clone())
            }),
        event_types: response.map_or_else(Vec::new, |response| response.event_types),
    };
    if is_client_message {
        return OpenAiWebSocketFrame::Request(Box::new(exchange));
    }
    let byte_len = message.text.as_ref().map_or_else(
        || message.binary.as_deref().map_or(0, <[u8]>::len),
        String::len,
    );
    OpenAiWebSocketFrame::Response(Box::new(OpenAiWebSocketResponse {
        exchange,
        document: payload.into_owned(),
        byte_len,
    }))
}

fn websocket_json_payload(message: &WebSocketMessage) -> Option<Cow<'_, Value>> {
    if let Some(body) = &message.captured_body {
        return body.json().map(Cow::Borrowed);
    }
    match (&message.text, &message.binary) {
        (Some(text), _) => serde_json::from_str(text).ok().map(Cow::Owned),
        (None, Some(bytes)) => serde_json::from_slice(bytes).ok().map(Cow::Owned),
        (None, None) => None,
    }
}

fn websocket_session_id(message: &WebSocketMessage, payload: &Value) -> String {
    header(message.upgrade_request.headers(), "session-id")
        .or_else(|| header(message.upgrade_request.headers(), "session_id"))
        .or_else(|| header(message.upgrade_request.headers(), "thread-id"))
        .or_else(|| header(message.upgrade_request.headers(), "x-hermes-session-id"))
        .or_else(|| opencode_session_id(message.upgrade_request.headers()))
        .map(str::to_owned)
        .or_else(|| collect_string_field(payload, "session_id"))
        .or_else(|| collect_string_field(payload, "thread_id"))
        .or_else(|| collect_string_field(payload, "conversation_id"))
        .or_else(|| collect_string_field(payload, "response_id"))
        .or_else(|| response_id(std::slice::from_ref(payload)))
        .or_else(|| {
            header(message.upgrade_request.headers(), "x-conversation-id").map(str::to_owned)
        })
        .unwrap_or_else(|| format!("flow-{}", message.flow.flow_id))
}
