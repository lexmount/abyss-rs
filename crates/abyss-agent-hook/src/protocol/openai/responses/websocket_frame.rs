//! Responses WebSocket frame decoding; accumulation is handled by websocket.

use abyss_mitm::{WebSocketDirection, WebSocketMessage};
use serde_json::Value;

use super::{
    request::ResponsesRequest,
    response::ResponsesResponse,
    websocket::{OpenAiWebSocketFrame, OpenAiWebSocketResponse, is_terminal_event},
};
use crate::protocol::model::usage::TokenUsage;
use crate::protocol::{
    model::conversation::ConversationProjection,
    openai::shared::{
        exchange::ParsedOpenAiExchange,
        images::extract_openai_request_images,
        metadata::{first_model, response_id},
        usage::best_usage,
    },
    shared::{
        digest::sha256_hex,
        http::{flow_server_name, header, opencode_session_id, request_host},
        json::{collect_string_field, event_types, string_field},
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
    let (request, request_images) = if is_client_message {
        (
            ResponsesRequest::parse(Some(request_payload), false),
            extract_openai_request_images(request_payload),
        )
    } else {
        (ResponsesRequest::parse(None, false), Vec::new())
    };
    let usage = if is_client_message {
        TokenUsage::default()
    } else {
        best_usage(std::slice::from_ref(&payload)).unwrap_or_default()
    };
    // Tool calls are output items, so a frame that carries one assembles a
    // non-empty response; the turn reads them from its assembled response.
    let relevant = if is_client_message {
        !request.is_empty() || !request_images.is_empty()
    } else {
        !ResponsesResponse::assemble(std::slice::from_ref(&payload), false).is_empty()
            || !usage.is_empty()
            || string_field(&payload, "type").is_some_and(is_terminal_event)
    };
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
        request_conversation: request.conversation(),
        // The accumulator assembles the response once the turn terminates.
        response_conversation: ConversationProjection::empty(),
        request_images,
        usage,
        response_id: if is_client_message {
            None
        } else {
            response_id(std::slice::from_ref(&payload))
        },
        previous_response_id: string_field(request_payload, "previous_response_id")
            .map(str::to_owned),
        client_metadata: if is_client_message {
            request_payload.get("client_metadata").cloned()
        } else {
            None
        },
        model: first_model(std::slice::from_ref(&payload)),
        event_types: if is_client_message {
            Vec::new()
        } else {
            event_types(&payload)
        },
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
        document: payload,
        byte_len,
    }))
}

fn websocket_json_payload(message: &WebSocketMessage) -> Option<Value> {
    match (&message.text, &message.binary) {
        (Some(text), _) => serde_json::from_str(text).ok(),
        (None, Some(bytes)) => serde_json::from_slice(bytes).ok(),
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
