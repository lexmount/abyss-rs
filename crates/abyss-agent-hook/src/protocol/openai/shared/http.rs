//! Shared HTTP capture decoding and exchange metadata; dialects supply projected content.

use abyss_mitm::HttpExchange;

use super::{exchange::ParsedOpenAiExchange, metadata::session_id};
use crate::protocol::{
    model::{request::RequestContent, response::ResponseContent},
    shared::{digest::sha256_hex, http::request_host},
};

pub struct OpenAiHttpExchange;
impl OpenAiHttpExchange {
    pub fn assemble_exchange(
        exchange: &HttpExchange,
        request: RequestContent,
        response: ResponseContent,
    ) -> Option<ParsedOpenAiExchange> {
        let request_conversation = request.conversation;
        let request_images = request.images;
        let host = request_host(exchange.request.headers(), exchange.request.uri())?;
        let path = exchange.request.uri().path();
        let response_conversation = response.conversation;
        // Providers usually report token usage on the final response event. Some
        // request styles may include useful usage-like fields on the request, so use
        // those as a fallback only when response usage is absent.
        //
        // Request body capture is policy bounded in the MITM relay. Large Codex
        // turns may therefore arrive here with a truncated, non-JSON request body
        // while the response may also be truncated before the final usage event.
        // Treat truncation itself as evidence that an audit-relevant exchange
        // occurred, even when the retained prefixes do not parse into entries or
        // usage.
        let usage = response.usage.or(request.usage).unwrap_or_default();
        let body_was_truncated =
            exchange.request.body().truncated() || exchange.response.body().truncated();
        if request_conversation.entries.is_empty()
            && request_images.is_empty()
            && response_conversation.entries.is_empty()
            && usage.is_empty()
            && !body_was_truncated
        {
            return None;
        }

        let response_id = response.response_id;
        let previous_response_id = request.metadata.previous_response_id;
        let model = response.model.or(request.metadata.model);
        let headers = exchange.request.headers();
        let request_hash = sha256_hex(&format!(
            "{}\0{}\0{}\0{}",
            exchange.request.method(),
            host,
            path,
            String::from_utf8_lossy(exchange.request.body().bytes())
        ));

        Some(ParsedOpenAiExchange {
            generates_output: None,
            session_id: session_id(headers)
                .unwrap_or_else(|| format!("flow-{}", &request_hash[..16])),
            request_hash,
            request_conversation,
            response_conversation,
            request_images,
            usage,
            response_id,
            previous_response_id,
            client_metadata: request.metadata.client_metadata,
            model,
            event_types: response.event_types,
        })
    }
}
