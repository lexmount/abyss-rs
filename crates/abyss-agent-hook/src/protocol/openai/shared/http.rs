//! Shared HTTP capture decoding and exchange metadata; dialects supply projected content.

use abyss_mitm::HttpExchange;
use abyss_plugin_protocol::event::Conversation;

use super::{
    exchange::ParsedOpenAiExchange,
    metadata::{first_model, response_id, session_id},
    response::OpenAiResponse,
    usage::best_usage,
};
use crate::protocol::{
    model::{image::ParsedImageAttachment, tool::ParsedToolEvent},
    shared::{
        digest::sha256_hex,
        http::{request_host, transport_name},
        json::{event_types, string_field},
        sse::ResponseDocuments,
    },
};

pub struct OpenAiHttpExchange<'a> {
    exchange: &'a HttpExchange,
    pub documents: ResponseDocuments,
}
impl<'a> OpenAiHttpExchange<'a> {
    pub fn decode(exchange: &'a HttpExchange) -> Self {
        Self {
            exchange,
            documents: ResponseDocuments::decode(exchange.response.body()),
        }
    }
    pub fn finish(
        self,
        request_conversation: Conversation,
        request_texts: Vec<String>,
        request_images: Vec<ParsedImageAttachment>,
        request_tool_events: Vec<ParsedToolEvent>,
        response: &OpenAiResponse,
    ) -> Option<ParsedOpenAiExchange> {
        let host = request_host(self.exchange.request.headers(), self.exchange.request.uri())?;
        let path = self.exchange.request.uri().path();
        let response_texts = response.texts();
        let response_tool_events = response.tool_calls();
        // Providers usually report token usage on the final response event. Some
        // request styles may include useful usage-like fields on the request, so use
        // those as a fallback only when response usage is absent.
        //
        // Request body capture is policy bounded in the MITM relay. Large Codex
        // turns may therefore arrive here with a truncated, non-JSON request body
        // while the response may also be truncated before the final usage event.
        // Treat truncation itself as evidence that an audit-relevant exchange
        // occurred, even when the retained prefixes do not parse into text or usage.
        let usage = best_usage(&self.documents.values).unwrap_or_else(|| {
            self.exchange
                .request
                .body()
                .json()
                .and_then(|json| best_usage(std::slice::from_ref(json)))
                .unwrap_or_default()
        });
        let body_was_truncated =
            self.exchange.request.body().truncated() || self.exchange.response.body().truncated();
        if request_texts.is_empty()
            && request_images.is_empty()
            && request_tool_events.is_empty()
            && response_texts.is_empty()
            && response_tool_events.is_empty()
            && usage.is_empty()
            && !body_was_truncated
        {
            return None;
        }

        let response_id = response_id(&self.documents.values);
        let previous_response_id = self
            .exchange
            .request
            .body()
            .json()
            .and_then(|json| string_field(json, "previous_response_id"))
            .map(str::to_owned);
        let model = first_model(&self.documents.values).or_else(|| {
            self.exchange
                .request
                .body()
                .json()
                .and_then(|json| string_field(json, "model").map(str::to_owned))
        });
        let headers = self.exchange.request.headers();
        let request_hash = sha256_hex(&format!(
            "{}\0{}\0{}\0{}",
            self.exchange.request.method(),
            host,
            path,
            String::from_utf8_lossy(self.exchange.request.body().bytes())
        ));

        Some(ParsedOpenAiExchange {
            generates_output: None,
            host,
            path: path.to_owned(),
            method: self.exchange.request.method().to_string(),
            transport: transport_name(&self.exchange.flow.protocol),
            session_id: session_id(headers)
                .unwrap_or_else(|| format!("flow-{}", &request_hash[..16])),
            request_hash,
            request_conversation,
            response_conversation: response.conversation(),
            request_texts,
            request_images,
            response_texts,
            usage,
            response_id,
            previous_response_id,
            client_metadata: self
                .exchange
                .request
                .body()
                .json()
                .and_then(|json| json.get("client_metadata").cloned()),
            request_metadata: self
                .exchange
                .request
                .body()
                .json()
                .and_then(|json| json.get("metadata").cloned()),
            request_tool_events,
            response_tool_events,
            model,
            event_types: self.documents.values.iter().flat_map(event_types).collect(),
        })
    }
}
