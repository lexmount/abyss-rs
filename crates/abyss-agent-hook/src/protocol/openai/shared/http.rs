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
    model::image::ParsedImageAttachment,
    shared::{
        digest::sha256_hex,
        http::request_host,
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
        request_images: Vec<ParsedImageAttachment>,
        response: &OpenAiResponse,
    ) -> Option<ParsedOpenAiExchange> {
        let host = request_host(self.exchange.request.headers(), self.exchange.request.uri())?;
        let path = self.exchange.request.uri().path();
        let response_conversation = response.conversation();
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
        if request_conversation.entries.is_empty()
            && request_images.is_empty()
            && response_conversation.entries.is_empty()
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
            session_id: session_id(headers)
                .unwrap_or_else(|| format!("flow-{}", &request_hash[..16])),
            request_hash,
            request_conversation,
            response_conversation,
            request_images,
            usage,
            response_id,
            previous_response_id,
            client_metadata: self
                .exchange
                .request
                .body()
                .json()
                .and_then(|json| json.get("client_metadata").cloned()),
            model,
            event_types: self.documents.values.iter().flat_map(event_types).collect(),
        })
    }
}
