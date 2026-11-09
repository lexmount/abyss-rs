//! Static protocol parsing stages; concrete dialects own their wire rules.
//! Inspection and observation share request results and the same exchange assembly.

use std::borrow::Cow;

use abyss_mitm::{CapturedBody, HttpExchange};
use serde_json::Value;

use super::{
    LlmProtocol,
    model::{
        request::{ParsedAgentRequest, RequestContent},
        response::ResponseContent,
    },
    shared::sse::ResponseDocuments,
};

#[cfg(test)]
mod tests;

pub trait ProtocolParser {
    const PROTOCOL: LlmProtocol;

    fn parse_request(payload: Option<&Value>, truncated: bool) -> RequestContent;

    fn parse_response(values: &[Value], incomplete: bool) -> ResponseContent;
}

/// Finds the request projection carried by forwarding control for this dialect.
pub fn prepared_request<P: ProtocolParser>(body: &CapturedBody) -> Option<&RequestContent> {
    let (protocol, content) = body
        .extensions()
        .get::<ParsedAgentRequest>()?
        .projection
        .as_ref()?;
    (*protocol == P::PROTOCOL).then_some(content.as_ref())
}

/// Uses a prepared request when available; otherwise parses at the observation boundary.
pub fn request_content<P: ProtocolParser>(body: &CapturedBody) -> Cow<'_, RequestContent> {
    prepared_request::<P>(body).map_or_else(
        || Cow::Owned(P::parse_request(body.json(), body.truncated())),
        Cow::Borrowed,
    )
}

/// Both inspected and streaming HTTP requests finish through this one composition.
pub fn parse_http_exchange<P: ProtocolParser, E, F>(
    exchange: &HttpExchange,
    assemble_exchange: F,
) -> Option<E>
where
    F: FnOnce(&HttpExchange, RequestContent, ResponseContent) -> Option<E>,
{
    let request = request_content::<P>(exchange.request.body());
    let documents = ResponseDocuments::decode(exchange.response.body());
    let response = P::parse_response(&documents.values, documents.incomplete);
    assemble_exchange(exchange, request.into_owned(), response)
}
