//! Messages projections and its request continuation semantics.

use crate::protocol::{
    AnthropicProtocol, LlmProtocol,
    anthropic::shared::parser::AnthropicContentParser,
    model::{request::RequestContent, response::ResponseContent},
    parser::ProtocolParser,
    shared::json::string_field,
};
use serde_json::Value;

pub struct MessagesParser;
impl ProtocolParser for MessagesParser {
    const PROTOCOL: LlmProtocol = LlmProtocol::Anthropic(AnthropicProtocol::Messages);

    fn parse_request(payload: Option<&Value>, truncated: bool) -> RequestContent {
        let mut request = AnthropicContentParser::parse_request(payload, truncated);
        request.metadata.previous_response_id = payload
            .and_then(|value| value.get("thread"))
            .filter(|thread| string_field(thread, "type") == Some("continue"))
            .and_then(|thread| string_field(thread, "previous_message_id"))
            .map(str::to_owned);
        request
    }

    fn parse_response(values: &[Value], incomplete: bool) -> ResponseContent {
        AnthropicContentParser::parse_response(values, incomplete)
    }
}
