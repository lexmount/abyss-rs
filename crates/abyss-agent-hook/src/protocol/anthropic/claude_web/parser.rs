//! Claude Web completion projections, including request-side file references.

use super::metadata::{assistant_message_uuid, claude_web_file_uuids};
use crate::protocol::{
    AnthropicProtocol, ClaudeWebProtocol, LlmProtocol,
    anthropic::shared::parser::AnthropicContentParser,
    model::{request::RequestContent, response::ResponseContent},
    parser::ProtocolParser,
};
use serde_json::Value;

pub struct ClaudeWebParser;
impl ProtocolParser for ClaudeWebParser {
    const PROTOCOL: LlmProtocol = LlmProtocol::Anthropic(AnthropicProtocol::ClaudeWeb(
        ClaudeWebProtocol::ConversationCompletion,
    ));

    fn parse_request(payload: Option<&Value>, truncated: bool) -> RequestContent {
        let mut request = AnthropicContentParser::parse_request(payload, truncated);
        if let Some(payload) = payload {
            request.file_uuids = claude_web_file_uuids(payload);
            request.assistant_message_uuid = assistant_message_uuid(payload);
        }
        request
    }

    fn parse_response(values: &[Value], incomplete: bool) -> ResponseContent {
        AnthropicContentParser::parse_response(values, incomplete)
    }
}
