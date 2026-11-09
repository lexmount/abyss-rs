//! Request-only protocol dispatch. Concrete dialects never call back into this module.

use super::{
    AnthropicProtocol, LlmProtocol, OpenAiProtocol,
    anthropic::{claude_web::ClaudeWebParser, messages::MessagesParser},
    model::request::RequestContent,
    openai::{chat_completions::ChatCompletionsParser, responses::ResponsesParser},
    parser::ProtocolParser,
};
use serde_json::Value;

pub struct RequestParser;
impl RequestParser {
    pub fn parse(
        protocol: LlmProtocol,
        payload: Option<&Value>,
        truncated: bool,
    ) -> RequestContent {
        match protocol {
            LlmProtocol::OpenAi(OpenAiProtocol::Responses) => {
                ResponsesParser::parse_request(payload, truncated)
            }
            LlmProtocol::OpenAi(OpenAiProtocol::ChatCompletions) => {
                ChatCompletionsParser::parse_request(payload, truncated)
            }
            LlmProtocol::Anthropic(AnthropicProtocol::Messages) => {
                MessagesParser::parse_request(payload, truncated)
            }
            LlmProtocol::Anthropic(AnthropicProtocol::ClaudeWeb(_)) => {
                ClaudeWebParser::parse_request(payload, truncated)
            }
        }
    }
}
