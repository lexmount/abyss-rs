//! Chat Completions choice/delta assembly with per-choice tool-call indexes.

use std::collections::BTreeMap;

use abyss_plugin_protocol::event::MessageRole;
use serde_json::Value;

use super::tools::ChatToolCalls;
use crate::protocol::{
    model::conversation::ConversationProjection,
    openai::shared::{output::OutputText, response::OpenAiResponse},
};

struct ChatChoice {
    text: OutputText,
    tools: ChatToolCalls,
}

impl ChatChoice {
    fn new() -> Self {
        Self {
            text: OutputText::new(MessageRole::Assistant),
            tools: ChatToolCalls::default(),
        }
    }
}

pub struct ChatResponse;
impl ChatResponse {
    pub fn assemble(values: &[Value], incomplete: bool) -> OpenAiResponse {
        let mut choices = BTreeMap::<u64, ChatChoice>::new();
        for value in values {
            for choice in value
                .get("choices")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let index = choice["index"].as_u64().unwrap_or(0);
                if let Some(message) = choice.get("message") {
                    let slot = choices.entry(index).or_insert_with(ChatChoice::new);
                    slot.text.reconcile_item(message);
                    slot.tools.reconcile(message);
                }
                if let Some(delta) = choice.get("delta") {
                    choices
                        .entry(index)
                        .or_insert_with(ChatChoice::new)
                        .tools
                        .apply_delta(delta);
                }
                if let Some(fragment) = choice
                    .pointer("/delta/content")
                    .or_else(|| choice.get("text"))
                    .and_then(Value::as_str)
                {
                    choices
                        .entry(index)
                        .or_insert_with(ChatChoice::new)
                        .text
                        .parts
                        .entry(0)
                        .or_default()
                        .push_str(fragment);
                }
            }
        }
        let tool_calls = choices
            .values()
            .flat_map(|slot| slot.tools.events())
            .collect();
        OpenAiResponse {
            messages: choices
                .into_values()
                .map(|slot| slot.text.into_draft())
                .collect(),
            tool_calls,
            completeness: ConversationProjection::completeness(!values.is_empty(), incomplete),
        }
    }
}
