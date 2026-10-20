//! Chat Completions choice/delta assembly with per-choice tool-call indexes.

use std::collections::BTreeMap;

use abyss_plugin_protocol::event::MessageRole;
use serde_json::Value;

use super::tools::ChatToolCalls;
use crate::protocol::{
    model::conversation::{ConversationProjection, MessageDraft},
    openai::shared::{output::OutputText, response::OpenAiResponse},
};

struct ChatChoice {
    text: OutputText,
    reasoning: OutputText,
    tools: ChatToolCalls,
}

impl ChatChoice {
    fn new() -> Self {
        Self {
            text: OutputText::new(MessageRole::Assistant),
            reasoning: OutputText::new(MessageRole::Reasoning),
            tools: ChatToolCalls::default(),
        }
    }

    fn into_messages(self) -> Vec<MessageDraft> {
        let mut messages = Vec::new();
        let reasoning = self.reasoning.into_draft();
        if !reasoning.parts.is_empty() {
            messages.push(reasoning);
        }
        messages.push(self.text.into_draft());
        messages
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
                    if let Some(text) = message.get("reasoning_content").and_then(Value::as_str) {
                        slot.reasoning.reconcile(0, text);
                    }
                }
                if let Some(delta) = choice.get("delta") {
                    let slot = choices.entry(index).or_insert_with(ChatChoice::new);
                    slot.tools.apply_delta(delta);
                    if let Some(fragment) = delta.get("reasoning_content").and_then(Value::as_str) {
                        slot.reasoning
                            .parts
                            .entry(0)
                            .or_default()
                            .push_str(fragment);
                    }
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
                .flat_map(ChatChoice::into_messages)
                .collect(),
            tool_calls,
            completeness: ConversationProjection::completeness(!values.is_empty(), incomplete),
        }
    }
}
