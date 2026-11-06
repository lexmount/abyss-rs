//! Chat Completions `choices`, whole or as streamed deltas, assembled per
//! choice index. A choice contributes its `reasoning_content`, its content,
//! its `refusal`, then its tool calls.

use std::collections::BTreeMap;

use abyss_plugin_protocol::event::{ConversationEntry, EntryRole};
use serde_json::Value;

use super::tools::ChatToolCalls;
use crate::protocol::{
    model::conversation::ConversationProjection,
    openai::shared::{
        output::{MessageParts, reconcile},
        response::OpenAiResponse,
    },
};

/// One choice under assembly.
#[derive(Default)]
struct ChatChoice {
    /// Thinking that compatible APIs return in `reasoning_content`.
    reasoning: String,
    content: MessageParts,
    refusal: String,
    tools: ChatToolCalls,
}

impl ChatChoice {
    /// Reconciles the choice with a whole `message`.
    fn reconcile(&mut self, message: &Value) {
        let field = |key| message.get(key).and_then(Value::as_str).unwrap_or_default();
        reconcile(&mut self.reasoning, field("reasoning_content"));
        self.content.reconcile_content(message);
        reconcile(&mut self.refusal, field("refusal"));
        self.tools.reconcile(message);
    }

    /// Accumulates one streamed `delta`.
    fn apply_delta(&mut self, delta: &Value) {
        let fragment = |key| delta.get(key).and_then(Value::as_str);
        if let Some(reasoning) = fragment("reasoning_content") {
            self.reasoning.push_str(reasoning);
        }
        if let Some(content) = fragment("content").filter(|content| !content.is_empty())
            && let Some(text) = self.content.text_part(0)
        {
            text.push_str(content);
        }
        if let Some(refusal) = fragment("refusal") {
            self.refusal.push_str(refusal);
        }
        self.tools.apply_delta(delta);
    }

    fn entries(&self) -> impl Iterator<Item = ConversationEntry> + '_ {
        let text =
            |role, text: &str| (!text.is_empty()).then(|| ConversationProjection::text(role, text));
        text(EntryRole::Reasoning, &self.reasoning)
            .into_iter()
            .chain(self.content.entries(EntryRole::Assistant))
            .chain(text(EntryRole::Assistant, &self.refusal))
            .chain(self.tools.entries())
    }
}

/// Chat Completions choice assembly.
pub struct ChatResponse;

impl ChatResponse {
    /// Assembles one response from its decoded documents in arrival order.
    #[must_use]
    pub fn assemble(values: &[Value], incomplete: bool) -> OpenAiResponse {
        let mut choices = BTreeMap::<u64, ChatChoice>::new();
        for choice in values
            .iter()
            .filter_map(|value| value.get("choices").and_then(Value::as_array))
            .flatten()
        {
            let slot = choices
                .entry(choice["index"].as_u64().unwrap_or(0))
                .or_default();
            if let Some(message) = choice.get("message") {
                slot.reconcile(message);
            }
            if let Some(delta) = choice.get("delta") {
                slot.apply_delta(delta);
            }
            // Legacy completion choices carry their text directly.
            if let Some(text) = choice
                .get("text")
                .and_then(Value::as_str)
                .filter(|text| !text.is_empty())
                && let Some(part) = slot.content.text_part(0)
            {
                part.push_str(text);
            }
        }
        OpenAiResponse {
            empty: choices.is_empty(),
            entries: choices.values().flat_map(ChatChoice::entries).collect(),
            completeness: ConversationProjection::completeness(!values.is_empty(), incomplete),
        }
    }
}
