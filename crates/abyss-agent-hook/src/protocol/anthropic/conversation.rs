//! Anthropic content projection shared by the Messages API and Claude Web.
//!
//! A content array is split into consecutive role groups: `thinking` and
//! `redacted_thinking` blocks become `reasoning` messages and every other block
//! stays with the enclosing message role, in provider order and with the
//! message id on each group. Request history and response assembly use the
//! same split, so identical content always projects to identical messages.
//! Tool blocks contribute no text; tool fields carry their content.

use std::collections::BTreeMap;

use abyss_plugin_protocol::event::{ContentCompleteness, Conversation, MessageRole};
use serde_json::Value;

use crate::protocol::model::{
    conversation::{ConversationProjection, MessageDraft},
    text::{MAX_PARSE_DEPTH, dedupe_texts, non_empty_trimmed, visible_text},
};

/// Anthropic-specific text and tool-block rules.
pub struct AnthropicContent;

impl AnthropicContent {
    /// Returns the visible text of a content value, skipping tool blocks.
    #[must_use]
    pub fn text(value: &Value, depth: usize) -> Option<String> {
        visible_text(value, depth, Self::is_tool_block)
    }

    /// Whether a block type carries tool calls or tool results.
    #[must_use]
    fn is_tool_block(block_type: &str) -> bool {
        matches!(block_type, "tool_use" | "tool_result")
            || block_type.ends_with("_tool_use")
            || block_type.ends_with("_tool_result")
    }

    fn blocks(content: &Value) -> Vec<ContentBlock> {
        match content {
            Value::Array(items) => items.iter().map(ContentBlock::from_value).collect(),
            Value::Null => Vec::new(),
            value => vec![ContentBlock::from_value(value)],
        }
    }

    /// Splits ordered blocks into consecutive role groups.
    fn groups<I>(blocks: I, role: MessageRole, id: Option<&str>) -> Vec<MessageDraft>
    where
        I: IntoIterator<Item = ContentBlock>,
    {
        let mut drafts: Vec<MessageDraft> = Vec::new();
        for block in blocks {
            let role = if block.reasoning {
                MessageRole::Reasoning
            } else {
                role
            };
            if drafts.last().is_none_or(|draft| draft.role != role) {
                drafts.push(MessageDraft::new(role, id.map(str::to_owned)));
            }
            if let Some(draft) = drafts.last_mut() {
                draft.push_part(&block.text);
            }
        }
        drafts
    }
}

/// One content block reduced to its conversation contribution.
struct ContentBlock {
    /// Whether the block is model reasoning.
    reasoning: bool,
    /// Visible text, possibly accumulated from streamed deltas.
    text: String,
}

impl ContentBlock {
    fn from_value(block: &Value) -> Self {
        match block.get("type").and_then(Value::as_str) {
            Some("thinking") => Self {
                reasoning: true,
                text: block["thinking"].as_str().unwrap_or_default().to_owned(),
            },
            Some("redacted_thinking") => Self {
                reasoning: true,
                text: String::new(),
            },
            Some(kind) if AnthropicContent::is_tool_block(kind) => Self {
                reasoning: false,
                text: String::new(),
            },
            _ => Self {
                reasoning: false,
                text: AnthropicContent::text(block, MAX_PARSE_DEPTH).unwrap_or_default(),
            },
        }
    }
}

/// Request-side messages, grouped by the request field that carried them.
pub struct AnthropicRequest {
    /// `system` prompt, including an explicitly empty one.
    system: Option<MessageDraft>,
    /// Legacy completion or Claude Web `prompt` string.
    prompt: Option<MessageDraft>,
    /// Non-standard `input` content.
    input: Option<MessageDraft>,
    /// Role groups of the `messages` history, in order.
    messages: Vec<MessageDraft>,
    /// Decoding state of the request body.
    completeness: ContentCompleteness,
}

impl AnthropicRequest {
    /// Projects one decoded request body.
    #[must_use]
    pub fn parse(payload: &Value, truncated: bool) -> Self {
        let system = payload.get("system").map(|system| {
            let mut draft = MessageDraft::new(MessageRole::System, None);
            for block in AnthropicContent::blocks(system) {
                draft.push_part(&block.text);
            }
            draft
        });
        let prompt = payload
            .get("prompt")
            .and_then(Value::as_str)
            .and_then(non_empty_trimmed)
            .map(|prompt| {
                let mut draft = MessageDraft::new(MessageRole::User, None);
                draft.push_part(prompt);
                draft
            });
        let input = payload.get("input").map(|input| {
            let role = if input.is_string() {
                MessageRole::User
            } else {
                MessageRole::Unknown
            };
            let mut draft = MessageDraft::new(role, None);
            draft.push_part(&AnthropicContent::text(input, MAX_PARSE_DEPTH).unwrap_or_default());
            draft
        });
        let messages = payload
            .get("messages")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .flat_map(|message| {
                let role = message
                    .get("role")
                    .and_then(Value::as_str)
                    .map_or(MessageRole::Unknown, ConversationProjection::role);
                AnthropicContent::groups(
                    AnthropicContent::blocks(message.get("content").unwrap_or(&Value::Null)),
                    role,
                    message.get("id").and_then(Value::as_str),
                )
            })
            .collect();
        Self {
            system,
            prompt,
            input,
            messages,
            completeness: ConversationProjection::completeness(true, truncated),
        }
    }

    /// Event text: the labeled system prompt, prompt, input, and user messages.
    #[must_use]
    pub fn texts(&self) -> Vec<String> {
        let mut texts = Vec::new();
        if let Some(system) = &self.system {
            let text = system.text();
            if !text.is_empty() {
                texts.push(format!("system: {text}"));
            }
        }
        texts.extend(
            self.prompt
                .iter()
                .chain(&self.input)
                .map(MessageDraft::text),
        );
        texts.extend(
            self.messages
                .iter()
                .filter(|draft| draft.role == MessageRole::User)
                .map(MessageDraft::text),
        );
        dedupe_texts(texts)
    }

    /// Public request conversation.
    #[must_use]
    pub fn conversation(&self) -> Conversation {
        let mut conversation = ConversationProjection::from_drafts(
            self.system
                .iter()
                .chain(&self.prompt)
                .chain(&self.input)
                .chain(&self.messages),
            self.completeness,
        );
        conversation.instructions_present = self.system.is_some();
        conversation
    }
}

/// Response-side messages assembled from JSON or streamed documents.
pub struct AnthropicResponse {
    /// Message id: `message_start.message.id` of a stream, or the top-level
    /// `id` of a whole message.
    id: Option<String>,
    /// Role groups of the assistant message.
    messages: Vec<MessageDraft>,
    /// Decoding state of the response body.
    completeness: ContentCompleteness,
}

impl AnthropicResponse {
    /// Assembles one response from its decoded documents.
    ///
    /// Streamed text and thinking deltas accumulate per block index; a
    /// non-streaming `content` array is authoritative when present.
    #[must_use]
    pub fn assemble(values: &[Value], incomplete: bool) -> Self {
        let mut blocks = BTreeMap::<u64, ContentBlock>::new();
        let mut snapshot = None;
        let mut id = None;
        for value in values {
            if let Some(message) = value.get("message") {
                id = message["id"].as_str().map(str::to_owned).or(id);
                if let Some(content) = message["content"].as_array() {
                    for (index, block) in content.iter().enumerate() {
                        blocks.insert(block_index(index), ContentBlock::from_value(block));
                    }
                }
            }
            if let Some(content) = value.get("content").and_then(Value::as_array) {
                snapshot = Some(
                    content
                        .iter()
                        .map(ContentBlock::from_value)
                        .collect::<Vec<_>>(),
                );
                id = value["id"].as_str().map(str::to_owned).or(id);
            }
            let index = value["index"].as_u64().unwrap_or(0);
            match value["type"].as_str() {
                Some("content_block_start") => {
                    if let Some(block) = value.get("content_block") {
                        blocks.insert(index, ContentBlock::from_value(block));
                    }
                }
                Some("content_block_delta") => {
                    let delta = &value["delta"];
                    let (reasoning, fragment) = match delta["type"].as_str() {
                        Some("text_delta") => (false, delta["text"].as_str()),
                        Some("thinking_delta") => (true, delta["thinking"].as_str()),
                        _ => continue,
                    };
                    if let Some(fragment) = fragment {
                        blocks
                            .entry(index)
                            .or_insert_with(|| ContentBlock {
                                reasoning,
                                text: String::new(),
                            })
                            .text
                            .push_str(fragment);
                    }
                }
                _ => {
                    // Legacy completion streams carry one text block.
                    if let Some(completion) = value.get("completion").and_then(Value::as_str) {
                        blocks
                            .entry(0)
                            .or_insert_with(|| ContentBlock {
                                reasoning: false,
                                text: String::new(),
                            })
                            .text
                            .push_str(completion);
                    }
                }
            }
        }
        let blocks = snapshot.unwrap_or_else(|| blocks.into_values().collect());
        Self {
            messages: AnthropicContent::groups(blocks, MessageRole::Assistant, id.as_deref()),
            id,
            completeness: ConversationProjection::completeness(!values.is_empty(), incomplete),
        }
    }

    /// The message id, shared by every message of the response.
    #[must_use]
    pub fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }

    /// Event text: assistant text blocks, excluding reasoning.
    #[must_use]
    pub fn texts(&self) -> Vec<String> {
        dedupe_texts(
            self.messages
                .iter()
                .filter(|draft| draft.role == MessageRole::Assistant)
                .flat_map(|draft| draft.parts.iter().cloned())
                .collect(),
        )
    }

    /// Public response conversation.
    #[must_use]
    pub fn conversation(&self) -> Conversation {
        ConversationProjection::from_drafts(&self.messages, self.completeness)
    }
}

fn block_index(position: usize) -> u64 {
    u64::try_from(position).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn response_splits_thinking_into_reasoning_messages_in_provider_order() {
        let values = vec![
            json!({"type":"message_start","message":{"id":"m1","content":[]}}),
            json!({"type":"content_block_start","index":0_i32,"content_block":{"type":"thinking","thinking":"think"}}),
            json!({"type":"content_block_delta","index":0_i32,"delta":{"type":"thinking_delta","thinking":"ing"}}),
            json!({"type":"content_block_delta","index":0_i32,"delta":{"type":"signature_delta","signature":"sig"}}),
            json!({"type":"content_block_start","index":1_i32,"content_block":{"type":"tool_use","id":"call1","name":"exec","input":{}}}),
            json!({"type":"content_block_delta","index":1_i32,"delta":{"type":"input_json_delta","partial_json":"{\"cmd\":\"pwd\"}"}}),
            json!({"type":"content_block_start","index":2_i32,"content_block":{"type":"text","text":"hel"}}),
            json!({"type":"content_block_delta","index":2_i32,"delta":{"type":"text_delta","text":"lo"}}),
        ];
        let response = AnthropicResponse::assemble(&values, false);
        let conversation = response.conversation();

        assert_eq!(conversation.messages.len(), 2);
        assert_eq!(conversation.messages[0].role, MessageRole::Reasoning);
        assert_eq!(conversation.messages[0].text, "thinking");
        assert_eq!(conversation.messages[1].role, MessageRole::Assistant);
        assert_eq!(conversation.messages[1].text, "hello");
        assert!(
            conversation
                .messages
                .iter()
                .all(|message| message.id.as_deref() == Some("m1"))
        );
        assert_eq!(response.texts(), vec!["hello"]);
    }

    #[test]
    fn request_history_and_response_project_identical_messages() {
        let content = json!([
            {"type":"thinking","thinking":"plan","signature":"sig"},
            {"type":"text","text":"answer"},
            {"type":"tool_use","id":"call1","name":"exec","input":{"cmd":"pwd"}},
            {"type":"redacted_thinking","data":"opaque"},
            {"type":"text","text":"more"}
        ]);
        let request = AnthropicRequest::parse(
            &json!({"messages":[
                {"role":"user","content":"hi"},
                {"role":"assistant","content":content}
            ]}),
            false,
        );
        let response =
            AnthropicResponse::assemble(&[json!({"id":"msg_1","content":content})], false);

        let history = request.conversation().messages;
        let reply = response.conversation().messages;
        assert_eq!(history.len(), 5);
        assert_eq!(history[0].role, MessageRole::User);
        assert_eq!(history.len().saturating_sub(1), reply.len());
        for (requested, responded) in history[1..].iter().zip(&reply) {
            assert_eq!(requested.role, responded.role);
            assert_eq!(requested.text, responded.text);
            assert_eq!(responded.id.as_deref(), Some("msg_1"));
        }
        assert_eq!(
            reply.iter().map(|message| message.role).collect::<Vec<_>>(),
            vec![
                MessageRole::Reasoning,
                MessageRole::Assistant,
                MessageRole::Reasoning,
                MessageRole::Assistant,
            ]
        );
        assert_eq!(reply[1].text, "answer");
        assert_eq!(response.texts(), vec!["answer", "more"]);
    }

    #[test]
    fn request_text_labels_system_and_keeps_only_user_messages() {
        let request = AnthropicRequest::parse(
            &json!({
                "system":[{"type":"text","text":"rules"}],
                "messages":[
                    {"role":"user","content":[{"type":"text","text":"a"},{"type":"text","text":"b"}]},
                    {"role":"assistant","content":"reply"},
                    {"role":"user","content":[{"type":"tool_result","tool_use_id":"t","content":"secret"}]}
                ]
            }),
            false,
        );
        let conversation = request.conversation();

        assert_eq!(request.texts(), vec!["system: rules", "a\nb"]);
        assert!(conversation.instructions_present);
        assert_eq!(conversation.messages[0].role, MessageRole::System);
        assert_eq!(conversation.messages[3].text, "");
    }
}
