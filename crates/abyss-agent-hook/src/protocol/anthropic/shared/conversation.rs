//! Anthropic content projection shared by the Messages API and Claude Web.
//!
//! Every content block is classified once, by the block-to-role table in
//! [`ContentBlock::from_value`], and yields one conversation entry. Request
//! history and response assembly use the same table, so identical content
//! always projects to identical entries. A thinking block's entry carries an
//! identity digested from the signature the provider issued, which the
//! client sends back unchanged, so replayed history matches the response
//! that produced it.

use std::collections::BTreeMap;

use abyss_plugin_protocol::event::{
    ContentCompleteness, Conversation, ConversationEntry, EntryRole,
};
use serde_json::Value;

use super::tools::tool_result_output;
use crate::protocol::{
    model::conversation::ConversationProjection,
    shared::{
        digest::sha256_hex,
        text::{MAX_PARSE_DEPTH, non_empty_trimmed, visible_text},
    },
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

    /// One entry per block, in order; text blocks take the message role.
    fn entries(
        blocks: &[ContentBlock],
        role: EntryRole,
    ) -> impl Iterator<Item = ConversationEntry> {
        blocks.iter().filter_map(move |block| block.entry(role))
    }
}

/// One content block, classified by the block-to-role table.
enum ContentBlock {
    /// `text`: the enclosing message's role.
    Text(String),
    /// `thinking` or `redacted_thinking`.
    Reasoning {
        text: String,
        /// What the block's identity is digested from: a `thinking` block's
        /// `signature`, accumulated from streamed `signature_delta`
        /// fragments, or a `redacted_thinking` block's `data`.
        signature: String,
    },
    /// `tool_use`, `server_tool_use`, or `mcp_tool_use`.
    ToolCall {
        call_id: Option<String>,
        name: Option<String>,
        /// The block's `input` as sent.
        input: String,
        /// Input accumulated from streamed `input_json_delta` fragments.
        streamed_input: String,
    },
    /// `tool_result` or any `*_tool_result`.
    ToolResult {
        call_id: Option<String>,
        output: String,
    },
    /// Any other block, with its visible text when it has some, in the
    /// enclosing message's role.
    Other(Option<String>),
}

impl ContentBlock {
    fn from_value(block: &Value) -> Self {
        if let Value::String(text) = block {
            return Self::Text(text.clone());
        }
        let field = |key| ConversationProjection::field(block, key);
        match block.get("type").and_then(Value::as_str) {
            Some("text") => Self::Text(field("text").unwrap_or_default()),
            Some("thinking") => Self::Reasoning {
                text: field("thinking").unwrap_or_default(),
                signature: field("signature").unwrap_or_default(),
            },
            Some("redacted_thinking") => Self::Reasoning {
                text: String::new(),
                signature: field("data").unwrap_or_default(),
            },
            Some("tool_use" | "server_tool_use" | "mcp_tool_use") => Self::ToolCall {
                call_id: field("id"),
                name: field("name"),
                input: block
                    .get("input")
                    .map(ConversationProjection::verbatim)
                    .unwrap_or_default(),
                streamed_input: String::new(),
            },
            Some(kind) if kind == "tool_result" || kind.ends_with("_tool_result") => {
                Self::ToolResult {
                    call_id: field("tool_use_id"),
                    output: block
                        .get("content")
                        .map(tool_result_output)
                        .unwrap_or_default(),
                }
            }
            _ => Self::Other(AnthropicContent::text(block, MAX_PARSE_DEPTH)),
        }
    }

    /// Applies one streamed `content_block_delta`.
    fn push_delta(blocks: &mut BTreeMap<u64, Self>, index: u64, delta: &Value) {
        let fragment = |key| delta.get(key).and_then(Value::as_str);
        match (delta["type"].as_str(), blocks.get_mut(&index)) {
            (Some("text_delta"), Some(Self::Text(text))) => {
                text.push_str(fragment("text").unwrap_or_default());
            }
            (Some("thinking_delta"), Some(Self::Reasoning { text, .. })) => {
                text.push_str(fragment("thinking").unwrap_or_default());
            }
            (Some("signature_delta"), Some(Self::Reasoning { signature, .. })) => {
                signature.push_str(fragment("signature").unwrap_or_default());
            }
            (Some("input_json_delta"), Some(Self::ToolCall { streamed_input, .. })) => {
                streamed_input.push_str(fragment("partial_json").unwrap_or_default());
            }
            // A delta whose block start was not captured starts the block.
            (Some("text_delta"), None) => {
                blocks.insert(
                    index,
                    Self::Text(fragment("text").unwrap_or_default().to_owned()),
                );
            }
            (Some("thinking_delta"), None) => {
                blocks.insert(
                    index,
                    Self::Reasoning {
                        text: fragment("thinking").unwrap_or_default().to_owned(),
                        signature: String::new(),
                    },
                );
            }
            (Some("signature_delta"), None) => {
                blocks.insert(
                    index,
                    Self::Reasoning {
                        text: String::new(),
                        signature: fragment("signature").unwrap_or_default().to_owned(),
                    },
                );
            }
            (Some("input_json_delta"), None) => {
                blocks.insert(
                    index,
                    Self::ToolCall {
                        call_id: None,
                        name: None,
                        input: String::new(),
                        streamed_input: fragment("partial_json").unwrap_or_default().to_owned(),
                    },
                );
            }
            _ => {}
        }
    }

    /// The block's entry; an unrecognized block without text has none.
    fn entry(&self, role: EntryRole) -> Option<ConversationEntry> {
        Some(match self {
            Self::Text(text) => ConversationProjection::text(role, text),
            Self::Reasoning { text, signature } => ConversationEntry {
                item_id: thinking_identity(signature),
                ..ConversationProjection::text(EntryRole::Reasoning, text)
            },
            Self::ToolCall {
                call_id,
                name,
                input,
                streamed_input,
            } => ConversationProjection::tool_call(
                call_id.clone(),
                name.clone(),
                if streamed_input.is_empty() {
                    input.clone()
                } else {
                    streamed_input.clone()
                },
            ),
            Self::ToolResult { call_id, output } => {
                ConversationProjection::tool_result(call_id.clone(), output.clone())
            }
            Self::Other(text) => ConversationProjection::text(role, text.as_deref()?),
        })
    }
}

/// Request-side entries.
pub struct AnthropicRequest {
    /// One entry per block: `system`, `prompt`, `input`, then `messages`.
    entries: Vec<ConversationEntry>,
    /// Decoding state of the request body.
    completeness: ContentCompleteness,
}

impl AnthropicRequest {
    /// Projects one decoded request body.
    #[must_use]
    pub fn parse(payload: &Value, truncated: bool) -> Self {
        let mut entries = Vec::new();
        if let Some(system) = payload.get("system") {
            entries.extend(AnthropicContent::entries(
                &AnthropicContent::blocks(system),
                EntryRole::System,
            ));
        }
        if let Some(prompt) = payload
            .get("prompt")
            .and_then(Value::as_str)
            .filter(|prompt| non_empty_trimmed(prompt).is_some())
        {
            entries.push(ConversationProjection::text(EntryRole::User, prompt));
        }
        if let Some(input) = payload.get("input") {
            let role = if input.is_string() {
                EntryRole::User
            } else {
                EntryRole::Unknown
            };
            entries.extend(AnthropicContent::entries(
                &AnthropicContent::blocks(input),
                role,
            ));
        }
        for message in payload
            .get("messages")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let role = message
                .get("role")
                .and_then(Value::as_str)
                .map_or(EntryRole::Unknown, ConversationProjection::role);
            let blocks = AnthropicContent::blocks(message.get("content").unwrap_or(&Value::Null));
            entries.extend(AnthropicContent::entries(&blocks, role));
        }
        Self {
            entries,
            completeness: ConversationProjection::completeness(true, truncated),
        }
    }

    /// Public request conversation.
    #[must_use]
    pub fn conversation(&self) -> Conversation {
        ConversationProjection::from_entries(self.entries.clone(), self.completeness)
    }
}

/// Response-side entries assembled from JSON or streamed documents.
pub struct AnthropicResponse {
    /// Message id: `message_start.message.id` of a stream, or the top-level
    /// `id` of a whole message.
    id: Option<String>,
    /// One entry per content block of the assistant message.
    entries: Vec<ConversationEntry>,
    /// Decoding state of the response body.
    completeness: ContentCompleteness,
}

impl AnthropicResponse {
    /// Assembles one response from its decoded documents.
    ///
    /// Streamed text, thinking, and tool-input deltas accumulate per block
    /// index; a non-streaming `content` array is authoritative when present.
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
                    ContentBlock::push_delta(&mut blocks, index, &value["delta"]);
                }
                _ => {
                    // Legacy completion streams carry one text block.
                    if let Some(completion) = value.get("completion").and_then(Value::as_str) {
                        let block = blocks
                            .entry(0)
                            .or_insert_with(|| ContentBlock::Text(String::new()));
                        if let ContentBlock::Text(text) = block {
                            text.push_str(completion);
                        }
                    }
                }
            }
        }
        let blocks = snapshot.unwrap_or_else(|| blocks.into_values().collect());
        Self {
            entries: AnthropicContent::entries(&blocks, EntryRole::Assistant).collect(),
            id,
            completeness: ConversationProjection::completeness(!values.is_empty(), incomplete),
        }
    }

    /// The message id of the response.
    #[must_use]
    pub fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }

    /// Public response conversation.
    #[must_use]
    pub fn conversation(&self) -> Conversation {
        ConversationProjection::from_entries(self.entries.clone(), self.completeness)
    }
}

/// The identity of a thinking block: `thinking:` and the hex SHA-256 of its
/// signature, or none when the block carries no signature.
fn thinking_identity(signature: &str) -> Option<String> {
    (!signature.is_empty()).then(|| format!("thinking:{}", sha256_hex(signature)))
}

fn block_index(position: usize) -> u64 {
    u64::try_from(position).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn summary(conversation: &Conversation) -> Vec<(EntryRole, &str, Option<&str>, Option<&str>)> {
        conversation
            .entries
            .iter()
            .map(|entry| {
                (
                    entry.role,
                    entry.text.as_str(),
                    entry.call_id.as_deref(),
                    entry.name.as_deref(),
                )
            })
            .collect()
    }

    #[test]
    fn streamed_response_yields_one_entry_per_block_in_order() {
        let values = vec![
            json!({"type":"message_start","message":{"id":"m1","content":[]}}),
            json!({"type":"content_block_start","index":0_i32,"content_block":{"type":"thinking","thinking":"think"}}),
            json!({"type":"content_block_delta","index":0_i32,"delta":{"type":"thinking_delta","thinking":"ing"}}),
            json!({"type":"content_block_delta","index":0_i32,"delta":{"type":"signature_delta","signature":"sig"}}),
            json!({"type":"content_block_start","index":1_i32,"content_block":{"type":"tool_use","id":"call1","name":"exec","input":{}}}),
            json!({"type":"content_block_delta","index":1_i32,"delta":{"type":"input_json_delta","partial_json":"{\"cmd\": "}}),
            json!({"type":"content_block_delta","index":1_i32,"delta":{"type":"input_json_delta","partial_json":"\"pwd\"}"}}),
            json!({"type":"content_block_start","index":2_i32,"content_block":{"type":"text","text":"hel"}}),
            json!({"type":"content_block_delta","index":2_i32,"delta":{"type":"text_delta","text":"lo"}}),
        ];
        let response = AnthropicResponse::assemble(&values, false);

        assert_eq!(
            summary(&response.conversation()),
            [
                (EntryRole::Reasoning, "thinking", None, None),
                (
                    EntryRole::ToolCall,
                    "{\"cmd\": \"pwd\"}",
                    Some("call1"),
                    Some("exec")
                ),
                (EntryRole::Assistant, "hello", None, None),
            ]
        );
        assert_eq!(response.id(), Some("m1"));
    }

    #[test]
    fn request_history_and_response_project_identical_entries() {
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

        let history = request.conversation().entries;
        let reply = response.conversation().entries;
        assert_eq!(
            history[0],
            ConversationProjection::text(EntryRole::User, "hi")
        );
        assert_eq!(history[1..], reply[..]);
        assert_eq!(
            reply.iter().map(|entry| entry.role).collect::<Vec<_>>(),
            [
                EntryRole::Reasoning,
                EntryRole::Assistant,
                EntryRole::ToolCall,
                EntryRole::Reasoning,
                EntryRole::Assistant,
            ]
        );
        assert_eq!(reply[2].text, "{\"cmd\":\"pwd\"}");
        assert_eq!(reply[3].text, "");
        assert_eq!(
            reply
                .iter()
                .map(|entry| entry.item_id.clone())
                .collect::<Vec<_>>(),
            [
                Some(format!("thinking:{}", sha256_hex("sig"))),
                None,
                None,
                Some(format!("thinking:{}", sha256_hex("opaque"))),
                None,
            ]
        );
    }

    #[test]
    fn streamed_thinking_identity_digests_the_complete_signature() {
        let signature = "EqQBCkYIBxgCKkDsignature/fragments==";
        let values = vec![
            json!({"type":"message_start","message":{"id":"msg_1","content":[]}}),
            json!({"type":"content_block_start","index":0_i32,"content_block":{"type":"thinking","thinking":"","signature":""}}),
            json!({"type":"content_block_delta","index":0_i32,"delta":{"type":"signature_delta","signature":&signature[..12]}}),
            json!({"type":"content_block_delta","index":0_i32,"delta":{"type":"signature_delta","signature":&signature[12..]}}),
            json!({"type":"content_block_start","index":1_i32,"content_block":{"type":"text","text":""}}),
            json!({"type":"content_block_delta","index":1_i32,"delta":{"type":"text_delta","text":"done"}}),
            json!({"type":"content_block_start","index":2_i32,"content_block":{"type":"redacted_thinking","data":"opaque"}}),
            // A thinking block whose signature was not captured has no identity.
            json!({"type":"content_block_start","index":3_i32,"content_block":{"type":"thinking","thinking":"","signature":""}}),
            json!({"type":"content_block_delta","index":3_i32,"delta":{"type":"thinking_delta","thinking":"cut"}}),
        ];
        let reply = AnthropicResponse::assemble(&values, true)
            .conversation()
            .entries;
        // The blocks as the next request sends them back.
        let history = AnthropicRequest::parse(
            &json!({"messages":[
                {"role":"user","content":"question"},
                {"role":"assistant","content":[
                    {"type":"thinking","thinking":"","signature":signature},
                    {"type":"text","text":"done"},
                    {"type":"redacted_thinking","data":"opaque"}
                ]},
                {"role":"user","content":"next"}
            ]}),
            false,
        )
        .conversation()
        .entries;

        // Thinking blocks yield entries even without readable text.
        assert_eq!(
            summary(&ConversationProjection::from_entries(
                reply.clone(),
                ContentCompleteness::Partial
            )),
            [
                (EntryRole::Reasoning, "", None, None),
                (EntryRole::Assistant, "done", None, None),
                (EntryRole::Reasoning, "", None, None),
                (EntryRole::Reasoning, "cut", None, None),
            ]
        );
        assert_eq!(
            reply[0].item_id,
            Some(format!("thinking:{}", sha256_hex(signature)))
        );
        assert_eq!(reply[3].item_id, None);
        assert_eq!(history[1..4], reply[..3]);
    }

    #[test]
    fn request_follows_the_block_table() {
        let request = AnthropicRequest::parse(
            &json!({
                "system":[
                    {"type":"text","text":"x-anthropic-billing-header: cc_version=1;"},
                    {"type":"text","text":"rules"}
                ],
                "messages":[
                    {"role":"user","content":[
                        {"type":"text","text":" a "},
                        {"type":"image","source":{"type":"base64","media_type":"image/png","data":"AA=="}},
                        {"type":"text","text":"b"}
                    ]},
                    {"role":"assistant","content":[
                        {"type":"server_tool_use","id":"srv_1","name":"web_search","input":{"query":"q"}},
                        {"type":"web_search_tool_result","tool_use_id":"srv_1","content":[{"type":"web_search_result","url":"u"}]},
                        {"type":"tool_addition","tool":{"name":"x"}},
                        {"type":"future_block","text":"future text"}
                    ]},
                    {"role":"user","content":[
                        {"type":"tool_result","tool_use_id":"srv_1","content":[{"type":"text","text":"out"}]}
                    ]},
                    {"role":"system","content":[{"type":"text","text":"<total_tokens>1</total_tokens>"}]}
                ]
            }),
            false,
        );

        assert_eq!(
            summary(&request.conversation()),
            [
                (
                    EntryRole::System,
                    "x-anthropic-billing-header: cc_version=1;",
                    None,
                    None
                ),
                (EntryRole::System, "rules", None, None),
                (EntryRole::User, " a ", None, None),
                (EntryRole::User, "b", None, None),
                (
                    EntryRole::ToolCall,
                    "{\"query\":\"q\"}",
                    Some("srv_1"),
                    Some("web_search")
                ),
                (
                    EntryRole::ToolResult,
                    "{\"type\":\"web_search_result\",\"url\":\"u\"}",
                    Some("srv_1"),
                    None
                ),
                (EntryRole::Assistant, "future text", None, None),
                (EntryRole::ToolResult, "out", Some("srv_1"), None),
                (
                    EntryRole::System,
                    "<total_tokens>1</total_tokens>",
                    None,
                    None
                ),
            ]
        );
    }
}
