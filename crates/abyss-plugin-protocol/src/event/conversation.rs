//! Structured provider content; consumers never need to decode transport bodies.

use serde::{Deserialize, Serialize};

/// Content observed on one side of a provider exchange.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Conversation {
    /// One entry per protocol block or item, in provider order, never merged
    /// or split.
    pub entries: Vec<ConversationEntry>,
    /// Whether the captured body could be completely decoded.
    pub completeness: ContentCompleteness,
}

/// One protocol block or item.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConversationEntry {
    /// What the block is, by the protocol block-to-role table.
    pub role: EntryRole,
    /// Visible text; a tool call's arguments or input as sent, a tool result's
    /// output.
    pub text: String,
    /// Identifier pairing a tool call with its result; tool entries only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_id: Option<String>,
    /// Tool name; tool calls only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Identity of the item the entry belongs to, as the traffic carries it.
    /// A model output keeps the identity its provider assigned when a later
    /// request sends it back as history, so the request entry and the
    /// response entry that produced it carry the same value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_id: Option<String>,
}

/// Role of one conversation entry.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EntryRole {
    /// System prompt block.
    System,
    /// Developer message part.
    Developer,
    /// End-user text.
    User,
    /// Model-visible assistant text.
    Assistant,
    /// Model reasoning, such as thinking blocks or reasoning summaries.
    Reasoning,
    /// A tool call; `text` is its arguments or input.
    ToolCall,
    /// A tool result; `text` is its output.
    ToolResult,
    /// Any other block or item that carries text.
    Unknown,
}

/// Decoding state independent of successful provider execution.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ContentCompleteness {
    /// Captured documents were decoded completely.
    Complete,
    /// Capture or document decoding is incomplete.
    Partial,
    /// No supported structured document could be decoded.
    Unsupported,
}

#[cfg(test)]
mod tests {
    use super::{ContentCompleteness, Conversation, ConversationEntry, EntryRole};
    use serde_json::json;

    #[test]
    fn roles_use_the_published_snake_case_names() {
        let roles = [
            (EntryRole::System, "system"),
            (EntryRole::Developer, "developer"),
            (EntryRole::User, "user"),
            (EntryRole::Assistant, "assistant"),
            (EntryRole::Reasoning, "reasoning"),
            (EntryRole::ToolCall, "tool_call"),
            (EntryRole::ToolResult, "tool_result"),
            (EntryRole::Unknown, "unknown"),
        ];
        for (role, wire) in roles {
            assert_eq!(serde_json::to_value(role).unwrap(), wire);
            assert_eq!(
                serde_json::from_value::<EntryRole>(json!(wire)).unwrap(),
                role
            );
        }
        assert!(serde_json::from_value::<EntryRole>(json!("tool")).is_err());
    }

    #[test]
    fn identities_are_omitted_when_absent() {
        let conversation = Conversation {
            entries: vec![
                ConversationEntry {
                    role: EntryRole::User,
                    text: "run pwd".to_owned(),
                    call_id: None,
                    name: None,
                    item_id: None,
                },
                ConversationEntry {
                    role: EntryRole::ToolCall,
                    text: "{\"cmd\":\"pwd\"}".to_owned(),
                    call_id: Some("call_1".to_owned()),
                    name: Some("exec".to_owned()),
                    item_id: Some("fc_1".to_owned()),
                },
            ],
            completeness: ContentCompleteness::Complete,
        };

        assert_eq!(
            serde_json::to_value(&conversation).unwrap(),
            json!({
                "entries": [
                    {"role": "user", "text": "run pwd"},
                    {"role": "tool_call", "text": "{\"cmd\":\"pwd\"}", "call_id": "call_1", "name": "exec", "item_id": "fc_1"}
                ],
                "completeness": "complete"
            })
        );
    }

    #[test]
    fn retired_and_raw_fields_are_rejected() {
        let conversation = json!({
            "entries": [{"role": "user", "text": "hello"}],
            "completeness": "partial"
        });
        serde_json::from_value::<Conversation>(conversation.clone())
            .expect("the structured conversation should decode");

        for (path, value) in [
            ("messages", json!([])),
            ("instructions_present", json!(true)),
            ("policy_omitted", json!(false)),
            ("payloads", json!([{"output": []}])),
        ] {
            let mut retired = conversation.clone();
            retired[path] = value;
            assert!(
                serde_json::from_value::<Conversation>(retired).is_err(),
                "{path}"
            );
        }
        let mut with_id = conversation;
        with_id["entries"][0]["id"] = json!("m1");
        assert!(serde_json::from_value::<Conversation>(with_id).is_err());
    }
}
