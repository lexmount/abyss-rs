//! Protocol-neutral conversation assembly.
//!
//! Provider modules own wire shapes. While walking a body they emit one
//! [`ConversationEntry`] per protocol block or item, using the helpers here;
//! parsers read request and response content only from the result.

use abyss_plugin_protocol::event::{
    ContentCompleteness, Conversation, ConversationEntry, EntryRole,
};
use serde_json::Value;

use crate::protocol::model::text::{MAX_PARSE_DEPTH, json_to_text};

/// Constructors for public conversation values.
pub struct ConversationProjection;

impl ConversationProjection {
    /// Returns a completely decoded conversation without entries.
    #[must_use]
    pub const fn empty() -> Conversation {
        Conversation {
            entries: Vec::new(),
            completeness: ContentCompleteness::Complete,
        }
    }

    /// Builds a conversation from its entries.
    #[must_use]
    pub const fn from_entries(
        entries: Vec<ConversationEntry>,
        completeness: ContentCompleteness,
    ) -> Conversation {
        Conversation {
            entries,
            completeness,
        }
    }

    /// Returns the decoding state of one side; truncation outranks decoding.
    #[must_use]
    pub const fn completeness(decoded: bool, truncated: bool) -> ContentCompleteness {
        if truncated {
            ContentCompleteness::Partial
        } else if decoded {
            ContentCompleteness::Complete
        } else {
            ContentCompleteness::Unsupported
        }
    }

    /// Downgrades a completely decoded conversation after a decoding failure.
    pub fn mark_partial(conversation: &mut Conversation) {
        if conversation.completeness == ContentCompleteness::Complete {
            conversation.completeness = ContentCompleteness::Partial;
        }
    }

    /// Maps a provider message role onto the entry role of its text.
    ///
    /// `tool` and `function` map to [`EntryRole::ToolResult`]; callers that
    /// build entries handle tool messages before using this mapping.
    #[must_use]
    pub fn role(value: &str) -> EntryRole {
        match value.trim().to_ascii_lowercase().as_str() {
            "system" => EntryRole::System,
            "developer" => EntryRole::Developer,
            "user" | "human" => EntryRole::User,
            "assistant" => EntryRole::Assistant,
            "tool" | "function" => EntryRole::ToolResult,
            _ => EntryRole::Unknown,
        }
    }

    /// A text-bearing entry.
    #[must_use]
    pub fn text(role: EntryRole, text: &str) -> ConversationEntry {
        ConversationEntry {
            role,
            text: text.to_owned(),
            call_id: None,
            name: None,
            item_id: None,
        }
    }

    /// A tool-call entry; `input` is the arguments or input as sent.
    #[must_use]
    pub const fn tool_call(
        call_id: Option<String>,
        name: Option<String>,
        input: String,
    ) -> ConversationEntry {
        ConversationEntry {
            role: EntryRole::ToolCall,
            text: input,
            call_id,
            name,
            item_id: None,
        }
    }

    /// A tool-result entry.
    #[must_use]
    pub const fn tool_result(call_id: Option<String>, output: String) -> ConversationEntry {
        ConversationEntry {
            role: EntryRole::ToolResult,
            text: output,
            call_id,
            name: None,
            item_id: None,
        }
    }

    /// Gives every entry projected from one item that item's identity.
    pub fn identify(entries: &mut [ConversationEntry], item_id: Option<&str>) {
        for entry in entries {
            entry.item_id = item_id.map(str::to_owned);
        }
    }

    /// The entry of an unrecognized block or item: its visible text, or none
    /// when it carries no text.
    #[must_use]
    pub fn unknown(value: &Value) -> Option<ConversationEntry> {
        json_to_text(value, MAX_PARSE_DEPTH).map(|text| Self::text(EntryRole::Unknown, &text))
    }

    /// A string as sent, or the compact JSON of any other value.
    #[must_use]
    pub fn verbatim(value: &Value) -> String {
        match value {
            Value::String(text) => text.clone(),
            Value::Null => String::new(),
            value => serde_json::to_string(value).unwrap_or_default(),
        }
    }

    /// A string field of one object, as sent.
    #[must_use]
    pub fn field(value: &Value, key: &str) -> Option<String> {
        value.get(key).and_then(Value::as_str).map(str::to_owned)
    }
}

/// The role and text of every entry, in order, for test assertions.
#[cfg(test)]
pub fn role_texts(conversation: &Conversation) -> Vec<(EntryRole, &str)> {
    conversation
        .entries
        .iter()
        .map(|entry| (entry.role, entry.text.as_str()))
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn roles_map_to_the_public_role_set() {
        assert_eq!(ConversationProjection::role("Human"), EntryRole::User);
        assert_eq!(
            ConversationProjection::role("developer"),
            EntryRole::Developer
        );
        assert_eq!(ConversationProjection::role("other"), EntryRole::Unknown);
    }

    #[test]
    fn verbatim_keeps_strings_and_object_key_order() {
        assert_eq!(
            ConversationProjection::verbatim(&json!(" {\"b\": 1} ")),
            " {\"b\": 1} "
        );
        let object: serde_json::Value =
            serde_json::from_str(r#"{"command":"ls","b":1,"a":[2]}"#).unwrap();
        assert_eq!(
            ConversationProjection::verbatim(&object),
            r#"{"command":"ls","b":1,"a":[2]}"#
        );
        assert!(ConversationProjection::unknown(&json!({"type": "tool_addition"})).is_none());
    }
}
