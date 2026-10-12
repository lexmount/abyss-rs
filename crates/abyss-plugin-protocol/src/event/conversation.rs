//! Structured provider content; consumers never need to decode transport bodies.

use serde::{Deserialize, Serialize};

/// Content observed on one side of a provider exchange.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Conversation {
    /// Ordered messages, with streamed fragments assembled by the collector.
    pub messages: Vec<ConversationMessage>,
    /// Provider continuation reference; absence does not invent an identity.
    pub previous_response_id: Option<String>,
    /// Agent-declared source, such as `user` or `thread_title`.
    pub thread_source: Option<String>,
    /// Whether the request carried explicit instructions or a system prompt,
    /// including an explicitly empty one.
    pub instructions_present: bool,
    /// Whether the captured input could be completely decoded.
    pub completeness: ContentCompleteness,
    /// Whether content policy omitted messages from this projection.
    pub policy_omitted: bool,
}

/// A provider message or standalone item, preserving its role and order.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConversationMessage {
    /// Provider item/message identity, when supplied.
    pub id: Option<String>,
    /// Message role; reasoning and tool items use their own role.
    pub role: MessageRole,
    /// Text projection excluding tool arguments and results.
    pub text: String,
}

/// Role of one conversation message.
/// TODO Context.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum MessageRole {
    /// Provider system prompt.
    System,
    /// Developer instructions, including OpenAI `instructions`.
    Developer,
    /// End-user input.
    User,
    /// Model-visible assistant output.
    Assistant,
    /// Model reasoning, such as thinking blocks or reasoning summaries.
    Reasoning,
    /// Tool call or tool result item; its content is carried by tool fields.
    Tool,
    /// The provider did not declare a role.
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
    use super::{ContentCompleteness, Conversation, ConversationMessage, MessageRole};
    use serde_json::json;

    #[test]
    fn roles_use_the_published_snake_case_names() {
        let roles = [
            (MessageRole::System, "system"),
            (MessageRole::Developer, "developer"),
            (MessageRole::User, "user"),
            (MessageRole::Assistant, "assistant"),
            (MessageRole::Reasoning, "reasoning"),
            (MessageRole::Tool, "tool"),
            (MessageRole::Unknown, "unknown"),
        ];
        for (role, wire) in roles {
            assert_eq!(serde_json::to_value(role).unwrap(), wire);
            assert_eq!(
                serde_json::from_value::<MessageRole>(json!(wire)).unwrap(),
                role
            );
        }
        assert!(
            serde_json::from_value::<MessageRole>(json!("request")).is_err(),
            "the former placeholder role is replaced by `unknown`"
        );
    }

    #[test]
    fn anthropic_thinking_is_a_reasoning_message_sharing_the_message_id() {
        let conversation = Conversation {
            messages: vec![
                ConversationMessage {
                    id: Some("msg_1".to_owned()),
                    role: MessageRole::Reasoning,
                    text: "plan".to_owned(),
                },
                ConversationMessage {
                    id: Some("msg_1".to_owned()),
                    role: MessageRole::Assistant,
                    text: "hi".to_owned(),
                },
            ],
            previous_response_id: None,
            thread_source: None,
            instructions_present: false,
            completeness: ContentCompleteness::Complete,
            policy_omitted: false,
        };

        assert_eq!(
            serde_json::to_value(&conversation).unwrap(),
            json!({
                "messages": [
                    {"id": "msg_1", "role": "reasoning", "text": "plan"},
                    {"id": "msg_1", "role": "assistant", "text": "hi"}
                ],
                "previous_response_id": null,
                "thread_source": null,
                "instructions_present": false,
                "completeness": "complete",
                "policy_omitted": false
            })
        );
    }

    #[test]
    fn raw_content_carriers_are_rejected() {
        let conversation = json!({
            "messages": [{"id": null, "role": "user", "text": "hello"}],
            "previous_response_id": null,
            "thread_source": null,
            "instructions_present": true,
            "completeness": "partial",
            "policy_omitted": false
        });
        serde_json::from_value::<Conversation>(conversation.clone())
            .expect("the structured conversation should decode");

        let mut with_payloads = conversation.clone();
        with_payloads["payloads"] = json!([{"output": []}]);
        assert!(serde_json::from_value::<Conversation>(with_payloads).is_err());

        let mut with_blocks = conversation;
        with_blocks["messages"][0]["blocks"] = json!([{"type": "text", "text": "hello"}]);
        assert!(serde_json::from_value::<Conversation>(with_blocks).is_err());
    }
}
