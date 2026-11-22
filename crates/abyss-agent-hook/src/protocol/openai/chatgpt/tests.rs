use abyss_plugin_protocol::event::ContentCompleteness;
use serde_json::{Value, json};

use super::*;

fn snapshot(id: &str, hidden: bool) -> Value {
    json!({"message":{"id":id,"author":{"role":"assistant"},"channel":"final",
        "metadata":{"is_visually_hidden_from_conversation":hidden,"model_slug":"actual-model"},
        "content":{"content_type":"text","parts":[""]}}})
}

#[test]
fn interleaved_deltas_reuse_coordinates_and_preserve_visible_identity() {
    let frames = [
        json!({"c":5_u64,"o":"add","v":snapshot("hidden", true)}),
        json!({"c":9_u64,"v":snapshot("visible", false)}),
        json!({"c":5_u64,"p":"","o":"patch","v":[{"p":"/message/content/parts/0","o":"append","v":"mirror"}]}),
        json!({"c":9_u64,"v":[{"p":"/message/content/parts/0","o":"append","v":"first"},
                           {"p":"/message/metadata","o":"append","v":{"model_slug":"updated-model"}},
                           {"p":"/message/content/parts/-","o":"add","v":"typo"},
                           {"p":"/message/content/parts/1","o":"replace","v":" second"},
                           {"p":"/message/content/parts/0","o":"remove"}]}),
        json!({"p":"/message/content/parts/0","o":"append","v":"!"}),
        json!({"type":"message_stream_complete","conversation_id":"chat-session"}),
    ];
    let parsed = ChatGptParser::parse_response(ResponseInput {
        capture_truncated: true,
        ..ResponseInput::new(&frames)
    });
    assert_eq!(
        parsed.conversation.completeness,
        ContentCompleteness::Complete
    );
    assert_eq!(parsed.conversation.entries.len(), 1);
    assert_eq!(parsed.conversation.entries[0].text, " second!");
    assert_eq!(parsed.response_id.as_deref(), Some("visible"));
    assert_eq!(parsed.model.as_deref(), Some("updated-model"));
    assert_eq!(parsed.session_id.as_deref(), Some("chat-session"));
    assert!(parsed.usage.is_none());

    let early = ChatGptParser::parse_response(ResponseInput {
        capture_truncated: true,
        ..ResponseInput::new(&frames[..5])
    });
    assert_eq!(
        early.conversation.completeness,
        ContentCompleteness::Partial
    );
    let lost = ChatGptParser::parse_response(ResponseInput {
        decode_failed: true,
        ..ResponseInput::new(&frames)
    });
    assert_eq!(lost.conversation.completeness, ContentCompleteness::Partial);
}

#[test]
fn only_visible_user_input_contributes_to_the_request() {
    let user = json!({"id":"u","author":{"role":"user"},
        "content":{"content_type":"multimodal_text","parts":["a",{"content_type":"text","text":"b"}]}});
    let payload =
        json!({"messages":[user, snapshot("a", false)["message"]],"parent_message_id":"root"});
    let request = ChatGptParser::parse_request(Some(&payload), false);
    assert_eq!(request.conversation.entries.len(), 1);
    assert_eq!(request.conversation.entries[0].text, "ab");
    assert!(request.metadata.previous_response_id.is_none());
    let mut next = payload;
    next["conversation_id"] = json!("thread");
    next["parent_message_id"] = json!("previous-answer");
    assert_eq!(
        ChatGptParser::parse_request(Some(&next), false)
            .metadata
            .previous_response_id
            .as_deref(),
        Some("previous-answer")
    );
}
