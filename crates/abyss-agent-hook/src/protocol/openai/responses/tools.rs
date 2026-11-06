//! Responses `*_call` items and the `*_output` items that answer them.

use serde_json::Value;

use abyss_plugin_protocol::event::ConversationEntry;

use crate::protocol::{
    model::conversation::ConversationProjection,
    openai::shared::{content::output_text, output::CallSlot},
};

/// The tool-call entry of one `*_call` item.
pub fn call_entry(item: &Value) -> ConversationEntry {
    ConversationProjection::tool_call(
        ConversationProjection::field(item, "call_id"),
        ConversationProjection::field(item, "name"),
        call_input(item),
    )
}

/// The tool-result entry of one `*_output` item.
pub fn output_entry(item: &Value) -> ConversationEntry {
    ConversationProjection::tool_result(
        ConversationProjection::field(item, "call_id"),
        item.get("output").map(output_text).unwrap_or_default(),
    )
}

/// The arguments or input of one `*_call` item, as sent.
fn call_input(item: &Value) -> String {
    [
        "arguments",
        "input",
        "action",
        "code",
        "queries",
        "operation",
    ]
    .iter()
    .find_map(|key| item.get(*key))
    .map(ConversationProjection::verbatim)
    .unwrap_or_default()
}

/// Reconciles a call with one `*_call` item snapshot.
pub fn reconcile_call(call: &mut CallSlot, item: &Value) {
    let field = |key| ConversationProjection::field(item, key);
    call.call_id = field("call_id").or_else(|| call.call_id.take());
    call.name = field("name").or_else(|| call.name.take());
    let input = call_input(item);
    if !input.is_empty() {
        call.input = input;
    }
}
