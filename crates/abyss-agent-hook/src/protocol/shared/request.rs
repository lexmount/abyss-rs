//! Common request metadata extraction, without protocol selection or dispatch.

use serde_json::Value;

use super::json::string_field;
use crate::protocol::model::request::RequestMetadata;

impl RequestMetadata {
    pub fn parse(payload: Option<&Value>) -> Self {
        Self {
            model: payload
                .and_then(|value| string_field(value, "model"))
                .map(str::to_owned),
            tool_definitions: payload.and_then(|value| value.get("tools")).cloned(),
            previous_response_id: payload
                .and_then(|value| string_field(value, "previous_response_id"))
                .map(str::to_owned),
            client_metadata: payload
                .and_then(|value| value.get("client_metadata"))
                .cloned(),
        }
    }
}
