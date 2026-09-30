//! Capture body bytes before parsing, retaining exact payloads and completeness.

use abyss_mitm::{CapturedBody, WebSocketMessage};
use abyss_plugin_protocol::event::{RawBody, RawBodyPart, RawTransport};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use http::HeaderMap;
use sha2::{Digest as _, Sha256};

use crate::config::HarnessUsageContentConfig;

/// Each observed body is a distinct record, even for identical provider retries.
/// Delivery retries reuse this event and its id after it enters the spool.
pub fn attach(event: &mut crate::event::NormalizedUsageEvent, body: RawBody) {
    event.event_id = format!("evt_{}", uuid::Uuid::new_v4().simple());
    event.raw_body = Some(body);
}

/// A raw body contains every category; never bypass an independent content gate.
pub const fn enabled(content: &HarnessUsageContentConfig) -> bool {
    content.conversation_text && content.tool_calls && content.images
}

pub fn http(body: &CapturedBody, headers: &HeaderMap) -> RawBody {
    let mut part = part(body.bytes());
    part.truncated = body.truncated();
    part.content_type = header(headers, "content-type");
    part.content_encoding = header(headers, "content-encoding");
    RawBody {
        transport: RawTransport::Http,
        parts: vec![part],
    }
}

pub fn websocket(message: &WebSocketMessage) -> RawBodyPart {
    let bytes = message
        .binary
        .as_deref()
        .or_else(|| message.text.as_deref().map(str::as_bytes))
        .unwrap_or_default();
    let mut part = part(bytes);
    part.sequence = Some(message.sequence);
    part
}

fn part(bytes: &[u8]) -> RawBodyPart {
    RawBodyPart {
        content_base64: STANDARD.encode(bytes),
        byte_size: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        sha256: hex::encode(Sha256::digest(bytes)),
        truncated: false,
        content_type: None,
        content_encoding: None,
        sequence: None,
    }
}

fn header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_body_obeys_every_content_gate() {
        for conversation_text in [false, true] {
            for tool_calls in [false, true] {
                for images in [false, true] {
                    assert_eq!(
                        enabled(&HarnessUsageContentConfig {
                            token_usage: false,
                            conversation_text,
                            tool_calls,
                            images
                        }),
                        conversation_text && tool_calls && images
                    );
                }
            }
        }
    }
}
