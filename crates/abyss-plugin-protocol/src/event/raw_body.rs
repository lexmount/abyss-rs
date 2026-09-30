//! Lossless body bytes retained independently of parsed text and tool projections.

use serde::{Deserialize, Serialize};

/// Original body of one HTTP side, or ordered WebSocket messages on that side.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawBody {
    /// Transport determines whether parts are an HTTP body or WebSocket messages.
    pub transport: RawTransport,
    /// Ordered original bytes; no JSON reserialization or SSE delta merging.
    pub parts: Vec<RawBodyPart>,
}

/// One captured HTTP body or WebSocket message.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawBodyPart {
    /// Base64 encodes exact bytes, including whitespace and non-UTF8 data.
    pub content_base64: String,
    /// Number of retained bytes before base64 encoding.
    pub byte_size: u64,
    /// SHA-256 of retained bytes for end-to-end verification.
    pub sha256: String,
    /// True means the transport capture contains only a prefix, never a full body.
    pub truncated: bool,
    /// Original Content-Type header, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// Original Content-Encoding header, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_encoding: Option<String>,
    /// Per-flow WebSocket sequence; absent for HTTP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u64>,
}

/// Transport of the retained body.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RawTransport {
    Http,
    Websocket,
}
