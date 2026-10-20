//! Raw HTTP capture and the separately decoded observation view.
//! Original headers describe raw bytes; content decoding never changes wire traffic.

use bytes::Bytes;
use serde_json::Value;

/// State of the content-decoded observation view, independent of network relay.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum BodyDecodingStatus {
    /// Encoded content has been captured but not yet processed by the hook worker.
    Pending,
    /// The full representation was decoded, or required no content decoding.
    Complete,
    /// Only a prefix is available because an input or output capture limit was hit.
    Truncated,
    /// The content coding is unsupported.
    UnsupportedEncoding,
    /// The encoding header is malformed.
    InvalidEncoding,
    /// A transfer coding other than chunked was not decoded by the relay.
    UnsupportedTransferEncoding,
    /// The encoded representation is corrupt or incomplete on the wire.
    InvalidData,
    /// The coding chain or processing time exceeded the decoder budget.
    BudgetExceeded,
}

/// Captured HTTP body made available to hooks.
///
/// The bytes may be a configured-size prefix of the decoded HTTP body when the
/// original message exceeded the relay capture budget. Network relay remains
/// independent from this representation and still forwards the full body.
#[derive(Debug, Clone)]
pub struct CapturedBody {
    raw_bytes: Bytes,
    raw_truncated: bool,
    pub(super) decode_limit: usize,
    status: BodyDecodingStatus,
    /// Decoded HTTP body bytes retained for hooks.
    bytes: Bytes,
    /// Whether the observation is incomplete because of capture limits or decoding state.
    truncated: bool,
    /// Best-effort structured view for JSON object/array payloads.
    ///
    /// Non-JSON payloads stay available through `bytes`; hooks should treat this
    /// as optional enrichment rather than a replacement for the raw body.
    json: Option<Value>,
}

impl CapturedBody {
    /// Builds a captured body and parses JSON when the bytes represent a JSON
    /// object or array.
    #[must_use]
    pub fn from_bytes(bytes: Bytes) -> Self {
        Self {
            raw_bytes: bytes.clone(),
            raw_truncated: false,
            decode_limit: super::engine::DEFAULT_MAX_HTTP1_BODY_BYTES,
            status: BodyDecodingStatus::Complete,
            json: parse_json_body(&bytes),
            bytes,
            truncated: false,
        }
    }

    /// Builds a captured body prefix for a message whose full body exceeded the
    /// hook capture budget.
    #[must_use]
    pub fn from_truncated_bytes(bytes: Bytes) -> Self {
        Self {
            raw_bytes: bytes.clone(),
            raw_truncated: true,
            decode_limit: super::engine::DEFAULT_MAX_HTTP1_BODY_BYTES,
            status: BodyDecodingStatus::Truncated,
            json: parse_json_body(&bytes),
            bytes,
            truncated: true,
        }
    }

    /// Content-decoded bytes for observers; empty while pending or on decode failure.
    ///
    /// Original HTTP headers continue to describe [`Self::raw_bytes`]. Do not
    /// apply their content coding a second time to this view.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Shared content-decoded bytes for observers.
    #[must_use]
    pub const fn bytes_ref(&self) -> &Bytes {
        &self.bytes
    }

    /// Parsed JSON body when the payload is a JSON object or array.
    #[must_use]
    pub const fn json(&self) -> Option<&Value> {
        self.json.as_ref()
    }

    /// Whether the observation view is incomplete, including decoding failures.
    #[must_use]
    pub const fn truncated(&self) -> bool {
        self.truncated
    }

    /// Original body bytes after HTTP transfer framing removal, before content decoding.
    #[must_use]
    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw_bytes
    }

    /// Whether the encoded capture itself was cut short by the relay's input limit.
    #[must_use]
    pub const fn raw_truncated(&self) -> bool {
        self.raw_truncated
    }

    /// Returns the content decoding outcome.
    #[must_use]
    pub const fn decoding_status(&self) -> BodyDecodingStatus {
        self.status
    }

    pub(super) const fn with_decode_limit(mut self, limit: usize) -> Self {
        self.decode_limit = limit;
        self
    }

    pub(super) fn encoded_bytes(&self) -> Bytes {
        self.raw_bytes.clone()
    }

    pub(super) fn set_decoded(&mut self, bytes: Bytes, status: BodyDecodingStatus) {
        self.json = if matches!(
            status,
            BodyDecodingStatus::Complete | BodyDecodingStatus::Truncated
        ) {
            parse_json_body(&bytes)
        } else {
            None
        };
        self.bytes = bytes;
        self.status = status;
        self.truncated = status != BodyDecodingStatus::Complete;
    }
}

fn parse_json_body(bytes: &[u8]) -> Option<Value> {
    let trimmed = trim_ascii_whitespace(bytes);
    if !matches!(trimmed.first(), Some(b'{' | b'[')) {
        return None;
    }
    serde_json::from_slice(trimmed).ok()
}

fn trim_ascii_whitespace(bytes: &[u8]) -> &[u8] {
    let leading = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let trailing = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(leading, |index| index.saturating_add(1));
    &bytes[leading..trailing]
}
