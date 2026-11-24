//! Provider-neutral response body decoding: JSON or Server-Sent Events framing.

use abyss_mitm::{CapturedBody, DEFAULT_MAX_HTTP1_BODY_BYTES};
use serde_json::Value;

use crate::protocol::model::response::ResponseInput;

/// JSON payloads decoded from a Server-Sent Events byte stream.
///
/// Each event may contain multiple `data:` lines. Stream sentinels such as
/// `[DONE]` are omitted. Events are decoded independently, so an event that is
/// not valid UTF-8 or JSON, such as one cut at the capture limit inside a
/// multibyte character, only sets `decode_failed`.
pub struct SseDocuments {
    /// Successfully decoded event payloads in stream order.
    pub values: Vec<Value>,
    /// Whether at least one event payload failed to decode.
    pub decode_failed: bool,
}

impl SseDocuments {
    /// Decodes every event of one captured stream.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Self {
        let mut result = Self {
            values: Vec::new(),
            decode_failed: false,
        };
        let mut data = Vec::new();
        // The trailing empty line terminates a final event without a blank line.
        for line in bytes.split(|byte| *byte == b'\n').chain([&b""[..]]) {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            if line.is_empty() {
                result.finish_event(&mut data);
            } else if let Some(value) = line.strip_prefix(b"data:") {
                data.push(value.strip_prefix(b" ").unwrap_or(value));
            }
        }
        result
    }

    fn finish_event(&mut self, data: &mut Vec<&[u8]>) {
        if data.is_empty() {
            return;
        }
        let payload = data.join(&b'\n');
        data.clear();
        if payload.trim_ascii() == b"[DONE]" {
            return;
        }
        match serde_json::from_slice(&payload) {
            Ok(value) => self.values.push(value),
            Err(_) => self.decode_failed = true,
        }
    }
}

/// Decodes an HTTP response once, shared by usage, tool, and conversation extraction.
pub struct ResponseDocuments {
    /// JSON documents in body order: one JSON body or the decoded SSE events.
    pub values: Vec<Value>,
    /// Whether the captured body ended before its normal transport boundary.
    pub capture_truncated: bool,
    /// Whether a document failed to decode, independently of transport EOF.
    pub decode_failed: bool,
}

impl ResponseDocuments {
    /// Decodes a JSON body, falling back to Server-Sent Events framing.
    #[must_use]
    pub fn decode(body: &CapturedBody) -> Self {
        if let Some(value) = body.json() {
            return Self {
                values: vec![value.clone()],
                capture_truncated: body.truncated(),
                decode_failed: false,
            };
        }
        let decoded = SseDocuments::decode(body.bytes());
        Self {
            values: decoded.values,
            capture_truncated: body.truncated(),
            decode_failed: decoded.decode_failed,
        }
    }

    /// Borrows the decoded HTTP documents without applying protocol semantics.
    #[must_use]
    pub fn as_input(&self) -> ResponseInput<'_> {
        ResponseInput {
            values: &self.values,
            capture_truncated: self.capture_truncated,
            decode_failed: self.decode_failed,
            assembly_overflowed: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use abyss_mitm::CapturedBody;

    use super::{ResponseDocuments, SseDocuments};

    #[test]
    fn parses_json_data_events() {
        let decoded = SseDocuments::decode(
            b"event: message\r\ndata: {\"type\":\"content_block_delta\"}\r\n\r\ndata: [DONE]\r\n\r\n",
        );

        assert_eq!(decoded.values.len(), 1);
        assert_eq!(decoded.values[0]["type"], "content_block_delta");
        assert!(!decoded.decode_failed);
    }

    #[test]
    fn truncated_multibyte_character_only_loses_its_own_event() {
        let mut body = "data: {\"text\":\"héllo\",\"usage\":{\"output_tokens\":2}}\n\n"
            .as_bytes()
            .to_vec();
        body.extend_from_slice(b"data: {\"text\":\"\xe4\xb8");

        let decoded = SseDocuments::decode(&body);

        assert_eq!(decoded.values.len(), 1);
        assert_eq!(decoded.values[0]["text"], "héllo");
        assert_eq!(decoded.values[0]["usage"]["output_tokens"], 2_i32);
        assert!(decoded.decode_failed);
    }

    #[test]
    fn malformed_sse_event_marks_documents_incomplete() {
        let body = CapturedBody::from_bytes(
            b"data: {\"type\":\"known\"}\n\ndata: {broken\n\n"
                .to_vec()
                .into(),
        );
        let decoded = ResponseDocuments::decode(&body);
        assert!(decoded.decode_failed);
        assert_eq!(decoded.values.len(), 1);
    }

    #[test]
    fn capture_and_decode_observations_are_independent() {
        for capture_truncated in [false, true] {
            for decode_failed in [false, true] {
                let mut bytes = b"data: {\"type\":\"known\"}\n\n".to_vec();
                if decode_failed {
                    bytes.extend_from_slice(b"data: {broken\n\n");
                }
                let body = if capture_truncated {
                    CapturedBody::from_truncated_bytes(bytes.into())
                } else {
                    CapturedBody::from_bytes(bytes.into())
                };
                let documents = ResponseDocuments::decode(&body);
                let input = documents.as_input();
                assert_eq!(input.values.len(), 1);
                assert_eq!(input.capture_truncated, capture_truncated);
                assert_eq!(input.decode_failed, decode_failed);
                assert!(!input.assembly_overflowed);
            }
        }
    }
}

/// Incremental SSE framing for a live observer. Only blank-line terminated
/// events are returned. The caller drops this state when the stream ends.
#[derive(Default)]
pub struct SseStream {
    line: Vec<u8>,
    data: Vec<u8>,
    started: bool,
    skip_lf: bool,
    stopped: bool,
}

impl SseStream {
    pub fn next_event(&mut self, input: &mut &[u8]) -> Option<String> {
        while !self.stopped && !input.is_empty() {
            if std::mem::take(&mut self.skip_lf)
                && let Some(rest) = input.strip_prefix(b"\n")
            {
                *input = rest;
                continue;
            }
            let line_end = input.iter().position(|byte| matches!(byte, b'\r' | b'\n'));
            let (piece, rest) = input.split_at(line_end.unwrap_or(input.len()));
            if self
                .data
                .len()
                .saturating_add(self.line.len())
                .saturating_add(piece.len())
                > DEFAULT_MAX_HTTP1_BODY_BYTES
            {
                *self = Self {
                    stopped: true,
                    ..Self::default()
                };
                tracing::debug!("HTTP event stream exceeded the SSE framing limit");
                return None;
            }
            self.line.extend_from_slice(piece);
            *input = rest;
            if let Some((&separator, remainder)) = input.split_first() {
                self.skip_lf = separator == b'\r';
                *input = remainder;
                if let Some(data) = self.finish_line() {
                    return Some(data);
                }
            }
        }
        None
    }

    fn finish_line(&mut self) -> Option<String> {
        let mut line = self.line.as_slice();
        if !std::mem::replace(&mut self.started, true) {
            line = line.strip_prefix(b"\xef\xbb\xbf").unwrap_or(line);
        }
        if line.is_empty() {
            self.line.clear();
            self.data.pop()?;
            return Some(
                String::from_utf8(std::mem::take(&mut self.data))
                    .unwrap_or_else(|error| String::from_utf8_lossy(error.as_bytes()).into_owned()),
            );
        }
        if let Some(value) = line
            .strip_prefix(b"data:")
            .or_else(|| (line == b"data").then_some(&[]))
        {
            self.data
                .extend_from_slice(value.strip_prefix(b" ").unwrap_or(value));
            self.data.push(b'\n');
        }
        self.line.clear();
        None
    }
}

#[cfg(test)]
mod incremental_tests {
    use super::{DEFAULT_MAX_HTTP1_BODY_BYTES, SseStream};

    #[test]
    fn frames_data_across_split_lines_delimiters_and_utf8() {
        let mut stream = SseStream::default();
        let bytes = b"\xef\xbb\xbf:keepalive\r\nevent: ignored\rdata: one\r\ndata: t\xc3\xa9\n\r\ndata: buffered\n";
        let events: Vec<_> = bytes
            .chunks(1)
            .filter_map(|mut chunk| stream.next_event(&mut chunk))
            .collect();
        assert_eq!(events, ["one\nté"]);
        assert_eq!(
            stream.next_event(&mut &b"\n"[..]).as_deref(),
            Some("buffered")
        );
    }

    #[test]
    fn oversized_event_stops_observation_and_releases_buffers() {
        let mut stream = SseStream::default();
        let prefix = [
            b"data: ".as_slice(),
            &vec![b'a'; DEFAULT_MAX_HTTP1_BODY_BYTES.div_ceil(2)],
            b"\n",
        ]
        .concat();
        assert!(stream.next_event(&mut prefix.as_slice()).is_none());
        assert!(stream.next_event(&mut prefix.as_slice()).is_none());
        assert!(stream.stopped);
        assert!(stream.data.is_empty() && stream.line.is_empty());
        assert!(stream.next_event(&mut &b"data: ignored\n\n"[..]).is_none());
    }
}
