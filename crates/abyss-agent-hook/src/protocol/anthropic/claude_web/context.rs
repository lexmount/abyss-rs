//! Claude Web private file-upload correlation.
//!
//! Claude Web clients upload image bytes in a multipart request before sending a
//! completion whose `files` array contains only the returned UUID. This module
//! validates those uploads and keeps a bounded, short-lived correlation cache
//! so the later completion can use the provider-neutral attachment pipeline.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    time::{Duration, Instant},
};

use abyss_mitm::HttpExchange;
use http::{HeaderMap, Method, header::CONTENT_TYPE};
use parking_lot::Mutex;

use crate::{
    protocol::anthropic::ParsedClaudeWebExchange,
    protocol::model::image::{
        MAX_IMAGE_ATTACHMENT_BYTES_PER_EVENT, MAX_IMAGE_ATTACHMENTS_PER_EVENT,
        ParsedImageAttachment,
    },
};

const MAX_CACHED_UPLOADS: usize = 64;
const MAX_CACHED_UPLOAD_BYTES: usize = 32 * 1024 * 1024;
const MAX_MULTIPART_PARTS: usize = 16;
const MAX_MULTIPART_HEADER_BYTES: usize = 16 * 1024;
const MAX_BOUNDARY_BYTES: usize = 70;
const UPLOAD_TTL: Duration = Duration::from_mins(30);

/// Synchronized upload correlation state shared by Claude Web exchanges.
#[doc(hidden)]
#[derive(Default)]
pub struct ClaudeWebContext {
    cache: Mutex<ClaudeWebUploadCache>,
}

#[derive(Default)]
struct ClaudeWebUploadCache {
    uploads: HashMap<UploadKey, CachedUpload>,
    insertion_order: VecDeque<UploadKey>,
    cached_bytes: usize,
}

impl ClaudeWebContext {
    /// Records one successful Claude Web image upload when the exchange
    /// matches the private upload endpoint.
    pub fn record_upload(&self, exchange: &HttpExchange) -> bool {
        // Multipart validation and image decoding are CPU work and must stay
        // outside the shared cache lock so unrelated exchanges can parse in
        // parallel.
        let Some(upload) = ParsedUpload::from_exchange(exchange) else {
            return false;
        };
        let now = Instant::now();
        let mut cache = self.cache.lock();
        cache.prune_expired(now);
        cache.insert(upload, now);
        true
    }

    /// Resolves file UUIDs carried by a completion into normal image
    /// attachments without exceeding the shared per-event limits.
    pub fn attach_referenced_images(&self, parsed: &mut ParsedClaudeWebExchange) {
        let referenced_images = {
            let mut cache = self.cache.lock();
            cache.prune_expired(Instant::now());
            let images = parsed
                .request_file_uuids
                .iter()
                .filter_map(|file_uuid| {
                    let key = UploadKey::new(&parsed.session_id, file_uuid);
                    cache
                        .uploads
                        .get(&key)
                        .map(|cached| (file_uuid.clone(), cached.image.clone()))
                })
                .collect::<Vec<_>>();
            drop(cache);
            images
        };
        let mut count = parsed.request_images.len();
        let mut decoded_bytes = parsed
            .request_images
            .iter()
            .map(ParsedImageAttachment::byte_size)
            .fold(0_usize, usize::saturating_add);
        let mut seen = HashSet::new();

        for (file_uuid, image) in referenced_images {
            if count >= MAX_IMAGE_ATTACHMENTS_PER_EVENT
                || decoded_bytes >= MAX_IMAGE_ATTACHMENT_BYTES_PER_EVENT
                || !seen.insert(file_uuid)
            {
                continue;
            }
            let next_bytes = decoded_bytes.saturating_add(image.byte_size());
            if next_bytes > MAX_IMAGE_ATTACHMENT_BYTES_PER_EVENT {
                continue;
            }
            decoded_bytes = next_bytes;
            count = count.saturating_add(1);
            parsed.request_images.push(image);
        }
    }
}

impl ClaudeWebUploadCache {
    fn insert(&mut self, upload: ParsedUpload, captured_at: Instant) {
        let key = UploadKey::new(&upload.session_id, &upload.file_uuid);
        if let Some(previous) = self.uploads.remove(&key) {
            self.cached_bytes = self.cached_bytes.saturating_sub(previous.image.byte_size());
            self.insertion_order.retain(|candidate| candidate != &key);
        }

        self.cached_bytes = self.cached_bytes.saturating_add(upload.image.byte_size());
        self.insertion_order.push_back(key.clone());
        self.uploads.insert(
            key,
            CachedUpload {
                image: upload.image,
                captured_at,
            },
        );
        self.enforce_capacity();
    }

    fn prune_expired(&mut self, now: Instant) {
        loop {
            let Some(key) = self.insertion_order.front() else {
                return;
            };
            let expired = self.uploads.get(key).is_none_or(|upload| {
                now.checked_duration_since(upload.captured_at)
                    .is_some_and(|age| age >= UPLOAD_TTL)
            });
            if !expired {
                return;
            }
            let key = self
                .insertion_order
                .pop_front()
                .expect("front upload key should remain present");
            self.remove(&key);
        }
    }

    fn enforce_capacity(&mut self) {
        while self.uploads.len() > MAX_CACHED_UPLOADS || self.cached_bytes > MAX_CACHED_UPLOAD_BYTES
        {
            let Some(key) = self.insertion_order.pop_front() else {
                break;
            };
            self.remove(&key);
        }
    }

    fn remove(&mut self, key: &UploadKey) {
        if let Some(upload) = self.uploads.remove(key) {
            self.cached_bytes = self.cached_bytes.saturating_sub(upload.image.byte_size());
        }
    }
}

#[derive(Clone, Eq, Hash, PartialEq)]
struct UploadKey {
    session_id: String,
    file_uuid: String,
}

impl UploadKey {
    fn new(session_id: &str, file_uuid: &str) -> Self {
        Self {
            session_id: session_id.to_owned(),
            file_uuid: file_uuid.to_owned(),
        }
    }
}

struct CachedUpload {
    image: ParsedImageAttachment,
    captured_at: Instant,
}

struct ParsedUpload {
    session_id: String,
    file_uuid: String,
    image: ParsedImageAttachment,
}

impl ParsedUpload {
    fn from_exchange(exchange: &HttpExchange) -> Option<Self> {
        if exchange.request.method() != Method::POST
            || !exchange.response.status().is_success()
            || exchange.request.body().truncated()
            || exchange.response.body().truncated()
            || !is_claude_web_host(exchange)
        {
            return None;
        }
        let session_id = upload_conversation_id(exchange.request.uri().path())?;
        let response = exchange.response.body().json()?.as_object()?;
        if response.get("success").and_then(serde_json::Value::as_bool) == Some(false) {
            return None;
        }
        let file_uuid = response
            .get("file_uuid")
            .or_else(|| response.get("uuid"))
            .and_then(serde_json::Value::as_str)?;
        let content_type = header(exchange.request.headers(), CONTENT_TYPE.as_str())?;
        let image = MultipartImage::parse(content_type, exchange.request.body().bytes())?;
        Some(Self {
            session_id: session_id.to_owned(),
            file_uuid: file_uuid.to_owned(),
            image,
        })
    }
}

struct MultipartImage;

impl MultipartImage {
    fn parse(content_type: &str, body: &[u8]) -> Option<ParsedImageAttachment> {
        let media_type = content_type.parse::<mime::Mime>().ok()?;
        if media_type.essence_str() != "multipart/form-data" {
            return None;
        }
        let boundary = media_type.get_param("boundary")?.as_str().as_bytes();
        if boundary.is_empty() || boundary.len() > MAX_BOUNDARY_BYTES {
            return None;
        }
        let mut delimiter = Vec::with_capacity(boundary.len().saturating_add(2));
        delimiter.extend_from_slice(b"--");
        delimiter.extend_from_slice(boundary);
        if !body.starts_with(&delimiter) {
            return None;
        }

        let mut cursor = 0_usize;
        for _part_index in 0..MAX_MULTIPART_PARTS {
            cursor = cursor.checked_add(delimiter.len())?;
            if body.get(cursor..cursor.saturating_add(2)) == Some(b"--") {
                return None;
            }
            if body.get(cursor..cursor.saturating_add(2)) != Some(b"\r\n") {
                return None;
            }
            cursor = cursor.checked_add(2)?;
            let header_length = find_bytes(body.get(cursor..)?, b"\r\n\r\n")?;
            if header_length > MAX_MULTIPART_HEADER_BYTES {
                return None;
            }
            let headers = body.get(cursor..cursor.checked_add(header_length)?)?;
            cursor = cursor.checked_add(header_length)?.checked_add(4)?;

            let mut next_delimiter = Vec::with_capacity(delimiter.len().saturating_add(2));
            next_delimiter.extend_from_slice(b"\r\n");
            next_delimiter.extend_from_slice(&delimiter);
            let content_length = find_bytes(body.get(cursor..)?, &next_delimiter)?;
            let content = body.get(cursor..cursor.checked_add(content_length)?)?;
            if is_file_part(headers) {
                let media_type = part_header(headers, "content-type")?;
                return ParsedImageAttachment::from_bytes(media_type, content);
            }
            cursor = cursor.checked_add(content_length)?.checked_add(2)?;
        }
        None
    }
}

fn is_claude_web_host(exchange: &HttpExchange) -> bool {
    header(exchange.request.headers(), "host").is_some_and(|host| {
        let host = host
            .split(':')
            .next()
            .unwrap_or(host)
            .trim_end_matches('.')
            .to_ascii_lowercase();
        host == "claude.ai" || host.ends_with(".claude.ai")
    })
}

fn upload_conversation_id(path: &str) -> Option<&str> {
    let segments = path.trim_matches('/').split('/').collect::<Vec<_>>();
    match segments.as_slice() {
        [
            "api",
            "organizations",
            organization_id,
            "conversations",
            conversation_id,
            "wiggle",
            "upload-file",
        ] if !organization_id.is_empty() && !conversation_id.is_empty() => Some(conversation_id),
        _ => None,
    }
}

fn is_file_part(headers: &[u8]) -> bool {
    part_header(headers, "content-disposition").is_some_and(|value| {
        value.split(';').skip(1).any(|parameter| {
            let Some((name, value)) = parameter.split_once('=') else {
                return false;
            };
            name.trim().eq_ignore_ascii_case("name")
                && value.trim().trim_matches('"').eq_ignore_ascii_case("file")
        })
    })
}

fn part_header<'a>(headers: &'a [u8], expected_name: &str) -> Option<&'a str> {
    let headers = std::str::from_utf8(headers).ok()?;
    headers.split("\r\n").find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case(expected_name)
            .then(|| value.trim())
    })
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name)?.to_str().ok()
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack
        .windows(needle.len())
        .position(|candidate| candidate == needle)
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use abyss_mitm::{
        CapturedBody, FlowContext, HttpExchange, OriginalDestination, TransparentProtocol,
    };
    use http::{Request, Response};
    use serde_json::json;

    use super::{ClaudeWebContext, ParsedUpload};
    use crate::{
        protocol::anthropic::claude_web::{
            ParsedClaudeWebExchange, conversation::ClaudeWebSessionIdSource,
        },
        protocol::model::usage::{TokenUsage, TokenUsageSource},
    };

    const PNG_BYTES: &[u8] = b"\x89PNG\r\n\x1a\nclaude-web-upload";

    #[test]
    fn parses_real_shaped_multipart_upload_and_resolves_completion_reference() {
        let upload = upload_exchange(PNG_BYTES, "image/png", "file-1");
        let parsed_upload =
            ParsedUpload::from_exchange(&upload).expect("valid Claude Web upload should parse");
        assert_eq!(parsed_upload.session_id, "conversation-1");
        assert_eq!(parsed_upload.file_uuid, "file-1");
        assert_eq!(parsed_upload.image.bytes, PNG_BYTES);

        let state = ClaudeWebContext::default();
        assert!(state.record_upload(&upload));
        let mut completion = completion_fixture("conversation-1", &["file-1"]);
        state.attach_referenced_images(&mut completion);
        assert_eq!(completion.request_images.len(), 1);
        assert_eq!(completion.request_images[0].bytes, PNG_BYTES);
    }

    #[test]
    fn keeps_uploads_isolated_by_conversation_and_rejects_signature_mismatch() {
        let state = ClaudeWebContext::default();
        assert!(state.record_upload(&upload_exchange(PNG_BYTES, "image/png", "file-1")));
        assert!(!state.record_upload(&upload_exchange(b"not-a-png", "image/png", "invalid-file")));

        let mut other_conversation = completion_fixture("conversation-2", &["file-1"]);
        state.attach_referenced_images(&mut other_conversation);
        assert!(other_conversation.request_images.is_empty());

        let mut invalid = completion_fixture("conversation-1", &["invalid-file"]);
        state.attach_referenced_images(&mut invalid);
        assert!(invalid.request_images.is_empty());
    }

    #[test]
    fn rejects_upload_when_response_capture_is_truncated() {
        let mut upload = upload_exchange(PNG_BYTES, "image/png", "file-1");
        *upload.response.body_mut() = CapturedBody::from_truncated_bytes(
            json!({"success": true, "file_uuid": "file-1"})
                .to_string()
                .into(),
        );

        assert!(ParsedUpload::from_exchange(&upload).is_none());
    }

    fn upload_exchange(bytes: &[u8], media_type: &str, file_uuid: &str) -> HttpExchange {
        let boundary = "----WebKitFormBoundaryAbyssClaudeWebTest";
        let mut body = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"fixture.png\"\r\nContent-Type: {media_type}\r\n\r\n"
        )
        .into_bytes();
        body.extend_from_slice(bytes);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

        exchange(
            "/api/organizations/org-1/conversations/conversation-1/wiggle/upload-file",
            format!("multipart/form-data; boundary={boundary}"),
            CapturedBody::from_bytes(body.into()),
            "application/json",
            CapturedBody::from_bytes(
                json!({"success": true, "file_uuid": file_uuid})
                    .to_string()
                    .into(),
            ),
        )
    }

    fn completion_fixture(session_id: &str, file_uuids: &[&str]) -> ParsedClaudeWebExchange {
        ParsedClaudeWebExchange {
            host: "claude.ai".to_owned(),
            path: format!("/api/organizations/org-1/chat_conversations/{session_id}/completion"),
            method: "POST".to_owned(),
            transport: "https",
            session_id: session_id.to_owned(),
            session_id_source: ClaudeWebSessionIdSource::ConversationPath,
            request_hash: "request-hash".to_owned(),
            request_texts: vec!["describe the image".to_owned()],
            request_images: Vec::new(),
            request_file_uuids: file_uuids.iter().map(|value| (*value).to_owned()).collect(),
            protocol_turn_id: Some("assistant-turn-1".to_owned()),
            request_tool_events: Vec::new(),
            response_tool_events: Vec::new(),
            response_texts: vec!["done".to_owned()],
            usage: TokenUsage::default(),
            usage_source: TokenUsageSource::Absent,
            message_id: Some("assistant-turn-1".to_owned()),
            model: Some("claude-sonnet-5".to_owned()),
            human_message_uuid: Some("human-turn-1".to_owned()),
            assistant_message_uuid: Some("assistant-turn-1".to_owned()),
            stop_reason: Some("end_turn".to_owned()),
            event_types: Vec::new(),
        }
    }

    fn exchange(
        path: &str,
        request_content_type: String,
        request_body: CapturedBody,
        response_content_type: &str,
        response_body: CapturedBody,
    ) -> HttpExchange {
        HttpExchange::new(
            FlowContext::new(
                SocketAddr::from(([127, 0, 0, 1], 50_000)),
                SocketAddr::from(([127, 0, 0, 1], 18_090)),
                OriginalDestination::from(SocketAddr::from(([198, 19, 0, 13], 443))),
                TransparentProtocol::TlsHttp {
                    server_name: "claude.ai".to_owned(),
                },
            ),
            Request::builder()
                .method("POST")
                .uri(path)
                .header("host", "claude.ai")
                .header("content-type", request_content_type)
                .body(request_body)
                .expect("test upload request should build"),
            Response::builder()
                .status(200)
                .header("content-type", response_content_type)
                .body(response_body)
                .expect("test upload response should build"),
        )
    }
}
