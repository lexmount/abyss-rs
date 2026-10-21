//! Bounded assembly of OpenAI Responses WebSocket message fragments.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use abyss_mitm::{FlowId, WebSocketDirection};
use abyss_plugin_protocol::event::{ContentCompleteness, Conversation};
use parking_lot::Mutex;
use serde_json::Value;

use crate::protocol::{
    model::conversation::ConversationProjection,
    openai::{ParsedOpenAiExchange, conversation::OpenAiResponse},
};

const PENDING_TURN_TTL: Duration = Duration::from_mins(1);
const MAX_PENDING_TURNS: usize = 64;
/// Most server documents buffered for one turn's response assembly.
const MAX_RESPONSE_DOCUMENTS: usize = 4096;
/// Most server frame bytes buffered for one turn's response assembly.
const MAX_RESPONSE_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;

/// Outcome of decoding one OpenAI Responses WebSocket frame.
#[derive(Debug)]
pub enum OpenAiWebSocketFrame {
    /// A client frame carrying request content.
    Request(Box<ParsedOpenAiExchange>),
    /// A server frame carrying response content, usage, tools, or a terminal state.
    Response(Box<OpenAiWebSocketResponse>),
    /// A decodable frame that carries nothing the turn needs.
    Irrelevant,
    /// A frame that could not be decoded; its direction marks the partial side.
    Undecodable(WebSocketDirection),
}

/// One decoded server frame.
#[derive(Debug)]
pub struct OpenAiWebSocketResponse {
    /// Values parsed from this frame alone.
    pub exchange: ParsedOpenAiExchange,
    /// Decoded document, replayed when the turn's response is assembled.
    pub document: Value,
    /// Size of the frame payload, counted against the turn buffer budget.
    pub byte_len: usize,
}

/// Collects request and streaming response messages until a terminal response arrives.
#[derive(Debug, Default)]
pub struct OpenAiWebSocketAccumulator {
    /// Unfinished turns keyed by WebSocket flow.
    pending: Mutex<HashMap<FlowId, PendingTurn>>,
}

#[derive(Debug)]
struct PendingTurn {
    /// Values merged from every relevant frame of the turn.
    exchange: Option<ParsedOpenAiExchange>,
    /// Request conversation merged from client frames; `None` until one arrives.
    request_conversation: Option<Conversation>,
    /// Decoded server documents in arrival order.
    response_documents: Vec<Value>,
    /// Frame bytes represented by `response_documents`.
    response_document_bytes: usize,
    /// Whether a server document exceeded the buffer budget.
    response_overflowed: bool,
    /// Whether a client frame failed to decode.
    request_decode_failed: bool,
    /// Whether a server frame failed to decode.
    response_decode_failed: bool,
    /// Last time a frame touched this turn.
    updated_at: Instant,
}

impl OpenAiWebSocketAccumulator {
    /// Adds one decoded frame and returns a complete interaction when available.
    pub fn push(
        &self,
        flow_id: &FlowId,
        frame: OpenAiWebSocketFrame,
    ) -> Option<ParsedOpenAiExchange> {
        if matches!(frame, OpenAiWebSocketFrame::Irrelevant) {
            return None;
        }
        let mut pending = self.pending.lock();
        let now = Instant::now();
        pending.retain(|_, turn| now.duration_since(turn.updated_at) <= PENDING_TURN_TTL);
        let mut turn = pending
            .remove(flow_id)
            .unwrap_or_else(|| PendingTurn::new(now));
        turn.record(frame);
        if turn.exchange.as_ref().is_some_and(is_terminal_response) {
            return turn.complete();
        }
        turn.updated_at = now;
        if pending.len() >= MAX_PENDING_TURNS
            && let Some(oldest) = pending
                .iter()
                .min_by_key(|(_, turn)| turn.updated_at)
                .map(|(flow_id, _)| flow_id.clone())
        {
            pending.remove(&oldest);
        }
        pending.insert(flow_id.clone(), turn);
        None
    }
}

impl PendingTurn {
    const fn new(now: Instant) -> Self {
        Self {
            exchange: None,
            request_conversation: None,
            response_documents: Vec::new(),
            response_document_bytes: 0,
            response_overflowed: false,
            request_decode_failed: false,
            response_decode_failed: false,
            updated_at: now,
        }
    }

    fn record(&mut self, frame: OpenAiWebSocketFrame) {
        match frame {
            OpenAiWebSocketFrame::Request(exchange) => {
                let mut exchange = *exchange;
                let conversation = std::mem::replace(
                    &mut exchange.request_conversation,
                    ConversationProjection::empty(),
                );
                // The first client frame that carries content, a conversation
                // entry or an image, identifies the turn.
                let identifies_turn = !self.carries_request_content()
                    && (!conversation.entries.is_empty() || !exchange.request_images.is_empty());
                self.merge_request_conversation(conversation);
                self.merge_exchange(exchange, identifies_turn);
            }
            OpenAiWebSocketFrame::Response(response) => {
                let OpenAiWebSocketResponse {
                    exchange,
                    document,
                    byte_len,
                } = *response;
                self.buffer_response_document(document, byte_len);
                self.merge_exchange(exchange, false);
            }
            OpenAiWebSocketFrame::Undecodable(WebSocketDirection::ClientToServer) => {
                self.request_decode_failed = true;
            }
            OpenAiWebSocketFrame::Undecodable(_) => self.response_decode_failed = true,
            OpenAiWebSocketFrame::Irrelevant => {}
        }
    }

    /// Whether a merged client frame carried a conversation entry or an image.
    fn carries_request_content(&self) -> bool {
        self.request_conversation
            .as_ref()
            .is_some_and(|conversation| !conversation.entries.is_empty())
            || self
                .exchange
                .as_ref()
                .is_some_and(|exchange| !exchange.request_images.is_empty())
    }

    /// Merges one client frame's request conversation into the turn.
    ///
    /// A turn normally has one `response.create`. When a client sends several
    /// content frames before the terminal response, the first frame supplies
    /// the turn's request conversation and later frames append their entries
    /// in arrival order. An incompletely decoded frame downgrades the whole
    /// request side.
    fn merge_request_conversation(&mut self, next: Conversation) {
        let Some(current) = self.request_conversation.as_mut() else {
            self.request_conversation = Some(next);
            return;
        };
        current.entries.extend(next.entries);
        if next.completeness != ContentCompleteness::Complete {
            ConversationProjection::mark_partial(current);
        }
    }

    /// Buffers one server document until the turn budget is exhausted.
    ///
    /// Once a document does not fit, buffering stops for the rest of the turn
    /// so the assembled response never silently skips a middle fragment.
    fn buffer_response_document(&mut self, document: Value, byte_len: usize) {
        if self.response_overflowed {
            return;
        }
        let bytes = self.response_document_bytes.saturating_add(byte_len);
        if self.response_documents.len() >= MAX_RESPONSE_DOCUMENTS
            || bytes > MAX_RESPONSE_DOCUMENT_BYTES
        {
            self.response_overflowed = true;
            return;
        }
        self.response_document_bytes = bytes;
        self.response_documents.push(document);
    }

    /// Merges one frame's values; a frame that `identifies_turn` supplies the
    /// turn's session id and request hash.
    fn merge_exchange(&mut self, next: ParsedOpenAiExchange, identifies_turn: bool) {
        let Some(current) = self.exchange.as_mut() else {
            self.exchange = Some(next);
            return;
        };
        if let Some(generates_output) = next.generates_output {
            // Never classify a mixed exchange as prewarm if any client frame
            // can generate output. Server frames cannot overwrite this choice.
            current.generates_output =
                Some(current.generates_output.unwrap_or(false) || generates_output);
        }
        if identifies_turn {
            current.session_id.clone_from(&next.session_id);
            current.request_hash.clone_from(&next.request_hash);
        }
        if current.request_images.is_empty() {
            current.request_images = next.request_images;
        }
        append_unique(&mut current.event_types, next.event_types);
        if !next.usage.is_empty() && next.usage.total_tokens >= current.usage.total_tokens {
            current.usage = next.usage;
        }
        if next.response_id.is_some() {
            current.response_id = next.response_id;
        }
        if current.previous_response_id.is_none() {
            current.previous_response_id = next.previous_response_id;
        }
        if current.client_metadata.is_none() {
            current.client_metadata = next.client_metadata;
        }
        if current.model.is_none() {
            current.model = next.model;
        }
    }

    /// Assembles the turn's conversations from the merged and buffered frames.
    fn complete(self) -> Option<ParsedOpenAiExchange> {
        let mut exchange = self.exchange?;
        let response = OpenAiResponse::assemble(
            &self.response_documents,
            self.response_overflowed || self.response_decode_failed,
        );
        exchange.response_conversation = response.conversation();
        exchange.request_conversation = self.request_conversation.unwrap_or_else(|| {
            let mut unobserved = ConversationProjection::empty();
            unobserved.completeness = ContentCompleteness::Unsupported;
            unobserved
        });
        if self.request_decode_failed {
            ConversationProjection::mark_partial(&mut exchange.request_conversation);
            // An undecodable client frame might have enabled generation.
            exchange.generates_output = None;
        }
        Some(exchange)
    }
}

/// Whether a Responses event type ends a turn.
pub fn is_terminal_event(kind: &str) -> bool {
    matches!(
        kind,
        "response.completed" | "response.failed" | "response.incomplete" | "error"
    )
}

fn is_terminal_response(parsed: &ParsedOpenAiExchange) -> bool {
    parsed
        .event_types
        .iter()
        .any(|kind| is_terminal_event(kind))
}

fn append_unique(target: &mut Vec<String>, source: Vec<String>) {
    for value in source {
        if !target.contains(&value) {
            target.push(value);
        }
    }
}

#[cfg(test)]
mod tests {
    use abyss_mitm::{FlowId, WebSocketDirection};
    use abyss_plugin_protocol::event::{ContentCompleteness, EntryRole};
    use serde_json::{Value, json};

    use crate::protocol::{
        model::{
            conversation::{ConversationProjection, role_texts},
            usage::TokenUsage,
        },
        openai::{ParsedOpenAiExchange, conversation::OpenAiRequest},
    };

    use super::{
        MAX_RESPONSE_DOCUMENT_BYTES, OpenAiWebSocketAccumulator, OpenAiWebSocketFrame,
        OpenAiWebSocketResponse,
    };

    #[test]
    fn assembles_request_fragments_and_terminal_response() {
        let accumulator = OpenAiWebSocketAccumulator::default();
        let flow_id = FlowId::generate();

        assert!(accumulator.push(&flow_id, request("hello")).is_none());
        assert!(
            accumulator
                .push(&flow_id, response(0, "part one", false))
                .is_none()
        );
        assert!(
            accumulator
                .push(&flow_id, OpenAiWebSocketFrame::Irrelevant)
                .is_none()
        );
        let completed = accumulator
            .push(&flow_id, response(1, "part two", true))
            .expect("terminal response should complete the interaction");

        assert_eq!(
            role_texts(&completed.request_conversation),
            [(EntryRole::User, "hello")]
        );
        assert_eq!(
            role_texts(&completed.response_conversation),
            [
                (EntryRole::Assistant, "part one"),
                (EntryRole::Assistant, "part two")
            ]
        );
        assert_eq!(
            completed.response_conversation.completeness,
            ContentCompleteness::Complete
        );
        assert_eq!(completed.usage.output_tokens, 2);
        assert!(
            completed
                .event_types
                .iter()
                .any(|event_type| event_type == "response.completed")
        );
    }

    #[test]
    fn mixed_or_undecodable_client_frames_cannot_be_excluded_as_prewarm() {
        for second in [Some(false), Some(true), None] {
            let accumulator = OpenAiWebSocketAccumulator::default();
            let flow = FlowId::generate();
            let mut prewarm = exchange();
            prewarm.generates_output = Some(false);
            accumulator.push(&flow, OpenAiWebSocketFrame::Request(Box::new(prewarm)));
            let frame = second.map_or(
                OpenAiWebSocketFrame::Undecodable(WebSocketDirection::ClientToServer),
                |generates_output| {
                    let mut next = exchange();
                    next.generates_output = Some(generates_output);
                    OpenAiWebSocketFrame::Request(Box::new(next))
                },
            );
            accumulator.push(&flow, frame);
            let completed = accumulator.push(&flow, response(0, "", true)).unwrap();
            assert_eq!(completed.generates_output, second);
        }
    }

    #[test]
    fn keeps_pending_interactions_isolated_by_flow() {
        let accumulator = OpenAiWebSocketAccumulator::default();
        let first_flow = FlowId::generate();
        let second_flow = FlowId::generate();

        assert!(accumulator.push(&first_flow, request("first")).is_none());
        assert!(accumulator.push(&second_flow, request("second")).is_none());

        let first = accumulator
            .push(&first_flow, response(0, "done", true))
            .expect("first flow should complete");
        assert_eq!(
            role_texts(&first.request_conversation),
            [(EntryRole::User, "first")]
        );
    }

    #[test]
    fn decode_failures_mark_only_their_own_side_partial() {
        for (direction, request_side, response_side) in [
            (
                WebSocketDirection::ClientToServer,
                ContentCompleteness::Partial,
                ContentCompleteness::Complete,
            ),
            (
                WebSocketDirection::ServerToClient,
                ContentCompleteness::Complete,
                ContentCompleteness::Partial,
            ),
        ] {
            let accumulator = OpenAiWebSocketAccumulator::default();
            let flow_id = FlowId::generate();
            assert!(accumulator.push(&flow_id, request("hello")).is_none());
            assert!(
                accumulator
                    .push(&flow_id, OpenAiWebSocketFrame::Undecodable(direction))
                    .is_none()
            );
            let completed = accumulator
                .push(&flow_id, response(0, "answer", true))
                .expect("terminal response should complete the interaction");

            assert_eq!(completed.request_conversation.completeness, request_side);
            assert_eq!(completed.response_conversation.completeness, response_side);
            assert_eq!(
                role_texts(&completed.response_conversation),
                [(EntryRole::Assistant, "answer")]
            );
        }
    }

    #[test]
    fn response_buffer_overflow_stops_buffering_and_marks_partial() {
        let accumulator = OpenAiWebSocketAccumulator::default();
        let flow_id = FlowId::generate();
        assert!(accumulator.push(&flow_id, request("hello")).is_none());
        assert!(
            accumulator
                .push(&flow_id, response(0, "kept", false))
                .is_none()
        );
        let mut oversized = response(1, "dropped", false);
        if let OpenAiWebSocketFrame::Response(frame) = &mut oversized {
            frame.byte_len = MAX_RESPONSE_DOCUMENT_BYTES;
        }
        assert!(accumulator.push(&flow_id, oversized).is_none());
        let completed = accumulator
            .push(&flow_id, response(2, "after overflow", true))
            .expect("terminal response should complete the interaction");

        assert_eq!(
            role_texts(&completed.response_conversation),
            [(EntryRole::Assistant, "kept")]
        );
        assert_eq!(
            completed.response_conversation.completeness,
            ContentCompleteness::Partial
        );
        assert_eq!(completed.usage.output_tokens, 2);
    }

    #[test]
    fn later_client_frames_append_messages_and_keep_first_metadata() {
        let accumulator = OpenAiWebSocketAccumulator::default();
        let flow_id = FlowId::generate();
        assert!(
            accumulator
                .push(
                    &flow_id,
                    request_frame(&json!({
                        "previous_response_id": "resp_1",
                        "input": [{"role": "user", "content": "first"}]
                    })),
                )
                .is_none()
        );
        assert!(
            accumulator
                .push(
                    &flow_id,
                    request_frame(&json!({
                        "previous_response_id": "resp_2",
                        "instructions": "rules",
                        "input": [{"role": "user", "content": "second"}]
                    })),
                )
                .is_none()
        );
        let completed = accumulator
            .push(&flow_id, response(0, "done", true))
            .expect("terminal response should complete the interaction");
        let conversation = &completed.request_conversation;

        assert_eq!(completed.previous_response_id.as_deref(), Some("resp_1"));
        assert_eq!(
            role_texts(conversation),
            [
                (EntryRole::User, "first"),
                (EntryRole::System, "rules"),
                (EntryRole::User, "second"),
            ]
        );
    }

    #[test]
    fn the_first_client_frame_with_content_identifies_the_turn() {
        let accumulator = OpenAiWebSocketAccumulator::default();
        let flow_id = FlowId::generate();
        let mut empty = exchange();
        empty.session_id = "frame-without-entries".to_owned();
        accumulator.push(&flow_id, OpenAiWebSocketFrame::Request(Box::new(empty)));
        for (session_id, text) in [("first-content", "first"), ("later-content", "second")] {
            let OpenAiWebSocketFrame::Request(mut frame) = request(text) else {
                unreachable!("request frames are requests");
            };
            frame.session_id = session_id.to_owned();
            frame.request_hash = format!("{session_id}-hash");
            accumulator.push(&flow_id, OpenAiWebSocketFrame::Request(frame));
        }
        let completed = accumulator
            .push(&flow_id, response(0, "done", true))
            .expect("terminal response should complete the interaction");

        assert_eq!(completed.session_id, "first-content");
        assert_eq!(completed.request_hash, "first-content-hash");
    }

    fn request(text: &str) -> OpenAiWebSocketFrame {
        request_frame(&json!({"input": [{"role": "user", "content": text}]}))
    }

    fn request_frame(payload: &Value) -> OpenAiWebSocketFrame {
        let request = OpenAiRequest::parse(Some(payload), false);
        let mut parsed = exchange();
        parsed.request_conversation = request.conversation();
        parsed.previous_response_id = payload
            .get("previous_response_id")
            .and_then(Value::as_str)
            .map(str::to_owned);
        OpenAiWebSocketFrame::Request(Box::new(parsed))
    }

    fn response(output_index: u64, text: &str, completed: bool) -> OpenAiWebSocketFrame {
        let mut parsed = exchange();
        if completed {
            parsed.usage = TokenUsage {
                input_tokens: 1,
                output_tokens: 2,
                total_tokens: 3,
                ..TokenUsage::default()
            };
            parsed.event_types = vec!["response.completed".to_owned()];
        }
        OpenAiWebSocketFrame::Response(Box::new(OpenAiWebSocketResponse {
            exchange: parsed,
            document: json!({
                "type": "response.output_text.done",
                "output_index": output_index,
                "content_index": 0_i32,
                "text": text
            }),
            byte_len: text.len(),
        }))
    }

    fn exchange() -> ParsedOpenAiExchange {
        ParsedOpenAiExchange {
            generates_output: None,
            host: "gateway.example".to_owned(),
            path: "/v1/responses".to_owned(),
            method: "GET".to_owned(),
            transport: "https",
            session_id: "session-1".to_owned(),
            request_hash: "request-hash".to_owned(),
            request_conversation: ConversationProjection::empty(),
            response_conversation: ConversationProjection::empty(),
            request_images: Vec::new(),
            usage: TokenUsage::default(),
            response_id: None,
            previous_response_id: None,
            client_metadata: None,
            model: Some("model-test".to_owned()),
            event_types: Vec::new(),
        }
    }
}
