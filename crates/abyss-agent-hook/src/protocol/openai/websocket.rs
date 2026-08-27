//! Bounded assembly of OpenAI Responses WebSocket message fragments.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use abyss_mitm::FlowId;
use parking_lot::Mutex;

use crate::protocol::{
    model::{tool::ParsedToolEvent, usage::TokenUsage},
    openai::ParsedOpenAiExchange,
};

const PENDING_TURN_TTL: Duration = Duration::from_mins(1);
const MAX_PENDING_TURNS: usize = 64;

/// Collects request and streaming response messages until a terminal response arrives.
#[derive(Debug, Default)]
pub struct OpenAiWebSocketAccumulator {
    pending: Mutex<HashMap<FlowId, PendingTurn>>,
}

#[derive(Debug)]
struct PendingTurn {
    exchange: Option<ParsedOpenAiExchange>,
    updated_at: Instant,
}

impl OpenAiWebSocketAccumulator {
    /// Adds one parsed message and returns a complete interaction when available.
    pub fn push(
        &self,
        flow_id: &FlowId,
        parsed: Option<ParsedOpenAiExchange>,
    ) -> Option<ParsedOpenAiExchange> {
        let mut pending = self.pending.lock();
        let now = Instant::now();
        pending.retain(|_, turn| now.duration_since(turn.updated_at) <= PENDING_TURN_TTL);
        let mut turn = pending.remove(flow_id).unwrap_or(PendingTurn {
            exchange: None,
            updated_at: now,
        });
        if let Some(parsed) = parsed {
            turn.exchange = Some(match turn.exchange {
                Some(current) => merge(current, parsed),
                None => parsed,
            });
        }
        if turn.exchange.as_ref().is_some_and(is_terminal_response) {
            return turn.exchange;
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

const fn is_request_only(parsed: &ParsedOpenAiExchange) -> bool {
    (!parsed.request_texts.is_empty() || !parsed.request_images.is_empty())
        && parsed.response_texts.is_empty()
        && parsed.usage.is_empty()
}

fn is_terminal_response(parsed: &ParsedOpenAiExchange) -> bool {
    let has_output_usage =
        parsed.usage.output_tokens > 0_i64 || parsed.usage.reasoning_tokens > 0_i64;
    !is_request_only(parsed)
        && has_output_usage
        && parsed
            .event_types
            .iter()
            .any(|event_type| event_type == "response.completed")
}

fn merge(mut current: ParsedOpenAiExchange, next: ParsedOpenAiExchange) -> ParsedOpenAiExchange {
    if current.request_texts.is_empty()
        && current.request_images.is_empty()
        && (!next.request_texts.is_empty() || !next.request_images.is_empty())
    {
        current.session_id.clone_from(&next.session_id);
        current.request_hash.clone_from(&next.request_hash);
    }
    append_unique(&mut current.request_texts, next.request_texts);
    if current.request_images.is_empty() {
        current.request_images = next.request_images;
    }
    append_unique(&mut current.response_texts, next.response_texts);
    append_unique(&mut current.event_types, next.event_types);
    append_unique_tools(&mut current.request_tool_events, next.request_tool_events);
    append_unique_tools(&mut current.response_tool_events, next.response_tool_events);
    if !next.usage.is_empty() && usage_rank(&next.usage) >= usage_rank(&current.usage) {
        current.usage = next.usage;
    }
    if next.response_id.is_some() {
        current.response_id = next.response_id;
    }
    if current.previous_response_id.is_none() {
        current.previous_response_id = next.previous_response_id;
    }
    if current.protocol_turn_id.is_none() {
        current.protocol_turn_id = next.protocol_turn_id;
    }
    if current.model.is_none() {
        current.model = next.model;
    }
    current
}

fn append_unique(target: &mut Vec<String>, source: Vec<String>) {
    for value in source {
        if !target.contains(&value) {
            target.push(value);
        }
    }
}

fn append_unique_tools(target: &mut Vec<ParsedToolEvent>, source: Vec<ParsedToolEvent>) {
    for event in source {
        if !target.contains(&event) {
            target.push(event);
        }
    }
}

fn usage_rank(usage: &TokenUsage) -> i64 {
    usage.total_tokens.max(
        usage
            .input_tokens
            .saturating_add(usage.output_tokens)
            .saturating_add(usage.reasoning_tokens),
    )
}

#[cfg(test)]
mod tests {
    use abyss_mitm::FlowId;

    use crate::protocol::{model::usage::TokenUsage, openai::ParsedOpenAiExchange};

    use super::OpenAiWebSocketAccumulator;

    #[test]
    fn assembles_request_fragments_and_terminal_response() {
        let accumulator = OpenAiWebSocketAccumulator::default();
        let flow_id = FlowId::generate();

        assert!(accumulator.push(&flow_id, Some(request("hello"))).is_none());
        assert!(
            accumulator
                .push(&flow_id, Some(response("part one", false)))
                .is_none()
        );
        let completed = accumulator
            .push(&flow_id, Some(response("part two", true)))
            .expect("terminal response should complete the interaction");

        assert_eq!(completed.request_texts, vec!["hello"]);
        assert_eq!(completed.response_texts, vec!["part one", "part two"]);
        assert_eq!(completed.usage.output_tokens, 2);
        assert!(
            completed
                .event_types
                .iter()
                .any(|event_type| event_type == "response.completed")
        );
    }

    #[test]
    fn keeps_pending_interactions_isolated_by_flow() {
        let accumulator = OpenAiWebSocketAccumulator::default();
        let first_flow = FlowId::generate();
        let second_flow = FlowId::generate();

        assert!(
            accumulator
                .push(&first_flow, Some(request("first")))
                .is_none()
        );
        assert!(
            accumulator
                .push(&second_flow, Some(request("second")))
                .is_none()
        );

        let first = accumulator
            .push(&first_flow, Some(response("done", true)))
            .expect("first flow should complete");
        assert_eq!(first.request_texts, vec!["first"]);
    }

    fn request(text: &str) -> ParsedOpenAiExchange {
        let mut parsed = exchange();
        parsed.request_texts = vec![text.to_owned()];
        parsed
    }

    fn response(text: &str, completed: bool) -> ParsedOpenAiExchange {
        let mut parsed = exchange();
        parsed.response_texts = vec![text.to_owned()];
        if completed {
            parsed.usage = TokenUsage {
                input_tokens: 1,
                output_tokens: 2,
                total_tokens: 3,
                ..TokenUsage::default()
            };
            parsed.event_types = vec!["response.completed".to_owned()];
        }
        parsed
    }

    fn exchange() -> ParsedOpenAiExchange {
        ParsedOpenAiExchange {
            host: "gateway.example".to_owned(),
            path: "/v1/responses".to_owned(),
            method: "GET".to_owned(),
            transport: "https",
            session_id: "session-1".to_owned(),
            request_hash: "request-hash".to_owned(),
            request_texts: Vec::new(),
            request_images: Vec::new(),
            response_texts: Vec::new(),
            usage: TokenUsage::default(),
            response_id: None,
            previous_response_id: None,
            protocol_turn_id: Some("turn-1".to_owned()),
            request_tool_events: Vec::new(),
            response_tool_events: Vec::new(),
            model: Some("model-test".to_owned()),
            event_types: Vec::new(),
        }
    }
}
