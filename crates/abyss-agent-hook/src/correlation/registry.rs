//! Bounded correlation state shared by built-in and configured Harnesses.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use parking_lot::Mutex;

use crate::harness::HarnessDetection;

const MAX_SESSIONS: usize = 1_024;
const MAX_STABLE_TURNS: usize = 4_096;
const CORRELATION_TTL: Duration = Duration::from_hours(24);

/// Correlation values attached to one parsed provider interaction.
#[derive(Debug)]
pub struct CorrelationContext {
    pub session_id: String,
    pub turn_index: i32,
    pub provider_call_index: i32,
}

/// Assigns stable turn indexes without knowing protocol payload details.
#[derive(Debug, Default)]
pub struct CorrelationRegistry {
    state: Mutex<CorrelationState>,
}

#[derive(Debug, Default)]
struct CorrelationState {
    sessions: HashMap<(String, String), SessionState>,
    stable_turns: HashMap<(String, String, String), StableTurn>,
}

#[derive(Debug)]
struct SessionState {
    next_turn_index: i32,
    updated_at: Instant,
}

#[derive(Debug)]
struct StableTurn {
    turn_index: i32,
    provider_call_index: i32,
    updated_at: Instant,
}

impl CorrelationRegistry {
    /// Correlates one protocol interaction inside the detected Harness namespace.
    pub fn assign(
        &self,
        detection: &HarnessDetection,
        session_id: &str,
        protocol_turn_id: Option<&str>,
    ) -> CorrelationContext {
        self.state
            .lock()
            .assign(detection.harness_id.as_str(), session_id, protocol_turn_id)
    }
}

impl CorrelationState {
    fn assign(
        &mut self,
        harness_id: &str,
        session_id: &str,
        protocol_turn_id: Option<&str>,
    ) -> CorrelationContext {
        let now = Instant::now();
        self.prune_expired(now);
        if let Some(protocol_turn_id) = protocol_turn_id {
            let key = (
                harness_id.to_owned(),
                session_id.to_owned(),
                protocol_turn_id.to_owned(),
            );
            if let Some(turn) = self.stable_turns.get_mut(&key) {
                turn.provider_call_index = turn.provider_call_index.saturating_add(1_i32);
                turn.updated_at = now;
                return CorrelationContext {
                    session_id: session_id.to_owned(),
                    turn_index: turn.turn_index,
                    provider_call_index: turn.provider_call_index,
                };
            }
            let turn_index = self.next_turn(harness_id, session_id, now);
            self.stable_turns.insert(
                key,
                StableTurn {
                    turn_index,
                    provider_call_index: 1_i32,
                    updated_at: now,
                },
            );
            self.enforce_bounds();
            return CorrelationContext {
                session_id: session_id.to_owned(),
                turn_index,
                provider_call_index: 1_i32,
            };
        }

        let turn_index = self.next_turn(harness_id, session_id, now);
        self.enforce_bounds();
        CorrelationContext {
            session_id: session_id.to_owned(),
            turn_index,
            provider_call_index: 1_i32,
        }
    }

    fn next_turn(&mut self, harness_id: &str, session_id: &str, now: Instant) -> i32 {
        let session = self
            .sessions
            .entry((harness_id.to_owned(), session_id.to_owned()))
            .or_insert(SessionState {
                next_turn_index: 0_i32,
                updated_at: now,
            });
        session.next_turn_index = session.next_turn_index.saturating_add(1_i32);
        session.updated_at = now;
        session.next_turn_index
    }

    fn enforce_bounds(&mut self) {
        while self.stable_turns.len() > MAX_STABLE_TURNS {
            let Some(oldest) = self
                .stable_turns
                .iter()
                .min_by_key(|(_, turn)| turn.updated_at)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            self.stable_turns.remove(&oldest);
        }
        while self.sessions.len() > MAX_SESSIONS {
            let Some(oldest) = self
                .sessions
                .iter()
                .min_by_key(|(_, session)| session.updated_at)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            self.sessions.remove(&oldest);
        }
    }

    fn prune_expired(&mut self, now: Instant) {
        self.sessions.retain(|_, session| {
            now.saturating_duration_since(session.updated_at) <= CORRELATION_TTL
        });
        self.stable_turns
            .retain(|_, turn| now.saturating_duration_since(turn.updated_at) <= CORRELATION_TTL);
    }
}

#[cfg(test)]
mod tests {
    use crate::harness::{BuiltInHarness, HarnessDetection, HarnessId};

    use super::CorrelationRegistry;

    #[test]
    fn stable_protocol_turn_reuses_turn_and_increments_provider_call() {
        let registry = CorrelationRegistry::default();
        let detection = detection("codex");

        let first = registry.assign(&detection, "session-1", Some("turn-1"));
        let second = registry.assign(&detection, "session-1", Some("turn-1"));
        let next = registry.assign(&detection, "session-1", Some("turn-2"));

        assert_eq!(first.turn_index, 1_i32);
        assert_eq!(first.provider_call_index, 1_i32);
        assert_eq!(second.turn_index, 1_i32);
        assert_eq!(second.provider_call_index, 2_i32);
        assert_eq!(next.turn_index, 2_i32);
    }

    #[test]
    fn harness_namespaces_do_not_share_session_counters() {
        let registry = CorrelationRegistry::default();

        let codex = registry.assign(&detection("codex"), "shared", None);
        let custom = registry.assign(&detection("acme-agent"), "shared", None);

        assert_eq!(codex.turn_index, 1_i32);
        assert_eq!(custom.turn_index, 1_i32);
    }

    fn detection(harness_id: &str) -> HarnessDetection {
        let harness_id = if harness_id == BuiltInHarness::Codex.id() {
            HarnessId::from(BuiltInHarness::Codex)
        } else {
            serde_json::from_str(&format!("\"{harness_id}\""))
                .expect("test Harness id should parse")
        };
        HarnessDetection {
            harness_id,
            evidence: Vec::new(),
            version: None,
            working_directory: None,
        }
    }
}
