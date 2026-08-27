//! Asynchronous publication of normalized Agent events to the broker.

use std::{error::Error as StdError, fmt, future::Future, sync::Arc};

use abyss_plugin_protocol::event::AgentEvent;
use thiserror::Error;

use crate::event::{AgentEventConversionError, NormalizedUsageEvent};

/// Failure while converting or publishing a normalized event.
#[derive(Debug, Error)]
pub enum AgentEventDeliveryError<E>
where
    E: StdError + 'static,
{
    #[error("convert normalized Agent event: {0}")]
    Conversion(#[from] AgentEventConversionError),
    #[error("publish Agent event: {source}")]
    Sink {
        #[source]
        source: E,
    },
}

/// Asynchronous boundary used by hooks to publish one normalized event.
pub trait AgentEventSink: fmt::Debug + Send + Sync {
    /// Sink-specific publication failure.
    type Error: StdError + Send + Sync + 'static;

    /// Publishes an event to its configured consumer boundary.
    fn publish(&self, event: AgentEvent) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

impl<S> AgentEventSink for Arc<S>
where
    S: AgentEventSink,
{
    type Error = S::Error;

    fn publish(&self, event: AgentEvent) -> impl Future<Output = Result<(), Self::Error>> + Send {
        self.as_ref().publish(event)
    }
}

/// Converts hook-internal events and publishes them to the broker-owned sink.
#[derive(Debug)]
pub struct EventDelivery<S> {
    sink: S,
}

impl<S> EventDelivery<S>
where
    S: AgentEventSink,
{
    /// Creates a publisher with a broker-owned Agent event sink.
    #[must_use]
    pub(super) const fn new(sink: S) -> Self {
        Self { sink }
    }

    /// Converts and publishes all normalized events.
    pub(super) async fn deliver(
        &self,
        events: Vec<NormalizedUsageEvent>,
    ) -> Result<(), AgentEventDeliveryError<S::Error>> {
        for event in events {
            let event = event.try_into()?;
            self.sink
                .publish(event)
                .await
                .map_err(|source| AgentEventDeliveryError::Sink { source })?;
        }
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use std::{convert::Infallible, future::Future, sync::Mutex};

    use abyss_plugin_protocol::event::AgentEvent;

    use super::{AgentEventDeliveryError, AgentEventSink, EventDelivery};
    use crate::{
        event::{AgentPayload, DevicePayload, LlmPayload, NormalizedUsageEvent},
        protocol::model::usage::TokenUsage,
    };

    #[derive(Debug, Default)]
    struct RecordingSink {
        events: Mutex<Vec<AgentEvent>>,
    }

    impl AgentEventSink for RecordingSink {
        type Error = Infallible;

        fn publish(
            &self,
            event: AgentEvent,
        ) -> impl Future<Output = Result<(), Self::Error>> + Send {
            self.events
                .lock()
                .expect("recording sink mutex should not be poisoned")
                .push(event);
            std::future::ready(Ok(()))
        }
    }

    #[derive(Debug, thiserror::Error)]
    #[error("test sink rejected the event")]
    struct TestSinkError;

    #[derive(Debug)]
    struct FailingSink;

    impl AgentEventSink for FailingSink {
        type Error = TestSinkError;

        fn publish(
            &self,
            _event: AgentEvent,
        ) -> impl Future<Output = Result<(), Self::Error>> + Send {
            std::future::ready(Err(TestSinkError))
        }
    }

    #[tokio::test]
    async fn publishes_typed_events_without_an_upload_destination() {
        let sink = std::sync::Arc::new(RecordingSink::default());
        let delivery = EventDelivery::new(std::sync::Arc::clone(&sink));

        delivery
            .deliver(vec![sample_normalized_event()])
            .await
            .expect("broker publication should succeed");

        let events = sink
            .events
            .lock()
            .expect("recording sink mutex should not be poisoned");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, "event-1");
        drop(events);
    }

    #[tokio::test]
    async fn preserves_the_concrete_sink_error() {
        let error = EventDelivery::new(FailingSink)
            .deliver(vec![sample_normalized_event()])
            .await
            .expect_err("sink failure should be returned");

        assert!(matches!(error, AgentEventDeliveryError::Sink { .. }));
        assert_eq!(
            error.to_string(),
            "publish Agent event: test sink rejected the event"
        );
    }

    fn sample_normalized_event() -> NormalizedUsageEvent {
        NormalizedUsageEvent {
            event_id: "event-1".to_owned(),
            observed_at: "2026-08-19T10:00:00.000000Z".to_owned(),
            device: DevicePayload {
                host_name: "test-host".to_owned(),
                platform: "macos".to_owned(),
                os_version: None,
            },
            agent: AgentPayload {
                name: "codex".to_owned(),
                version: None,
            },
            session_id: "session-1".to_owned(),
            turn_index: 1_i32,
            llm: LlmPayload {
                provider: "openai".to_owned(),
                model: "gpt-test".to_owned(),
            },
            event_type: "request",
            text: Some("hello".to_owned()),
            token_usage: TokenUsage {
                input_tokens: 1_i64,
                total_tokens: 1_i64,
                ..TokenUsage::default()
            },
            metadata: serde_json::json!({}),
            attachments: Vec::new(),
        }
    }
}
