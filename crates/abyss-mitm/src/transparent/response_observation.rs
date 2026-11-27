//! Observe-only delivery of incrementally decoded HTTP response bytes.

use std::time::SystemTime;

use bytes::Bytes;
use http::HeaderMap;
use tokio::sync::mpsc;

use super::{
    FlowId, HookFuture, content_encoding::StreamDecoder, hook::DEFAULT_HOOK_QUEUE_CAPACITY,
};

/// One hook's state for a single observed HTTP response.
pub trait HttpResponseObserver: Send {
    /// Receives body bytes after HTTP content decoding, in stream order.
    /// Chunk boundaries are independent of the HTTP and application framing.
    /// `at` is when the input bytes producing this chunk entered the observation queue.
    /// Returning an error affects neither forwarding nor other observers.
    fn on_http_response_chunk<'a>(&'a mut self, at: SystemTime, chunk: &'a [u8]) -> HookFuture<'a>;
}

pub(super) struct ResponseObservation {
    flow_id: FlowId,
    sender: mpsc::Sender<(SystemTime, Bytes)>,
}

impl ResponseObservation {
    pub(super) fn start(
        flow_id: FlowId,
        headers: HeaderMap,
        observers: Vec<(usize, Box<dyn HttpResponseObserver>)>,
        max_body_bytes: usize,
    ) -> Self {
        let (sender, chunks) = mpsc::channel(DEFAULT_HOOK_QUEUE_CAPACITY);
        tokio::spawn(Self::observe(
            flow_id.clone(),
            headers,
            chunks,
            observers,
            max_body_bytes,
        ));
        Self { flow_id, sender }
    }

    pub(super) fn push_if_active(observation: &mut Option<Self>, bytes: &[u8]) {
        let Some(active) = observation.as_ref() else {
            return;
        };
        let chunk = (SystemTime::now(), Bytes::copy_from_slice(bytes));
        let Err(error) = active.sender.try_send(chunk) else {
            return;
        };
        if matches!(error, mpsc::error::TrySendError::Full(_)) {
            tracing::warn!(flow_id = %active.flow_id, "MITM HTTP response observation queue full");
        }
        // Drain the queued prefix without observing bytes across a gap.
        *observation = None;
    }

    async fn observe(
        flow_id: FlowId,
        headers: HeaderMap,
        mut chunks: mpsc::Receiver<(SystemTime, Bytes)>,
        mut observers: Vec<(usize, Box<dyn HttpResponseObserver>)>,
        max_body_bytes: usize,
    ) {
        let Ok(mut decoder) = StreamDecoder::new(&headers, max_body_bytes).inspect_err(|status| {
            tracing::debug!(%flow_id, ?status, "MITM observation content decoding unavailable");
        }) else {
            return;
        };
        while let Some((at, input)) = chunks.recv().await {
            let Ok(plaintext) = decoder.decode(&input).inspect_err(|error| {
                tracing::debug!(%flow_id, %error, "MITM observation content decoding ended");
            }) else {
                return;
            };
            if !plaintext.is_empty() {
                for (hook_index, observer) in &mut observers {
                    if let Err(error) = observer.on_http_response_chunk(at, plaintext).await {
                        tracing::warn!(%hook_index, %flow_id, %error, "MITM hook failed while observing HTTP response");
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{future, time::Duration};

    use super::*;
    use crate::DEFAULT_MAX_HTTP1_BODY_BYTES;

    struct Recorder(mpsc::UnboundedSender<Bytes>);

    impl HttpResponseObserver for Recorder {
        fn on_http_response_chunk<'a>(
            &'a mut self,
            _at: SystemTime,
            chunk: &'a [u8],
        ) -> HookFuture<'a> {
            self.0.send(Bytes::copy_from_slice(chunk)).unwrap();
            Box::pin(future::ready(Ok(())))
        }
    }

    #[tokio::test]
    async fn drops_observation_after_queue_overflow_but_drains_the_queued_prefix() {
        let (events, mut receiver) = mpsc::unbounded_channel();
        let mut observation = Some(ResponseObservation::start(
            FlowId::generate(),
            HeaderMap::new(),
            vec![(0, Box::new(Recorder(events)))],
            DEFAULT_MAX_HTTP1_BODY_BYTES,
        ));
        for _ in 0..DEFAULT_HOOK_QUEUE_CAPACITY {
            ResponseObservation::push_if_active(&mut observation, b"k");
        }
        ResponseObservation::push_if_active(&mut observation, b"overflow");
        assert!(observation.is_none());
        ResponseObservation::push_if_active(&mut observation, b"after the gap");
        let observed = tokio::time::timeout(Duration::from_secs(2), async {
            let mut observed = Vec::new();
            while let Some(chunk) = receiver.recv().await {
                observed.extend_from_slice(&chunk);
            }
            observed
        })
        .await
        .unwrap();
        assert_eq!(observed, vec![b'k'; DEFAULT_HOOK_QUEUE_CAPACITY]);
    }
}
