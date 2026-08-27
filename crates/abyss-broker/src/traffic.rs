//! In-memory live traffic telemetry for the local endpoint dashboard.
//!
//! This module records only flow metadata and byte counts. It deliberately does
//! not retain payloads or provider content, and it is scoped to one broker
//! process so live samples never become another control-plane audit stream.

use std::{
    collections::{HashMap, VecDeque},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use abyss_mitm::{SourceProcess, TrafficDirection, TrafficObserver};
use parking_lot::Mutex;
use serde::Serialize;
use uuid::Uuid;

use crate::ingress::PlatformFlow;

const RATE_BUCKET_MS: u64 = 1_000;
const RATE_WINDOW_MS: u64 = 5_000;
const MAX_RATE_BUCKETS: usize = 6;
const MAX_VISIBLE_FLOWS: usize = 24;

/// Shared live traffic recorder owned by the broker runtime.
#[derive(Clone)]
pub struct TrafficMonitor {
    inner: Arc<Mutex<TrafficState>>,
}

/// Metadata known when a platform flow enters the common MITM pipeline.
#[derive(Debug, Clone)]
pub struct TrafficFlowMetadata {
    host: String,
    process: Option<String>,
    pid: Option<u32>,
}

#[derive(Default)]
struct TrafficState {
    flows: HashMap<Uuid, ActiveFlow>,
    buckets: VecDeque<RateBucket>,
    total_upload_bytes: u64,
    total_download_bytes: u64,
}

struct ActiveFlow {
    metadata: TrafficFlowMetadata,
    upload_bytes: u64,
    download_bytes: u64,
}

struct RateBucket {
    start_ms: u64,
    upload_bytes: u64,
    download_bytes: u64,
}

/// Handle for one active flow's byte observer.
#[derive(Clone)]
pub struct TrafficFlowHandle {
    id: Uuid,
    started_at_unix_ms: u64,
    monitor: TrafficMonitor,
    finished: Arc<AtomicBool>,
}

/// JSON snapshot returned to the Host App.
#[derive(Debug, Serialize)]
pub struct TrafficSnapshot {
    /// Unix timestamp at which the snapshot was produced.
    pub sampled_at_unix_ms: u64,
    /// Recent client-to-upstream bytes per second.
    pub upload_bytes_per_second: u64,
    /// Recent upstream-to-client bytes per second.
    pub download_bytes_per_second: u64,
    /// Total client-to-upstream bytes observed since broker startup.
    pub total_upload_bytes: u64,
    /// Total upstream-to-client bytes observed since broker startup.
    pub total_download_bytes: u64,
    /// Currently active flows, bounded for predictable dashboard payload size.
    pub active_flows: Vec<ActiveFlowSnapshot>,
}

/// One active flow shown in the dashboard's compact activity list.
#[derive(Debug, Serialize)]
pub struct ActiveFlowSnapshot {
    /// Opaque short-lived flow identifier.
    pub id: String,
    /// Host or original destination associated with the flow.
    pub host: String,
    /// Source process name when the platform adapter supplied it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<String>,
    /// Source process ID when the platform adapter supplied it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    /// Bytes read from the local client for this flow.
    pub upload_bytes: u64,
    /// Bytes read from the upstream service for this flow.
    pub download_bytes: u64,
}

impl TrafficMonitor {
    /// Creates an empty live traffic recorder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(TrafficState::default())),
        }
    }

    /// Starts tracking one normalized platform flow.
    #[must_use]
    pub fn start_flow(&self, metadata: TrafficFlowMetadata) -> TrafficFlowHandle {
        let id = Uuid::new_v4();
        let started_at_unix_ms = current_unix_ms();
        self.inner.lock().flows.insert(
            id,
            ActiveFlow {
                metadata,
                upload_bytes: 0,
                download_bytes: 0,
            },
        );
        TrafficFlowHandle {
            id,
            started_at_unix_ms,
            monitor: self.clone(),
            finished: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Builds the current live snapshot and prunes expired rate buckets.
    #[must_use]
    pub fn snapshot(&self) -> TrafficSnapshot {
        let now = current_unix_ms();
        let mut state = self.inner.lock();
        state.prune_buckets(now);
        let (upload_bytes, download_bytes) = state.recent_bytes(now);
        let elapsed_ms = state.rate_elapsed_ms(now);
        let mut active_flows: Vec<_> = state
            .flows
            .iter()
            .map(|(id, flow)| ActiveFlowSnapshot {
                id: id.to_string(),
                host: flow.metadata.host.clone(),
                process: flow.metadata.process.clone(),
                pid: flow.metadata.pid,
                upload_bytes: flow.upload_bytes,
                download_bytes: flow.download_bytes,
            })
            .collect();
        active_flows.sort_by(|left, right| {
            let left_total = left.upload_bytes.saturating_add(left.download_bytes);
            let right_total = right.upload_bytes.saturating_add(right.download_bytes);
            right_total
                .cmp(&left_total)
                .then_with(|| left.host.cmp(&right.host))
        });
        let active_flows = active_flows.into_iter().take(MAX_VISIBLE_FLOWS).collect();

        TrafficSnapshot {
            sampled_at_unix_ms: now,
            upload_bytes_per_second: bytes_per_second(upload_bytes, elapsed_ms),
            download_bytes_per_second: bytes_per_second(download_bytes, elapsed_ms),
            total_upload_bytes: state.total_upload_bytes,
            total_download_bytes: state.total_download_bytes,
            active_flows,
        }
    }

    fn record_bytes(&self, id: Uuid, direction: TrafficDirection, bytes: usize) {
        let Ok(bytes) = u64::try_from(bytes) else {
            return;
        };
        let now = current_unix_ms();
        let mut state = self.inner.lock();
        if !state.flows.contains_key(&id) {
            return;
        }
        match direction {
            TrafficDirection::ClientToUpstream => {
                let flow = state
                    .flows
                    .get_mut(&id)
                    .expect("flow existence was checked before recording bytes");
                flow.upload_bytes = flow.upload_bytes.saturating_add(bytes);
                state.total_upload_bytes = state.total_upload_bytes.saturating_add(bytes);
                let bucket = state.ensure_bucket(now);
                bucket.upload_bytes = bucket.upload_bytes.saturating_add(bytes);
            }
            TrafficDirection::UpstreamToClient => {
                let flow = state
                    .flows
                    .get_mut(&id)
                    .expect("flow existence was checked before recording bytes");
                flow.download_bytes = flow.download_bytes.saturating_add(bytes);
                state.total_download_bytes = state.total_download_bytes.saturating_add(bytes);
                let bucket = state.ensure_bucket(now);
                bucket.download_bytes = bucket.download_bytes.saturating_add(bytes);
            }
            _ => {}
        }
        drop(state);
    }

    fn finish_flow(&self, id: Uuid) {
        self.inner.lock().flows.remove(&id);
    }
}

impl TrafficFlowMetadata {
    /// Converts normalized broker flow metadata into dashboard-safe labels.
    #[must_use]
    pub fn from_platform_flow(flow: &PlatformFlow) -> Self {
        let process = flow.source_process().and_then(process_label);
        let pid = flow.source_process().and_then(|source| source.pid);
        Self {
            host: flow
                .destination_host()
                .map_or_else(|| flow.original_destination().to_string(), str::to_owned),
            process,
            pid,
        }
    }
}

impl TrafficFlowHandle {
    /// Returns the opaque identifier assigned to this active flow.
    #[must_use]
    pub const fn id(&self) -> Uuid {
        self.id
    }

    /// Returns the Unix millisecond timestamp captured when this flow started.
    #[must_use]
    pub const fn started_at_unix_ms(&self) -> u64 {
        self.started_at_unix_ms
    }

    /// Returns an observer object suitable for the shared MITM stream layer.
    #[must_use]
    pub fn observer(&self) -> Arc<dyn TrafficObserver> {
        Arc::new(self.clone())
    }

    /// Removes the flow from the active set.
    pub fn finish(&self) {
        if !self.finished.swap(true, Ordering::AcqRel) {
            self.monitor.finish_flow(self.id);
        }
    }
}

impl TrafficObserver for TrafficFlowHandle {
    fn record_bytes(&self, direction: TrafficDirection, bytes: usize) {
        if !self.finished.load(Ordering::Acquire) {
            self.monitor.record_bytes(self.id, direction, bytes);
        }
    }
}

impl TrafficState {
    #[expect(
        clippy::integer_division_remainder_used,
        reason = "rate buckets are aligned to whole-second Unix timestamps."
    )]
    fn ensure_bucket(&mut self, now: u64) -> &mut RateBucket {
        let start_ms = now
            .checked_sub(now % RATE_BUCKET_MS)
            .expect("a bucket boundary cannot be after its timestamp");
        if self
            .buckets
            .back()
            .is_none_or(|bucket| bucket.start_ms != start_ms)
        {
            self.buckets.push_back(RateBucket {
                start_ms,
                upload_bytes: 0,
                download_bytes: 0,
            });
        }
        while self.buckets.len() > MAX_RATE_BUCKETS {
            self.buckets.pop_front();
        }
        self.buckets
            .back_mut()
            .expect("rate bucket should exist after insertion")
    }

    fn prune_buckets(&mut self, now: u64) {
        let cutoff = now.saturating_sub(RATE_WINDOW_MS);
        while self
            .buckets
            .front()
            .is_some_and(|bucket| bucket.start_ms.saturating_add(RATE_BUCKET_MS) < cutoff)
        {
            self.buckets.pop_front();
        }
    }

    fn recent_bytes(&self, now: u64) -> (u64, u64) {
        let cutoff = now.saturating_sub(RATE_WINDOW_MS);
        self.buckets
            .iter()
            .filter(|bucket| bucket.start_ms.saturating_add(RATE_BUCKET_MS) >= cutoff)
            .fold((0, 0), |(upload, download), bucket| {
                (
                    upload.saturating_add(bucket.upload_bytes),
                    download.saturating_add(bucket.download_bytes),
                )
            })
    }

    fn rate_elapsed_ms(&self, now: u64) -> u64 {
        self.buckets.front().map_or(RATE_BUCKET_MS, |bucket| {
            now.saturating_sub(bucket.start_ms)
                .saturating_add(RATE_BUCKET_MS)
                .clamp(RATE_BUCKET_MS, RATE_WINDOW_MS)
        })
    }
}

fn bytes_per_second(bytes: u64, elapsed_ms: u64) -> u64 {
    bytes
        .saturating_mul(1_000)
        .checked_div(elapsed_ms.max(1))
        .unwrap_or(0)
}

fn process_label(source: &SourceProcess) -> Option<String> {
    source
        .name
        .clone()
        .or_else(|| source.application_id.clone())
        .or_else(|| source.executable_path.clone())
}

fn current_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

#[cfg(test)]
mod tests {
    use abyss_mitm::{SourceProcess, TrafficDirection, TrafficObserver};

    use super::{TrafficFlowMetadata, TrafficMonitor};

    #[test]
    fn snapshot_reports_flow_bytes_and_metadata() {
        let monitor = TrafficMonitor::new();
        let flow = monitor.start_flow(TrafficFlowMetadata {
            host: "api.openai.com".to_owned(),
            process: Some("codex".to_owned()),
            pid: Some(42),
        });
        flow.record_bytes(TrafficDirection::ClientToUpstream, 2_048);
        flow.record_bytes(TrafficDirection::UpstreamToClient, 4_096);

        let snapshot = monitor.snapshot();
        assert_eq!(snapshot.total_upload_bytes, 2_048);
        assert_eq!(snapshot.total_download_bytes, 4_096);
        assert_eq!(snapshot.active_flows.len(), 1);
        assert_eq!(snapshot.active_flows[0].host, "api.openai.com");
        assert_eq!(snapshot.active_flows[0].process.as_deref(), Some("codex"));
        assert_eq!(snapshot.active_flows[0].pid, Some(42));
        assert!(snapshot.upload_bytes_per_second > 0);
        assert!(snapshot.download_bytes_per_second > 0);

        flow.finish();
        assert!(monitor.snapshot().active_flows.is_empty());
    }

    #[test]
    fn traffic_handle_observer_records_only_after_flow_is_active() {
        let monitor = TrafficMonitor::new();
        let flow = monitor.start_flow(TrafficFlowMetadata {
            host: "example.test".to_owned(),
            process: None,
            pid: None,
        });
        let observer = flow.observer();
        observer.record_bytes(TrafficDirection::ClientToUpstream, 10);
        flow.finish();
        observer.record_bytes(TrafficDirection::ClientToUpstream, 10);

        let snapshot = monitor.snapshot();
        assert_eq!(snapshot.total_upload_bytes, 10);
        assert!(snapshot.active_flows.is_empty());
    }

    #[test]
    fn platform_metadata_prefers_source_process_name() {
        let source = SourceProcess::new(
            Some(7),
            Some("Claude".to_owned()),
            Some("/Applications/Claude.app/Contents/MacOS/Claude".to_owned()),
        );
        assert_eq!(super::process_label(&source).as_deref(), Some("Claude"));
    }
}
