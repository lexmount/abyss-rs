//! Observe ingress worker exit and publish lifecycle state before waking callers.
//!
//! Supervision owns the join handle independently of REST request cancellation.
//! A weak state reference avoids retaining the service after its last owner drops.

use std::{
    io,
    sync::{Arc, Weak},
};

use tokio::{
    sync::{Mutex, watch},
    task::{JoinError, JoinHandle},
};
use uuid::Uuid;

use super::ProxyRuntimeState;
use crate::error::BrokerError;

/// Completion can be observed by a stop caller and a later restart after cancellation.
#[derive(Clone)]
pub(super) enum WorkerExit {
    Pending,
    Finished(Result<(), Arc<JoinError>>),
}

impl WorkerExit {
    pub(super) async fn wait(mut receiver: watch::Receiver<Self>) -> Result<Self, BrokerError> {
        let outcome = receiver
            .wait_for(|exit| matches!(exit, Self::Finished(_)))
            .await
            .map_err(|source| {
                BrokerError::io(
                    "wait for proxy worker exit",
                    io::Error::new(io::ErrorKind::BrokenPipe, source),
                )
            })?;
        Ok(outcome.clone())
    }

    pub(super) fn into_result(self) -> Result<(), BrokerError> {
        match self {
            Self::Finished(result) => {
                result.map_err(|source| BrokerError::task("stop proxy listener", source))
            }
            Self::Pending => unreachable!("completion wait must return a finished outcome"),
        }
    }
}

/// Observes exactly one run, including cancellation and panic of its worker.
pub(super) struct WorkerSupervisor {
    state: Weak<Mutex<ProxyRuntimeState>>,
    run_id: Uuid,
    completion: watch::Sender<WorkerExit>,
}

impl WorkerSupervisor {
    pub(super) const fn new(
        state: Weak<Mutex<ProxyRuntimeState>>,
        run_id: Uuid,
        completion: watch::Sender<WorkerExit>,
    ) -> Self {
        Self {
            state,
            run_id,
            completion,
        }
    }

    pub(super) async fn run(self, worker: JoinHandle<()>) {
        let outcome = worker.await.map_err(Arc::new);
        if let Err(error) = &outcome {
            tracing::error!(%error, run_id = %self.run_id, "broker ingress worker terminated");
        }
        if let Some(state) = self.state.upgrade() {
            state.lock().await.finish(self.run_id);
        }
        // Explicit stop observes completion only after the state transition above.
        self.completion.send_replace(WorkerExit::Finished(outcome));
    }
}
