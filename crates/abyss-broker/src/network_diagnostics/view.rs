//! Dashboard projection of stored network facts using the shared Harness registry.
//! Identity is derived from captured metadata and current policy, without changing
//! historical records or adding product-specific recognition to the Host App.

use abyss_agent_hook::{HarnessId, HarnessRegistry, HarnessUsageConfig};
use abyss_mitm::SourceProcess;
use serde::Serialize;

use super::NetworkObservation;

#[derive(Serialize)]
pub struct NetworkObservationView {
    #[serde(flatten)]
    observation: NetworkObservation,
    agent_name: Option<HarnessId>,
}

impl NetworkObservationView {
    pub fn new(observation: NetworkObservation, config: &HarnessUsageConfig) -> Self {
        let source = SourceProcess::new(
            observation.source_pid,
            observation.source_process_name.clone(),
            observation.source_executable_path.clone(),
        )
        .with_application_id(observation.source_bundle_id.clone());
        let agent_name = HarnessRegistry::identify_source(Some(&source), config);
        Self {
            observation,
            agent_name,
        }
    }
}
