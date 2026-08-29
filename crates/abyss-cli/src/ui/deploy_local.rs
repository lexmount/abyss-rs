//! Presentation of semantic local-deployment progress events.

use crate::{
    deploy_local::DeploymentEvent,
    ui::{CliUi, UiActivity, UiDownload},
};

/// Stateful renderer for one `abyss deploy-local start` operation.
pub struct LocalDeploymentUi<'a> {
    ui: &'a CliUi,
    active: Option<Indicator>,
}

enum Indicator {
    Activity(UiActivity),
    Download(UiDownload),
}

impl<'a> LocalDeploymentUi<'a> {
    /// Creates a renderer bound to the invocation-wide terminal policy.
    pub const fn new(ui: &'a CliUi) -> Self {
        Self { ui, active: None }
    }

    /// Renders one semantic deployment transition.
    pub fn report(&mut self, event: DeploymentEvent) {
        match event {
            DeploymentEvent::PreparingArtifact(component) => {
                self.start_activity(format!("Preparing {}...", component.artifact_label()));
            }
            DeploymentEvent::DownloadingArtifact { component, total } => {
                self.start_download(
                    total,
                    format!("Downloading {}...", component.artifact_label()),
                );
            }
            DeploymentEvent::DownloadAdvanced { downloaded } => {
                if let Some(Indicator::Download(progress)) = &self.active {
                    progress.set_position(downloaded);
                }
            }
            DeploymentEvent::VerifyingArtifact(component) => self.set_message(format!(
                "Verifying {} checksum...",
                component.artifact_label()
            )),
            DeploymentEvent::InstallingArtifact(component) => {
                self.set_message(format!("Installing {}...", component.artifact_label()));
            }
            DeploymentEvent::ArtifactReady {
                component,
                disposition,
            } => self.finish(format!(
                "{} {}.",
                component.artifact_label(),
                disposition.label()
            )),
            DeploymentEvent::StartingService(component) => {
                self.start_activity(format!("Starting local {}...", component.service_label()));
            }
            DeploymentEvent::ServiceReady {
                component,
                disposition,
                url,
            } => self.finish(format!(
                "Local {} {} at {url}.",
                component.service_label(),
                disposition.label()
            )),
        }
    }

    fn start_activity(&mut self, message: String) {
        self.active = Some(Indicator::Activity(self.ui.activity(message)));
    }

    fn start_download(&mut self, total: Option<u64>, message: String) {
        self.active = Some(Indicator::Download(self.ui.download(total, message)));
    }

    fn set_message(&self, message: String) {
        match &self.active {
            Some(Indicator::Activity(progress)) => progress.set_message(message),
            Some(Indicator::Download(progress)) => progress.set_message(message),
            None => {}
        }
    }

    fn finish(&mut self, message: String) {
        match self.active.take() {
            Some(Indicator::Activity(progress)) => progress.finish(message),
            Some(Indicator::Download(progress)) => progress.finish(message),
            None => self.ui.success(message),
        }
    }
}
