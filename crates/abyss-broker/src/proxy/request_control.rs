//! Request-side parsing and forwarding decisions, using only the plugin channel client.
//! The plugin service receives prepared context and owns all session interaction.

use std::sync::Arc;

use abyss_agent_hook::{AgentRequestParser, HooksRuntimeConfig};
use abyss_mitm::{LocalRejection, RequestForwardingControl, RequestView};
use axum::http::{Extensions, StatusCode};

use crate::plugin::{InspectionDecision, InspectionError, InspectionPlan, PluginClient};

#[derive(Clone)]
pub(super) struct RequestControl {
    plugins: PluginClient,
    hooks: HooksRuntimeConfig,
}

impl RequestControl {
    pub(super) const fn new(plugins: PluginClient, hooks: HooksRuntimeConfig) -> Self {
        Self { plugins, hooks }
    }
}

impl RequestForwardingControl for RequestControl {
    type Plan = InspectionPlan;

    fn plan(&self) -> Option<Self::Plan> {
        self.plugins.inspection_plan()
    }

    async fn before_forward(
        &self,
        plan: Self::Plan,
        request: RequestView<'_>,
    ) -> Result<Extensions, LocalRejection> {
        let request_id = uuid::Uuid::new_v4().to_string();
        let parsed = AgentRequestParser::prepare(&request);
        let context = Arc::new(AgentRequestParser::parse_prepared(
            &parsed,
            &request,
            &self.hooks.snapshot().harness_usage.config,
            request_id.clone(),
        ));
        match self.plugins.inspect(plan, context).await {
            Ok(InspectionDecision::Allow) => {
                let mut annotations = Extensions::new();
                annotations.insert(parsed);
                Ok(annotations)
            }
            Ok(InspectionDecision::Block { reason }) => Err(LocalRejection::new(
                StatusCode::FORBIDDEN,
                "agent_request_blocked",
                reason.unwrap_or_else(|| "Request blocked by abyss-broker".to_owned()),
                request_id,
            )),
            Err(error) => {
                let (status, code) = match error {
                    InspectionError::PayloadTooLarge => {
                        (StatusCode::PAYLOAD_TOO_LARGE, "inspection_body_too_large")
                    }
                    InspectionError::Encoding | InspectionError::Unavailable => {
                        (StatusCode::SERVICE_UNAVAILABLE, "inspection_unavailable")
                    }
                };
                Err(LocalRejection::new(
                    status,
                    code,
                    error.to_string(),
                    request_id,
                ))
            }
        }
    }
}
