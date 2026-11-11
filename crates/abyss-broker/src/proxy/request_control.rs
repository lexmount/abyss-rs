//! Request-side parsing and forwarding decisions, using only the plugin channel client.
//! The plugin service receives prepared context and owns all session interaction.

use std::sync::Arc;

use abyss_agent_hook::{AgentRequestParser, HooksRuntimeConfig, RequestActions};
use abyss_mitm::{
    LocalRejection, RequestEditor, RequestForwardingControl, RequestForwardingResult, RequestView,
};
use axum::http::StatusCode;

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
    ) -> Result<RequestForwardingResult, LocalRejection> {
        let request_id = uuid::Uuid::new_v4().to_string();
        let mut request = RequestEditor::new(request);
        let actions = RequestActions::new(&request.view());
        let config = self.hooks.snapshot();
        let mut parsed = AgentRequestParser::prepare(&request.view());
        let mut context = Arc::new(AgentRequestParser::parse_prepared(
            &parsed,
            &request.view(),
            &config.harness_usage.config,
            request_id.clone(),
        ));
        let mut participants = plan.participants().peekable();
        while let Some(participant) = participants.next() {
            match self.plugins.inspect(participant, context.clone()).await {
                Ok(InspectionDecision::Allow) => {}
                Ok(InspectionDecision::Modify(list)) => {
                    if list.is_empty() {
                        continue;
                    }
                    actions.apply(&mut request, list).map_err(|error| {
                        LocalRejection::new(
                            StatusCode::BAD_GATEWAY,
                            "invalid_agent_request_edit",
                            error.to_string(),
                            request_id.clone(),
                        )
                    })?;
                    parsed = AgentRequestParser::prepare(&request.view());
                    if participants.peek().is_some() {
                        let mut updated = AgentRequestParser::parse_prepared(
                            &parsed,
                            &request.view(),
                            &config.harness_usage.config,
                            request_id.clone(),
                        );
                        actions.annotate(&request.view(), &mut updated);
                        context = Arc::new(updated);
                    }
                }
                Ok(InspectionDecision::Block(reason)) => {
                    return Err(LocalRejection::new(
                        StatusCode::FORBIDDEN,
                        "agent_request_blocked",
                        reason,
                        request_id,
                    ));
                }
                Ok(_) => {
                    return Err(LocalRejection::new(
                        StatusCode::BAD_GATEWAY,
                        "invalid_agent_request_edit",
                        "Unsupported request decision",
                        request_id,
                    ));
                }
                Err(error) => {
                    let (status, code) = match error {
                        InspectionError::PayloadTooLarge => {
                            (StatusCode::PAYLOAD_TOO_LARGE, "inspection_body_too_large")
                        }
                        InspectionError::Encoding | InspectionError::Unavailable => {
                            (StatusCode::SERVICE_UNAVAILABLE, "inspection_unavailable")
                        }
                    };
                    return Err(LocalRejection::new(
                        status,
                        code,
                        error.to_string(),
                        request_id,
                    ));
                }
            }
        }
        Ok(request.finish(parsed))
    }
}
