//! Wires incremental Claude Code session calls into the existing usage hook.

use std::{sync::Arc, time::SystemTime};

use abyss_mitm::{FlowContext, HookError, HookFuture, HttpResponseObserver};
use abyss_plugin_protocol::event::LlmProvider;
use http::{Request, Response};

use crate::{
    config::{HarnessUsageHookConfig, HooksRuntimeConfig},
    delivery::{AgentEventSink, EventDelivery},
    event::{ExchangePassthrough, normalize_exchange},
    harness::{AgentDeclaration, DeclarationSource, HarnessDetection, HarnessRegistry},
    protocol::{
        anthropic::claude_code_session::{ClaudeCodeSession, session_segment},
        shared::sse::SseStream,
    },
};

use super::HarnessUsageHook;

impl<S: AgentEventSink + 'static> HarnessUsageHook<S> {
    pub(super) fn observe_claude_code_session(
        &self,
        flow: &FlowContext,
        request: &Request<()>,
        response: &Response<()>,
    ) -> Option<Box<dyn HttpResponseObserver>> {
        let session = session_segment(request)?;
        let policy = self.runtime_config.snapshot();
        let detection =
            HarnessRegistry::recognize_request(flow, request, &policy.harness_usage.config, true)?;
        let declaration = HarnessRegistry::declare(
            &detection.harness_id,
            &DeclarationSource {
                headers: Some(request.headers()),
                connection_headers: None,
                client_metadata: None,
            },
        );
        Some(Box::new(ClaudeCodeObserver {
            sse: SseStream::default(),
            session: ClaudeCodeSession::new(session),
            detection,
            declaration,
            passthrough: ExchangePassthrough::from_headers(
                request.uri(),
                request.headers(),
                response.headers(),
            ),
            config: Arc::clone(&self.config),
            runtime_config: self.runtime_config.clone(),
            delivery: Arc::clone(&self.delivery),
        }))
    }
}

struct ClaudeCodeObserver<S> {
    sse: SseStream,
    session: ClaudeCodeSession,
    detection: HarnessDetection,
    declaration: AgentDeclaration,
    passthrough: ExchangePassthrough,
    config: Arc<HarnessUsageHookConfig>,
    runtime_config: HooksRuntimeConfig,
    delivery: Arc<EventDelivery<S>>,
}

impl<S: AgentEventSink> HttpResponseObserver for ClaudeCodeObserver<S> {
    fn on_http_response_chunk<'a>(
        &'a mut self,
        at: SystemTime,
        mut chunk: &'a [u8],
    ) -> HookFuture<'a> {
        Box::pin(async move {
            let mut result = Ok(());
            while let Some(data) = self.sse.next_event(&mut chunk) {
                let policy = self.runtime_config.snapshot();
                let usage = &policy.harness_usage;
                let harness = self.detection.harness_id.as_str();
                if !usage.enabled || !usage.config.enabled_for_harness(harness) {
                    self.session.reset();
                    continue;
                }
                if let Some(call) = self.session.push(&data, at) {
                    self.passthrough
                        .set_times(call.request_at, call.response_at);
                    let events = normalize_exchange(
                        &self.config,
                        &call,
                        &usage.config.content_for_harness(harness),
                        &self.detection,
                        &LlmProvider::Anthropic,
                        &self.declaration,
                        &self.passthrough,
                    );
                    if let Err(error) = self.delivery.deliver(events).await {
                        result = Err(HookError::failed(error.to_string()));
                    }
                }
            }
            result
        })
    }
}

#[cfg(test)]
mod tests;
