//! Real-Codex inspection participant, driven by `scripts/blackbox_sdk_codex.py`.
//! Evidence contains test markers and metadata only, never request bodies or credentials.

use std::{fs::OpenOptions, io::Write as _, path::PathBuf, sync::Arc};

use abyss_sdk::{
    event::AgentEvent,
    plugin::{AgentRequestContext, BrokerPlugin, DecodedContent, RequestDecision},
};
use serde_json::{Value, json};

struct Evidence {
    path: PathBuf,
    allow_marker: String,
    block_marker: String,
}

impl Evidence {
    fn record(&self, value: &Value) {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .unwrap();
        writeln!(file, "{value}").unwrap();
    }

    fn inspect(&self, context: &AgentRequestContext) -> RequestDecision {
        if context.path == "/__abyss_sdk_ready" {
            self.record(&json!({"kind": "ready"}));
        }
        let agent = context.agent.as_ref();
        let blocked = agent.is_some_and(|agent| {
            agent
                .conversation
                .entries
                .iter()
                .any(|entry| entry.text.contains(&self.block_marker))
        });
        for (case, marker) in [("allow", &self.allow_marker), ("block", &self.block_marker)] {
            if !matches!(&context.body, DecodedContent::Utf8(body) if body.contains(marker)) {
                continue;
            }
            self.record(&json!({
                "kind": "inspection", "case": case, "request_id": context.request_id,
                "harness": context.harness.as_ref().map(|harness| &harness.id),
                "host": context.destination_host, "server_name": context.server_name,
                "source_process_absent": context.source_process.is_none(),
                "parsing_status": context.parsing_status,
                "model": agent.and_then(|agent| agent.model.as_ref()),
                "protocol": agent.map(|agent| &agent.protocol),
                "agent_has_marker": agent.is_some_and(|agent| agent.conversation.entries.iter().any(|entry| entry.text.contains(marker))),
                "json_has_marker": context.json.as_ref().is_some_and(|value| value.to_string().contains(marker)),
                "credential_headers_absent": !context.headers.iter().any(|(name, _)| matches!(name.to_ascii_lowercase().as_str(), "authorization" | "proxy-authorization" | "cookie" | "x-api-key")),
                "allow": !blocked,
            }));
        }
        if blocked {
            RequestDecision::Block("SDK black-box policy".to_owned())
        } else {
            RequestDecision::Allow
        }
    }

    fn event(&self, event: &AgentEvent) {
        let contains = |marker: &str| {
            event.conversation.as_ref().is_some_and(|conversation| {
                conversation
                    .entries
                    .iter()
                    .any(|entry| entry.text.contains(marker))
            })
        };
        self.record(&json!({
            "kind": "event", "side": event.side, "agent": event.agent.name,
            "response_id": event.response_id, "session_id": event.session_id,
            "model": event.llm.model, "provider": event.llm.provider,
            "allow_marker": contains(&self.allow_marker), "block_marker": contains(&self.block_marker),
            "token_usage": event.token_usage,
        }));
    }
}

#[tokio::test]
#[ignore = "requires the real broker and Codex runner: make test-blackbox-sdks-codex"]
async fn codex_inspection_plugin() {
    let evidence = Arc::new(Evidence {
        path: std::env::var_os("ABYSS_SDK_CODEX_EVIDENCE")
            .expect("evidence path")
            .into(),
        allow_marker: std::env::var("ABYSS_SDK_CODEX_ALLOW_MARKER").unwrap(),
        block_marker: std::env::var("ABYSS_SDK_CODEX_BLOCK_MARKER").unwrap(),
    });
    let requests = evidence.clone();
    let close = BrokerPlugin::new("blackbox.codex.rust")
        .with_endpoint(std::env::var("ABYSS_SDK_CODEX_ENDPOINT").unwrap())
        .on_agent_request(move |context| {
            std::future::ready(Ok::<_, std::convert::Infallible>(
                requests.inspect(&context),
            ))
        })
        .run_with_events(move |event| {
            evidence.event(&event);
            std::future::ready(Ok::<_, std::convert::Infallible>(()))
        })
        .await
        .unwrap();
    assert_eq!(close.code, 100, "broker must close the SDK session cleanly");
}
