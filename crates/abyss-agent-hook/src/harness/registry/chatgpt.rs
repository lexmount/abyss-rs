//! `ChatGPT` desktop mode attribution from the source application and its HTTP operation.

use abyss_mitm::SourceProcess;
use http::Method;

use crate::harness::{BuiltInHarness, HarnessDetection};
use crate::http_metadata::{flow_server_name, request_host};

use super::{HarnessDetector, HarnessRequest};

pub(super) struct ChatGptDetector;

impl HarnessDetector for ChatGptDetector {
    fn detect(&self, request: &HarnessRequest<'_>) -> Option<HarnessDetection> {
        let source = request.flow.source_process.as_ref()?;
        if !is_desktop_app(source) || request.method != Method::POST {
            return None;
        }

        // Both modes can send Codex headers from the same helper. Attribute chat
        // turns by the operation the desktop app invokes, regardless of wire format.
        let path = request.uri.path().trim_end_matches('/');
        if !matches!(
            path,
            "/backend-api/f/conversation" | "/backend-api/conversation"
        ) {
            return None;
        }
        let host = request_host(request.headers, request.uri)
            .or_else(|| flow_server_name(request.flow))?;
        matches!(host.as_str(), "chatgpt.com" | "chat.openai.com").then_some(HarnessDetection {
            harness_id: BuiltInHarness::ChatGpt.into(),
            version: None,
        })
    }

    // The shared helper can also carry Codex headers on a desktop chat turn.
    fn is_exclusive(&self) -> bool {
        true
    }
}

fn is_desktop_app(source: &SourceProcess) -> bool {
    matches!(
        source.application_id.as_deref(),
        Some(
            "com.openai.chat"
                | "com.openai.chat.helper"
                | "com.openai.codex"
                | "com.openai.codex.helper"
        )
    ) || source
        .name
        .as_deref()
        .into_iter()
        .chain(source.executable_path.as_deref())
        .any(|value| {
            let name = value.rsplit(['/', '\\']).next().unwrap_or(value);
            [
                "ChatGPT",
                "ChatGPT Helper",
                "ChatGPT.exe",
                "ChatGPT Helper.exe",
            ]
            .iter()
            .any(|known| name.eq_ignore_ascii_case(known))
        })
}
