//! Windows module identity reaches observation and inspection without product headers.

use abyss_agent_hook::{AgentRequestParser, HarnessUsageConfig};
use abyss_mitm::{
    CapturedBody, ModuleRuntime, ProcessEntry, RequestTransport, RequestView, SourceProcess,
};
use http::Request;
use serde_json::json;

use super::Scenario;

fn python_source(entry: Option<ProcessEntry>) -> SourceProcess {
    SourceProcess::new(
        Some(42),
        Some("python.exe".to_owned()),
        Some(r"C:\Apps\Hermes\python.exe".to_owned()),
    )
    .with_application_id(Some(
        r"\device\harddiskvolume3\apps\hermes\python.exe".to_owned(),
    ))
    .with_entry_point(entry)
}

fn module(name: &str) -> ProcessEntry {
    ProcessEntry::module(ModuleRuntime::Python, name.to_owned()).unwrap()
}

#[tokio::test]
async fn module_identifies_generic_sdk_requests_across_protocols() {
    let scenario = Scenario::new(json!({}));
    for path in ["/v1/responses", "/v1/chat/completions", "/v1/messages"] {
        scenario
            .http_from_source(
                &[("user-agent", "OpenAI/Python 2.24.0")],
                path,
                "response-1",
                Some(python_source(Some(module("hermes_cli.main")))),
            )
            .await;
    }
    let events = scenario.sink.0.lock();
    assert_eq!(events.len(), 6);
    assert!(events.iter().all(|event| event.agent.name == "hermes"));
    assert!(events.iter().all(|event| event.agent.version.is_none()));
    drop(events);
}

#[tokio::test]
async fn generic_python_paths_scripts_and_other_modules_are_not_hermes() {
    for entry in [
        None,
        Some(ProcessEntry::script(
            r"C:\Apps\Hermes\hermes_cli\main.py".to_owned(),
        )),
        Some(module("hermes_cli")),
        Some(module("hermes_cli.main.other")),
        Some(module("other.hermes_cli.main")),
        Some(module("Hermes_cli.main")),
    ] {
        let scenario = Scenario::new(json!({}));
        scenario
            .http_from_source(
                &[("user-agent", "OpenAI/Python 2.24.0")],
                "/v1/chat/completions",
                "response-1",
                Some(python_source(entry)),
            )
            .await;
        assert!(scenario.sink.0.lock().is_empty());
    }
}

#[tokio::test]
async fn module_observation_respects_policy_without_falling_back_to_codex() {
    for enabled in [true, false] {
        let scenario = Scenario::new(json!({"harness_usage": {"config": {"harnesses": {
            "hermes": {"enabled": enabled}, "codex": {"enabled": true}
        }}}}));
        for user_agent in ["OpenAI/Python 2.24.0", "codex_cli_rs/1.0"] {
            scenario
                .http_from_source(
                    &[("user-agent", user_agent)],
                    "/v1/responses",
                    "response-1",
                    Some(python_source(Some(module("hermes_cli.main")))),
                )
                .await;
        }
        let events = scenario.sink.0.lock();
        assert_eq!(events.len(), if enabled { 4 } else { 0 });
        assert!(events.iter().all(|event| event.agent.name == "hermes"));
        drop(events);
    }
}

#[test]
fn module_inspection_recognition_is_independent_of_observation_policy() {
    let mut flow = Scenario::flow();
    let entry = module("hermes_cli.main");
    flow.source_process = Some(python_source(Some(entry.clone())));
    let head = Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("host", "api.deepseek.com")
        .header("user-agent", "OpenAI/Python 2.24.0")
        .body(())
        .unwrap();
    let body = CapturedBody::from_bytes(
        json!({"model": "test-model", "messages": [{"role": "user", "content": "hello"}]})
            .to_string()
            .into(),
    );
    let config: HarnessUsageConfig =
        serde_json::from_value(json!({"harnesses": {"hermes": {"enabled": false}}})).unwrap();
    let context = AgentRequestParser::parse(
        &RequestView {
            flow: &flow,
            head: &head,
            body: &body,
            transport: RequestTransport::Http,
        },
        &config,
        "request-1".to_owned(),
    );
    assert_eq!(context.harness.unwrap().id, "hermes");
    assert_eq!(context.source_process.unwrap().entry_point, Some(entry));
    assert!(context.agent.is_some());
}
