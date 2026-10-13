//! Replay isolated HTTP fixtures through the real hook, emitting v2 Agent events.

use std::{
    convert::Infallible,
    future::Future,
    io::{self, BufRead as _},
    net::SocketAddr,
};

use abyss_agent_hook::{
    AgentEventSink, DeviceIdentity, HarnessUsageHook, HarnessUsageHookConfig, HooksConfig,
    HooksRuntimeConfig,
};
use abyss_mitm::{
    CapturedBody, FlowContext, HttpExchange, MitmHook as _, OriginalDestination, SourceProcess,
    TransparentProtocol,
};
use abyss_plugin_protocol::event::AgentEvent;
use http::{Request, Response};
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug)]
struct JsonSink;

impl AgentEventSink for JsonSink {
    type Error = Infallible;

    fn publish(&self, event: AgentEvent) -> impl Future<Output = Result<(), Self::Error>> + Send {
        println!(
            "{}",
            serde_json::to_string(&event).expect("event serializes")
        );
        std::future::ready(Ok(()))
    }
}

#[derive(Deserialize)]
struct Exchange {
    path: String,
    session_id: String,
    request: Value,
    response: Value,
}

fn body(value: Value) -> Result<CapturedBody, serde_json::Error> {
    let bytes = match value {
        Value::String(text) => text.into_bytes(),
        value => serde_json::to_vec(&value)?,
    };
    Ok(CapturedBody::from_bytes(bytes.into()))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config: HooksConfig = serde_json::from_value(serde_json::json!({
        "harness_usage":{"config":{"harnesses":{"replay-agent":{
            "enabled":true,"matchers":[{"process_names":["replay-agent"]}]
        }}}}
    }))?;
    let hook = HarnessUsageHook::with_runtime_config_and_event_sink(
        HarnessUsageHookConfig::new(DeviceIdentity::new()),
        HooksRuntimeConfig::new(config),
        JsonSink,
    );
    for line in io::stdin().lock().lines() {
        let exchange: Exchange = serde_json::from_str(&line?)?;
        let flow = FlowContext::from_optional_addrs(
            None,
            None,
            OriginalDestination::from(SocketAddr::from(([127, 0, 0, 1], 443))),
            TransparentProtocol::PlainHttp,
            Some(SourceProcess::new(
                Some(42),
                Some("replay-agent".to_owned()),
                None,
            )),
        );
        let request = Request::builder()
            .method("POST")
            .uri(&exchange.path)
            .header(
                "host",
                if exchange.path == "/v1/messages" {
                    "api.anthropic.com"
                } else {
                    "api.openai.com"
                },
            )
            .header("session-id", &exchange.session_id)
            .header("content-type", "application/json")
            .body(body(exchange.request)?)?;
        let response = Response::builder()
            .header("content-type", "application/json")
            .body(body(exchange.response)?)?;
        hook.on_http_exchange(&HttpExchange::new(flow, request, response))
            .await?;
    }
    Ok(())
}
