//! Native `OpenCode` requests through the real explicit broker and plugin socket.
//! A local HTTP provider exercises streaming tools and session correlation.

use std::{
    io::{Read as _, Write as _},
    net::TcpListener,
    os::unix::net::UnixStream,
    thread,
};

use reqwest::blocking::Client;
use serde_json::{Value, json};

use super::{
    BrokerProcess, HTTP_TIMEOUT, REST_TIMEOUT, loopback_ephemeral_addr, read_plugin_frame,
    reserve_api_loopback_addr, runtime_root_path, write_plugin_frame,
};

struct OpenCodeScenario {
    broker: BrokerProcess,
    plugin: UnixStream,
    client: Client,
}

impl OpenCodeScenario {
    fn start() -> Self {
        let api_addr = reserve_api_loopback_addr();
        let startup_path = runtime_root_path(api_addr).join("opencode-startup.json");
        let mut broker = BrokerProcess::spawn_with_options(
            api_addr,
            Some(&startup_path),
            json!({"mode": "explicit", "listen_addr": loopback_ephemeral_addr()}),
        );
        let startup = broker.wait_for_startup_info(&startup_path);
        let proxy_addr = broker.wait_for_running().listen_addr.unwrap();
        let mut plugin = UnixStream::connect(startup.plugin_endpoint).unwrap();
        plugin.set_read_timeout(Some(REST_TIMEOUT)).unwrap();
        write_plugin_frame(
            &mut plugin,
            &json!({"protocol_version": 1_u16, "plugin_id": "opencode-blackbox"}),
        );
        assert_eq!(
            read_plugin_frame(&mut plugin)["protocol_version"],
            1_u16,
            "the broker must accept the plugin handshake"
        );
        let client = Client::builder()
            .proxy(reqwest::Proxy::all(format!("http://{proxy_addr}")).unwrap())
            .timeout(HTTP_TIMEOUT)
            .build()
            .unwrap();
        Self {
            broker,
            plugin,
            client,
        }
    }

    fn exchange(&mut self, session: &str, id: &str, messages: &Value, delta: &Value) -> [Value; 2] {
        let upstream = TcpListener::bind(loopback_ephemeral_addr()).unwrap();
        let address = upstream.local_addr().unwrap();
        let request = json!({"model": "deepseek-flash", "stream": true,
            "stream_options": {"include_usage": true}, "messages": messages})
        .to_string();
        let response = format!(
            "data: {}\n\ndata: {}\n\ndata: [DONE]\n\n",
            json!({"id": id, "model": "deepseek-flash", "choices": [{"index": 0_i32,
                "delta": delta, "finish_reason": null}]}),
            json!({"id": id, "model": "deepseek-flash", "choices": [],
                "usage": {"prompt_tokens": 10_i32, "completion_tokens": 5_i32,
                    "prompt_tokens_details": {"cached_tokens": 3_i32}, "total_tokens": 15_i32}}),
        );
        let server = Self::upstream(upstream, request.clone(), response.clone());
        let forwarded = self
            .client
            .post(format!("http://{address}/chat/completions"))
            .header("user-agent", "opencode/latest/1.19.4/cli")
            .header("x-opencode-session-id", session)
            .header("x-session-id", session)
            .header("content-type", "application/json")
            .body(request)
            .send()
            .unwrap()
            .error_for_status()
            .unwrap()
            .text()
            .unwrap();
        assert_eq!(
            forwarded, response,
            "SSE bytes must reach the client intact"
        );
        server.join().unwrap();
        let events = [
            read_plugin_frame(&mut self.plugin),
            read_plugin_frame(&mut self.plugin),
        ];
        for (event, side) in events.iter().zip(["request", "response"]) {
            assert_eq!(
                event["side"], side,
                "events must retain request/response order"
            );
            assert_eq!(
                event["agent"]["name"], "opencode",
                "native headers must identify OpenCode"
            );
            assert_eq!(
                event["agent"]["version"], "1.19.4",
                "the version must exclude the release channel"
            );
            assert_eq!(
                event["session_id"], session,
                "the native session must survive proxying"
            );
            assert_eq!(
                event["response_id"], id,
                "each inference must retain its provider response ID"
            );
            assert_eq!(
                event["llm"]["model"], "deepseek-flash",
                "harness identity must not override the model"
            );
            assert!(
                event.get("turn_id").is_none(),
                "ordinary provider requests declare no turn"
            );
        }
        assert_eq!(
            events[0]["token_usage"]["input_tokens"], 7_i32,
            "input tokens must exclude cached tokens"
        );
        assert_eq!(
            events[0]["token_usage"]["cache_read_tokens"], 3_i32,
            "cache reads belong on the request event"
        );
        assert_eq!(
            events[1]["token_usage"]["output_tokens"], 5_i32,
            "output usage must survive SSE parsing"
        );
        events
    }

    fn upstream(listener: TcpListener, body: String, response: String) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(HTTP_TIMEOUT)).unwrap();
            let mut request = Vec::new();
            while !request.ends_with(body.as_bytes()) {
                let mut buffer = [0_u8; 4096];
                let count = stream.read(&mut buffer).unwrap();
                assert!(count > 0, "the upstream must receive the complete request");
                request.extend_from_slice(&buffer[..count]);
            }
            let request = String::from_utf8(request).unwrap();
            assert!(
                request.starts_with("POST /chat/completions HTTP/1.1"),
                "the provider route must be forwarded unchanged"
            );
            assert!(
                request.contains("opencode/latest/1.19.4/cli"),
                "the provider must receive the native client identity"
            );
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}", response.len()).unwrap();
        })
    }

    fn stop(mut self) {
        self.broker.shutdown();
        self.broker.wait_for_exit();
    }
}

/// The first conversation entry of `event` in `role`.
fn entry<'a>(event: &'a Value, role: &str) -> &'a Value {
    event["conversation"]["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["role"] == role)
        .unwrap_or_else(|| panic!("the event must carry a {role} entry"))
}

#[test]
fn opencode_streaming_tools_and_resumed_sessions_reach_plugin() {
    let mut scenario = OpenCodeScenario::start();
    let user = json!({"role": "user", "content": "Read fixture.txt"});
    let call = json!({"id": "call-read", "type": "function",
        "function": {"name": "read", "arguments": "{\"filePath\":\"fixture.txt\"}"}});
    let first = scenario.exchange(
        "session-a",
        "reply-tool",
        &json!([user]),
        &json!({"role": "assistant", "tool_calls": [{"index": 0_i32,
            "id": call["id"], "type": "function", "function": call["function"]}]}),
    );
    let tool_call = entry(&first[1], "tool_call");
    assert_eq!(tool_call["call_id"], "call-read");
    assert_eq!(tool_call["name"], "read");
    let followup = scenario.exchange(
        "session-a",
        "reply-followup",
        &json!([
            user, {"role": "assistant", "tool_calls": [call]},
            {"role": "tool", "tool_call_id": "call-read", "content": "fixture contents"}
        ]),
        &json!({"role": "assistant", "content": "The file contains fixture contents."}),
    );
    assert_eq!(entry(&followup[0], "tool_result")["call_id"], "call-read");
    assert!(
        entry(&followup[1], "assistant")["text"]
            .as_str()
            .unwrap()
            .contains("fixture contents")
    );
    for (session, reply) in [("session-a", "reply-resumed"), ("session-b", "reply-new")] {
        scenario.exchange(
            session,
            reply,
            &json!([{"role": "user", "content": "Hello again"}]),
            &json!({"role": "assistant", "content": "Hello"}),
        );
    }
    scenario.stop();
}
