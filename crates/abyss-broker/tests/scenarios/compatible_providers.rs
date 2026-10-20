//! Compatible provider streams through the real explicit broker and plugin socket.

use std::{
    io::{Read as _, Write as _},
    net::TcpListener,
    os::unix::net::UnixStream,
    thread,
};

use serde_json::json;

use super::{
    BrokerProcess, HTTP_TIMEOUT, REST_TIMEOUT, loopback_ephemeral_addr, read_plugin_frame,
    reserve_api_loopback_addr, write_plugin_frame,
};

struct StreamScenario<'a> {
    path: &'a str,
    request: &'a str,
    response: &'a str,
    model: &'a str,
    input_tokens: u64,
    cache_read_tokens: u64,
    cache_write_tokens: u64,
    reasoning_tokens: u64,
    thinking: &'a str,
    tool_name: &'a str,
    call_id: &'a str,
}

#[test]
fn glm_stream_reaches_plugin_with_thinking_tool_call_and_usage() {
    StreamScenario {
        path: "/api/paas/v4/chat/completions",
        request: include_str!("../../../abyss-agent-hook/tests/fixtures/glm/request.json"),
        response: include_str!("../../../abyss-agent-hook/tests/fixtures/glm/response.sse"),
        model: "glm-4.7",
        input_tokens: 20,
        cache_read_tokens: 80,
        cache_write_tokens: 0,
        reasoning_tokens: 5,
        thinking: "I should read the file.",
        tool_name: "read_file",
        call_id: "glm-call-1",
    }
    .verify();
}

#[test]
fn kimi_protocol_streams_reach_plugin_with_disjoint_cache_and_thinking_usage() {
    for (fixture, response, reasoning_tokens) in [
        (
            include_str!("../../../abyss-agent-hook/tests/fixtures/kimi/chat-completions.json"),
            include_str!("../../../abyss-agent-hook/tests/fixtures/kimi/chat-completions.sse"),
            0,
        ),
        (
            include_str!("../../../abyss-agent-hook/tests/fixtures/kimi/responses.json"),
            include_str!("../../../abyss-agent-hook/tests/fixtures/kimi/responses.sse"),
            5,
        ),
        (
            include_str!("../../../abyss-agent-hook/tests/fixtures/kimi/messages.json"),
            include_str!("../../../abyss-agent-hook/tests/fixtures/kimi/messages.sse"),
            5,
        ),
    ] {
        let fixture: serde_json::Value = serde_json::from_str(fixture).unwrap();
        StreamScenario {
            path: fixture["path"].as_str().unwrap(),
            request: &fixture["request"].to_string(),
            response,
            model: "kimi-k3",
            call_id: "kimi-call-1",
            input_tokens: 10,
            cache_read_tokens: 60,
            cache_write_tokens: 30,
            reasoning_tokens,
            thinking: "Read the file.",
            tool_name: "read",
        }
        .verify();
    }
}

#[test]
fn qwen_streams_preserve_tool_identity_and_corrected_messages_usage() {
    for (fixture, response, reasoning_tokens) in [
        (
            include_str!("../../../abyss-agent-hook/tests/fixtures/qwen/chat-completions.json"),
            include_str!("../../../abyss-agent-hook/tests/fixtures/qwen/chat-completions.sse"),
            5,
        ),
        (
            include_str!("../../../abyss-agent-hook/tests/fixtures/qwen/responses.json"),
            include_str!("../../../abyss-agent-hook/tests/fixtures/qwen/responses.sse"),
            5,
        ),
        (
            include_str!("../../../abyss-agent-hook/tests/fixtures/qwen/messages.json"),
            include_str!("../../../abyss-agent-hook/tests/fixtures/qwen/messages.sse"),
            0,
        ),
    ] {
        let fixture: serde_json::Value = serde_json::from_str(fixture).unwrap();
        StreamScenario {
            path: fixture["path"].as_str().unwrap(),
            request: &fixture["request"].to_string(),
            response,
            model: "qwen3.8-flash",
            call_id: "qwen-call-1",
            input_tokens: 40,
            cache_read_tokens: 60,
            cache_write_tokens: 0,
            reasoning_tokens,
            thinking: "Read the file.",
            tool_name: "read",
        }
        .verify();
    }
}

impl StreamScenario<'_> {
    fn verify(&self) {
        let api_addr = reserve_api_loopback_addr();
        let startup_path = super::runtime_root_path(api_addr).join("provider-startup.json");
        let mut broker = BrokerProcess::spawn_with_options(
            api_addr,
            Some(&startup_path),
            json!({"mode": "explicit", "listen_addr": loopback_ephemeral_addr()}),
        );
        let startup = broker.wait_for_startup_info(&startup_path);
        let running = broker.wait_for_running();
        let proxy_addr = running.listen_addr.unwrap();
        let mut plugin = UnixStream::connect(startup.plugin_endpoint)
            .expect("plugin should connect to the explicit broker");
        plugin.set_read_timeout(Some(REST_TIMEOUT)).unwrap();
        write_plugin_frame(
            &mut plugin,
            &json!({"protocol_version": 1_u16, "plugin_id": "provider-blackbox"}),
        );
        assert_eq!(
            read_plugin_frame(&mut plugin)["protocol_version"],
            1_u16,
            "plugin handshake must negotiate the expected version"
        );

        let upstream = TcpListener::bind(loopback_ephemeral_addr()).unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let request_body = self.request.to_owned();
        let response_body = self.response.to_owned();
        let path = self.path.to_owned();
        let server = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            stream.set_read_timeout(Some(HTTP_TIMEOUT)).unwrap();
            let mut request = Vec::new();
            loop {
                let mut chunk = [0_u8; 4096];
                let count = stream.read(&mut chunk).unwrap();
                assert!(
                    count > 0,
                    "broker must forward the complete provider request"
                );
                request.extend_from_slice(&chunk[..count]);
                if request.ends_with(request_body.as_bytes()) {
                    break;
                }
            }
            let request = String::from_utf8(request).unwrap();
            assert!(
                request.starts_with(&format!("POST {path} HTTP/1.1")),
                "broker must preserve the provider request path"
            );
            assert!(
                !request.to_ascii_lowercase().contains("accept-encoding:"),
                "broker must request uncompressed Agent response content"
            );
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response_body}",
                response_body.len()
            )
            .unwrap();
        });
        let client = reqwest::blocking::Client::builder()
            .proxy(reqwest::Proxy::all(format!("http://{proxy_addr}")).unwrap())
            .timeout(HTTP_TIMEOUT)
            .build()
            .unwrap();
        let response = client
            .post(format!("http://{upstream_addr}{}", self.path))
            .header("user-agent", "deepseek-harness/0.2.0-rc.2")
            .header("x-deepseek-harness-session-id", "provider-blackbox-session")
            .header("content-type", "application/json")
            .header("accept-encoding", "gzip, br")
            .body(self.request.to_owned())
            .send()
            .unwrap()
            .error_for_status()
            .unwrap();
        assert_eq!(
            response.text().unwrap(),
            self.response,
            "the client must receive the original provider stream"
        );
        server.join().unwrap();

        let request = read_plugin_frame(&mut plugin);
        let response = read_plugin_frame(&mut plugin);
        self.verify_events(&request, &response);
        assert_eq!(
            response["tool_calls"][0]["call_id"], self.call_id,
            "empty argument-only metadata must not erase the tool call ID"
        );
        broker.shutdown();
        broker.wait_for_exit();
    }

    fn verify_events(&self, request: &serde_json::Value, response: &serde_json::Value) {
        assert_eq!(
            request["agent"]["name"], "deepseek-harness",
            "provider selection must preserve Harness attribution"
        );
        assert_eq!(
            request["session_id"], "provider-blackbox-session",
            "request must carry the client session"
        );
        assert_eq!(
            response["session_id"], request["session_id"],
            "request and response must share a session"
        );
        assert_eq!(
            response["llm"]["model"], self.model,
            "provider model must survive delivery"
        );
        assert_eq!(
            request["token_usage"],
            json!({
                "input_tokens": self.input_tokens,
                "cache_read_tokens": self.cache_read_tokens,
                "cache_write_tokens": self.cache_write_tokens,
                "output_tokens": 0_u64,
                "reasoning_tokens": 0_u64,
                "total_tokens": 100_u64
            }),
            "input, cache reads and cache writes must remain disjoint"
        );
        assert_eq!(
            response["token_usage"],
            json!({
                "input_tokens": 0_u64, "cache_read_tokens": 0_u64, "cache_write_tokens": 0_u64,
                "output_tokens": 12_u64, "reasoning_tokens": self.reasoning_tokens, "total_tokens": 12_u64
            }),
            "reasoning tokens must not inflate output totals"
        );
        assert_eq!(
            response["conversation"]["messages"][0]["role"], "reasoning",
            "thinking must have its own conversation role"
        );
        assert_eq!(
            response["conversation"]["messages"][0]["text"], self.thinking,
            "thinking fragments must be assembled once"
        );
        assert_eq!(
            response["tool_calls"][0]["name"], self.tool_name,
            "tool name must survive delivery"
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(
                response["tool_calls"][0]["input"].as_str().unwrap()
            )
            .unwrap(),
            json!({"path": "probe.txt"}),
            "tool arguments must be assembled into the original JSON"
        );
    }
}
