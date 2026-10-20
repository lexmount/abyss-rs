//! GLM-compatible streamed traffic through the real explicit broker and plugin socket.

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

const REQUEST: &str = include_str!("../../../abyss-agent-hook/tests/fixtures/glm/request.json");
const RESPONSE: &str = include_str!("../../../abyss-agent-hook/tests/fixtures/glm/response.sse");

#[test]
fn glm_stream_reaches_plugin_with_thinking_tool_call_and_usage() {
    let api_addr = reserve_api_loopback_addr();
    let startup_path = super::runtime_root_path(api_addr).join("glm-startup.json");
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
        &json!({"protocol_version": 1_u16, "plugin_id": "glm-blackbox"}),
    );
    assert_eq!(read_plugin_frame(&mut plugin)["protocol_version"], 1_u16);

    let upstream = TcpListener::bind(loopback_ephemeral_addr()).unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        stream.set_read_timeout(Some(HTTP_TIMEOUT)).unwrap();
        let mut request = Vec::new();
        loop {
            let mut chunk = [0_u8; 4096];
            let count = stream.read(&mut chunk).unwrap();
            assert!(count > 0, "broker must forward the complete GLM request");
            request.extend_from_slice(&chunk[..count]);
            if request.ends_with(REQUEST.as_bytes()) {
                break;
            }
        }
        let request = String::from_utf8(request).unwrap();
        assert!(request.starts_with("POST /api/paas/v4/chat/completions HTTP/1.1"));
        assert!(!request.to_ascii_lowercase().contains("accept-encoding:"));
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{RESPONSE}",
            RESPONSE.len()
        )
        .unwrap();
    });
    let client = reqwest::blocking::Client::builder()
        .proxy(reqwest::Proxy::all(format!("http://{proxy_addr}")).unwrap())
        .timeout(HTTP_TIMEOUT)
        .build()
        .unwrap();
    let response = client
        .post(format!(
            "http://{upstream_addr}/api/paas/v4/chat/completions"
        ))
        .header("user-agent", "deepseek-harness/0.2.0-rc.2")
        .header("x-deepseek-harness-session-id", "glm-blackbox-session")
        .header("content-type", "application/json")
        .header("accept-encoding", "gzip, br")
        .body(REQUEST)
        .send()
        .unwrap()
        .error_for_status()
        .unwrap();
    assert_eq!(response.text().unwrap(), RESPONSE);
    server.join().unwrap();

    let request = read_plugin_frame(&mut plugin);
    let response = read_plugin_frame(&mut plugin);
    assert_eq!(request["agent"]["name"], "deepseek-harness");
    assert_eq!(request["session_id"], "glm-blackbox-session");
    assert_eq!(response["session_id"], request["session_id"]);
    assert_eq!(response["llm"]["model"], "glm-4.7");
    assert_eq!(request["token_usage"]["input_tokens"], 20_u64);
    assert_eq!(request["token_usage"]["cache_read_tokens"], 80_u64);
    assert_eq!(response["token_usage"]["output_tokens"], 12_u64);
    assert_eq!(response["token_usage"]["reasoning_tokens"], 5_u64);
    assert_eq!(response["conversation"]["messages"][0]["role"], "reasoning");
    assert_eq!(
        response["conversation"]["messages"][0]["text"],
        "I should read the file."
    );
    assert_eq!(response["tool_calls"][0]["name"], "read_file");
    assert_eq!(
        response["tool_calls"][0]["input"],
        r#"{"path":"probe.txt"}"#
    );
    broker.shutdown();
    broker.wait_for_exit();
}
