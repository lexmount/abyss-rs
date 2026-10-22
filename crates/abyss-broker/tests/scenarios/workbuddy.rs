//! `WorkBuddy` identity, legacy policy migration, and correlation across real
//! broker REST, framed ingress, and plugin boundaries. No live services are used.

use std::{
    fs,
    io::{Read as _, Write as _},
    net::TcpListener,
    os::unix::net::UnixStream,
    path::Path,
    process::{Command, Stdio},
    thread,
};

use serde_json::{Value, json};
use uuid::Uuid;

use super::{
    BrokerProcess, HTTP_TIMEOUT, REST_TIMEOUT, broker_binary, client, complete_http_request_len,
    loopback_ephemeral_addr, read_auth_token, read_plugin_frame, request_hooks_config,
    reserve_api_loopback_addr, update_hooks_config, url, write_flow_frame, write_plugin_frame,
};

#[test]
fn workbuddy_builtin_migrates_legacy_policy_and_publishes_correlated_events() {
    let api_addr = reserve_api_loopback_addr();
    let socket_path = std::env::temp_dir().join(format!("wb-{}.sock", Uuid::new_v4()));
    let startup_path = socket_path.with_extension("json");
    let mut broker =
        BrokerProcess::spawn_framed_unix_with_startup_info(api_addr, &socket_path, &startup_path);
    broker.wait_for_startup_info(&startup_path);
    broker.wait_for_running();
    broker.shutdown();
    broker.wait_for_exit();

    // Exercise the on-disk upgrade path before the first request after restart.
    let legacy: Value = serde_json::from_str(include_str!(
        "../../../abyss-agent-hook/tests/fixtures/workbuddy/legacy-hooks.json"
    ))
    .unwrap();
    fs::write(
        broker.runtime_policy_path(),
        toml::to_string_pretty(&json!({
            "schema_version": 1_u32, "hooks": legacy
        }))
        .unwrap(),
    )
    .unwrap();
    restart(&mut broker, &startup_path);
    let token = read_auth_token(&broker.auth_token_file);
    let normalized = request_hooks_config(api_addr, &token);
    assert_eq!(
        normalized["harness_usage"]["config"]["harnesses"]["workbuddy"]["enabled"],
        true
    );
    assert!(
        normalized["harness_usage"]["config"]["harnesses"]["workbuddy"]
            .get("matchers")
            .is_none()
    );

    // Old clients can still submit the original shape; subsequent saves are canonical.
    assert_eq!(update_hooks_config(api_addr, &token, &legacy), normalized);
    let persisted: Value =
        toml::from_str(&fs::read_to_string(broker.runtime_policy_path()).unwrap()).unwrap();
    assert_eq!(persisted["hooks"], normalized);
    broker.shutdown();
    broker.wait_for_exit();
    restart(&mut broker, &startup_path);
    let token = read_auth_token(&broker.auth_token_file);
    assert_eq!(request_hooks_config(api_addr, &token), normalized);

    let startup = broker.wait_for_startup_info(&startup_path);
    let mut plugin = UnixStream::connect(startup.plugin_endpoint).unwrap();
    plugin.set_read_timeout(Some(REST_TIMEOUT)).unwrap();
    write_plugin_frame(
        &mut plugin,
        &json!({"protocol_version": 1_u16, "plugin_id": "workbuddy-blackbox"}),
    );
    assert_eq!(read_plugin_frame(&mut plugin)["protocol_version"], 1_u16);

    send_model_request(&socket_path, "Electron", Some("com.tencent.workbuddy.mac"));
    for side in ["request", "response"] {
        let event = read_plugin_frame(&mut plugin);
        assert_eq!(event["side"], side);
        assert_eq!(event["agent"]["name"], "workbuddy");
        assert_eq!(event["session_id"], "workbuddy-session");
        assert_eq!(event["turn_id"], "workbuddy-turn");
        assert!(event.get("text").is_none_or(Value::is_null));
        if side == "response" {
            assert_eq!(event["token_usage"]["output_tokens"], 3_u64);
        }
    }

    let mut invalid = legacy;
    invalid["harness_usage"]["config"]["harnesses"]["workbuddy"]["matchers"][0]["process_names"] =
        json!(["node"]);
    let rejected = client()
        .put(url(api_addr, "/v1/hooks/config"))
        .bearer_auth(&token)
        .json(&invalid)
        .send()
        .unwrap();
    assert!(rejected.status().is_client_error());
    assert_eq!(request_hooks_config(api_addr, &token), normalized);

    send_model_request(&socket_path, "node", None);
    assert_no_event(&mut plugin);
    let mut disabled = normalized;
    disabled["harness_usage"]["config"]["harnesses"]["workbuddy"]["enabled"] = json!(false);
    update_hooks_config(api_addr, &token, &disabled);
    send_model_request(&socket_path, "Electron", Some("com.tencent.workbuddy.mac"));
    assert_no_event(&mut plugin);
    broker.shutdown();
    broker.wait_for_exit();
    fs::remove_file(startup_path).unwrap();
}

fn restart(broker: &mut BrokerProcess, startup_path: &Path) {
    fs::remove_file(startup_path).unwrap();
    let stdout = fs::File::create(&broker.log_file).unwrap();
    let stderr = stdout.try_clone().unwrap();
    broker.child = Command::new(broker_binary())
        .arg("--api")
        .arg(broker.api_addr.to_string())
        .arg("--config")
        .arg(broker.runtime_root.join("broker-config.toml"))
        .arg("--auth-token-file")
        .arg(&broker.auth_token_file)
        .arg("--startup-info-file")
        .arg(startup_path)
        .env("ABYSS_HOME", &broker.runtime_root)
        .env("TMPDIR", &broker.runtime_root)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .unwrap();
    broker.wait_for_startup_info(startup_path);
    broker.wait_for_running();
}

fn assert_no_event(plugin: &mut UnixStream) {
    plugin
        .set_read_timeout(Some(std::time::Duration::from_millis(500)))
        .unwrap();
    let error = plugin.read(&mut [0_u8; 4]).unwrap_err();
    assert!(
        matches!(
            error.kind(),
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
        ),
        "no event should arrive for disabled or unidentified traffic: {error}"
    );
    plugin.set_read_timeout(Some(REST_TIMEOUT)).unwrap();
}

fn send_model_request(socket_path: &Path, process: &str, application_id: Option<&str>) {
    let body = br#"{"model":"fixture-model","messages":[{"role":"user","content":"hello"}]}"#;
    let response_body = br#"{"id":"reply-1","model":"fixture-model","choices":[{"index":0,"message":{"role":"assistant","content":"hello back"},"finish_reason":"stop"}],"usage":{"prompt_tokens":2,"completion_tokens":3,"total_tokens":5}}"#;
    let upstream = TcpListener::bind(loopback_ephemeral_addr()).unwrap();
    let address = upstream.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        stream.set_read_timeout(Some(HTTP_TIMEOUT)).unwrap();
        let mut request = Vec::new();
        while complete_http_request_len(&request).is_none_or(|len| request.len() < len) {
            let mut chunk = [0_u8; 4096];
            let count = stream.read(&mut chunk).unwrap();
            assert_ne!(count, 0, "broker must forward the complete request");
            request.extend_from_slice(&chunk[..count]);
        }
        assert!(
            request.ends_with(body),
            "request body must be forwarded unchanged"
        );
        write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", response_body.len()).unwrap();
        stream.write_all(response_body).unwrap();
    });
    let flow_id = Uuid::new_v4();
    let mut stream = UnixStream::connect(socket_path).unwrap();
    stream.set_read_timeout(Some(REST_TIMEOUT)).unwrap();
    write_flow_frame(
        &mut stream,
        1,
        0,
        flow_id,
        &serde_json::to_vec(&json!({
            "flow_id": flow_id, "platform": "macos", "protocol": "tcp",
            "source_pid": null, "source_pid_version": null,
            "source_process": process, "source_application_id": application_id,
            "destination_host": "gateway.example", "destination_ip": address.ip(),
            "destination_port": address.port(), "original_tls_sni": null
        }))
        .unwrap(),
    );
    let mut request = format!(
        "POST /v2/chat/completions HTTP/1.1\r\nHost: gateway.example\r\nUser-Agent: axios/1.18.1\r\nX-Conversation-ID: workbuddy-session\r\nX-Conversation-Request-ID: workbuddy-turn\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()
    ).into_bytes();
    request.extend_from_slice(body);
    write_flow_frame(&mut stream, 2, 1, flow_id, &request);
    write_flow_frame(
        &mut stream,
        3,
        1,
        flow_id,
        &serde_json::to_vec(&json!({
            "flow_id": flow_id, "reason": "request_complete"
        }))
        .unwrap(),
    );
    let response = read_response(&mut stream);
    assert!(
        response.ends_with(response_body),
        "response body must be forwarded unchanged"
    );
    server.join().unwrap();
}

#[expect(
    clippy::big_endian_bytes,
    reason = "Ingress frame lengths are network byte order."
)]
fn read_response(stream: &mut UnixStream) -> Vec<u8> {
    let mut response = Vec::new();
    loop {
        let mut header = [0_u8; 28];
        stream.read_exact(&mut header).unwrap();
        assert_eq!(
            &header[..4],
            b"ABY1",
            "response must use the framed ingress protocol"
        );
        let len = u32::from_be_bytes([header[24], header[25], header[26], header[27]]);
        assert!(
            len < 0x0100_0000,
            "response frame must stay within the protocol size limit"
        );
        let mut payload = vec![0_u8; usize::try_from(len).unwrap()];
        stream.read_exact(&mut payload).unwrap();
        if header[4..6] == [2, 2] {
            response.extend_from_slice(&payload);
        }
        if header[4..6] == [3, 2] {
            return response;
        }
        assert_ne!(header[4], 4, "broker returned flow error: {payload:?}");
    }
}
