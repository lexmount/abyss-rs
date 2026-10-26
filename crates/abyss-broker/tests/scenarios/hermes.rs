//! Hermes identity across native ingress and Agent events.
//! Fixtures use ordinary SDK headers and a local upstream, without live services.

use std::{
    fs,
    io::{Read as _, Write as _},
    net::{SocketAddr, TcpListener},
    os::unix::net::UnixStream,
    path::Path,
    sync::mpsc,
    thread,
    time::Instant,
};

use serde_json::{Value, json};
use uuid::Uuid;

use super::{
    BrokerProcess, HTTP_TIMEOUT, POLL_INTERVAL, REST_TIMEOUT, client, complete_http_request_len,
    framed::{assert_no_event, read_response},
    loopback_ephemeral_addr, read_auth_token, read_plugin_frame, reserve_api_loopback_addr,
    update_hooks_config, url, write_flow_frame, write_plugin_frame,
};

const HERMES_ID: &str = "com.nousresearch.hermes.managed-python";

#[test]
fn hermes_sdk_requests_are_identified_from_native_source_metadata() {
    let api_addr = reserve_api_loopback_addr();
    let socket_path = std::env::temp_dir().join(format!("hm-{}.sock", Uuid::new_v4()));
    let startup_path = socket_path.with_extension("json");
    let mut broker =
        BrokerProcess::spawn_framed_unix_with_startup_info(api_addr, &socket_path, &startup_path);
    let startup = broker.wait_for_startup_info(&startup_path);
    broker.wait_for_running();
    let token = read_auth_token(&broker.auth_token_file);
    let mut plugin = UnixStream::connect(startup.plugin_endpoint).unwrap();
    plugin.set_read_timeout(Some(REST_TIMEOUT)).unwrap();
    write_plugin_frame(
        &mut plugin,
        &json!({"protocol_version": 1_u16, "plugin_id": "hermes-blackbox"}),
    );
    assert_eq!(read_plugin_frame(&mut plugin)["protocol_version"], 1_u16);

    for (application, enabled, expected) in [
        (Some(HERMES_ID), true, Some("hermes")),
        (None, true, None),
        (
            Some("com.nousresearch.hermes.managed-python.other"),
            true,
            None,
        ),
        (Some(HERMES_ID), false, None),
    ] {
        update_hooks_config(
            api_addr,
            &token,
            &json!({"harness_usage": {"config": {"harnesses": {
                "hermes": {"enabled": enabled}
            }}}}),
        );
        let flow_id = send_model_request(&socket_path, application, || {
            let snapshot = read_api(api_addr, &token, "/v1/traffic/snapshot");
            let flows = snapshot["active_flows"].as_array().unwrap();
            assert_eq!(flows.len(), 1, "in-flight request must be visible");
            assert_eq!(flows[0]["process"], "python3.14");
            assert_eq!(flows[0]["application_id"].as_str(), application);
            Uuid::parse_str(flows[0]["id"].as_str().unwrap()).unwrap()
        });
        if expected.is_some() {
            for side in ["request", "response"] {
                let event = read_plugin_frame(&mut plugin);
                assert_eq!(event["side"], side);
                assert_eq!(event["agent"]["name"], "hermes");
            }
        } else {
            assert_no_event(&mut plugin);
        }
        let deadline = Instant::now() + REST_TIMEOUT;
        loop {
            let result = read_api(api_addr, &token, "/v1/network/observations?limit=100");
            if let Some(observation) = result["observations"]
                .as_array()
                .unwrap()
                .iter()
                .find(|observation| observation["flow_id"] == flow_id.to_string())
            {
                assert_eq!(observation["source_bundle_id"].as_str(), application);
                break;
            }
            assert!(Instant::now() < deadline, "completed flow must be recorded");
            thread::sleep(POLL_INTERVAL);
        }
    }
    broker.shutdown();
    broker.wait_for_exit();
    fs::remove_file(startup_path).unwrap();
}

fn read_api(api_addr: SocketAddr, token: &str, path: &str) -> Value {
    client()
        .get(url(api_addr, path))
        .bearer_auth(token)
        .send()
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .unwrap()
}

fn send_model_request(
    socket_path: &Path,
    application_id: Option<&str>,
    inspect_live: impl FnOnce() -> Uuid,
) -> Uuid {
    let body = br#"{"model":"fixture-model","input":[{"role":"user","content":"hello"}]}"#;
    let response_body = br#"{"id":"resp-hermes","object":"response","model":"fixture-model","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"hello back"}]}],"usage":{"input_tokens":2,"output_tokens":3,"total_tokens":5}}"#;
    let upstream = TcpListener::bind(loopback_ephemeral_addr()).unwrap();
    let address = upstream.local_addr().unwrap();
    let (arrived, wait_for_request) = mpsc::channel();
    let (resume, wait_for_resume) = mpsc::channel();
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
        arrived.send(()).unwrap();
        wait_for_resume.recv_timeout(REST_TIMEOUT).unwrap();
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
            "source_process": "python3.14", "source_application_id": application_id,
            "destination_host": "api.openai.com", "destination_ip": address.ip(),
            "destination_port": address.port(), "original_tls_sni": null
        }))
        .unwrap(),
    );
    let mut request = format!(
        "POST /v1/responses HTTP/1.1\r\nHost: api.openai.com\r\nUser-Agent: OpenAI/Python 2.24.0\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()
    ).into_bytes();
    request.extend_from_slice(body);
    write_flow_frame(&mut stream, 2, 1, flow_id, &request);
    write_flow_frame(
        &mut stream,
        3,
        1,
        flow_id,
        &serde_json::to_vec(&json!({"flow_id": flow_id, "reason": "request_complete"})).unwrap(),
    );
    wait_for_request.recv_timeout(REST_TIMEOUT).unwrap();
    let broker_flow_id = inspect_live();
    resume.send(()).unwrap();
    assert!(
        read_response(&mut stream).ends_with(response_body),
        "response body must be forwarded unchanged"
    );
    server.join().unwrap();
    broker_flow_id
}
