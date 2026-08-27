//! Process-level coverage for broker handshake, Agent event delivery, and close.

#![cfg(unix)]

use std::{
    io::{Read as _, Write as _},
    net::TcpListener,
    os::unix::net::{UnixListener, UnixStream},
    process::Command,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use abyss_sdk::plugin::{AgentEvent, BrokerClose, BrokerCloseCode, BrokerHello, PluginHello};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use tempfile::tempdir;

fn product_config(delivery_worker: &Value) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schema_version": 1,
        "product": {"kind": "cli"},
        "delivery_worker": delivery_worker
    }))
    .expect("product config should serialize")
}

#[test]
fn real_plugin_process_delivers_a_broker_event_to_the_configured_destination() {
    let directory = tempdir().expect("temporary directory should exist");
    let socket_path = directory.path().join("plugins.sock");
    let broker = UnixListener::bind(&socket_path).expect("fake broker should bind");
    let (destination, received) = spawn_destination();
    let config_path = directory.path().join("product-config.json");
    let startup_info_path = directory.path().join("worker-startup.json");
    std::fs::write(
        &config_path,
        product_config(&serde_json::json!({
            "plugin_id": "official-delivery-blackbox",
            "broker_endpoint": socket_path,
            "delivery": {
                "endpoint": destination,
                "spool_enabled": false
            },
            "authentication": {"mode": "none"}
        })),
    )
    .expect("config should write");

    let mut child = Command::new(env!("CARGO_BIN_EXE_abyss-delivery-plugin"))
        .arg("--config")
        .arg(&config_path)
        .arg("--startup-info-file")
        .arg(&startup_info_path)
        .arg("--broker-pid")
        .arg("4242")
        .spawn()
        .expect("delivery plugin should start");
    let (mut stream, _) = broker.accept().expect("plugin should connect");
    let hello: PluginHello = read_frame(&mut stream);
    assert_eq!(hello.plugin_id, "official-delivery-blackbox");
    assert!(
        !startup_info_path.exists(),
        "a spawned worker must not publish readiness before BrokerHello"
    );
    write_frame(&mut stream, &BrokerHello::v1());
    let startup_info = wait_for_startup_info(&startup_info_path);
    assert_eq!(startup_info["worker_pid"], child.id());
    assert_eq!(startup_info["broker_pid"], 4_242_u32);
    write_frame(&mut stream, &fixture_agent_event());

    let request = received
        .recv_timeout(Duration::from_secs(5))
        .expect("configured destination should receive the event");
    let payload: Value = serde_json::from_slice(&request).expect("request JSON should decode");
    assert_eq!(payload["events"][0]["event_id"], "evt-123");
    assert_eq!(payload["events"][0]["event_type"], "response");
    assert_eq!(
        payload["events"][0]["metadata"]["content_segments"][0]["name"],
        "exec"
    );
    assert!(
        payload["diagnostic_captures"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    write_frame(
        &mut stream,
        &BrokerClose::new(BrokerCloseCode::BrokerShutdown, "test complete"),
    );
    let status = child.wait().expect("plugin process should exit");
    assert!(
        status.success(),
        "plugin should accept the deliberate broker close"
    );
    assert!(
        !startup_info_path.exists(),
        "a stopped worker should remove its own readiness record"
    );
}

#[test]
fn managed_bearer_hot_update_replays_spool_without_restarting_worker() {
    let directory = tempdir().expect("temporary directory should exist");
    let socket_path = directory.path().join("plugins.sock");
    let broker = UnixListener::bind(&socket_path).expect("fake broker should bind");
    let (destination, received) = spawn_authenticated_destination();
    let config_path = directory.path().join("product-config.json");
    let spool_path = directory.path().join("failed-events.jsonl");
    let startup_info_path = directory.path().join("worker-startup.json");
    let control_token_path = directory.path().join("delivery-control.token");
    std::fs::write(
        &config_path,
        product_config(&serde_json::json!({
            "plugin_id": "managed-delivery-blackbox",
            "broker_endpoint": socket_path,
            "delivery": {
                "endpoint": destination,
                "spool_enabled": true,
                "spool_path": spool_path
            },
            "authentication": {"mode": "managed_bearer"}
        })),
    )
    .expect("config should write");

    let mut child = Command::new(env!("CARGO_BIN_EXE_abyss-delivery-plugin"))
        .arg("--config")
        .arg(&config_path)
        .arg("--startup-info-file")
        .arg(&startup_info_path)
        .arg("--broker-pid")
        .arg("4243")
        .arg("--control-token-file")
        .arg(&control_token_path)
        .spawn()
        .expect("delivery plugin should start");
    let original_pid = child.id();
    let (mut stream, _) = broker.accept().expect("plugin should connect");
    let _: PluginHello = read_frame(&mut stream);
    write_frame(&mut stream, &BrokerHello::v1());
    let startup_info = wait_for_startup_info(&startup_info_path);
    assert_eq!(startup_info["worker_pid"], original_pid);
    assert_eq!(
        startup_info["control_token_file"],
        control_token_path.to_string_lossy().as_ref()
    );

    write_frame(&mut stream, &fixture_agent_event());
    wait_for_non_empty_file(&spool_path);
    assert!(
        received.recv_timeout(Duration::from_millis(250)).is_err(),
        "managed mode must not upload before a credential is installed"
    );

    let token =
        std::fs::read_to_string(&control_token_path).expect("control token should be readable");
    let control_endpoint = startup_info["control_endpoint"]
        .as_str()
        .expect("control endpoint should be a string");
    let control_client = reqwest::blocking::Client::new();
    let unauthorized = control_client
        .get(format!("{control_endpoint}/v1/delivery/status"))
        .send()
        .expect("unauthenticated status request should complete");
    assert_eq!(unauthorized.status(), reqwest::StatusCode::UNAUTHORIZED);
    let response = control_client
        .put(format!("{control_endpoint}/v1/delivery/auth"))
        .bearer_auth(token.trim())
        .json(&serde_json::json!({
            "bearer_token": "native-token",
            "audience": destination
        }))
        .send()
        .expect("credential update should reach the worker");
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let request = received
        .recv_timeout(Duration::from_secs(5))
        .expect("credential update should replay the spooled event");
    assert_eq!(
        request.authorization.as_deref(),
        Some("Bearer native-token")
    );
    let payload: Value =
        serde_json::from_slice(&request.body).expect("replayed request should decode");
    assert_eq!(payload["events"][0]["event_id"], "evt-123");
    assert_eq!(child.id(), original_pid, "credential update must be hot");
    assert!(
        !spool_path.exists(),
        "successful replay should drain the spool"
    );

    write_frame(
        &mut stream,
        &BrokerClose::new(BrokerCloseCode::BrokerShutdown, "test complete"),
    );
    let status = child.wait().expect("plugin process should exit");
    assert!(status.success());
    assert!(!control_token_path.exists());
}

#[test]
fn destination_unauthorized_invalidates_token_and_refresh_replays_without_restart() {
    let directory = tempdir().expect("temporary directory should exist");
    let socket_path = directory.path().join("plugins.sock");
    let broker = UnixListener::bind(&socket_path).expect("fake broker should bind");
    let (destination, received) = spawn_refreshing_destination();
    let config_path = directory.path().join("product-config.json");
    let spool_path = directory.path().join("failed-events.jsonl");
    let startup_info_path = directory.path().join("worker-startup.json");
    let control_token_path = directory.path().join("delivery-control.token");
    std::fs::write(
        &config_path,
        product_config(&serde_json::json!({
            "plugin_id": "managed-refresh-blackbox",
            "broker_endpoint": socket_path,
            "delivery": {
                "endpoint": destination,
                "spool_enabled": true,
                "spool_path": spool_path
            },
            "authentication": {"mode": "managed_bearer"}
        })),
    )
    .expect("config should write");

    let mut child = Command::new(env!("CARGO_BIN_EXE_abyss-delivery-plugin"))
        .arg("--config")
        .arg(&config_path)
        .arg("--startup-info-file")
        .arg(&startup_info_path)
        .arg("--broker-pid")
        .arg("4244")
        .arg("--control-token-file")
        .arg(&control_token_path)
        .spawn()
        .expect("delivery plugin should start");
    let original_pid = child.id();
    let (mut stream, _) = broker.accept().expect("plugin should connect");
    let _: PluginHello = read_frame(&mut stream);
    write_frame(&mut stream, &BrokerHello::v1());
    let startup_info = wait_for_startup_info(&startup_info_path);
    let control_endpoint = startup_info["control_endpoint"]
        .as_str()
        .expect("control endpoint should be a string");
    let control_token =
        std::fs::read_to_string(&control_token_path).expect("control token should read");
    let control_client = reqwest::blocking::Client::new();

    let response = control_client
        .put(format!("{control_endpoint}/v1/delivery/auth"))
        .bearer_auth(control_token.trim())
        .json(&serde_json::json!({
            "bearer_token": "expired-token",
            "audience": destination
        }))
        .send()
        .expect("initial credential update should complete");
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    write_frame(&mut stream, &fixture_agent_event());
    let first = received
        .recv_timeout(Duration::from_secs(5))
        .expect("destination should receive expired credential");
    assert_eq!(first.authorization.as_deref(), Some("Bearer expired-token"));
    wait_for_non_empty_file(&spool_path);

    let status: Value = control_client
        .get(format!("{control_endpoint}/v1/delivery/status"))
        .bearer_auth(control_token.trim())
        .send()
        .expect("status request should complete")
        .json()
        .expect("status response should decode");
    assert_eq!(status["authentication_state"], "auth_required");
    assert_eq!(status["spooled_events"].as_u64(), Some(1_u64));

    let response = control_client
        .put(format!("{control_endpoint}/v1/delivery/auth"))
        .bearer_auth(control_token.trim())
        .json(&serde_json::json!({
            "bearer_token": "refreshed-token",
            "audience": destination
        }))
        .send()
        .expect("refreshed credential update should complete");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let response: Value = response.json().expect("update response should decode");
    assert_eq!(response["authentication_state"], "configured");
    assert_eq!(response["replay"]["replayed"].as_u64(), Some(1_u64));
    assert_eq!(response["replay"]["remaining"].as_u64(), Some(0_u64));
    let replay = received
        .recv_timeout(Duration::from_secs(5))
        .expect("refreshed credential should replay the event");
    assert_eq!(
        replay.authorization.as_deref(),
        Some("Bearer refreshed-token")
    );
    assert_eq!(child.id(), original_pid, "credential refresh must be hot");
    assert!(!spool_path.exists());

    write_frame(
        &mut stream,
        &BrokerClose::new(BrokerCloseCode::BrokerShutdown, "test complete"),
    );
    let status = child.wait().expect("plugin process should exit");
    assert!(status.success());
}

fn wait_for_startup_info(path: &std::path::Path) -> Value {
    let started_at = Instant::now();
    while started_at.elapsed() < Duration::from_secs(5) {
        match std::fs::read(path) {
            Ok(body) => {
                return serde_json::from_slice(&body).expect("worker startup info should decode");
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                thread::sleep(Duration::from_millis(25));
            }
            Err(error) => panic!("worker startup info should read: {error}"),
        }
    }
    panic!("worker did not publish startup info after BrokerHello");
}

fn fixture_agent_event() -> AgentEvent {
    serde_json::from_str(include_str!(
        "../../../specs/broker-plugin-protocol/v1/fixtures/agent-event.json"
    ))
    .expect("Agent event fixture should decode")
}

fn wait_for_non_empty_file(path: &std::path::Path) {
    let started_at = Instant::now();
    while started_at.elapsed() < Duration::from_secs(5) {
        if std::fs::metadata(path).is_ok_and(|metadata| metadata.len() > 0) {
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("worker did not spool the unauthenticated event");
}

struct RecordedRequest {
    authorization: Option<String>,
    body: Vec<u8>,
}

fn spawn_authenticated_destination() -> (String, mpsc::Receiver<RecordedRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("destination should bind");
    let address = listener
        .local_addr()
        .expect("destination address should read");
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("delivery request should connect");
        let request = read_recorded_http_request(&mut stream);
        sender.send(request).expect("request should be recorded");
        let response = br#"{"accepted":1,"duplicates":0,"rejected":0,"errors":[]}"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            response.len()
        )
        .expect("response headers should write");
        stream
            .write_all(response)
            .expect("response body should write");
    });
    (format!("http://{address}/v1/agent-usage/events"), receiver)
}

fn spawn_refreshing_destination() -> (String, mpsc::Receiver<RecordedRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("destination should bind");
    let address = listener
        .local_addr()
        .expect("destination address should read");
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        for status in [401_u16, 200_u16] {
            let (mut stream, _) = listener.accept().expect("delivery request should connect");
            let request = read_recorded_http_request(&mut stream);
            sender.send(request).expect("request should be recorded");
            let response = if status == 200 {
                br#"{"accepted":1,"duplicates":0,"rejected":0,"errors":[]}"#.as_slice()
            } else {
                br#"{"error":"unauthorized"}"#.as_slice()
            };
            write!(
                stream,
                "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response.len()
            )
            .expect("response headers should write");
            stream
                .write_all(response)
                .expect("response body should write");
        }
    });
    (format!("http://{address}/v1/agent-usage/events"), receiver)
}

fn spawn_destination() -> (String, mpsc::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("destination should bind");
    let address = listener
        .local_addr()
        .expect("destination address should read");
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("delivery request should connect");
        let request = read_http_request(&mut stream);
        sender.send(request).expect("request should be recorded");
        let response = br#"{"accepted":1,"duplicates":0,"rejected":0,"errors":[]}"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            response.len()
        )
        .expect("response headers should write");
        stream
            .write_all(response)
            .expect("response body should write");
    });
    (format!("http://{address}/v1/agent-usage/events"), receiver)
}

fn read_http_request(stream: &mut std::net::TcpStream) -> Vec<u8> {
    read_recorded_http_request(stream).body
}

fn read_recorded_http_request(stream: &mut std::net::TcpStream) -> RecordedRequest {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 4096];
    let header_end = loop {
        let count = stream.read(&mut buffer).expect("request should read");
        assert_ne!(count, 0, "request should contain headers");
        bytes.extend_from_slice(&buffer[..count]);
        if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break position.checked_add(4).expect("header boundary should fit");
        }
    };
    let headers = String::from_utf8_lossy(&bytes[..header_end]);
    let content_length = headers
        .lines()
        .find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(str::trim)
                .and_then(|value| value.parse::<usize>().ok())
        })
        .expect("request should carry content length");
    let authorization = headers.lines().find_map(|line| {
        line.strip_prefix("authorization:")
            .or_else(|| line.strip_prefix("Authorization:"))
            .map(str::trim)
            .map(str::to_owned)
    });
    let request_end = header_end
        .checked_add(content_length)
        .expect("request length should fit");
    while bytes.len() < request_end {
        let count = stream.read(&mut buffer).expect("request body should read");
        assert_ne!(count, 0, "request body should be complete");
        bytes.extend_from_slice(&buffer[..count]);
    }
    RecordedRequest {
        authorization,
        body: bytes[header_end..request_end].to_vec(),
    }
}

#[expect(
    clippy::big_endian_bytes,
    reason = "the broker plugin protocol defines a big-endian u32 length"
)]
fn read_frame<T>(stream: &mut UnixStream) -> T
where
    T: DeserializeOwned,
{
    let mut header = [0_u8; 4];
    stream
        .read_exact(&mut header)
        .expect("frame header should read");
    let length = usize::try_from(u32::from_be_bytes(header))
        .expect("platform should represent protocol frame lengths");
    let mut payload = vec![0_u8; length];
    stream
        .read_exact(&mut payload)
        .expect("frame payload should read");
    serde_json::from_slice(&payload).expect("frame should decode")
}

#[expect(
    clippy::big_endian_bytes,
    reason = "the broker plugin protocol defines a big-endian u32 length"
)]
fn write_frame<T>(stream: &mut UnixStream, value: &T)
where
    T: Serialize,
{
    let payload = serde_json::to_vec(value).expect("frame should encode");
    let length = u32::try_from(payload.len()).expect("frame should fit protocol length");
    stream
        .write_all(&length.to_be_bytes())
        .expect("frame header should write");
    stream
        .write_all(&payload)
        .expect("frame payload should write");
}
