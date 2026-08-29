use std::{
    collections::HashSet,
    fs::{self, File},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

#[cfg(unix)]
use std::io::{Read as _, Write as _};

#[cfg(windows)]
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::windows::named_pipe::{ClientOptions, NamedPipeClient},
    runtime::Builder,
    time::timeout,
};

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use reqwest::blocking::{Client, Response};
use serde::Deserialize;
use serde_json::{Value, json};

#[cfg(unix)]
use nix::{
    sys::signal::{Signal, kill},
    unistd::Pid,
};

const HTTP_TIMEOUT: Duration = Duration::from_secs(2);
const REST_TIMEOUT: Duration = Duration::from_secs(10);
const STARTUP_TIMEOUT: Duration = Duration::from_secs(10);
const POLL_INTERVAL: Duration = Duration::from_millis(50);
#[cfg(windows)]
const ERROR_SHARING_VIOLATION: i32 = 32;
static TEST_PATH_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static RESERVED_API_PORTS: OnceLock<Mutex<HashSet<u16>>> = OnceLock::new();

#[test]
fn broker_command_rejects_dual_proxy_mode() {
    let runtime_root = runtime_root_path(reserve_api_loopback_addr());
    fs::create_dir_all(&runtime_root).expect("runtime root should create");
    let config_path = runtime_root.join("broker-config.toml");
    fs::write(
        &config_path,
        b"schema_version = 1\n[proxy]\nmode = \"dual\"\n",
    )
    .expect("invalid config fixture should write");
    let output = Command::new(broker_binary())
        .arg("--config")
        .arg(&config_path)
        .env("ABYSS_HOME", &runtime_root)
        .output()
        .expect("broker command should run");

    assert!(!output.status.success(), "dual proxy mode must be rejected");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unknown variant `dual`"),
        "config error should identify dual as unsupported: {stderr}"
    );
    drop(fs::remove_dir_all(runtime_root));
}

#[test]
fn broker_loads_current_toml_config_with_relative_paths_and_devtools_controls() {
    let api_addr = reserve_api_loopback_addr();
    let mut broker = BrokerProcess::spawn_from_platform_default_config(api_addr);

    let running = broker.wait_for_running();
    assert_eq!(running.lifecycle, ProxyLifecycle::Running);
    let actual_proxy_addr = running
        .listen_addr
        .expect("default startup config should start the explicit proxy");
    assert_ne!(actual_proxy_addr.port(), 0);

    let stopped = broker.shutdown();
    assert_eq!(stopped.lifecycle, ProxyLifecycle::Stopped);
    broker.wait_for_exit();

    let broker_log_path = broker.runtime_log_dir.join("abyss-broker.log");
    let broker_log = fs::read_to_string(&broker_log_path).unwrap_or_else(|error| {
        panic!(
            "relative broker log `{}` should be readable: {error}",
            broker_log_path.display()
        )
    });
    assert!(
        !broker_log.contains("abyss-broker REST API listening"),
        "log_level=error should filter informational startup records: {broker_log}"
    );

    let trace_path = broker.runtime_log_dir.join("abyss-broker-trace.log");
    let trace = fs::read_to_string(&trace_path).unwrap_or_else(|error| {
        panic!(
            "enabled performance trace `{}` should be readable: {error}",
            trace_path.display()
        )
    });
    assert!(
        trace.contains("abyss-broker REST API listening"),
        "performance_trace=true should retain startup tracing independently of the normal log level: {trace}"
    );
}

#[test]
#[cfg(unix)]
fn broker_command_runs_explicit_ingress() {
    let api_addr = reserve_api_loopback_addr();
    let mut broker = BrokerProcess::spawn_explicit(api_addr, loopback_ephemeral_addr());

    let running = broker.wait_for_running();
    assert_eq!(running.lifecycle, ProxyLifecycle::Running);
    assert_eq!(running.mode, Some(ProxyMode::Explicit));
    assert_eq!(running.ingresses.len(), 1);
    assert_eq!(running.ingresses[0].source, IngressSource::ExplicitHttp);
    let actual_proxy_addr = running
        .listen_addr
        .expect("explicit proxy should report its concrete bound address");
    assert_eq!(running.ingresses[0].listen_addr, Some(actual_proxy_addr));
    assert_ne!(actual_proxy_addr.port(), 0);

    let connection = TcpStream::connect_timeout(&actual_proxy_addr, Duration::from_secs(2))
        .expect("explicit proxy listener should accept a loopback connection");
    drop(connection);

    let stopped = broker.shutdown();
    assert_eq!(stopped.lifecycle, ProxyLifecycle::Stopped);
    assert_eq!(stopped.mode, None);
    assert!(stopped.ingresses.is_empty());
    broker.wait_for_exit();
}

#[test]
#[cfg(unix)]
fn broker_sigterm_stops_gracefully_and_removes_control_token() {
    let api_addr = reserve_api_loopback_addr();
    let mut broker = BrokerProcess::spawn_explicit(api_addr, loopback_ephemeral_addr());
    broker.wait_for_running();
    assert!(
        broker.auth_token_file.exists(),
        "running broker should expose its control token"
    );

    broker.send_sigterm();
    let exit_status = broker.wait_for_exit_status();

    assert!(
        exit_status.success(),
        "SIGTERM should complete the broker's graceful shutdown path, got {exit_status}\n{}",
        broker.read_log()
    );
    assert!(
        !broker.auth_token_file.exists(),
        "graceful shutdown should remove the per-process control token"
    );
}

#[test]
#[cfg(unix)]
fn broker_records_and_traces_a_completed_proxy_flow() {
    let upstream = TcpListener::bind(loopback_ephemeral_addr())
        .expect("test upstream listener should bind to loopback");
    let upstream_addr = upstream
        .local_addr()
        .expect("test upstream listener should expose its address");
    let upstream_task = thread::spawn(move || {
        let (mut connection, _peer_addr) = upstream
            .accept()
            .expect("broker should connect to the test upstream");
        connection
            .set_read_timeout(Some(HTTP_TIMEOUT))
            .expect("test upstream should configure its read timeout");
        let mut request = Vec::new();
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let mut buffer = [0_u8; 256];
            let count = connection
                .read(&mut buffer)
                .expect("test upstream should receive the forwarded request");
            assert!(count > 0, "proxy closed before forwarding the request");
            request.extend_from_slice(&buffer[..count]);
            assert!(
                request.len() <= 4_096,
                "forwarded request was unexpectedly large"
            );
        }
        assert!(
            request.starts_with(b"GET /observed HTTP/1.1"),
            "proxy should normalize the absolute-form request: {}",
            String::from_utf8_lossy(&request)
        );
        connection
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .expect("test upstream should return a response");
    });
    let api_addr = reserve_api_loopback_addr();
    let mut broker = BrokerProcess::spawn_explicit(api_addr, loopback_ephemeral_addr());
    let running = broker.wait_for_running();
    let proxy_addr = running
        .listen_addr
        .expect("explicit proxy should report its concrete bound address");
    let mut proxy_client = TcpStream::connect_timeout(&proxy_addr, HTTP_TIMEOUT)
        .expect("test client should connect to the explicit proxy");
    proxy_client
        .set_read_timeout(Some(HTTP_TIMEOUT))
        .expect("test client should configure its read timeout");
    write!(
        proxy_client,
        "GET http://{upstream_addr}/observed HTTP/1.1\r\nHost: {upstream_addr}\r\nConnection: close\r\n\r\n"
    )
    .expect("test client should send an absolute-form request");
    let mut response = Vec::new();
    proxy_client
        .read_to_end(&mut response)
        .expect("test client should receive the upstream response");
    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "explicit proxy should return the upstream response: {}",
        String::from_utf8_lossy(&response)
    );
    assert!(response.ends_with(b"ok"));
    drop(proxy_client);
    upstream_task
        .join()
        .expect("test upstream task should finish after accepting the connection");

    let diagnostics = broker.wait_for_completed_flow_diagnostics();
    assert_eq!(diagnostics["flow"]["totals"]["accepted"], 1_u64);
    assert_eq!(diagnostics["flow"]["totals"]["completed"], 1_u64);
    assert_eq!(diagnostics["flow"]["totals"]["in_flight"], 0_u64);
    assert_eq!(
        diagnostics["flow"]["recent_flows"][0]["decision"],
        "intercepted"
    );
    assert!(diagnostics["flow"]["recent_flows"][0]["miss_reason"].is_null());
    broker.wait_for_log_record("broker proxy intercepted flow closed");

    let stopped = broker.shutdown();
    assert_eq!(stopped.lifecycle, ProxyLifecycle::Stopped);
    broker.wait_for_exit();
}

#[test]
#[cfg(unix)]
fn broker_traffic_snapshot_requires_auth_and_returns_live_shape() {
    let api_addr = reserve_api_loopback_addr();
    let mut broker = BrokerProcess::spawn_explicit(api_addr, loopback_ephemeral_addr());
    broker.wait_for_running();

    let unauthenticated = client()
        .get(url(api_addr, "/v1/traffic/snapshot"))
        .send()
        .expect("unauthenticated traffic snapshot request should send");
    assert_eq!(
        unauthenticated.status().as_u16(),
        401,
        "traffic snapshot endpoint should reject requests without the bearer token"
    );

    let token = read_auth_token(&broker.auth_token_file);
    let snapshot: serde_json::Value = client()
        .get(url(api_addr, "/v1/traffic/snapshot"))
        .bearer_auth(token)
        .send()
        .expect("authenticated traffic snapshot request should send")
        .error_for_status()
        .expect("traffic snapshot should return success")
        .json()
        .expect("traffic snapshot should be valid JSON");
    assert!(snapshot["sampled_at_unix_ms"].is_number());
    assert!(snapshot["upload_bytes_per_second"].is_number());
    assert!(snapshot["download_bytes_per_second"].is_number());
    assert!(snapshot["active_flows"].is_array());

    let stopped = broker.shutdown();
    assert_eq!(stopped.lifecycle, ProxyLifecycle::Stopped);
    broker.wait_for_exit();
}

#[test]
#[cfg(unix)]
fn broker_network_observations_requires_auth_and_returns_local_shape() {
    let api_addr = reserve_api_loopback_addr();
    let mut broker = BrokerProcess::spawn_explicit(api_addr, loopback_ephemeral_addr());
    broker.wait_for_running();

    let unauthenticated = client()
        .get(url(api_addr, "/v1/network/observations"))
        .send()
        .expect("unauthenticated network observations request should send");
    assert_eq!(
        unauthenticated.status().as_u16(),
        401,
        "network observations should require the broker bearer token"
    );

    let token = read_auth_token(&broker.auth_token_file);
    let response: serde_json::Value = client()
        .get(url(api_addr, "/v1/network/observations?limit=10"))
        .bearer_auth(token)
        .send()
        .expect("authenticated network observations request should send")
        .error_for_status()
        .expect("network observations should return success")
        .json()
        .expect("network observations should be valid JSON");
    assert_eq!(response["schema_version"], 1_i32);
    assert!(response["broker_started_at_unix_ms"].as_u64().is_some());
    assert!(response["observations"].is_array());

    let stopped = broker.shutdown();
    assert_eq!(stopped.lifecycle, ProxyLifecycle::Stopped);
    broker.wait_for_exit();
}

#[test]
#[cfg(target_os = "windows")]
fn broker_command_runs_rest_and_proxy_workers() {
    let api_addr = reserve_api_loopback_addr();
    let proxy_addr = loopback_ephemeral_addr();
    let mut broker = BrokerProcess::spawn(api_addr, proxy_addr);

    let running = broker.wait_for_running();
    assert_eq!(running.lifecycle, ProxyLifecycle::Running);
    let actual_proxy_addr = running
        .listen_addr
        .expect("running proxy should report the concrete bound address");
    assert_ne!(
        actual_proxy_addr, proxy_addr,
        "broker should expand proxy port 0 to a concrete OS-assigned port"
    );
    assert!(
        running.process_id.is_some(),
        "running proxy status should include the broker process id"
    );

    let unauthenticated_shutdown = client()
        .post(url(api_addr, "/v1/broker/shutdown"))
        .send()
        .expect("unauthenticated shutdown request should send");
    assert_eq!(
        unauthenticated_shutdown.status().as_u16(),
        401,
        "shutdown endpoint should reject requests without the bearer token"
    );

    TcpStream::connect_timeout(&actual_proxy_addr, Duration::from_secs(2))
        .expect("proxy worker should accept a redirected TCP connection");

    let stopped = broker.shutdown();
    assert_eq!(stopped.lifecycle, ProxyLifecycle::Stopped);
    assert_eq!(stopped.listen_addr, None);
    broker.wait_for_exit();
}

#[cfg(target_os = "macos")]
#[test]
fn broker_command_runs_framed_unix_ingress() {
    let api_addr = reserve_api_loopback_addr();
    let socket_path = std::env::temp_dir().join(format!(
        "abyss-broker-framed-{}-{}.sock",
        std::process::id(),
        api_addr.port()
    ));
    let mut broker = BrokerProcess::spawn_framed_unix(api_addr, &socket_path);

    let running = broker.wait_for_running();
    assert_eq!(running.lifecycle, ProxyLifecycle::Running);
    assert_eq!(running.listen_addr, None);
    assert_eq!(running.socket_path.as_deref(), Some(socket_path.as_path()));
    assert!(
        running.process_id.is_some(),
        "running framed ingress status should include the broker process id"
    );

    let stopped = broker.shutdown();
    assert_eq!(stopped.lifecycle, ProxyLifecycle::Stopped);
    assert_eq!(stopped.listen_addr, None);
    assert_eq!(stopped.socket_path, None);
    broker.wait_for_exit();
}

#[cfg(target_os = "macos")]
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the black-box scenario keeps the real Broker setup and end-to-end assertions together"
)]
fn custom_harness_emits_events_through_real_broker_flow_and_plugin_boundaries() {
    let api_addr = reserve_api_loopback_addr();
    let socket_path = std::env::temp_dir().join(format!(
        "abyss-broker-custom-harness-{}-{}.sock",
        std::process::id(),
        api_addr.port()
    ));
    let startup_info_file = std::env::temp_dir().join(format!(
        "abyss-broker-custom-harness-startup-{}-{}.json",
        std::process::id(),
        next_test_path_sequence()
    ));
    let mut broker = BrokerProcess::spawn_framed_unix_with_startup_info(
        api_addr,
        &socket_path,
        &startup_info_file,
    );
    let startup_info = broker.wait_for_startup_info(&startup_info_file);
    broker.api_addr = startup_info.api_addr;
    broker.wait_for_running();

    let token = read_auth_token(&broker.auth_token_file);
    let updated = update_hooks_config(
        broker.api_addr,
        &token,
        &json!({
            "harness_usage": {
                "enabled": true,
                "config": {
                    "content": {
                        "token_usage": true,
                        "conversation_text": true,
                        "tool_calls": true,
                        "images": true
                    },
                    "harnesses": {
                        "acme-agent": {
                            "enabled": true,
                            "matchers": [{
                                "process_names": ["acme-agent"],
                                "application_ids": ["com.acme.agent"]
                            }]
                        }
                    }
                }
            }
        }),
    );
    assert_eq!(
        updated["harness_usage"]["config"]["harnesses"]["acme-agent"]["enabled"],
        true
    );

    let mut plugin = std::os::unix::net::UnixStream::connect(&startup_info.plugin_endpoint)
        .expect("plugin should connect to the real broker");
    plugin
        .set_read_timeout(Some(REST_TIMEOUT))
        .expect("plugin should configure a read timeout");
    write_plugin_frame(
        &mut plugin,
        &json!({"protocol_version": 1_u16, "plugin_id": "custom-harness-blackbox"}),
    );
    assert_eq!(read_plugin_frame(&mut plugin)["protocol_version"], 1_u16);

    let upstream =
        TcpListener::bind(loopback_ephemeral_addr()).expect("custom Harness upstream should bind");
    let upstream_addr = upstream
        .local_addr()
        .expect("upstream address should resolve");
    let upstream_task = thread::spawn(move || {
        let (mut connection, _) = upstream.accept().expect("broker should connect upstream");
        connection
            .set_read_timeout(Some(HTTP_TIMEOUT))
            .expect("upstream read timeout should configure");
        let mut request = Vec::new();
        loop {
            let mut chunk = [0_u8; 256];
            let count = connection
                .read(&mut chunk)
                .expect("upstream should receive request bytes");
            assert!(count > 0, "broker should forward the complete request body");
            request.extend_from_slice(&chunk[..count]);
            if complete_http_request_len(&request)
                .is_some_and(|request_len| request.len() >= request_len)
            {
                break;
            }
        }
        assert!(
            String::from_utf8_lossy(&request).contains("POST /v1/responses"),
            "upstream should receive the OpenAI Responses request"
        );
        let body = serde_json::to_vec(&json!({
            "id": "resp-custom-blackbox",
            "model": "gpt-test",
            "output": [{"content": [{"type": "output_text", "text": "hello back"}]}],
            "usage": {"input_tokens": 2_i32, "output_tokens": 3_i32, "total_tokens": 5_i32}
        }))
        .expect("upstream response should serialize");
        write!(
            connection,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .expect("upstream response head should write");
        connection
            .write_all(&body)
            .expect("upstream response body should write");
    });

    send_custom_harness_flow(&socket_path, upstream_addr, &broker.log_file);
    upstream_task.join().expect("upstream task should complete");

    let request_event = read_plugin_frame(&mut plugin);
    let response_event = read_plugin_frame(&mut plugin);
    for event in [&request_event, &response_event] {
        assert_eq!(event["agent"]["name"], "acme-agent");
        assert_eq!(event["llm"]["provider"], "gateway.example");
        assert!(
            event["session_id"].as_str().is_some(),
            "published events should include a string session id"
        );
    }
    assert_eq!(request_event["side"], "request");
    assert_eq!(response_event["side"], "response");

    let stopped = broker.shutdown();
    assert_eq!(stopped.lifecycle, ProxyLifecycle::Stopped);
    broker.wait_for_exit();
    drop(fs::remove_file(startup_info_file));
}

#[cfg(target_os = "macos")]
fn complete_http_request_len(request: &[u8]) -> Option<usize> {
    let head_len = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")?
        .checked_add(4)?;
    let head = std::str::from_utf8(&request[..head_len]).ok()?;
    let content_len = head
        .lines()
        .find_map(|line| line.strip_prefix("Content-Length: "))?
        .parse::<usize>()
        .ok()?;
    head_len.checked_add(content_len)
}

#[cfg(target_os = "macos")]
#[expect(
    clippy::big_endian_bytes,
    reason = "the framed ingress wire format specifies network-byte-order lengths"
)]
fn send_custom_harness_flow(socket_path: &Path, upstream_addr: SocketAddr, broker_log_path: &Path) {
    let flow_id = uuid::Uuid::new_v4();
    let mut stream = std::os::unix::net::UnixStream::connect(socket_path)
        .expect("framed flow should connect to the real broker");
    stream
        .set_read_timeout(Some(REST_TIMEOUT))
        .expect("framed flow read timeout should configure");
    let open = serde_json::to_vec(&json!({
        "flow_id": flow_id,
        "platform": "macos",
        "protocol": "tcp",
        "source_pid": null,
        "source_pid_version": null,
        "source_process": "/usr/local/bin/acme-agent",
        "source_application_id": "com.acme.agent",
        "destination_host": "gateway.example",
        "destination_ip": upstream_addr.ip(),
        "destination_port": upstream_addr.port(),
        "original_tls_sni": null
    }))
    .expect("FlowOpen should serialize");
    write_flow_frame(&mut stream, 1, 0, flow_id, &open);

    let body = serde_json::to_vec(&json!({
        "model": "gpt-test",
        "input": [{"role": "user", "content": "hello custom Harness"}]
    }))
    .expect("request body should serialize");
    let request = format!(
        "POST /v1/responses HTTP/1.1\r\nHost: gateway.example\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut request_bytes = request.into_bytes();
    request_bytes.extend_from_slice(&body);
    write_flow_frame(&mut stream, 2, 1, flow_id, &request_bytes);
    let close = serde_json::to_vec(&json!({
        "flow_id": flow_id,
        "reason": "request_complete"
    }))
    .expect("FlowClose should serialize");
    write_flow_frame(&mut stream, 3, 1, flow_id, &close);

    let mut response = Vec::new();
    loop {
        let mut header = [0_u8; 28];
        stream.read_exact(&mut header).unwrap_or_else(|error| {
            let broker_log = fs::read_to_string(broker_log_path)
                .unwrap_or_else(|log_error| format!("<broker log unavailable: {log_error}>"));
            panic!("broker flow response frame should read: {error}\n{broker_log}");
        });
        assert_eq!(
            &header[..4],
            b"ABY1",
            "broker response should use the framed ingress magic"
        );
        let payload_len = u32::from_be_bytes([header[24], header[25], header[26], header[27]]);
        let mut payload = vec![0_u8; usize::try_from(payload_len).unwrap()];
        stream
            .read_exact(&mut payload)
            .expect("broker flow response payload should read");
        if header[4] == 2 && header[5] == 2 {
            response.extend_from_slice(&payload);
        }
        if header[4] == 3 && header[5] == 2 {
            break;
        }
    }
    assert!(
        String::from_utf8_lossy(&response).contains("hello back"),
        "framed ingress should return the real upstream response"
    );
}

#[cfg(target_os = "macos")]
#[expect(
    clippy::arithmetic_side_effects,
    clippy::big_endian_bytes,
    reason = "the fixed frame header and network-byte-order length follow the ingress wire format"
)]
fn write_flow_frame(
    stream: &mut std::os::unix::net::UnixStream,
    frame_type: u8,
    direction: u8,
    flow_id: uuid::Uuid,
    payload: &[u8],
) {
    let payload_len = u32::try_from(payload.len()).expect("test frame payload should fit u32");
    let mut frame = Vec::with_capacity(28 + payload.len());
    frame.extend_from_slice(b"ABY1");
    frame.extend_from_slice(&[frame_type, direction, 0, 0]);
    frame.extend_from_slice(flow_id.as_bytes());
    frame.extend_from_slice(&payload_len.to_be_bytes());
    frame.extend_from_slice(payload);
    stream.write_all(&frame).expect("flow frame should write");
}

#[test]
fn broker_writes_startup_info_for_dynamic_control_endpoint() {
    let requested_api_addr: SocketAddr = "127.0.0.1:0"
        .parse()
        .expect("ephemeral loopback API address should parse");
    let startup_info_file = std::env::temp_dir().join(format!(
        "abyss-broker-startup-{}-{}.json",
        std::process::id(),
        next_test_path_sequence()
    ));
    let mut broker = BrokerProcess::spawn_platform_default_with_startup_info(
        requested_api_addr,
        &startup_info_file,
    );

    let startup_info = broker.wait_for_startup_info(&startup_info_file);
    assert_ne!(
        startup_info.api_addr.port(),
        0,
        "startup info should report the concrete bound REST API port"
    );
    assert_eq!(
        startup_info.auth_token_file, broker.auth_token_file,
        "startup info should point the host to the broker bearer token file"
    );
    assert_eq!(
        startup_info.pid,
        broker.child.id(),
        "startup info should report the broker process id"
    );
    assert!(
        !startup_info.plugin_endpoint.is_empty(),
        "startup info should publish the concrete plugin endpoint"
    );

    broker.api_addr = startup_info.api_addr;
    let running = broker.wait_for_running();
    assert_eq!(running.lifecycle, ProxyLifecycle::Running);
    let stopped = broker.shutdown();
    assert_eq!(stopped.lifecycle, ProxyLifecycle::Stopped);
    broker.wait_for_exit();
    drop(fs::remove_file(startup_info_file));
}

#[test]
#[cfg(unix)]
fn broker_plugin_endpoint_accepts_a_v1_session_and_closes_it_on_shutdown() {
    let requested_api_addr: SocketAddr = "127.0.0.1:0"
        .parse()
        .expect("ephemeral loopback API address should parse");
    let startup_info_file = std::env::temp_dir().join(format!(
        "abyss-broker-plugin-startup-{}-{}.json",
        std::process::id(),
        next_test_path_sequence()
    ));
    let mut broker = BrokerProcess::spawn_platform_default_with_startup_info(
        requested_api_addr,
        &startup_info_file,
    );
    let startup_info = broker.wait_for_startup_info(&startup_info_file);
    broker.api_addr = startup_info.api_addr;
    broker.wait_for_running();

    let plugin_endpoint = PathBuf::from(&startup_info.plugin_endpoint);
    let mut plugin = std::os::unix::net::UnixStream::connect(&plugin_endpoint)
        .expect("plugin should connect to the broker Unix socket");
    plugin
        .set_read_timeout(Some(HTTP_TIMEOUT))
        .expect("plugin should configure a read timeout");
    write_plugin_frame(
        &mut plugin,
        &json!({"protocol_version": 1_u16, "plugin_id": "blackbox-plugin"}),
    );
    let hello = read_plugin_frame(&mut plugin);
    assert_eq!(hello["protocol_version"], 1_u16);

    let stopped = broker.shutdown();
    assert_eq!(stopped.lifecycle, ProxyLifecycle::Stopped);
    let close = read_plugin_frame(&mut plugin);
    assert_eq!(close["code"], 100_u32);
    broker.wait_for_exit();
    assert!(
        !plugin_endpoint.exists(),
        "broker shutdown should remove its plugin Unix socket"
    );
    drop(fs::remove_file(startup_info_file));
}

#[test]
#[cfg(windows)]
fn broker_plugin_named_pipe_accepts_a_v1_session_and_closes_it_on_shutdown() {
    let requested_api_addr: SocketAddr = "127.0.0.1:0"
        .parse()
        .expect("ephemeral loopback API address should parse");
    let startup_info_file = std::env::temp_dir().join(format!(
        "abyss-broker-plugin-startup-{}-{}.json",
        std::process::id(),
        next_test_path_sequence()
    ));
    let mut broker = BrokerProcess::spawn_platform_default_with_startup_info(
        requested_api_addr,
        &startup_info_file,
    );
    let startup_info = broker.wait_for_startup_info(&startup_info_file);
    broker.api_addr = startup_info.api_addr;
    broker.wait_for_running();

    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Windows plugin test runtime should build");
    let mut plugin = runtime.block_on(async {
        let mut plugin = ClientOptions::new()
            .open(&startup_info.plugin_endpoint)
            .expect("plugin should connect to the broker Named Pipe");
        write_windows_plugin_frame(
            &mut plugin,
            &json!({"protocol_version": 1_u16, "plugin_id": "blackbox-plugin"}),
        )
        .await;
        let hello = read_windows_plugin_frame(&mut plugin).await;
        assert_eq!(hello["protocol_version"], 1_u16);
        plugin
    });

    let stopped = broker.shutdown();
    assert_eq!(stopped.lifecycle, ProxyLifecycle::Stopped);
    let close = runtime.block_on(read_windows_plugin_frame(&mut plugin));
    assert_eq!(close["code"], 100_u32);
    broker.wait_for_exit();
    drop(fs::remove_file(startup_info_file));
}

#[cfg(unix)]
#[expect(
    clippy::big_endian_bytes,
    reason = "the published plugin protocol defines a big-endian u32 frame length"
)]
fn write_plugin_frame(stream: &mut std::os::unix::net::UnixStream, payload: &Value) {
    let payload = serde_json::to_vec(payload).expect("plugin payload should serialize");
    let payload_length = u32::try_from(payload.len()).expect("test payload should fit in u32");
    stream
        .write_all(&payload_length.to_be_bytes())
        .expect("plugin frame header should write");
    stream
        .write_all(&payload)
        .expect("plugin frame payload should write");
}

#[cfg(unix)]
#[expect(
    clippy::big_endian_bytes,
    reason = "the published plugin protocol defines a big-endian u32 frame length"
)]
fn read_plugin_frame(stream: &mut std::os::unix::net::UnixStream) -> Value {
    let mut header = [0_u8; 4];
    stream
        .read_exact(&mut header)
        .expect("plugin frame header should read");
    let payload_length = usize::try_from(u32::from_be_bytes(header))
        .expect("plugin payload length should fit usize");
    let mut payload = vec![0_u8; payload_length];
    stream
        .read_exact(&mut payload)
        .expect("plugin frame payload should read");
    serde_json::from_slice(&payload).expect("plugin frame should contain JSON")
}

#[cfg(windows)]
#[expect(
    clippy::big_endian_bytes,
    reason = "the published plugin protocol defines a big-endian u32 frame length"
)]
async fn write_windows_plugin_frame(stream: &mut NamedPipeClient, payload: &Value) {
    let payload = serde_json::to_vec(payload).expect("plugin payload should serialize");
    let payload_length = u32::try_from(payload.len()).expect("test payload should fit in u32");
    timeout(
        HTTP_TIMEOUT,
        stream.write_all(&payload_length.to_be_bytes()),
    )
    .await
    .expect("plugin frame header write should not time out")
    .expect("plugin frame header should write");
    timeout(HTTP_TIMEOUT, stream.write_all(&payload))
        .await
        .expect("plugin frame payload write should not time out")
        .expect("plugin frame payload should write");
}

#[cfg(windows)]
#[expect(
    clippy::big_endian_bytes,
    reason = "the published plugin protocol defines a big-endian u32 frame length"
)]
async fn read_windows_plugin_frame(stream: &mut NamedPipeClient) -> Value {
    let mut header = [0_u8; 4];
    timeout(HTTP_TIMEOUT, stream.read_exact(&mut header))
        .await
        .expect("plugin frame header read should not time out")
        .expect("plugin frame header should read");
    let payload_length = usize::try_from(u32::from_be_bytes(header))
        .expect("plugin payload length should fit usize");
    let mut payload = vec![0_u8; payload_length];
    timeout(HTTP_TIMEOUT, stream.read_exact(&mut payload))
        .await
        .expect("plugin frame payload read should not time out")
        .expect("plugin frame payload should read");
    serde_json::from_slice(&payload).expect("plugin frame should contain JSON")
}

#[test]
fn broker_inherits_and_holds_the_launcher_lifecycle_lock() {
    let requested_api_addr: SocketAddr = "127.0.0.1:0"
        .parse()
        .expect("ephemeral loopback API address should parse");
    let sequence = next_test_path_sequence();
    let startup_info_file = std::env::temp_dir().join(format!(
        "abyss-broker-lifecycle-startup-{}-{sequence}.json",
        std::process::id()
    ));
    let lifecycle_lock_file = std::env::temp_dir().join(format!(
        "abyss-broker-lifecycle-{}-{sequence}.lock",
        std::process::id()
    ));
    let lifecycle_lock = acquire_launcher_lifecycle_lock(&lifecycle_lock_file);
    let mut broker = BrokerProcess::spawn_platform_default_with_startup_info_and_lifecycle_lock(
        requested_api_addr,
        &startup_info_file,
        lifecycle_lock,
    );

    let startup_info = broker.wait_for_startup_info(&startup_info_file);
    broker.api_addr = startup_info.api_addr;
    assert_lifecycle_lock_is_held(&lifecycle_lock_file);

    let _stopped = broker.shutdown();
    broker.wait_for_exit();
    assert_lifecycle_lock_is_released(&lifecycle_lock_file);
    drop(fs::remove_file(startup_info_file));
    drop(fs::remove_file(lifecycle_lock_file));
}

fn acquire_launcher_lifecycle_lock(path: &Path) -> File {
    let file = lifecycle_lock_open_options(true)
        .open(path)
        .expect("launcher lifecycle lock should open");
    #[cfg(not(windows))]
    file.lock()
        .expect("launcher should hold the lifecycle lock before spawn");
    file
}

fn assert_lifecycle_lock_is_held(path: &Path) {
    #[cfg(windows)]
    {
        let Err(error) = lifecycle_lock_open_options(false).open(path) else {
            panic!("broker should retain the exclusive lifecycle lock handle");
        };
        assert_eq!(
            error.raw_os_error(),
            Some(ERROR_SHARING_VIOLATION),
            "contending open should fail because the broker inherited the exclusive handle"
        );
    }
    #[cfg(not(windows))]
    {
        let contender = lifecycle_lock_open_options(false)
            .open(path)
            .expect("lifecycle lock should remain openable");
        assert!(
            matches!(contender.try_lock(), Err(fs::TryLockError::WouldBlock)),
            "contender should observe the broker-held lifecycle lock"
        );
    }
}

fn assert_lifecycle_lock_is_released(path: &Path) {
    let contender = lifecycle_lock_open_options(false)
        .open(path)
        .expect("broker exit should release the lifecycle lock");
    #[cfg(windows)]
    drop(contender);
    #[cfg(not(windows))]
    {
        contender
            .try_lock()
            .expect("broker exit should release the lifecycle lock");
        contender.unlock().expect("test lock should release");
    }
}

fn lifecycle_lock_open_options(create: bool) -> fs::OpenOptions {
    let mut options = fs::OpenOptions::new();
    options
        .create(create)
        .read(true)
        .write(true)
        .truncate(false);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;

        options.share_mode(0);
    }
    options
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
#[test]
fn broker_mitm_config_updates_over_rest_without_restart() {
    let api_addr = reserve_api_loopback_addr();
    let mut broker = BrokerProcess::spawn_platform_default(api_addr);
    let running = broker.wait_for_running();
    assert_eq!(running.lifecycle, ProxyLifecycle::Running);

    let unauthenticated = client()
        .get(url(api_addr, "/v1/mitm/config"))
        .send()
        .expect("unauthenticated MITM config request should send");
    assert_eq!(
        unauthenticated.status().as_u16(),
        401,
        "MITM config endpoint should reject unauthenticated reads"
    );
    let unauthenticated_malformed_update = client()
        .put(url(api_addr, "/v1/mitm/config"))
        .header("content-type", "application/json")
        .body("{")
        .send()
        .expect("unauthenticated malformed MITM config request should send");
    assert_eq!(
        unauthenticated_malformed_update.status().as_u16(),
        401,
        "MITM config endpoint should authenticate before deserializing request bodies"
    );

    let token = read_auth_token(&broker.auth_token_file);
    let initial = request_mitm_config(api_addr, &token);
    assert_eq!(
        initial["tls_decryption"]["default_action"], "passthrough",
        "default runtime MITM config should pass TLS through"
    );

    let requested = json!({
        "tls_decryption": {
            "default_action": "passthrough",
            "missing_sni_action": "passthrough",
            "rules": [
                {
                    "id": "decrypt-openai",
                    "action": "intercept",
                    "process_names": ["codex"],
                    "application_ids": ["com.openai.codex"],
                    "destination_hosts": ["api.openai.com"]
                }
            ]
        }
    });
    let updated = update_mitm_config(api_addr, &token, &requested);
    assert_eq!(
        updated["tls_decryption"]["default_action"], "passthrough",
        "updated runtime MITM config should be returned"
    );
    assert_eq!(
        updated["tls_decryption"]["rules"][0]["enabled"], true,
        "defaulted rule fields should be visible in the effective config"
    );
    assert_eq!(
        updated["tls_decryption"]["rules"][0]["process_names"][0], "codex",
        "REST config should retain source process selectors"
    );
    assert_eq!(
        updated["tls_decryption"]["rules"][0]["application_ids"][0], "com.openai.codex",
        "REST config should expose one platform-neutral application identity"
    );

    let read_back = request_mitm_config(api_addr, &token);
    assert_eq!(
        read_back["tls_decryption"]["rules"][0]["id"], "decrypt-openai",
        "GET should read the current runtime MITM config"
    );
    assert_runtime_mitm_policy_persisted(&broker, "com.openai.codex");

    let invalid = json!({
        "tls_decryption": {
            "default_action": "intercept",
            "rules": [
                {
                    "id": "invalid-empty-selectors",
                    "action": "passthrough"
                }
            ]
        }
    });
    let invalid_response = client()
        .put(url(api_addr, "/v1/mitm/config"))
        .bearer_auth(&token)
        .json(&invalid)
        .send()
        .expect("invalid MITM config request should send");
    assert_eq!(
        invalid_response.status().as_u16(),
        400,
        "invalid MITM config should be rejected as a client error"
    );
    let after_invalid = request_mitm_config(api_addr, &token);
    assert_eq!(
        after_invalid["tls_decryption"]["default_action"], "passthrough",
        "rejected config should not replace the current runtime MITM config"
    );

    let stopped = broker.shutdown();
    assert_eq!(stopped.lifecycle, ProxyLifecycle::Stopped);
    broker.wait_for_exit();
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
#[test]
fn broker_hooks_config_updates_over_rest_without_restart() {
    let api_addr = reserve_api_loopback_addr();
    let mut broker = BrokerProcess::spawn_platform_default(api_addr);
    let running = broker.wait_for_running();
    assert_eq!(running.lifecycle, ProxyLifecycle::Running);

    let unauthenticated = client()
        .get(url(api_addr, "/v1/hooks/config"))
        .send()
        .expect("unauthenticated hooks config request should send");
    assert_eq!(
        unauthenticated.status().as_u16(),
        401,
        "hooks config endpoint should reject unauthenticated reads"
    );
    let unauthenticated_malformed_update = client()
        .put(url(api_addr, "/v1/hooks/config"))
        .header("content-type", "application/json")
        .body("{")
        .send()
        .expect("unauthenticated malformed hooks config request should send");
    assert_eq!(
        unauthenticated_malformed_update.status().as_u16(),
        401,
        "hooks config endpoint should authenticate before deserializing request bodies"
    );

    let token = read_auth_token(&broker.auth_token_file);
    let initial = request_hooks_config(api_addr, &token);
    assert_eq!(
        initial["harness_usage"]["enabled"], true,
        "Harness usage hook should be enabled by default"
    );
    assert_eq!(
        initial["harness_usage"]["config"]["content"],
        json!({
            "token_usage": true,
            "conversation_text": true,
            "tool_calls": true,
            "images": true,
        }),
        "default hooks config should retain every supported event field"
    );

    let requested = harness_usage_hooks_update_request();
    let updated = update_hooks_config(api_addr, &token, &requested);
    assert_eq!(
        updated["harness_usage"]["config"]["harnesses"]["codex"]["content"]["token_usage"], false,
        "Codex should keep its independent token override"
    );
    assert_eq!(
        updated["harness_usage"]["config"]["harnesses"]["claude-code"]["content"]["conversation_text"],
        true,
        "Claude CLI should keep its independent text override"
    );
    assert_eq!(
        updated["harness_usage"]["config"]["harnesses"]["claude-desktop"]["content"]["images"],
        true,
        "Claude Desktop should keep its independent image override"
    );
    assert_eq!(
        updated["harness_usage"]["config"]["harnesses"]["acme-agent"]["matchers"][0]["process_names"],
        json!(["acme-agent"]),
        "custom Harness process matchers should round-trip through the real Broker"
    );
    assert!(
        updated["harness_usage"]["config"]["content"]
            .get("mode")
            .is_none(),
        "REST responses must expose the four independent controls"
    );

    let read_back = request_hooks_config(api_addr, &token);
    assert_eq!(
        read_back["harness_usage"]["config"]["content"]["conversation_text"], false,
        "GET should read the current dynamic hooks config"
    );

    let unknown_hook = client()
        .put(url(api_addr, "/v1/hooks/config"))
        .bearer_auth(&token)
        .json(&json!({
            "future_hook": {
                "enabled": true,
                "config": {}
            }
        }))
        .send()
        .expect("unknown hook config request should send");
    assert!(
        unknown_hook.status().is_client_error(),
        "unknown hooks should be rejected as client errors, got {}",
        unknown_hook.status()
    );
    let after_invalid = request_hooks_config(api_addr, &token);
    assert_eq!(
        after_invalid["harness_usage"]["config"]["content"]["conversation_text"], false,
        "rejected hooks config should not replace the current runtime config"
    );

    let stopped = broker.shutdown();
    assert_eq!(stopped.lifecycle, ProxyLifecycle::Stopped);
    broker.wait_for_exit();
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn harness_usage_hooks_update_request() -> Value {
    json!({
        "harness_usage": {
            "enabled": true,
            "config": {
                "content": {
                    "token_usage": true,
                    "conversation_text": false,
                    "tool_calls": false,
                    "images": false
                },
                "harnesses": {
                    "codex": {
                        "content": {
                            "token_usage": false,
                            "conversation_text": true,
                            "tool_calls": true,
                            "images": true
                        }
                    },
                    "claude-code": {
                        "content": {
                            "token_usage": true,
                            "conversation_text": true,
                            "tool_calls": false,
                            "images": false
                        }
                    },
                    "claude-desktop": {
                        "content": {
                            "token_usage": true,
                            "conversation_text": false,
                            "tool_calls": false,
                            "images": true
                        }
                    },
                    "acme-agent": {
                        "enabled": true,
                        "matchers": [{
                            "process_names": ["acme-agent"],
                            "application_ids": ["com.acme.agent"]
                        }]
                    }
                }
            }
        }
    })
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn assert_runtime_mitm_policy_persisted(broker: &BrokerProcess, application_id: &str) {
    let persisted = toml::from_str::<toml::Value>(
        &fs::read_to_string(broker.runtime_policy_path())
            .expect("REST policy update should create the durable policy file"),
    )
    .expect("durable runtime policy should be valid TOML");
    assert_eq!(
        persisted["mitm"]["tls_decryption"]["rules"][0]["application_ids"][0].as_str(),
        Some(application_id),
        "durable policy should preserve REST-managed application selectors"
    );
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
#[test]
fn broker_support_logs_export_broker_owned_files() {
    let api_addr = reserve_api_loopback_addr();
    let mut broker = BrokerProcess::spawn_platform_default(api_addr);
    let running = broker.wait_for_running();
    assert_eq!(running.lifecycle, ProxyLifecycle::Running);

    let unauthenticated = client()
        .post(url(api_addr, "/v1/support/logs/broker"))
        .json(&json!({
            "max_bytes_per_file": 4_096_u64
        }))
        .send()
        .expect("unauthenticated support logs request should send");
    assert_eq!(
        unauthenticated.status().as_u16(),
        401,
        "broker support logs endpoint should reject unauthenticated requests"
    );

    let token = read_auth_token(&broker.auth_token_file);
    let response = request_broker_support_logs(api_addr, &token);
    let files = response["files"]
        .as_array()
        .expect("support logs response should contain files");
    assert!(
        files.iter().any(|file| {
            file["name"] == "abyss-broker.log"
                && file["content"]
                    .as_str()
                    .is_some_and(|content| content.contains("abyss-broker REST API listening"))
        }),
        "support logs should include broker runtime log; response: {response}"
    );
    assert!(
        response["errors"]
            .as_array()
            .expect("support logs response should contain errors")
            .is_empty(),
        "support log collection should not report errors: {response}"
    );

    let stopped = broker.shutdown();
    assert_eq!(stopped.lifecycle, ProxyLifecycle::Stopped);
    broker.wait_for_exit();
}

fn query_status(api_addr: SocketAddr) -> Option<ProxyStatus> {
    let response = client()
        .get(url(api_addr, "/v1/proxy/status"))
        .send()
        .ok()?;
    Some(parse_status_response(response))
}

fn shutdown_broker(api_addr: SocketAddr, auth_token_file: &Path) -> ProxyStatus {
    let response = client()
        .post(url(api_addr, "/v1/broker/shutdown"))
        .bearer_auth(read_auth_token(auth_token_file))
        .send()
        .expect("broker shutdown request should send");
    parse_status_response(response)
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn request_mitm_config(api_addr: SocketAddr, token: &str) -> serde_json::Value {
    let response = client()
        .get(url(api_addr, "/v1/mitm/config"))
        .bearer_auth(token)
        .send()
        .expect("MITM config request should send");
    parse_json_response(response)
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn update_mitm_config(
    api_addr: SocketAddr,
    token: &str,
    body: &serde_json::Value,
) -> serde_json::Value {
    let response = client()
        .put(url(api_addr, "/v1/mitm/config"))
        .bearer_auth(token)
        .json(body)
        .send()
        .expect("MITM config update request should send");
    parse_json_response(response)
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn request_hooks_config(api_addr: SocketAddr, token: &str) -> serde_json::Value {
    let response = client()
        .get(url(api_addr, "/v1/hooks/config"))
        .bearer_auth(token)
        .send()
        .expect("hooks config request should send");
    parse_json_response(response)
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn update_hooks_config(
    api_addr: SocketAddr,
    token: &str,
    body: &serde_json::Value,
) -> serde_json::Value {
    let response = client()
        .put(url(api_addr, "/v1/hooks/config"))
        .bearer_auth(token)
        .json(body)
        .send()
        .expect("hooks config update request should send");
    parse_json_response(response)
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn request_broker_support_logs(api_addr: SocketAddr, token: &str) -> serde_json::Value {
    let response = client()
        .post(url(api_addr, "/v1/support/logs/broker"))
        .bearer_auth(token)
        .json(&json!({
            "max_bytes_per_file": 4_096_u64
        }))
        .send()
        .expect("broker support logs request should send");
    parse_json_response(response)
}

fn request_shutdown(api_addr: SocketAddr, auth_token_file: &Path) {
    let Ok(token) = fs::read_to_string(auth_token_file) else {
        return;
    };
    drop(
        client()
            .post(url(api_addr, "/v1/broker/shutdown"))
            .bearer_auth(token.trim())
            .send(),
    );
}

fn parse_status_response(response: Response) -> ProxyStatus {
    parse_success_response(response)
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn parse_json_response(response: Response) -> serde_json::Value {
    parse_success_response(response)
}

fn parse_success_response<T>(response: Response) -> T
where
    T: serde::de::DeserializeOwned,
{
    assert!(
        response.status().is_success(),
        "broker REST request failed with status {}",
        response.status()
    );
    response.json().expect("broker REST response should parse")
}

fn client() -> Client {
    Client::builder()
        .timeout(REST_TIMEOUT)
        .build()
        .expect("reqwest client should build with static configuration")
}

fn reserve_api_loopback_addr() -> SocketAddr {
    loop {
        let listener =
            TcpListener::bind("127.0.0.1:0").expect("test should reserve a loopback port");
        let address = listener
            .local_addr()
            .expect("reserved listener should expose its address");
        let mut ports = RESERVED_API_PORTS
            .get_or_init(|| Mutex::new(HashSet::new()))
            .lock()
            .expect("reserved API port set should remain available");
        if ports.insert(address.port()) {
            return address;
        }
    }
}

fn loopback_ephemeral_addr() -> SocketAddr {
    "127.0.0.1:0"
        .parse()
        .expect("loopback ephemeral address should parse")
}

fn url(api_addr: SocketAddr, path: &str) -> String {
    format!("http://{api_addr}{path}")
}

fn read_auth_token(path: &Path) -> String {
    fs::read_to_string(path)
        .expect("broker auth token file should be readable")
        .trim()
        .to_owned()
}

const fn broker_binary() -> &'static str {
    env!("CARGO_BIN_EXE_abyss-broker")
}

struct BrokerProcess {
    api_addr: SocketAddr,
    auth_token_file: PathBuf,
    ca_dir: PathBuf,
    log_file: PathBuf,
    runtime_log_dir: PathBuf,
    runtime_root: PathBuf,
    child: Child,
}

impl BrokerProcess {
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    fn runtime_policy_path(&self) -> PathBuf {
        self.runtime_root.join("runtime-policy.toml")
    }

    #[cfg(unix)]
    fn spawn_explicit(api_addr: SocketAddr, proxy_addr: SocketAddr) -> Self {
        Self::spawn_with_options(
            api_addr,
            None,
            json!({
                "mode": "explicit",
                "listen_addr": proxy_addr,
            }),
        )
    }

    #[cfg(target_os = "windows")]
    fn spawn(api_addr: SocketAddr, _proxy_addr: SocketAddr) -> Self {
        Self::spawn_with_options(
            api_addr,
            None,
            json!({
                "mode": "windows_wfp",
            }),
        )
    }

    #[cfg(target_os = "macos")]
    fn spawn_framed_unix(api_addr: SocketAddr, socket_path: &Path) -> Self {
        Self::spawn_with_options(
            api_addr,
            None,
            json!({
                "mode": "macos_network_extension",
                "socket_path": socket_path,
            }),
        )
    }

    #[cfg(target_os = "macos")]
    fn spawn_framed_unix_with_startup_info(
        api_addr: SocketAddr,
        socket_path: &Path,
        startup_info_file: &Path,
    ) -> Self {
        Self::spawn_with_options(
            api_addr,
            Some(startup_info_file),
            json!({
                "mode": "macos_network_extension",
                "socket_path": socket_path,
            }),
        )
    }

    fn spawn_with_options(
        api_addr: SocketAddr,
        startup_info_file: Option<&Path>,
        proxy_config: Value,
    ) -> Self {
        Self::spawn_with_bootstrap_options(api_addr, startup_info_file, None, proxy_config)
    }

    fn spawn_with_bootstrap_options(
        api_addr: SocketAddr,
        startup_info_file: Option<&Path>,
        stdin: Option<Stdio>,
        proxy_config: Value,
    ) -> Self {
        let auth_token_file = auth_token_path(api_addr);
        let ca_dir = ca_dir_path(api_addr);
        let log_file = log_path(api_addr);
        let runtime_log_dir = runtime_log_dir_path(api_addr);
        let runtime_root = runtime_root_path(api_addr);
        let config_path = runtime_root.join("broker-config.toml");
        write_ca_fixture(&ca_dir);
        fs::create_dir_all(&runtime_root).expect("broker runtime root should create");
        let mut broker_config = json!({
            "schema_version": 1_u32,
            "devtools": {
                "log_location": runtime_log_dir,
            },
            "ca": {"path": ca_dir},
        });
        broker_config["proxy"] = proxy_config;
        fs::write(
            &config_path,
            toml::to_string_pretty(&broker_config).expect("broker config fixture should serialize"),
        )
        .expect("broker config fixture should write");
        let mut command = Command::new(broker_binary());
        command
            .arg("--api")
            .arg(api_addr.to_string())
            .arg("--config")
            .arg(&config_path)
            .arg("--auth-token-file")
            .arg(&auth_token_file);
        command.env("ABYSS_HOME", &runtime_root);
        command.env("TMPDIR", &runtime_root);
        command.env("ProgramData", &runtime_root);
        if let Some(startup_info_file) = startup_info_file {
            command.arg("--startup-info-file").arg(startup_info_file);
        }
        let stdout = File::create(&log_file).expect("broker test log should create");
        let stderr = stdout
            .try_clone()
            .expect("broker test log should clone for stderr");
        let child = command
            .stdin(stdin.unwrap_or_else(Stdio::null))
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()
            .expect("abyss-broker should spawn");
        Self {
            api_addr,
            auth_token_file,
            ca_dir,
            log_file,
            runtime_log_dir,
            runtime_root,
            child,
        }
    }

    fn spawn_from_platform_default_config(api_addr: SocketAddr) -> Self {
        let auth_token_file = auth_token_path(api_addr);
        let log_file = log_path(api_addr);
        let runtime_root = runtime_root_path(api_addr);
        let broker_home = runtime_root.clone();
        let ca_dir = broker_home.join("relative-ca");
        let runtime_log_dir = broker_home.join("relative-logs");
        fs::create_dir_all(&broker_home).expect("platform broker home should create");
        write_ca_fixture(&ca_dir);
        fs::write(
            broker_home.join("config.json"),
            br#"{"proxy":{"mode":"dual"}}"#,
        )
        .expect("invalid legacy config fixture should write");
        fs::write(
            broker_home.join("broker-config.toml"),
            format!(
                "schema_version = 1\n\n[devtools]\nlog_level = \"error\"\nperformance_trace = true\nlog_location = \"relative-logs\"\n\n[ca]\npath = \"relative-ca\"\n\n[proxy]\nmode = \"explicit\"\nlisten_addr = \"{}\"\n",
                loopback_ephemeral_addr()
            ),
        )
        .expect("default broker config fixture should write");

        let stdout = File::create(&log_file).expect("broker test log should create");
        let stderr = stdout
            .try_clone()
            .expect("broker test log should clone for stderr");
        let child = Command::new(broker_binary())
            .arg("--api")
            .arg(api_addr.to_string())
            .arg("--auth-token-file")
            .arg(&auth_token_file)
            .env("ABYSS_HOME", &runtime_root)
            .env("TMPDIR", &runtime_root)
            .env("ProgramData", &runtime_root)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()
            .expect("abyss-broker should spawn without an explicit config argument");
        Self {
            api_addr,
            auth_token_file,
            ca_dir,
            log_file,
            runtime_log_dir,
            runtime_root,
            child,
        }
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    fn spawn_platform_default(api_addr: SocketAddr) -> Self {
        #[cfg(target_os = "macos")]
        {
            let socket_path = std::env::temp_dir().join(format!(
                "abyss-broker-framed-{}-{}.sock",
                std::process::id(),
                api_addr.port()
            ));
            Self::spawn_framed_unix(api_addr, &socket_path)
        }
        #[cfg(target_os = "windows")]
        {
            Self::spawn(api_addr, loopback_ephemeral_addr())
        }
    }

    fn spawn_platform_default_with_startup_info(
        api_addr: SocketAddr,
        startup_info_file: &Path,
    ) -> Self {
        Self::spawn_platform_default_with_bootstrap(api_addr, startup_info_file, None)
    }

    fn spawn_platform_default_with_startup_info_and_lifecycle_lock(
        api_addr: SocketAddr,
        startup_info_file: &Path,
        lifecycle_lock: File,
    ) -> Self {
        Self::spawn_platform_default_with_bootstrap(
            api_addr,
            startup_info_file,
            Some(Stdio::from(lifecycle_lock)),
        )
    }

    fn spawn_platform_default_with_bootstrap(
        api_addr: SocketAddr,
        startup_info_file: &Path,
        stdin: Option<Stdio>,
    ) -> Self {
        #[cfg(target_os = "linux")]
        {
            Self::spawn_with_bootstrap_options(
                api_addr,
                Some(startup_info_file),
                stdin,
                json!({
                    "mode": "explicit",
                    "listen_addr": loopback_ephemeral_addr(),
                }),
            )
        }
        #[cfg(target_os = "macos")]
        {
            let socket_path = PathBuf::from(format!(
                "/tmp/abyss-s-{}-{}.sock",
                std::process::id(),
                rand::random::<u64>()
            ));
            Self::spawn_with_bootstrap_options(
                api_addr,
                Some(startup_info_file),
                stdin,
                json!({
                    "mode": "macos_network_extension",
                    "socket_path": socket_path,
                }),
            )
        }
        #[cfg(target_os = "windows")]
        {
            Self::spawn_with_bootstrap_options(
                api_addr,
                Some(startup_info_file),
                stdin,
                json!({
                    "mode": "windows_wfp",
                }),
            )
        }
    }

    fn wait_for_running(&mut self) -> ProxyStatus {
        let start_time = Instant::now();
        while start_time.elapsed() < STARTUP_TIMEOUT {
            if let Some(status) = query_status(self.api_addr)
                && status.process_id.is_some()
            {
                return status;
            }
            if let Some(status) = self
                .child
                .try_wait()
                .expect("broker process should be pollable")
            {
                panic!(
                    "abyss-broker exited with {status} before exposing REST status\n{}",
                    self.read_log()
                );
            }
            thread::sleep(POLL_INTERVAL);
        }
        panic!(
            "abyss-broker did not expose REST status before timeout\n{}",
            self.read_log()
        );
    }

    #[cfg(unix)]
    fn wait_for_completed_flow_diagnostics(&mut self) -> serde_json::Value {
        let start_time = Instant::now();
        let token = read_auth_token(&self.auth_token_file);
        let http_client = client();
        while start_time.elapsed() < STARTUP_TIMEOUT {
            if let Ok(response) = http_client
                .get(url(self.api_addr, "/v1/support/diagnostics"))
                .bearer_auth(&token)
                .send()
                && response.status().is_success()
                && let Ok(snapshot) = response.json::<serde_json::Value>()
                && snapshot["flow"]["totals"]["completed"]
                    .as_u64()
                    .is_some_and(|completed| completed > 0)
            {
                return snapshot;
            }
            if let Some(status) = self
                .child
                .try_wait()
                .expect("broker process should be pollable")
            {
                panic!(
                    "abyss-broker exited with {status} before recording the test flow\n{}",
                    self.read_log()
                );
            }
            thread::sleep(POLL_INTERVAL);
        }
        panic!(
            "abyss-broker did not record the completed test flow before timeout\n{}",
            self.read_log()
        );
    }

    #[cfg(unix)]
    fn wait_for_log_record(&mut self, expected: &str) {
        let start_time = Instant::now();
        while start_time.elapsed() < STARTUP_TIMEOUT {
            if self.read_log().contains(expected) {
                return;
            }
            if let Some(status) = self
                .child
                .try_wait()
                .expect("broker process should be pollable")
            {
                panic!(
                    "abyss-broker exited with {status} before writing `{expected}`\n{}",
                    self.read_log()
                );
            }
            thread::sleep(POLL_INTERVAL);
        }
        panic!(
            "abyss-broker did not write `{expected}` before timeout\n{}",
            self.read_log()
        );
    }

    fn wait_for_startup_info(&mut self, path: &Path) -> StartupInfoOutput {
        let start_time = Instant::now();
        while start_time.elapsed() < STARTUP_TIMEOUT {
            if let Ok(body) = fs::read(path)
                && let Ok(startup_info) = serde_json::from_slice::<StartupInfoOutput>(&body)
            {
                return startup_info;
            }
            if let Some(status) = self
                .child
                .try_wait()
                .expect("broker process should be pollable")
            {
                panic!(
                    "abyss-broker exited with {status} before writing startup info\n{}",
                    self.read_log()
                );
            }
            thread::sleep(POLL_INTERVAL);
        }
        panic!(
            "abyss-broker did not write startup info before timeout\n{}",
            self.read_log()
        );
    }

    fn shutdown(&self) -> ProxyStatus {
        shutdown_broker(self.api_addr, &self.auth_token_file)
    }

    #[cfg(unix)]
    fn send_sigterm(&self) {
        let process_id =
            i32::try_from(self.child.id()).expect("broker process id should fit the Unix pid type");
        kill(Pid::from_raw(process_id), Signal::SIGTERM)
            .expect("SIGTERM should be delivered to the broker process");
    }

    fn wait_for_exit(&mut self) {
        let _exit_status = self.wait_for_exit_status();
    }

    fn wait_for_exit_status(&mut self) -> std::process::ExitStatus {
        let start_time = Instant::now();
        while start_time.elapsed() < STARTUP_TIMEOUT {
            if let Some(status) = self
                .child
                .try_wait()
                .expect("broker process should be pollable")
            {
                return status;
            }
            thread::sleep(POLL_INTERVAL);
        }
        panic!(
            "abyss-broker did not exit before timeout\n{}",
            self.read_log()
        );
    }

    fn read_log(&self) -> String {
        fs::read_to_string(&self.log_file).unwrap_or_else(|error| {
            format!(
                "failed to read broker test log `{}`: {error}",
                self.log_file.display()
            )
        })
    }
}

impl Drop for BrokerProcess {
    fn drop(&mut self) {
        if self
            .child
            .try_wait()
            .expect("broker process should be pollable during cleanup")
            .is_none()
        {
            request_shutdown(self.api_addr, &self.auth_token_file);
            let _killed = self.child.kill();
            let _waited = self.child.wait();
        }
        drop(fs::remove_file(&self.auth_token_file));
        drop(fs::remove_dir_all(&self.ca_dir));
        drop(fs::remove_file(&self.log_file));
        drop(fs::remove_dir_all(&self.runtime_log_dir));
        drop(fs::remove_dir_all(&self.runtime_root));
    }
}

fn auth_token_path(api_addr: SocketAddr) -> PathBuf {
    std::env::temp_dir().join(format!(
        "abyss-broker-test-{}-{}-{}.token",
        std::process::id(),
        api_addr.port(),
        next_test_path_sequence()
    ))
}

fn ca_dir_path(api_addr: SocketAddr) -> PathBuf {
    std::env::temp_dir().join(format!(
        "abyss-broker-test-{}-{}-{}-ca",
        std::process::id(),
        api_addr.port(),
        next_test_path_sequence()
    ))
}

fn log_path(api_addr: SocketAddr) -> PathBuf {
    std::env::temp_dir().join(format!(
        "abyss-broker-test-{}-{}-{}.log",
        std::process::id(),
        api_addr.port(),
        next_test_path_sequence()
    ))
}

fn runtime_log_dir_path(api_addr: SocketAddr) -> PathBuf {
    std::env::temp_dir().join(format!(
        "abyss-broker-test-{}-{}-{}-runtime-logs",
        std::process::id(),
        api_addr.port(),
        next_test_path_sequence()
    ))
}

fn next_test_path_sequence() -> u64 {
    TEST_PATH_SEQUENCE.fetch_add(1, Ordering::Relaxed)
}

fn runtime_root_path(api_addr: SocketAddr) -> PathBuf {
    std::env::temp_dir().join(format!(
        "abyss-broker-test-{}-{}-{}-root",
        std::process::id(),
        api_addr.port(),
        next_test_path_sequence()
    ))
}

fn write_ca_fixture(directory: &Path) {
    fs::create_dir_all(directory).expect("test CA directory should be created");
    // The blackbox fixture writes CA material directly, bypassing CaStore's
    // provider setup, so install it before rcgen key generation.
    abyss_mitm::install_default_crypto_provider();
    let key_pair = KeyPair::generate().expect("test CA key should generate");
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, "Abyss Broker Blackbox Root CA");
    let mut params = CertificateParams::default();
    params.distinguished_name = distinguished_name;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::CrlSign,
    ];
    let certificate = params
        .self_signed(&key_pair)
        .expect("test root CA should self-sign");
    fs::write(directory.join("abyss-root-ca.der"), certificate.der())
        .expect("test DER certificate should be written");
    fs::write(directory.join("abyss-root-ca.pem"), certificate.pem())
        .expect("test PEM certificate should be written");
    fs::write(
        directory.join("abyss-root-ca-key.pem"),
        key_pair.serialize_pem(),
    )
    .expect("test private key should be written");
}

#[derive(Debug, Deserialize)]
struct StartupInfoOutput {
    api_addr: SocketAddr,
    auth_token_file: PathBuf,
    plugin_endpoint: String,
    pid: u32,
}

#[derive(Debug, Deserialize)]
struct ProxyStatus {
    lifecycle: ProxyLifecycle,
    process_id: Option<u32>,
    #[cfg(unix)]
    mode: Option<ProxyMode>,
    #[cfg(unix)]
    #[serde(default)]
    ingresses: Vec<IngressStatus>,
    listen_addr: Option<SocketAddr>,
    #[cfg_attr(
        not(target_os = "macos"),
        expect(
            dead_code,
            reason = "Only macOS blackbox tests read the framed ingress socket_path."
        )
    )]
    socket_path: Option<PathBuf>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum ProxyLifecycle {
    Running,
    Stopped,
}

#[cfg(unix)]
#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum ProxyMode {
    Explicit,
    Transparent,
}

#[cfg(unix)]
#[derive(Debug, Deserialize)]
struct IngressStatus {
    source: IngressSource,
    listen_addr: Option<SocketAddr>,
}

#[cfg(unix)]
#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum IngressSource {
    ExplicitHttp,
    MacosNetworkExtension,
    WindowsWfp,
}
