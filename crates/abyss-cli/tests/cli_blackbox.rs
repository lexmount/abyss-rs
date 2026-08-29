use std::{
    fs,
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    process::Command,
    thread::{self, JoinHandle},
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;

#[test]
fn version_commands_report_the_workspace_version() {
    let version = Command::new(env!("CARGO_BIN_EXE_abyss"))
        .arg("version")
        .output()
        .expect("endpoint CLI should run");
    assert!(
        version.status.success(),
        "version command should succeed; stderr={}",
        String::from_utf8_lossy(&version.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&version.stdout).trim(),
        env!("CARGO_PKG_VERSION")
    );
    assert!(version.stderr.is_empty());

    let flag = Command::new(env!("CARGO_BIN_EXE_abyss"))
        .arg("--version")
        .output()
        .expect("endpoint CLI should run");
    assert!(flag.status.success());
    assert_eq!(
        String::from_utf8_lossy(&flag.stdout).trim(),
        concat!("abyss ", env!("CARGO_PKG_VERSION"))
    );
    assert!(flag.stderr.is_empty());
}

#[test]
fn proxy_env_preserves_the_posix_explicit_proxy_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_abyss"))
        .args(["proxy", "env", "--proxy-url", "http://127.0.0.1:28999"])
        .output()
        .expect("Abyss CLI should run");

    assert!(
        output.status.success(),
        "proxy env should succeed; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "export HTTP_PROXY='http://127.0.0.1:28999'\n\
export HTTPS_PROXY='http://127.0.0.1:28999'\n\
export http_proxy='http://127.0.0.1:28999'\n\
export https_proxy='http://127.0.0.1:28999'\n\
export NO_PROXY='127.0.0.1,localhost'\n"
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn login_persists_the_cli_owned_credential() {
    let control_plane = FakeControlPlane::spawn();
    let root = unique_test_dir();
    fs::create_dir_all(&root).expect("test state should create");
    fs::write(
        root.join("product-config.json"),
        format!(
            r#"{{
                "schema_version": 1,
                "product": {{
                    "kind": "cli",
                    "control_plane": {{"url": "{}"}}
                }},
                "delivery_worker": {{
                    "plugin_id": "example.delivery",
                    "delivery": {{"endpoint": "{}/v1/events"}},
                    "authentication": {{"mode": "managed_bearer"}}
                }}
            }}"#,
            control_plane.base_url, control_plane.base_url
        ),
    )
    .expect("deployment product configuration should write");

    let output = Command::new(env!("CARGO_BIN_EXE_abyss"))
        .env("ABYSS_HOME", &root)
        .args([
            "login",
            "--control-plane",
            &control_plane.base_url,
            "--timeout-seconds",
            "5",
            "--poll-interval-seconds",
            "1",
            "--skip-runtime",
        ])
        .output()
        .expect("endpoint CLI should run");

    assert!(
        output.status.success(),
        "login should succeed; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let login_progress = String::from_utf8_lossy(&output.stderr);
    assert!(login_progress.contains("Abyss login"));
    assert!(login_progress.contains("Waiting for login to complete"));
    assert!(login_progress.contains("Login succeeded as linux@example.invalid"));
    assert!(!login_progress.contains("\u{1b}["));
    let credential_path = root.join("auth/credentials.json");
    let credential = fs::read_to_string(&credential_path).expect("credential should be written");
    assert!(credential.contains("native-token"));
    #[cfg(unix)]
    assert_eq!(
        fs::metadata(&credential_path)
            .expect("credential metadata should read")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    control_plane.join();
    fs::remove_dir_all(root).expect("test state should be removed");
}

#[test]
fn status_and_log_dump_work_without_a_running_broker() {
    let root = unique_test_dir();
    let support_bundle = root.join("support.zip");
    fs::create_dir_all(&root).expect("test state should create");
    fs::write(
        root.join("product-config.json"),
        r#"{
            "schema_version": 1,
            "product": {
                "kind": "cli",
                "dashboard": {"url": "http://127.0.0.1:43123"}
            },
            "delivery_worker": {"authentication": {"mode": "none"}}
        }"#,
    )
    .expect("product configuration should write");
    let output = Command::new(env!("CARGO_BIN_EXE_abyss"))
        .env("ABYSS_HOME", &root)
        .args(["status", "--broker-api", "127.0.0.1:1"])
        .output()
        .expect("endpoint CLI should run");

    assert!(output.status.success());
    let status = String::from_utf8_lossy(&output.stdout);
    assert!(status.contains("Auth: logged_out"));
    assert!(status.contains("Broker: stopped"));
    assert!(status.contains("Dashboard: http://127.0.0.1:43123"));

    let output = Command::new(env!("CARGO_BIN_EXE_abyss"))
        .env("ABYSS_HOME", &root)
        .args([
            "log",
            "dump",
            "--file",
            support_bundle
                .to_str()
                .expect("support path should be UTF-8"),
            "--broker-api",
            "127.0.0.1:1",
        ])
        .output()
        .expect("endpoint CLI should run");

    assert!(
        output.status.success(),
        "log dump should succeed; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let progress = String::from_utf8_lossy(&output.stderr);
    assert!(progress.contains("Collecting the Abyss support bundle"));
    assert!(progress.contains("Support bundle collected"));
    assert!(!progress.contains("\u{1b}["));
    let bundle = fs::read(&support_bundle).expect("support bundle should be written");
    assert!(bundle.starts_with(b"PK\x03\x04"));
    assert!(
        bundle
            .windows(b"manifest.json".len())
            .any(|window| window == b"manifest.json")
    );
    assert!(
        bundle
            .windows(b"diagnostics/state.json".len())
            .any(|window| window == b"diagnostics/state.json")
    );
    assert!(
        bundle
            .windows(b"config/runtime-config.redacted.json".len())
            .any(|window| window == b"config/runtime-config.redacted.json")
    );
    assert!(
        bundle
            .windows(b"cli/cli.log".len())
            .any(|window| window == b"cli/cli.log")
    );
    fs::remove_dir_all(root).expect("test state should be removed");
}

#[test]
fn deploy_local_reports_plain_progress_and_preserves_command_results() {
    let root = unique_test_dir();
    fs::create_dir_all(&root).expect("test state should create");
    let service = root.join("fake-local-service.py");
    write_fake_local_service(&service);
    let binary = env!("CARGO_BIN_EXE_abyss");

    let start = local_deployment_command(binary, &root, &service)
        .args(["deploy-local", "start"])
        .output()
        .expect("local deployment should start");
    assert!(
        start.status.success(),
        "local deployment should start; stderr={}",
        String::from_utf8_lossy(&start.stderr)
    );
    let stdout = String::from_utf8_lossy(&start.stdout);
    assert!(stdout.contains("Backend: http://127.0.0.1:"));
    assert!(stdout.contains("Dashboard: http://127.0.0.1:"));
    assert!(stdout.contains("Proxy: skipped"));
    assert!(stdout.contains("Local environment is ready."));
    let stderr = String::from_utf8_lossy(&start.stderr);
    for expected in [
        "Abyss local deployment",
        "Preparing abyss-backend v1.0.0",
        "abyss-backend v1.0.0 provided by configuration",
        "Preparing abyss-dashboard v0.1.0",
        "abyss-dashboard v0.1.0 provided by configuration",
        "Starting local backend",
        "Local backend ready at http://127.0.0.1:",
        "Starting local dashboard",
        "Local dashboard ready at http://127.0.0.1:",
    ] {
        assert!(
            stderr.contains(expected),
            "missing `{expected}` in {stderr}"
        );
    }
    assert!(!stderr.contains("\u{1b}["));

    let repeated = local_deployment_command(binary, &root, &service)
        .args(["deploy-local", "start"])
        .output()
        .expect("running local deployment should be reusable");
    assert!(
        repeated.status.success(),
        "repeated start should succeed; stderr={}",
        String::from_utf8_lossy(&repeated.stderr)
    );
    let repeated_progress = String::from_utf8_lossy(&repeated.stderr);
    assert!(repeated_progress.contains("Local backend already running"));
    assert!(repeated_progress.contains("Local dashboard already running"));

    let status = local_deployment_command(binary, &root, &service)
        .args(["deploy-local", "status"])
        .output()
        .expect("local deployment status should run");
    assert!(status.status.success());
    let status_output = String::from_utf8_lossy(&status.stdout);
    assert!(status_output.contains("Backend: running"));
    assert!(status_output.contains("Dashboard: running"));
    assert!(status_output.contains("Proxy: skipped"));
    assert!(status.stderr.is_empty());

    let stop = local_deployment_command(binary, &root, &service)
        .args(["deploy-local", "stop"])
        .output()
        .expect("local deployment should stop");
    assert!(
        stop.status.success(),
        "local deployment should stop; stderr={}",
        String::from_utf8_lossy(&stop.stderr)
    );
    assert!(stop.stdout.is_empty());
    let stop_progress = String::from_utf8_lossy(&stop.stderr);
    assert!(stop_progress.contains("Stop Abyss local deployment"));
    assert!(stop_progress.contains("Local dashboard and backend stopped"));
    assert!(stop_progress.contains("Local environment stopped"));
    assert!(!stop_progress.contains("\u{1b}["));

    fs::remove_dir_all(root).expect("test state should be removed");
}

#[test]
fn log_dump_reports_startup_identity_discovery_failures_in_a_partial_bundle() {
    for (case, startup_info, expected_error) in [
        ("missing", None, "broker startup identity was not found at"),
        (
            "malformed",
            Some(b"{not-json".as_slice()),
            "broker startup identity is invalid at",
        ),
        (
            "invalid-address",
            Some(
                br#"{"api_addr":"0.0.0.0:12345","auth_token_file":"ignored","pid":42}"#.as_slice(),
            ),
            "broker startup identity contains invalid API address",
        ),
    ] {
        let root = unique_test_dir().join(case);
        let runtime = root.join("runtime");
        fs::create_dir_all(&runtime).expect("runtime directory should be created");
        if let Some(startup_info) = startup_info {
            fs::write(runtime.join("startup-info.json"), startup_info)
                .expect("startup identity fixture should be written");
        }
        let support_bundle = root.join("support.zip");

        let output = Command::new(env!("CARGO_BIN_EXE_abyss"))
            .env("ABYSS_HOME", &root)
            .args([
                "log",
                "dump",
                "--file",
                support_bundle
                    .to_str()
                    .expect("support path should be UTF-8"),
            ])
            .output()
            .expect("endpoint CLI should run");

        assert!(
            output.status.success(),
            "{case} startup identity should produce a partial bundle; stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        let bundle = fs::read(&support_bundle).expect("support bundle should be written");
        let archive = String::from_utf8_lossy(&bundle);
        assert!(archive.contains("collection-errors.json"));
        assert!(archive.contains("\"source\": \"broker-discovery\""));
        assert!(archive.contains(expected_error));
        assert!(archive.contains("\"partial\": true"));
        fs::remove_dir_all(root).expect("test state should be removed");
    }
}

#[test]
fn unauthenticated_proxy_start_and_run_skip_login_without_a_control_plane() {
    let root = unique_test_dir();
    write_cli_startup_fixture(
        &root,
        r#"{
            "schema_version": 1,
            "product": {"kind": "cli"},
            "delivery_worker": {
                "delivery": {"endpoint": "https://events.example.test/v1/events"},
                "authentication": {"mode": "none"}
            }
        }"#,
    );
    let binary = env!("CARGO_BIN_EXE_abyss");

    for args in [vec!["proxy", "start"], vec!["run", "--", "true"]] {
        let output = Command::new(binary)
            .env("ABYSS_HOME", &root)
            .args(args)
            .output()
            .expect("endpoint CLI should run");
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("ca.path must not be empty"),
            "stderr={stderr}"
        );
        assert!(!stderr.contains("abyss login"), "stderr={stderr}");
        assert!(!stderr.contains("product.control_plane"), "stderr={stderr}");
    }

    assert!(!root.join("ca").exists());
    fs::remove_dir_all(root).expect("test state should be removed");
}

#[test]
fn authenticated_proxy_start_and_run_require_login() {
    let root = unique_test_dir();
    write_cli_startup_fixture(
        &root,
        r#"{
            "schema_version": 1,
            "product": {
                "kind": "cli",
                "control_plane": {"url": "https://control.example.test/api"}
            },
            "delivery_worker": {
                "authentication": {"mode": "managed_bearer"}
            }
        }"#,
    );
    let binary = env!("CARGO_BIN_EXE_abyss");

    for args in [vec!["proxy", "start"], vec!["run", "--", "true"]] {
        let output = Command::new(binary)
            .env("ABYSS_HOME", &root)
            .args(args)
            .output()
            .expect("endpoint CLI should run");
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("abyss login"), "stderr={stderr}");
    }

    assert!(!root.join("ca").exists());
    fs::remove_dir_all(root).expect("test state should be removed");
}

#[test]
fn authenticated_proxy_without_a_control_plane_reports_configuration_error() {
    let root = unique_test_dir();
    write_cli_startup_fixture(
        &root,
        r#"{
            "schema_version": 1,
            "product": {"kind": "cli"},
            "delivery_worker": {
                "authentication": {"mode": "managed_bearer"}
            }
        }"#,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_abyss"))
        .env("ABYSS_HOME", &root)
        .args(["proxy", "start"])
        .output()
        .expect("endpoint CLI should run");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(
            "product.control_plane is required when delivery_worker.authentication.mode is \"managed_bearer\""
        ),
        "stderr={stderr}"
    );
    assert!(!stderr.contains("abyss login"), "stderr={stderr}");
    assert!(!root.join("ca").exists());
    fs::remove_dir_all(root).expect("test state should be removed");
}

#[test]
fn diagnostics_command_renders_provider_guidance_from_local_observations() {
    let broker = FakeDiagnosticsBroker::spawn();
    let root = unique_test_dir();
    fs::create_dir_all(root.join("runtime")).expect("runtime directory should be created");
    let token_file = root.join("runtime/broker.token");
    fs::write(&token_file, "broker-token\n").expect("broker token should be written");
    write_startup_info(&root, &broker.base_url, &token_file, 42);

    let output = Command::new(env!("CARGO_BIN_EXE_abyss"))
        .env("ABYSS_HOME", &root)
        .arg("diagnostics")
        .output()
        .expect("endpoint CLI should run");

    assert!(
        output.status.success(),
        "diagnostics should succeed; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let diagnosis = String::from_utf8_lossy(&output.stdout);
    assert!(diagnosis.contains("Abyss Network Diagnostics"));
    assert!(diagnosis.contains("4 most recent Agent network events"));
    assert!(diagnosis.contains("Could not find the model provider address."));
    assert!(diagnosis.contains("DNS, VPN, or network settings"));
    assert!(!diagnosis.contains("The Agent connection was interrupted."));
    assert!(diagnosis.contains("The Agent request completed normally."));
    assert!(!diagnosis.contains("dns_error"));
    assert!(!diagnosis.contains("\u{1b}["));

    broker.join();
    fs::remove_dir_all(root).expect("test state should be removed");
}

#[test]
fn log_dump_materializes_redacted_broker_logs() {
    let broker = FakeSupportBroker::spawn();
    let expected_base_url = format!("http://{}", broker.base_url);
    let root = unique_test_dir();
    fs::create_dir_all(root.join("runtime")).expect("runtime directory should be created");
    fs::write(root.join("runtime/broker.token"), "broker-token\n")
        .expect("broker token should be written");
    let support_bundle = root.join("support.zip");

    let output = Command::new(env!("CARGO_BIN_EXE_abyss"))
        .env("ABYSS_HOME", &root)
        .args([
            "log",
            "dump",
            "--file",
            support_bundle
                .to_str()
                .expect("support path should be UTF-8"),
            "--broker-api",
            &broker.base_url,
        ])
        .output()
        .expect("endpoint CLI should run");
    assert!(
        output.status.success(),
        "log dump should succeed; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let bundle = fs::read(&support_bundle).expect("support bundle should be written");
    assert!(
        bundle
            .windows(b"broker/abyss-broker.log".len())
            .any(|window| window == b"broker/abyss-broker.log")
    );
    assert!(
        !bundle
            .windows(b"broker-secret".len())
            .any(|window| { window == b"broker-secret" })
    );
    assert!(
        bundle
            .windows(b"<redacted>".len())
            .any(|window| { window == b"<redacted>" })
    );
    assert!(
        bundle
            .windows(expected_base_url.len())
            .any(|window| window == expected_base_url.as_bytes()),
        "support metadata should retain the discovered dynamic broker URL"
    );

    broker.join();
    fs::remove_dir_all(root).expect("test state should be removed");
}

struct FakeControlPlane {
    base_url: String,
    join_handle: JoinHandle<()>,
}

impl FakeControlPlane {
    fn spawn() -> Self {
        let listener =
            TcpListener::bind("127.0.0.1:0").expect("control-plane listener should bind");
        let address = listener
            .local_addr()
            .expect("control-plane address should read");
        let join_handle = thread::spawn(move || {
            let responses = [
                (
                    "POST /auth/terminal/start HTTP/1.1",
                    r#"{"attempt_id":"018fbeef-0000-7000-8000-000000000001","poll_token":"poll-token","verification_url":"http://127.0.0.1/verify","expires_at":"2099-01-01T00:00:00Z","poll_interval_seconds":1}"#,
                ),
                (
                    "POST /auth/terminal/poll HTTP/1.1",
                    r#"{"status":"completed"}"#,
                ),
                (
                    "POST /auth/terminal/exchange HTTP/1.1",
                    r#"{"token":"native-token","expires_at":"2099-01-01T00:00:00Z","user":{"id":"018fbeef-0000-7000-8000-000000000002","email":"linux@example.invalid","name":"Linux User","roles":["user"]}}"#,
                ),
            ];
            for (expected_request, response_body) in responses {
                let (stream, _) = listener
                    .accept()
                    .expect("control-plane request should arrive");
                let request = read_request(stream, expected_request);
                if expected_request.contains("/poll") {
                    assert!(
                        !request.body.contains("code_verifier"),
                        "poll request must not expose the PKCE verifier"
                    );
                }
                if expected_request.contains("/exchange") {
                    assert!(
                        request.body.contains("code_verifier"),
                        "exchange request must carry the PKCE verifier"
                    );
                }
                write_json_response(response_body, request.stream);
            }
        });
        Self {
            base_url: format!("http://{address}"),
            join_handle,
        }
    }

    fn join(self) {
        self.join_handle
            .join()
            .expect("control-plane server should finish");
    }
}

struct FakeDiagnosticsBroker {
    base_url: String,
    join_handle: JoinHandle<()>,
}

impl FakeDiagnosticsBroker {
    fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("diagnostics listener should bind");
        let address = listener
            .local_addr()
            .expect("diagnostics address should read");
        let join_handle = thread::spawn(move || {
            let responses = [
                (
                    "GET /v1/proxy/status HTTP/1.1",
                    r#"{"lifecycle":"running","process_id":42,"mode":"explicit","ingresses":[{"source":"explicit_http","listen_addr":"127.0.0.1:18191"}],"listen_addr":"127.0.0.1:18191"}"#,
                    false,
                ),
                (
                    "GET /v1/network/observations?limit=5 HTTP/1.1",
                    r#"{"schema_version":1,"observations":[
                    {"observed_at_unix_ms":100,"destination_host":"api.example.test","source_process_name":"claude","hop":"abyss_to_provider","stage":"dns_resolution","outcome":"failed","failure_class":"dns_error","technical_error_code":"provider_dns_error","http_status":null},
                    {"observed_at_unix_ms":90,"destination_host":"api.example.test","source_process_name":"claude","hop":"agent_to_abyss","stage":"stream","outcome":"interrupted","failure_class":"client_closed","technical_error_code":"agent_connection_closed","http_status":null},
                    {"observed_at_unix_ms":80,"destination_host":"api.example.test","source_process_name":"codex","hop":"abyss_to_provider","stage":"stream","outcome":"succeeded","failure_class":null,"technical_error_code":null,"http_status":200},
                    {"observed_at_unix_ms":70,"destination_host":"api.example.test","source_process_name":"codex","hop":"abyss_to_provider","stage":"request","outcome":"failed","failure_class":"http_error","technical_error_code":"provider_http_error","http_status":429},
                    {"observed_at_unix_ms":60,"destination_host":"api.example.test","source_process_name":"codex","hop":"abyss_to_provider","stage":"tcp_connect","outcome":"failed","failure_class":"timeout","technical_error_code":"provider_tcp_error","http_status":null}
                ]}"#,
                    true,
                ),
            ];
            for (expected_request, response, authenticated) in responses {
                let (stream, _) = listener
                    .accept()
                    .expect("diagnostics request should arrive");
                let request = read_request(stream, expected_request);
                assert_eq!(
                    request
                        .headers
                        .contains("authorization: Bearer broker-token"),
                    authenticated,
                    "diagnostics authentication must match the route boundary"
                );
                write_json_response(response, request.stream);
            }
        });
        Self {
            base_url: format!("{address}"),
            join_handle,
        }
    }

    fn join(self) {
        self.join_handle
            .join()
            .expect("diagnostics server should finish");
    }
}

struct FakeSupportBroker {
    base_url: String,
    join_handle: JoinHandle<()>,
}

impl FakeSupportBroker {
    fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("broker listener should bind");
        let address = listener.local_addr().expect("broker address should read");
        let join_handle = thread::spawn(move || {
            let responses = [
                (
                    "GET /v1/proxy/status HTTP/1.1",
                    r#"{"lifecycle":"running","process_id":42,"mode":"explicit","ingresses":[{"source":"explicit_http","listen_addr":"127.0.0.1:18191"}],"listen_addr":"127.0.0.1:18191"}"#,
                ),
                (
                    "GET /healthz HTTP/1.1",
                    r#"{"service":"abyss-broker","status":"ok"}"#,
                ),
                (
                    "POST /v1/support/logs/broker HTTP/1.1",
                    r#"{"files":[{"name":"abyss-broker.log","content":"Authorization: Bearer broker-secret\n","truncated":false,"original_size":43}],"errors":[]}"#,
                ),
                (
                    "GET /v1/support/diagnostics HTTP/1.1",
                    r#"{"schema_version":1}"#,
                ),
                (
                    "GET /v1/mitm/config HTTP/1.1",
                    r#"{"tls_decryption":{"default_action":"passthrough","missing_sni_action":"passthrough","rules":[]}}"#,
                ),
                ("GET /v1/hooks/config HTTP/1.1", r#"{"harness_usage":{}}"#),
            ];
            for (expected_request, response_body) in responses {
                let (stream, _) = listener
                    .accept()
                    .expect("broker support request should arrive");
                let request = read_request(stream, expected_request);
                if expected_request.contains("/v1/support/logs/broker") {
                    assert!(
                        request
                            .headers
                            .contains("authorization: Bearer broker-token"),
                        "broker support request must authenticate with its local token"
                    );
                }
                write_json_response(response_body, request.stream);
            }
        });
        Self {
            base_url: format!("{address}"),
            join_handle,
        }
    }

    fn join(self) {
        self.join_handle
            .join()
            .expect("broker support server should finish");
    }
}

struct Request {
    headers: String,
    body: String,
    stream: TcpStream,
}

fn read_request(mut stream: TcpStream, expected_request: &str) -> Request {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let count = stream.read(&mut buffer).expect("request should read");
        assert_ne!(count, 0, "request should contain headers");
        bytes.extend_from_slice(&buffer[..count]);
        if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    let header_end = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .and_then(|position| position.checked_add(4))
        .expect("request headers should end");
    let headers = String::from_utf8_lossy(&bytes[..header_end]).into_owned();
    assert!(
        headers.starts_with(expected_request),
        "unexpected request: {headers}"
    );
    let content_length = headers
        .lines()
        .find_map(|line| {
            line.strip_prefix("content-length:")
                .or_else(|| line.strip_prefix("Content-Length:"))
        })
        .map(str::trim)
        .map(str::parse::<usize>)
        .transpose()
        .expect("content length should parse")
        .unwrap_or(0);
    while bytes.len().saturating_sub(header_end) < content_length {
        let count = stream.read(&mut buffer).expect("request body should read");
        assert_ne!(count, 0, "request should contain its full body");
        bytes.extend_from_slice(&buffer[..count]);
    }
    let body_end = header_end
        .checked_add(content_length)
        .expect("request body length should fit in memory");
    let body = String::from_utf8_lossy(&bytes[header_end..body_end]).into_owned();
    Request {
        headers,
        body,
        stream,
    }
}

fn write_json_response(body: &str, mut stream: TcpStream) {
    let response = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream
        .write_all(response.as_bytes())
        .expect("response should write");
}

fn unique_test_dir() -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("abyss-cli-blackbox-{}-{nonce}", std::process::id()))
}

fn local_deployment_command(
    binary: &str,
    root: &std::path::Path,
    service: &std::path::Path,
) -> Command {
    let mut command = Command::new(binary);
    command
        .env("ABYSS_HOME", root)
        .env("ABYSS_LOCAL_BACKEND_BIN", service)
        .env("ABYSS_LOCAL_DASHBOARD_BIN", service)
        .env("ABYSS_LOCAL_SKIP_PROXY", "1");
    command
}

fn write_fake_local_service(path: &std::path::Path) {
    fs::write(
        path,
        r#"#!/usr/bin/env python3
import argparse
import http.server
import os

if "ABYSS_BACKEND_ADDR" in os.environ:
    host, port = os.environ["ABYSS_BACKEND_ADDR"].rsplit(":", 1)
else:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--backend", required=True)
    parser.add_argument("--token-file", required=True)
    args = parser.parse_args()
    host, port = args.host, args.port

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass

http.server.ThreadingHTTPServer((host, int(port)), Handler).serve_forever()
"#,
    )
    .expect("fake local service should write");
    #[cfg(unix)]
    {
        let mut permissions = fs::metadata(path)
            .expect("fake local service metadata should read")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(path, permissions)
            .expect("fake local service should become executable");
    }
}

fn write_cli_startup_fixture(root: &std::path::Path, product_config: &str) {
    fs::create_dir_all(root).expect("test state should create");
    fs::write(root.join("product-config.json"), product_config)
        .expect("product configuration should write");
    fs::write(
        root.join("broker-config.toml"),
        r#"schema_version = 1

[ca]
path = ""

[proxy]
mode = "explicit"
"#,
    )
    .expect("broker configuration should write");
}

fn write_startup_info(
    root: &std::path::Path,
    api_addr: &str,
    token_file: &std::path::Path,
    pid: u32,
) {
    let body = serde_json::json!({
        "api_addr": api_addr,
        "auth_token_file": token_file,
        "pid": pid,
    });
    fs::write(
        root.join("runtime/startup-info.json"),
        serde_json::to_vec(&body).expect("startup identity should serialize"),
    )
    .expect("startup identity should be written");
}
