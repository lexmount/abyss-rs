//! Connection readiness, socket reuse, and legacy/configured route compatibility.

use std::{fs, io, net::SocketAddr, path::PathBuf, time::Duration};

use abyss_mitm::{
    FlowId, FlowOperation, MitmEngine, SourceProcess, TransparentFlowError,
    outbound::{HttpConnectProxy, UpstreamProxyConfig, UpstreamProxyProtocol},
};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, UnixStream},
    task::JoinHandle,
    time::timeout,
};
use uuid::Uuid;

use super::{FramedUnixConnection, connection_failure_reason};
use crate::{
    ingress::{
        IngressConnection as _, IngressError, PlatformFlow, PlatformFlowMetadata,
        macos::framed_protocol::{FlowFrame, FlowFrameCodec, FlowFrameDirection, FlowFrameType},
    },
    network_diagnostics::{NetworkErrorCode, NetworkHop, NetworkObservation, NetworkStage},
    process_context::default_process_context_resolver,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(3);

struct TestConnection {
    flow_id: Uuid,
    client: UnixStream,
    task: JoinHandle<Result<PlatformFlow, IngressError>>,
}

impl TestConnection {
    async fn start(
        destination: SocketAddr,
        connect_before_open: Option<bool>,
        proxy: Option<HttpConnectProxy>,
    ) -> Self {
        let flow_id = Uuid::new_v4();
        let (mut client, stream) = UnixStream::pair().expect("test Unix socket pair");
        let destination_host = proxy.is_none().then_some("only-proxy-knows.invalid");
        let connection = FramedUnixConnection {
            proxy,
            stream,
            socket_path: PathBuf::from("unused-paired-test-socket"),
            process_context_resolver: default_process_context_resolver(),
        };
        let task = tokio::spawn(connection.into_flow());
        let mut payload = json!({
            "flow_id": flow_id,
            "platform": "macos",
            "protocol": "tcp",
            "source_process": "/usr/bin/claude",
            "source_application_id": "com.example.test-agent",
            // This must not be resolved instead of the original captured IP.
            "destination_host": destination_host,
            "destination_ip": destination.ip().to_string(),
            "destination_port": destination.port(),
        });
        if let Some(requested) = connect_before_open {
            payload["connect_before_open"] = json!(requested);
        }
        let open = FlowFrame::new(
            FlowFrameType::Open,
            FlowFrameDirection::None,
            flow_id,
            serde_json::to_vec(&payload).expect("test metadata encodes"),
        );
        FlowFrameCodec::write_frame(&mut client, &open)
            .await
            .expect("test metadata writes");
        Self {
            flow_id,
            client,
            task,
        }
    }

    async fn result(&mut self) -> Value {
        let frame = timeout(TEST_TIMEOUT, FlowFrameCodec::read_frame(&mut self.client))
            .await
            .expect("readiness result is bounded")
            .expect("readiness frame decodes")
            .expect("readiness frame exists");
        assert_eq!(frame.frame_type(), FlowFrameType::OpenResult);
        assert_eq!(frame.direction(), FlowFrameDirection::BrokerToClient);
        assert_eq!(frame.flow_id(), self.flow_id);
        serde_json::from_slice(frame.payload()).expect("readiness payload decodes")
    }
}

#[tokio::test]
async fn direct_connects_before_application_bytes_and_mitm_reuses_the_same_socket() {
    timeout(TEST_TIMEOUT, async {
        let origin = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("origin binds");
        let destination = origin.local_addr().expect("origin address");
        let mut connection = TestConnection::start(destination, Some(true), None).await;
        // No FlowData has been sent. Readiness cannot wait for HTTP/TLS bytes.
        let (mut upstream, _) = origin.accept().await.expect("original IP connects");
        assert_eq!(connection.result().await, json!({"status": "connected"}));
        assert_eq!(
            upstream.try_read(&mut [0; 1]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        // A second connection cannot succeed after the listener closes.
        drop(origin);
        let flow = connection
            .task
            .await
            .expect("ingress joins")
            .expect("flow prepares");
        assert_eq!(flow.original_destination().socket_addr(), Some(destination));
        let engine = test_mitm_engine();
        let worker = tokio::spawn(async move { engine.handle_flow(flow.into_mitm_flow()).await });
        let origin_worker = tokio::spawn(async move {
            let request = read_http_head(&mut upstream).await;
            assert!(request.starts_with("GET /reuse HTTP/1.1\r\n"));
            upstream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .expect("origin responds");
            upstream.shutdown().await.expect("origin closes");
        });
        write_request(&mut connection.client, connection.flow_id).await;
        let response = read_response(&mut connection.client, connection.flow_id).await;
        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(response.ends_with(b"\r\n\r\nok"));
        origin_worker.await.expect("origin joins");
        worker
            .await
            .expect("MITM joins")
            .expect("prepared connection is reused");
    })
    .await
    .expect("direct readiness and reuse complete");
}

#[tokio::test]
async fn refused_connection_reports_failure_and_retains_network_diagnostics() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("unused port binds");
    let destination = listener.local_addr().expect("unused port address");
    drop(listener);
    let mut connection = TestConnection::start(destination, Some(true), None).await;
    assert_eq!(
        connection.result().await,
        json!({"status": "failed", "reason": "connection_refused"})
    );
    let Err(error) = connection.task.await.expect("ingress joins") else {
        panic!("a refused original destination must not acknowledge a ready flow");
    };
    assert!(matches!(error, IngressError::FramedConnect { .. }));
    let observation = NetworkObservation::from_ingress_error(&error, 100, 120)
        .expect("TCP preparation failure retains network diagnostics");
    assert_eq!(observation.flow_id, Some(connection.flow_id));
    assert_eq!(observation.destination_addr, Some(destination.to_string()));
    assert_eq!(
        observation.destination_host.as_deref(),
        Some("only-proxy-knows.invalid")
    );
    assert_eq!(observation.source_process_name.as_deref(), Some("claude"));
    assert_eq!(
        observation.source_bundle_id.as_deref(),
        Some("com.example.test-agent")
    );
    assert_eq!(observation.hop, NetworkHop::AbyssToProvider);
    assert_eq!(observation.stage, NetworkStage::TcpConnect);
    assert_eq!(
        observation.operation,
        Some(FlowOperation::ConnectProviderTcp)
    );
    assert_eq!(
        observation.technical_error_code,
        Some(NetworkErrorCode::ProviderTcp)
    );
    assert!(
        FlowFrameCodec::read_frame(&mut connection.client)
            .await
            .expect("failure EOF")
            .is_none()
    );
}

#[tokio::test]
async fn legacy_missing_or_false_request_does_not_connect_or_send_a_result() {
    for requested in [None, Some(false)] {
        let origin = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("origin binds");
        let mut connection =
            TestConnection::start(origin.local_addr().unwrap(), requested, None).await;
        let flow = timeout(TEST_TIMEOUT, connection.task)
            .await
            .expect("legacy preparation is immediate")
            .expect("ingress joins")
            .expect("legacy flow prepares");
        assert!(flow.prepared_upstream.is_none());
        assert!(
            timeout(Duration::from_millis(20), origin.accept())
                .await
                .is_err()
        );
        assert!(
            timeout(
                Duration::from_millis(20),
                FlowFrameCodec::read_frame(&mut connection.client)
            )
            .await
            .is_err()
        );
    }
}

#[tokio::test]
async fn configured_proxy_defers_without_connecting_fake_ip_and_preserves_http_host_target() {
    timeout(TEST_TIMEOUT, async {
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.expect("proxy binds");
        let proxy = HttpConnectProxy::new(&UpstreamProxyConfig {
            protocol: UpstreamProxyProtocol::HttpConnect,
            endpoint: format!("http://{}", proxy_listener.local_addr().unwrap()),
            connect_timeout_ms: 1_000,
            handshake_timeout_ms: 1_000,
        })
        .expect("proxy config validates");
        let mut connection =
            TestConnection::start("198.18.0.1:443".parse().unwrap(), Some(true), Some(proxy)).await;
        assert_eq!(connection.result().await, json!({"status": "deferred"}));
        let flow = connection
            .task
            .await
            .expect("ingress joins")
            .expect("proxy flow prepares");
        assert!(flow.prepared_upstream.is_none());
        assert!(flow.configured_upstream.is_some());
        assert!(
            timeout(Duration::from_millis(20), proxy_listener.accept())
                .await
                .is_err()
        );
        let engine = test_mitm_engine();
        let worker = tokio::spawn(async move { engine.handle_flow(flow.into_mitm_flow()).await });
        let proxy_worker = tokio::spawn(async move {
            let (mut stream, _) = proxy_listener
                .accept()
                .await
                .expect("proxy connects after application bytes");
            let connect = read_http_head(&mut stream).await;
            assert!(connect.starts_with("CONNECT only-proxy-knows.invalid:443 HTTP/1.1\r\n"));
            assert!(!connect.contains("198.18.0.1"));
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .expect("CONNECT accepts");
            assert!(
                read_http_head(&mut stream)
                    .await
                    .starts_with("GET /reuse HTTP/1.1\r\n")
            );
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .expect("proxy responds");
            stream.shutdown().await.expect("proxy closes");
        });
        write_request(&mut connection.client, connection.flow_id).await;
        assert!(
            read_response(&mut connection.client, connection.flow_id)
                .await
                .ends_with(b"\r\n\r\nok")
        );
        proxy_worker.await.expect("proxy joins");
        worker
            .await
            .expect("MITM joins")
            .expect("configured proxy behavior is retained");
    })
    .await
    .expect("configured deferred routing completes");
}

#[test]
fn direct_failure_reason_uses_the_shared_stable_labels() {
    for (kind, reason) in [
        (io::ErrorKind::TimedOut, "timed_out"),
        (io::ErrorKind::ConnectionRefused, "connection_refused"),
        (io::ErrorKind::HostUnreachable, "host_unreachable"),
        (io::ErrorKind::NetworkUnreachable, "host_unreachable"),
        (io::ErrorKind::PermissionDenied, "connect_failed"),
    ] {
        assert_eq!(
            connection_failure_reason(&TransparentFlowError::Io {
                operation: FlowOperation::ConnectProviderTcp,
                source: io::Error::from(kind),
            }),
            reason
        );
    }
    assert_eq!(
        connection_failure_reason(&TransparentFlowError::Timeout {
            operation: FlowOperation::ConnectProviderTcp,
            timeout: Duration::from_secs(10),
        }),
        "timed_out"
    );
}

#[test]
fn preparation_failure_diagnostics_retain_original_flow_and_source_metadata() {
    let flow_id = Uuid::new_v4();
    let destination: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
    let metadata = PlatformFlowMetadata::from_parts(
        None,
        None,
        destination.into(),
        Some("api.example.test".to_owned()),
        Some(
            SourceProcess::new(
                Some(42),
                Some("claude".to_owned()),
                Some("/usr/bin/claude".to_owned()),
            )
            .with_application_id(Some("com.example.test-agent".to_owned())),
        ),
    )
    .with_flow_id(FlowId::from(flow_id));
    let error = IngressError::FramedConnect {
        flow_id,
        metadata: Box::new(metadata),
        source: TransparentFlowError::Timeout {
            operation: FlowOperation::ConnectProviderTcp,
            timeout: Duration::from_secs(10),
        },
    };
    let observation = NetworkObservation::from_ingress_error(&error, 100, 10_100)
        .expect("pre-open TCP failures remain diagnosable");
    assert_eq!(observation.flow_id, Some(flow_id));
    assert_eq!(
        observation.destination_addr.as_deref(),
        Some("[2001:db8::1]:443")
    );
    assert_eq!(
        observation.destination_host.as_deref(),
        Some("api.example.test")
    );
    assert_eq!(observation.source_pid, Some(42));
    assert_eq!(
        observation.source_executable_path.as_deref(),
        Some("/usr/bin/claude")
    );
    assert_eq!(
        observation.source_bundle_id.as_deref(),
        Some("com.example.test-agent")
    );
    assert_eq!(
        observation.operation,
        Some(FlowOperation::ConnectProviderTcp)
    );
    assert_eq!(observation.hop, NetworkHop::AbyssToProvider);
    assert_eq!(observation.stage, NetworkStage::TcpConnect);
    assert_eq!(
        observation.technical_error_code,
        Some(NetworkErrorCode::ProviderTcp)
    );
}

async fn write_request(client: &mut UnixStream, flow_id: Uuid) {
    FlowFrameCodec::write_frame(
        client,
        &FlowFrame::new(
            FlowFrameType::Data,
            FlowFrameDirection::ClientToBroker,
            flow_id,
            b"GET /reuse HTTP/1.1\r\nHost: only-proxy-knows.invalid\r\nConnection: close\r\n\r\n"
                .to_vec(),
        ),
    )
    .await
    .expect("application request writes");
}

async fn read_response(client: &mut UnixStream, flow_id: Uuid) -> Vec<u8> {
    let mut response = Vec::new();
    loop {
        let frame = FlowFrameCodec::read_frame(client)
            .await
            .expect("response frame decodes")
            .expect("response frame exists");
        assert_eq!(frame.flow_id(), flow_id);
        assert_eq!(frame.direction(), FlowFrameDirection::BrokerToClient);
        match frame.frame_type() {
            FlowFrameType::Data => response.extend_from_slice(frame.payload()),
            FlowFrameType::Close => return response,
            kind => panic!("unexpected post-readiness frame: {kind:?}"),
        }
    }
}

async fn read_http_head<S: AsyncRead + Unpin>(stream: &mut S) -> String {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        bytes.push(stream.read_u8().await.expect("HTTP head completes"));
    }
    String::from_utf8(bytes).expect("HTTP head is text")
}

fn test_mitm_engine() -> MitmEngine {
    abyss_mitm::install_default_crypto_provider();
    let key = KeyPair::generate().expect("test CA key generates");
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let certificate = params.self_signed(&key).expect("test CA signs");
    let directory = std::env::temp_dir().join(format!("abyss-readiness-ca-{}", Uuid::new_v4()));
    fs::create_dir(&directory).expect("test CA directory creates");
    fs::write(directory.join("abyss-root-ca.der"), certificate.der()).expect("test CA DER writes");
    fs::write(directory.join("abyss-root-ca.pem"), certificate.pem()).expect("test CA PEM writes");
    fs::write(directory.join("abyss-root-ca-key.pem"), key.serialize_pem())
        .expect("test CA key writes");
    let ca = abyss_mitm::CaStore::at(&directory)
        .load_required()
        .expect("test CA loads");
    fs::remove_dir_all(directory).expect("test CA fixture cleans up");
    MitmEngine::from_ca(&ca).expect("test MITM initializes")
}
