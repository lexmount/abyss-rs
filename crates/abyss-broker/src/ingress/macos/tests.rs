//! Tests for framed macOS ingress metadata and byte forwarding.

use std::{os::unix::fs::PermissionsExt as _, path::PathBuf, sync::Arc};

use tokio::{
    fs,
    io::{AsyncReadExt as _, AsyncWriteExt as _},
};

use super::framed_protocol::{
    FlowFrame, FlowFrameCodec, FlowFrameDirection, FlowFrameType, FlowOpenPayload,
    FlowTransportProtocol,
};
use super::{
    FramedFlowIo, FramedUnixIngress, FramedUnixIngressFactory, SOCKET_FILE_MODE,
    SourceProcessBuilder,
};
use crate::ingress::{Ingress as _, IngressConnection as _, IngressError, IngressFactory as _};
use crate::process_context::ProcessContextResolver;

struct FixedProcessContextResolver {
    working_directory: PathBuf,
}

impl ProcessContextResolver for FixedProcessContextResolver {
    fn working_directory(&self, _pid: Option<u32>, _pid_version: Option<u32>) -> Option<PathBuf> {
        Some(self.working_directory.clone())
    }
}

struct UnavailableProcessContextResolver;

impl ProcessContextResolver for UnavailableProcessContextResolver {
    fn working_directory(&self, _pid: Option<u32>, _pid_version: Option<u32>) -> Option<PathBuf> {
        None
    }
}

#[test]
fn source_process_builder_retains_application_identity_without_pid_or_path() {
    let payload = FlowOpenPayload {
        flow_id: uuid::Uuid::new_v4(),
        platform: "macos".to_owned(),
        protocol_name: FlowTransportProtocol::Tcp,
        connect_before_open: false,
        source_pid: None,
        source_pid_version: None,
        source_process: None,
        source_application_id: Some("com.openai.codex".to_owned()),
        destination_host: Some("api.openai.com".to_owned()),
        destination_ip: None,
        destination_port: Some(443),
        original_tls_sni: None,
    };

    let source_process = SourceProcessBuilder::from_open(&payload)
        .build(&UnavailableProcessContextResolver)
        .expect("application identity alone should retain source metadata");

    assert_eq!(source_process.pid, None);
    assert_eq!(source_process.name, None);
    assert_eq!(source_process.executable_path, None);
    assert_eq!(
        source_process.application_id.as_deref(),
        Some("com.openai.codex")
    );
}

#[tokio::test]
async fn framed_flow_io_reads_client_data_and_writes_broker_data() {
    let flow_id = uuid::Uuid::from_u128(0x1234_5678_90ab_cdef_1234_5678_90ab_cdef);
    let (client, mut broker_peer) =
        tokio::net::UnixStream::pair().expect("test UnixStream pair should create");
    let mut io = FramedFlowIo::new(client, flow_id);

    let client_frame = FlowFrame::new(
        FlowFrameType::Data,
        FlowFrameDirection::ClientToBroker,
        flow_id,
        b"GET / HTTP/1.1\r\n".to_vec(),
    );
    FlowFrameCodec::write_frame(&mut broker_peer, &client_frame)
        .await
        .expect("client data frame should write");

    let mut received = vec![0; 16];
    io.read_exact(&mut received)
        .await
        .expect("framed IO should expose client payload bytes");
    assert_eq!(received, b"GET / HTTP/1.1\r\n");

    io.write_all(b"HTTP/1.1 200 OK\r\n\r\n")
        .await
        .expect("framed IO should write broker payload bytes");
    let response_frame = FlowFrameCodec::read_frame(&mut broker_peer)
        .await
        .expect("response frame should read")
        .expect("response frame should exist");
    assert_eq!(response_frame.frame_type(), FlowFrameType::Data);
    assert_eq!(
        response_frame.direction(),
        FlowFrameDirection::BrokerToClient
    );
    assert_eq!(response_frame.flow_id(), flow_id);
    assert_eq!(response_frame.payload(), b"HTTP/1.1 200 OK\r\n\r\n");
}

#[tokio::test]
async fn framed_flow_io_shutdown_sends_complete_close_frame() {
    // Regression coverage for HTTP flows that finish immediately after a
    // response body. The MITM relay calls `shutdown()` after forwarding the
    // response; the macOS bridge must receive the response bytes and then a
    // FlowClose frame, not a bare socket EOF.
    let flow_id = uuid::Uuid::from_u128(0x1234_5678_90ab_cdef_1234_5678_90ab_cdef);
    let (client, mut broker_peer) =
        tokio::net::UnixStream::pair().expect("test UnixStream pair should create");
    let mut io = FramedFlowIo::new(client, flow_id);

    io.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        .await
        .expect("framed IO should write response data");
    io.shutdown()
        .await
        .expect("framed IO should write a close frame before shutdown");

    let response_frame = FlowFrameCodec::read_frame(&mut broker_peer)
        .await
        .expect("response frame should read")
        .expect("response frame should exist");
    assert_eq!(response_frame.frame_type(), FlowFrameType::Data);
    assert_eq!(
        response_frame.direction(),
        FlowFrameDirection::BrokerToClient
    );
    assert_eq!(
        response_frame.payload(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
    );

    // The close frame must be a real framed protocol message. If this were
    // replaced by a socket-level EOF, the Swift bridge could report
    // `unexpectedEOF` and terminate the intercepted client stream.
    let close_frame = FlowFrameCodec::read_frame(&mut broker_peer)
        .await
        .expect("close frame should read")
        .expect("close frame should exist");
    assert_eq!(close_frame.frame_type(), FlowFrameType::Close);
    assert_eq!(close_frame.direction(), FlowFrameDirection::BrokerToClient);
    assert_eq!(close_frame.flow_id(), flow_id);
}

fn test_network() -> crate::network_config::NetworkRuntime {
    crate::network_config::NetworkRuntime::new(None, None)
        .expect("test network policy should be valid")
}

#[tokio::test]
async fn ingress_accepts_flow_open_metadata() {
    let socket_path = std::env::temp_dir().join(format!(
        "abyss-framed-ingress-{}-{}.sock",
        std::process::id(),
        rand::random::<u64>()
    ));
    let mut ingress = FramedUnixIngress::bind_with_resolver(
        socket_path.clone(),
        Arc::new(FixedProcessContextResolver {
            working_directory: PathBuf::from("/tmp/abyss-project"),
        }),
        test_network(),
    )
    .await
    .expect("framed ingress should start");
    assert_eq!(ingress.socket_path(), socket_path.as_path());

    let flow_id = uuid::Uuid::from_u128(0x1234_5678_90ab_cdef_1234_5678_90ab_cdef);
    let accept_task = tokio::spawn(async move {
        let accepted = ingress.accept().await?;
        let flow = accepted.into_flow().await?;
        Ok::<_, IngressError>((flow, ingress))
    });
    let mut client = tokio::net::UnixStream::connect(&socket_path)
        .await
        .expect("client should connect to framed ingress");
    let payload = format!(
        r#"{{
            "flow_id": "{flow_id}",
            "platform": "macos",
            "protocol": "tcp",
            "source_pid": 123,
            "source_pid_version": 7,
            "source_process": "/usr/bin/curl",
            "source_application_id": "com.apple.curl",
            "destination_host": null,
            "destination_ip": "127.0.0.1",
            "destination_port": 443,
            "original_tls_sni": null
        }}"#
    );
    let open = FlowFrame::new(
        FlowFrameType::Open,
        FlowFrameDirection::None,
        flow_id,
        payload.into_bytes(),
    );
    FlowFrameCodec::write_frame(&mut client, &open)
        .await
        .expect("FlowOpen should write");

    let (flow, ingress) = accept_task
        .await
        .expect("accept task should join")
        .expect("FlowOpen should produce PlatformFlow");
    assert_eq!(
        flow.original_destination().socket_addr(),
        Some(
            crate::connection::OriginalDestination {
                ip: "127.0.0.1".parse().expect("test IP address should parse"),
                port: 443,
            }
            .socket_addr()
        )
    );
    assert_eq!(flow.peer_addr(), None);
    assert_eq!(flow.local_addr(), None);
    let source_process = flow
        .source_process()
        .expect("FlowOpen source process should be retained");
    assert_eq!(source_process.pid, Some(123));
    assert_eq!(source_process.pid_version, Some(7));
    assert_eq!(
        source_process.application_id.as_deref(),
        Some("com.apple.curl")
    );
    assert_eq!(
        source_process.working_directory.as_deref(),
        Some("/tmp/abyss-project")
    );
    assert_eq!(
        flow.into_mitm_flow().flow_id(),
        &abyss_mitm::FlowId::from(flow_id)
    );
    ingress.shutdown().await;
}

#[tokio::test]
async fn ingress_rebinds_socket_left_by_an_unordered_shutdown() {
    let socket_path = std::env::temp_dir().join(format!(
        "abyss-framed-stale-{}-{}.sock",
        std::process::id(),
        rand::random::<u64>()
    ));
    let stale_listener =
        tokio::net::UnixListener::bind(&socket_path).expect("stale test listener should bind");
    drop(stale_listener);
    assert!(
        fs::try_exists(&socket_path)
            .await
            .expect("stale socket path should be queryable"),
        "dropping a Unix listener should leave its socket path behind"
    );

    let ingress = FramedUnixIngress::bind_with_resolver(
        socket_path.clone(),
        Arc::new(FixedProcessContextResolver {
            working_directory: PathBuf::from("/tmp/abyss-project"),
        }),
        test_network(),
    )
    .await
    .expect("framed ingress should replace a stale socket");
    assert_eq!(ingress.socket_path(), socket_path.as_path());

    ingress.shutdown().await;
    assert!(
        !fs::try_exists(socket_path)
            .await
            .expect("socket path should be queryable after shutdown"),
        "orderly shutdown should remove the replacement socket"
    );
}

#[tokio::test]
async fn dropping_ingress_removes_socket_file() {
    let socket_path = std::env::temp_dir().join(format!(
        "abyss-framed-drop-{}-{}.sock",
        std::process::id(),
        rand::random::<u64>()
    ));
    let ingress = FramedUnixIngress::bind_with_resolver(
        socket_path.clone(),
        Arc::new(FixedProcessContextResolver {
            working_directory: PathBuf::from("/tmp/abyss-project"),
        }),
        test_network(),
    )
    .await
    .expect("framed ingress should start");
    assert!(
        fs::try_exists(&socket_path)
            .await
            .expect("socket path should be queryable before drop"),
        "bound ingress should create its socket file"
    );

    drop(ingress);

    assert!(
        !fs::try_exists(socket_path)
            .await
            .expect("socket path should be queryable after drop"),
        "dropping an ingress should remove its socket file"
    );
}

#[tokio::test]
async fn ingress_sets_socket_permissions_for_platform_extension() {
    let socket_path = PathBuf::from(format!(
        "/tmp/abyss-fi-mode-{}-{}.sock",
        std::process::id(),
        rand::random::<u64>()
    ));
    let started = FramedUnixIngressFactory::new(socket_path.clone(), test_network())
        .start()
        .await
        .expect("framed ingress should start");

    let mode = fs::metadata(&socket_path)
        .await
        .expect("framed ingress socket should exist")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, SOCKET_FILE_MODE);

    let (ingress, _status) = started.into_parts();
    ingress.shutdown().await;
}
