//! Real-socket contract tests for next-hop negotiation and stream boundaries.

use std::{net::SocketAddr, time::Duration};

use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpListener,
    task::JoinHandle,
    time::{sleep, timeout},
};

use super::{HttpConnectProxy, ProxyConnectStage, UpstreamProxyConfig, UpstreamProxyError};
use crate::TargetAuthority;

struct ProxyFixture {
    connector: HttpConnectProxy,
    task: JoinHandle<Vec<u8>>,
}

impl ProxyFixture {
    async fn start(response: Vec<u8>, delay: Duration) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
        let config = config(listener.local_addr().expect("proxy address"));
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept proxy client");
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(stream.read_u8().await.expect("read CONNECT"));
            }
            sleep(delay).await;
            if stream.write_all(&response).await.is_ok()
                && response.starts_with(b"HTTP/1.1 2")
                && response.windows(4).any(|bytes| bytes == b"\r\n\r\n")
            {
                let (mut reader, mut writer) = stream.split();
                let _result = tokio::io::copy(&mut reader, &mut writer).await;
            }
            request
        });
        Self {
            connector: HttpConnectProxy::new(&config).expect("valid config"),
            task,
        }
    }

    async fn connect(&self, authority: &str) -> Result<super::ConnectedTunnel, UpstreamProxyError> {
        self.connector
            .connect(
                &TargetAuthority::parse(authority).expect("target"),
                "127.0.0.1:0".parse().expect("listener"),
            )
            .await
    }
}

fn config(address: SocketAddr) -> UpstreamProxyConfig {
    UpstreamProxyConfig {
        protocol: super::UpstreamProxyProtocol::HttpConnect,
        endpoint: format!("http://{address}"),
        connect_timeout_ms: 1000,
        handshake_timeout_ms: 1000,
    }
}

#[test]
fn rejects_unsupported_and_ambiguous_configuration() {
    let mut candidate = config("127.0.0.1:3128".parse().expect("endpoint"));
    for endpoint in [
        "https://proxy.test:443",
        "socks5://proxy.test:1080",
        "http://proxy.test",
        "http://proxy.test:0",
        "http://proxy.test:65536",
        "http://user:secret@proxy.test:3128",
        "http://proxy.test:3128/path",
        "http://proxy.test:3128?secret=x",
        "http://proxy.test:3128#x",
        "http://proxy.test:3128//",
        "http://bad host:3128",
    ] {
        candidate.endpoint = endpoint.to_owned();
        let error = candidate
            .validate()
            .expect_err("invalid endpoint must fail");
        assert!(
            !error.to_string().contains("secret"),
            "errors must not echo URL secrets"
        );
    }
    candidate.endpoint = "http://proxy.test:3128/".to_owned();
    candidate.validate().expect("trailing slash is allowed");
    for invalid in [0, 120_001, u64::MAX] {
        candidate.connect_timeout_ms = invalid;
        assert!(
            candidate.validate().is_err(),
            "connection timeout must be bounded"
        );
        candidate.connect_timeout_ms = 1000;
        candidate.handshake_timeout_ms = invalid;
        assert!(
            candidate.validate().is_err(),
            "handshake timeout must be bounded"
        );
        candidate.handshake_timeout_ms = 1000;
    }
}

#[test]
fn configuration_rejects_unknown_protocols_and_fields() {
    for json in [
        r#"{"protocol":"socks5","endpoint":"http://localhost:3128"}"#,
        r#"{"protocol":"http_connect","endpoint":"http://localhost:3128","ca_file":"private.pem"}"#,
        r#"{"protocol":"http_connect","endpoint":"http://localhost:3128","credentials_file":"secret"}"#,
    ] {
        assert!(
            serde_json::from_str::<UpstreamProxyConfig>(json).is_err(),
            "unsupported config must fail"
        );
    }
    let parsed: UpstreamProxyConfig =
        serde_json::from_str(r#"{"protocol":"http_connect","endpoint":"http://localhost:3128"}"#)
            .expect("minimal config");
    assert_eq!(parsed.connect_timeout_ms, 10_000, "default connect budget");
    assert_eq!(
        parsed.handshake_timeout_ms, 10_000,
        "default handshake budget"
    );
}

#[tokio::test]
async fn preserves_domain_and_coalesced_tunnel_bytes_without_resolving_target() {
    let fixture = ProxyFixture::start(
        b"HTTP/1.1 201 Tunnel ready\r\nContent-Length: 9999\r\nTransfer-Encoding: chunked\r\n\r\nprefix".to_vec(),
        Duration::ZERO,
    ).await;
    let mut tunnel = fixture
        .connect("only-proxy-knows.invalid:443")
        .await
        .expect("domain tunnel");
    let mut prefix = [0; 6];
    tunnel
        .stream
        .read_exact(&mut prefix)
        .await
        .expect("preserved prefix");
    assert_eq!(
        &prefix, b"prefix",
        "CONNECT body framing must not consume tunnel data"
    );
    tunnel
        .stream
        .write_all(b"target TLS bytes")
        .await
        .expect("write tunnel");
    let mut echoed = [0; 16];
    tunnel
        .stream
        .read_exact(&mut echoed)
        .await
        .expect("read tunnel");
    assert_eq!(
        &echoed, b"target TLS bytes",
        "tunnel must remain bidirectional"
    );
    drop(tunnel);
    let request = fixture.task.await.expect("proxy completed");
    assert_eq!(request, b"CONNECT only-proxy-knows.invalid:443 HTTP/1.1\r\nHost: only-proxy-knows.invalid:443\r\n\r\n",
        "only authority and Host belong in CONNECT");
}

#[tokio::test]
async fn accepts_all_success_statuses_and_bracketed_ipv6() {
    for status in 200_u16..300 {
        let fixture = ProxyFixture::start(
            format!("HTTP/1.1 {status} Custom\r\nx-extra: value\r\n\r\n").into_bytes(),
            Duration::ZERO,
        )
        .await;
        let tunnel = fixture
            .connect("[2001:db8::1]:443")
            .await
            .expect("every 2xx opens a tunnel");
        drop(tunnel);
        let request = fixture.task.await.expect("proxy completed");
        assert!(
            request.starts_with(b"CONNECT [2001:db8::1]:443 HTTP/1.1"),
            "IPv6 authority must be bracketed"
        );
    }
}

#[tokio::test]
async fn rejects_statuses_without_forwarding_proxy_response_details() {
    for status in [301, 403, 405, 407, 502, 504] {
        let fixture = ProxyFixture::start(format!("HTTP/1.1 {status} secret reason\r\nProxy-Authenticate: secret challenge\r\n\r\nsecret body").into_bytes(), Duration::ZERO).await;
        let error = fixture
            .connect("example.invalid:443")
            .await
            .err()
            .expect("reject non-2xx");
        assert!(
            matches!(error, UpstreamProxyError::Rejected { status: actual } if actual == status),
            "preserve only status"
        );
        assert!(
            !error.to_string().contains("secret"),
            "do not expose proxy response content"
        );
        fixture.task.await.expect("proxy completed");
    }
}

#[tokio::test]
async fn bounds_headers_informational_responses_and_eof() {
    let oversized = format!(
        "HTTP/1.1 200 OK\r\nX-Large: {}\r\n\r\n",
        "a".repeat(16 * 1024)
    );
    let too_many = format!("HTTP/1.1 200 OK\r\n{}\r\n", "X: a\r\n".repeat(65));
    let informational = "HTTP/1.1 100 Continue\r\n\r\n".repeat(9);
    for response in [
        "garbage".to_owned(),
        "HTTP/1.1 200".to_owned(),
        "HTTP/1.1 101 Switching Protocols\r\n\r\n".to_owned(),
        oversized,
        too_many,
        informational,
    ] {
        let fixture = ProxyFixture::start(response.into_bytes(), Duration::ZERO).await;
        let error = fixture
            .connect("example.invalid:443")
            .await
            .err()
            .expect("invalid response must fail");
        assert!(
            matches!(error, UpstreamProxyError::Protocol { .. }),
            "protocol failure expected"
        );
        fixture.task.abort();
    }
}

#[tokio::test]
async fn consumes_informational_headers_before_success() {
    let fixture = ProxyFixture::start(
        b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 204 Ready\r\n\r\nhello".to_vec(),
        Duration::ZERO,
    )
    .await;
    let mut tunnel = fixture
        .connect("example.invalid:443")
        .await
        .expect("informational then success");
    let mut prefix = [0; 5];
    tunnel
        .stream
        .read_exact(&mut prefix)
        .await
        .expect("tunnel prefix");
    assert_eq!(&prefix, b"hello", "preserve bytes after final response");
    drop(tunnel);
    fixture.task.await.expect("proxy completed");
}

#[tokio::test]
async fn handshake_deadline_does_not_extend_with_partial_progress() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
    let mut settings = config(listener.local_addr().expect("address"));
    settings.handshake_timeout_ms = 50;
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nX-Slow: ")
            .await
            .expect("partial headers");
        loop {
            if stream.write_all(b"a").await.is_err() {
                break;
            }
            sleep(Duration::from_millis(15)).await;
        }
    });
    let result = timeout(
        Duration::from_secs(2),
        HttpConnectProxy::new(&settings).expect("config").connect(
            &TargetAuthority::parse("target.invalid:443").expect("target"),
            "127.0.0.1:0".parse().expect("listener"),
        ),
    )
    .await
    .expect("bounded operation");
    assert!(
        matches!(
            result,
            Err(UpstreamProxyError::Timeout {
                stage: ProxyConnectStage::Handshake,
                ..
            })
        ),
        "one deadline covers every fragment"
    );
    task.abort();
}

#[tokio::test]
async fn rejects_proxy_listener_loop_before_connecting() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let address = listener.local_addr().expect("address");
    let proxy = HttpConnectProxy::new(&config(address)).expect("config");
    let result = proxy
        .connect(
            &TargetAuthority::parse("target.invalid:443").expect("target"),
            address,
        )
        .await;
    assert!(
        matches!(result, Err(UpstreamProxyError::Loop { .. })),
        "proxy must not dial its own ingress"
    );
    assert!(
        timeout(Duration::from_millis(25), listener.accept())
            .await
            .is_err(),
        "no TCP connection on loop"
    );
}

#[tokio::test]
async fn failed_proxy_does_not_connect_to_reachable_target() {
    let origin = TcpListener::bind("127.0.0.1:0").await.expect("origin");
    let target = origin.local_addr().expect("origin address").to_string();
    let fixture =
        ProxyFixture::start(b"HTTP/1.1 403 Forbidden\r\n\r\n".to_vec(), Duration::ZERO).await;
    assert!(
        fixture.connect(&target).await.is_err(),
        "proxy failure must fail the request"
    );
    assert!(
        timeout(Duration::from_millis(25), origin.accept())
            .await
            .is_err(),
        "no direct fallback"
    );
    fixture.task.await.expect("proxy completed");
}

#[tokio::test]
async fn resolves_proxy_hostname_and_preserves_tunnel_half_close() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
    let address = listener.local_addr().expect("proxy address");
    let mut settings = config(address);
    settings.endpoint = format!("http://localhost:{}", address.port());
    let peer = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept proxy client");
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            request.push(stream.read_u8().await.expect("read CONNECT"));
        }
        assert!(request.starts_with(b"CONNECT target.invalid:443 HTTP/1.1\r\n"));
        // Fragment a valid response to exercise incremental header parsing.
        for fragment in [b"HTTP/1.1 200".as_slice(), b" Ready\r\n", b"\r\n"] {
            stream.write_all(fragment).await.expect("write response");
            sleep(Duration::from_millis(5)).await;
        }
        let mut upload = Vec::new();
        stream.read_to_end(&mut upload).await.expect("read to FIN");
        assert_eq!(upload, b"request payload");
        stream
            .write_all(b"final reply")
            .await
            .expect("reply after FIN");
        stream.shutdown().await.expect("close reply direction");
    });
    let mut tunnel = HttpConnectProxy::new(&settings)
        .expect("proxy hostname config")
        .connect(
            &TargetAuthority::parse("target.invalid:443").expect("logical target"),
            "127.0.0.1:0".parse().expect("broker listener"),
        )
        .await
        .expect("resolve only proxy hostname");
    assert_eq!(tunnel.proxy_peer, address);
    tunnel
        .stream
        .write_all(b"request payload")
        .await
        .expect("upload");
    tunnel.stream.shutdown().await.expect("half-close upload");
    let mut reply = Vec::new();
    timeout(
        Duration::from_secs(2),
        tunnel.stream.read_to_end(&mut reply),
    )
    .await
    .expect("reply must not stall after half-close")
    .expect("read reply");
    assert_eq!(reply, b"final reply");
    peer.await.expect("proxy completed");
}

#[tokio::test]
async fn cancelling_handshake_closes_proxy_socket() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
    let proxy =
        HttpConnectProxy::new(&config(listener.local_addr().expect("address"))).expect("config");
    let worker = tokio::spawn(async move {
        proxy
            .connect(
                &TargetAuthority::parse("target.invalid:443").expect("target"),
                "127.0.0.1:0".parse().expect("broker listener"),
            )
            .await
    });
    let (mut stream, _) = timeout(Duration::from_secs(2), listener.accept())
        .await
        .expect("bounded accept")
        .expect("accept proxy client");
    let mut request = Vec::new();
    timeout(Duration::from_secs(2), async {
        while !request.ends_with(b"\r\n\r\n") {
            request.push(stream.read_u8().await.expect("read CONNECT"));
        }
    })
    .await
    .expect("bounded CONNECT write");
    worker.abort();
    assert!(worker.await.is_err(), "connector task should be cancelled");
    let mut bytes = [0; 1];
    let count = timeout(Duration::from_secs(2), stream.read(&mut bytes))
        .await
        .expect("cancelled connector must release its socket")
        .expect("read EOF");
    assert_eq!(count, 0);
}

#[tokio::test]
async fn connection_refusal_remains_a_proxy_tcp_failure() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve port");
    let proxy =
        HttpConnectProxy::new(&config(listener.local_addr().expect("address"))).expect("config");
    drop(listener);
    let result = proxy
        .connect(
            &TargetAuthority::parse("target.invalid:443").expect("target"),
            "127.0.0.1:0".parse().expect("broker listener"),
        )
        .await;
    assert!(matches!(
        result,
        Err(UpstreamProxyError::Io {
            stage: ProxyConnectStage::ConnectProxy,
            ..
        })
    ));
}
