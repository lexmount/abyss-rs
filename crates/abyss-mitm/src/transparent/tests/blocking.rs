//! Transport-level rejection and original-byte forwarding across real local sockets.

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpListener,
};

use crate::{
    AcceptedTcpFlow, LocalRejection, MitmEngine, OriginalDestination, RequestForwardingControl,
    RequestView, TlsDecryptionPolicy, TransparentFlowError,
};

struct DecisionControl {
    reject: bool,
    calls: Arc<AtomicUsize>,
}

impl RequestForwardingControl for DecisionControl {
    type Plan = ();
    fn plan(&self) -> Option<Self::Plan> {
        Some(())
    }
    fn before_forward(
        &self,
        (): (),
        request: RequestView<'_>,
    ) -> impl std::future::Future<Output = Result<(), LocalRejection>> + Send {
        self.calls.fetch_add(1, Ordering::Relaxed);
        assert_eq!(
            request.body.json().unwrap()["input"],
            "secret",
            "inspection must see a complete decoded request"
        );
        std::future::ready(if self.reject {
            Err(LocalRejection::new(
                http::StatusCode::FORBIDDEN,
                "agent_request_blocked",
                "test policy",
                request.flow.flow_id.to_string(),
            ))
        } else {
            Ok(())
        })
    }
}

async fn exchange(
    wire: Vec<u8>,
    reject: bool,
    limit: usize,
) -> (
    Vec<u8>,
    Vec<u8>,
    usize,
    Result<crate::TransparentFlowOutcome, TransparentFlowError>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let destination = listener.local_addr().unwrap();
    let (mut client, server) = super::connected_pair().await;
    let calls = Arc::new(AtomicUsize::new(0));
    let control = DecisionControl {
        reject,
        calls: calls.clone(),
    };
    let engine = MitmEngine::from_ca(&super::test_ca())
        .unwrap()
        .with_max_http1_body_bytes(limit);
    let flow = AcceptedTcpFlow::new(
        server,
        SocketAddr::from(([127, 0, 0, 1], 50000)),
        SocketAddr::from(([127, 0, 0, 1], 18090)),
        OriginalDestination::from(destination),
    );
    let relay = tokio::spawn(async move { engine.handle_flow_with_control(flow, &control).await });
    let wire_length = wire.len();
    let provider = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut received = Vec::new();
        if reject || limit < 20 {
            stream.read_to_end(&mut received).await.unwrap();
        } else {
            let head = super::read_http_head(&mut stream).await;
            received.extend_from_slice(head.as_bytes());
            let length = wire_length.saturating_sub(head.len());
            let mut body = vec![0; length];
            stream.read_exact(&mut body).await.unwrap();
            received.extend_from_slice(&body);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
        }
        received
    });
    client.write_all(&wire).await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    let result = relay.await.unwrap();
    (
        response,
        provider.await.unwrap(),
        calls.load(Ordering::Relaxed),
        result,
    )
}

#[tokio::test]
async fn complete_body_is_checked_before_any_provider_header_or_body_byte() {
    for framing in [
        "Content-Length: 18\r\n\r\n{\"input\":\"secret\"}",
        "Transfer-Encoding: chunked\r\n\r\n12\r\n{\"input\":\"secret\"}\r\n0\r\n\r\n",
    ] {
        let wire =
            format!("POST /v1/responses HTTP/1.1\r\nHost: example.test\r\n{framing}").into_bytes();
        let (response, provider, calls, result) = exchange(wire, true, 1024).await;
        assert!(
            response.starts_with(b"HTTP/1.1 403"),
            "must identify a local HTTP rejection"
        );
        assert!(
            String::from_utf8(response)
                .unwrap()
                .contains("abyss-broker"),
            "local rejection must identify the broker"
        );
        assert!(
            provider.is_empty(),
            "rejected headers and body must never reach provider"
        );
        assert_eq!(calls, 1);
        assert!(
            matches!(result, Err(TransparentFlowError::Rejected(_))),
            "typed rejection must survive the transport boundary"
        );
    }
}

#[tokio::test]
async fn allow_reuses_original_chunk_framing() {
    let wire = b"POST /v1/responses HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n12\r\n{\"input\":\"secret\"}\r\n0\r\n\r\n".to_vec();
    let (response, provider, calls, result) = exchange(wire.clone(), false, 1024).await;
    assert!(result.is_ok(), "allowed request must complete");
    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "provider response must be relayed"
    );
    assert_eq!(provider, wire, "allowed chunk framing must be preserved");
    assert_eq!(calls, 1);
}

#[tokio::test]
async fn incomplete_inspection_never_invokes_a_plugin_with_a_prefix() {
    let wire = b"POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 18\r\n\r\n{\"input\":\"secret\"}".to_vec();
    let (response, provider, calls, result) = exchange(wire, false, 8).await;
    assert!(
        response.starts_with(b"HTTP/1.1 413"),
        "inspection must reject oversized bodies"
    );
    assert!(
        provider.is_empty(),
        "oversized requests must not reach provider"
    );
    assert_eq!(calls, 0);
    assert!(
        matches!(result, Err(TransparentFlowError::Rejected(_))),
        "oversize must be a local rejection"
    );
}

#[test]
fn block_obeys_order_and_missing_source_metadata() {
    let policy: TlsDecryptionPolicy = serde_json::from_value(serde_json::json!({
        "default_action":"block", "missing_sni_action":"block", "rules":[
            {"id":"process", "action":"block", "process_names":["agent"]},
            {"id":"allowed", "action":"intercept", "destination_hosts":["example.test"]},
            {"id":"blocked", "action":"block", "destination_hosts":["example.test"]}
        ]
    }))
    .unwrap();
    policy.validate().unwrap();
    assert_eq!(
        policy.decide(Some("example.test")).matched_rule_id(),
        Some("allowed")
    );
    assert_eq!(
        policy.decide(None).action(),
        crate::TlsDecryptionAction::Block
    );
    assert!(
        policy.requires_sni_peek(),
        "default block must not take unconditional intercept shortcut"
    );
}

#[test]
fn executable_selector_requires_matching_native_absolute_path() {
    let path = std::env::current_exe()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let policy: TlsDecryptionPolicy = serde_json::from_value(serde_json::json!({
        "rules":[{"id":"executable", "action":"block", "executable_paths":[path]}]
    }))
    .unwrap();
    policy.validate().unwrap();
    let process = crate::SourceProcess::new(None, None, Some(path));
    assert_eq!(
        policy
            .decide(crate::TlsDecryptionContext::new(None, Some(&process)))
            .action(),
        crate::TlsDecryptionAction::Block
    );
    assert_eq!(
        policy.decide(None).action(),
        crate::TlsDecryptionAction::Passthrough
    );
    let invalid: TlsDecryptionPolicy = serde_json::from_value(serde_json::json!({
        "rules":[{"id":"relative", "action":"block", "executable_paths":["bin/agent"]}]
    }))
    .unwrap();
    assert!(
        invalid.validate().is_err(),
        "relative executable selectors must be rejected"
    );
}

#[tokio::test]
async fn network_block_closes_tls_without_provider_connection_or_client_mitm() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (client, server) = super::connected_pair().await;
    let ca = super::test_ca();
    let engine = MitmEngine::from_ca(&ca)
        .unwrap()
        .with_tls_decryption_policy(
            serde_json::from_value(serde_json::json!({"default_action":"block"})).unwrap(),
        )
        .unwrap();
    let flow = AcceptedTcpFlow::new(
        server,
        "127.0.0.1:50001".parse().unwrap(),
        "127.0.0.1:18091".parse().unwrap(),
        listener.local_addr().unwrap().into(),
    );
    let relay = tokio::spawn(async move { engine.handle_flow(flow).await });
    let result = tokio_rustls::TlsConnector::from(super::test_client_config_trusting(&ca))
        .connect(
            tokio_rustls::rustls::pki_types::ServerName::try_from("example.test").unwrap(),
            client,
        )
        .await;
    assert!(
        result.is_err(),
        "network block must not accept client TLS just to send HTTP"
    );
    let Err(TransparentFlowError::Rejected(rejection)) = relay.await.unwrap() else {
        panic!("network block should retain its reason");
    };
    assert_eq!(rejection.code, "network_blocked");
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(30), listener.accept())
            .await
            .is_err(),
        "blocked transparent TLS must not connect to the provider"
    );
}

#[tokio::test]
async fn provider_tls_completes_before_request_inspection_but_receives_no_rejected_http() {
    let ca = super::test_ca();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let destination = listener.local_addr().unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(
        crate::tls::MitmTlsAuthority::from_ca(&ca)
            .unwrap()
            .server_config_for_sni("example.test")
            .await
            .unwrap(),
    );
    let (ready, handshake) = tokio::sync::oneshot::channel();
    let provider = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(stream).await.unwrap();
        ready.send(()).unwrap();
        let mut bytes = Vec::new();
        let _closed = stream.read_to_end(&mut bytes).await;
        bytes
    });
    let (client, server) = super::connected_pair().await;
    let flow = AcceptedTcpFlow::new(
        server,
        "127.0.0.1:50001".parse().unwrap(),
        "127.0.0.1:18091".parse().unwrap(),
        destination.into(),
    );
    let engine = super::test_mitm_engine_trusting(&ca)
        .with_tls_decryption_policy(
            serde_json::from_value(serde_json::json!({"default_action":"intercept"})).unwrap(),
        )
        .unwrap();
    let control = DecisionControl {
        reject: true,
        calls: Arc::new(AtomicUsize::new(0)),
    };
    let relay = tokio::spawn(async move { engine.handle_flow_with_control(flow, &control).await });
    let mut client = tokio_rustls::TlsConnector::from(super::test_client_config_trusting(&ca))
        .connect(
            tokio_rustls::rustls::pki_types::ServerName::try_from("example.test").unwrap(),
            client,
        )
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), handshake)
        .await
        .expect("provider TLS must finish before the client sends HTTP")
        .unwrap();
    client.write_all(b"POST /v1/responses HTTP/1.1\r\nHost: example.test\r\nContent-Length: 18\r\n\r\n{\"input\":\"secret\"}").await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    assert!(
        response.starts_with(b"HTTP/1.1 403"),
        "decrypted clients must receive the explicit block error"
    );
    assert!(
        matches!(relay.await.unwrap(), Err(TransparentFlowError::Rejected(_))),
        "request must be rejected after TLS setup"
    );
    assert!(
        provider.await.unwrap().is_empty(),
        "provider TLS must carry no rejected HTTP bytes"
    );
}
