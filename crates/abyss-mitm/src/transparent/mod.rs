//! Transparent proxy flow orchestration.
//!
//! A platform adapter redirects a TCP connection to the broker and provides the
//! original destination. This module coordinates the protocol pipeline after
//! that handoff: detect plain HTTP vs TLS, terminate TLS when needed, decode the
//! first HTTP/1 request, connect to the original upstream endpoint, and relay
//! bytes.

mod accepted_flow;
mod client_hello;
mod decrypt_policy;
mod display;
mod engine;
mod flow_id;
mod hook;
mod io;
mod passthrough;
mod plain_http;
mod protocol;
mod relay;
mod tls;
mod tls_flow;
mod tls_http;
mod types;
mod upstream;
mod utils;
mod websocket;

pub use self::accepted_flow::AcceptedTcpFlow;
pub use self::decrypt_policy::{
    TlsDecryptionAction, TlsDecryptionContext, TlsDecryptionDecision, TlsDecryptionPolicy,
    TlsDecryptionPolicyError, TlsDecryptionRule, ValidatedTlsDecryptionPolicy,
};
pub use self::display::{
    CapturedBodyPlaintextDisplay, HttpHeadersDisplay, HttpRequestHeadDisplay,
    HttpResponseHeadDisplay,
};
pub use self::engine::{MitmEngine, MitmTimeouts};
pub use self::flow_id::FlowId;
pub use self::hook::{
    CapturedBody, FlowContext, HookError, HookFuture, HookResult, HttpExchange, MitmHook,
    SourceProcess, WebSocketDirection, WebSocketMessage,
};
pub use self::io::{BoxedDuplexStream, DuplexStream, TrafficDirection, TrafficObserver};
pub use self::types::{
    FlowIngress, FlowOperation, InterceptedHttpOutcome, OriginalDestination, TlsErrorSide,
    TransparentFlowError, TransparentFlowOutcome, TransparentFlowSource,
    TransparentPassthroughOutcome, TransparentPassthroughProtocol, TransparentProtocol,
};

#[cfg(test)]
mod tests {
    use std::{
        future,
        net::{Ipv4Addr, SocketAddr},
        sync::Arc,
        time::Duration,
    };

    use futures_util::{SinkExt as _, StreamExt as _};
    use parking_lot::Mutex;
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
        KeyUsagePurpose,
    };
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::{TcpListener, TcpStream},
        time::{sleep, timeout},
    };
    use tokio_rustls::{
        TlsAcceptor, TlsConnector,
        rustls::{
            ClientConfig, RootCertStore,
            pki_types::{CertificateDer, ServerName},
        },
    };
    use tokio_tungstenite::{
        WebSocketStream,
        tungstenite::{
            Message,
            protocol::{Role, WebSocketConfig},
        },
    };

    use super::{
        AcceptedTcpFlow, FlowId, HookFuture, HttpExchange, InterceptedHttpOutcome, MitmEngine,
        MitmHook, MitmTimeouts, OriginalDestination, SourceProcess, TlsDecryptionAction,
        TlsDecryptionPolicy, TlsDecryptionRule, TransparentFlowOutcome,
        TransparentPassthroughOutcome, TransparentPassthroughProtocol, TransparentProtocol,
        WebSocketMessage, accepted_flow::UpstreamConnection, protocol::DetectedProtocol,
        upstream::connect_upstream_with_observer,
    };
    use crate::tls::MitmTlsAuthority;

    #[tokio::test]
    async fn detects_plain_http() {
        let (client, server) = connected_pair().await;
        client
            .writable()
            .await
            .expect("test client should become writable");
        client
            .try_write(b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
            .expect("test client should write HTTP preface");

        let flow = AcceptedTcpFlow::new(
            server,
            SocketAddr::from(([127, 0, 0, 1], 41000)),
            SocketAddr::from(([127, 0, 0, 1], 41001)),
            OriginalDestination {
                ip: Ipv4Addr::LOCALHOST.into(),
                port: 80,
            },
        );
        let detected = DetectedProtocol::detect(flow, MitmTimeouts::default().protocol_detection)
            .await
            .expect("HTTP protocol should be detected");

        assert!(
            matches!(
                detected.protocol(),
                super::protocol::DetectedProtocol::PlainHttp
            ),
            "HTTP request preface should be classified as plain HTTP"
        );
    }

    #[tokio::test]
    async fn client_tls_handshake_obeys_timeout_budget() {
        let (mut client, server) = connected_pair().await;
        client
            .write_all(&[0x16, 0x03])
            .await
            .expect("partial TLS prefix should write");
        let flow = AcceptedTcpFlow::new(
            server,
            SocketAddr::from(([127, 0, 0, 1], 41000)),
            SocketAddr::from(([127, 0, 0, 1], 41001)),
            OriginalDestination {
                ip: Ipv4Addr::LOCALHOST.into(),
                port: 443,
            },
        );
        let mut mitm = MitmEngine::from_ca(&test_ca())
            .expect("test CA should build MITM engine")
            .with_tls_decryption_policy(TlsDecryptionPolicy {
                default_action: TlsDecryptionAction::Intercept,
                missing_sni_action: None,
                rules: vec![TlsDecryptionRule {
                    id: "passthrough-example".to_owned(),
                    enabled: true,
                    action: TlsDecryptionAction::Passthrough,
                    process_names: Vec::new(),
                    application_ids: Vec::new(),
                    destination_hosts: vec!["passthrough.example.test".to_owned()],
                }],
            })
            .expect("intercept policy should validate");
        mitm.timeouts.client_tls_handshake = Duration::from_millis(25);

        let error = mitm
            .handle_flow(flow)
            .await
            .expect_err("stalled client TLS handshake should time out");

        assert!(matches!(
            error,
            super::TransparentFlowError::Timeout {
                operation: super::FlowOperation::ReadAgentTlsClientHello,
                ..
            }
        ));
        drop(client);
    }

    #[tokio::test]
    async fn handles_plain_http_flow_against_original_destination() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test upstream should bind");
        let upstream_addr = upstream_listener
            .local_addr()
            .expect("test upstream should expose listen address");
        let upstream = tokio::spawn(async move {
            let (mut stream, _peer_addr) = upstream_listener
                .accept()
                .await
                .expect("test upstream should accept one connection");
            let mut request = [0_u8; 1024];
            let read_len = stream
                .read(&mut request)
                .await
                .expect("test upstream should read request");
            assert!(
                request[..read_len].starts_with(b"GET /hello HTTP/1.1"),
                "upstream should receive the decoded request preface"
            );
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .expect("test upstream response should write");
        });

        let (mut client, server) = connected_pair().await;
        let flow = AcceptedTcpFlow::new(
            server,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 50000)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 18090)),
            OriginalDestination::from(upstream_addr),
        );
        let mitm = MitmEngine::from_ca(&test_ca()).expect("test CA should build MITM engine");
        let worker = tokio::spawn(async move { Box::pin(mitm.handle_flow(flow)).await });

        client
            .write_all(b"GET /hello HTTP/1.1\r\nHost: example.test\r\n\r\n")
            .await
            .expect("test client request should write");
        client
            .shutdown()
            .await
            .expect("test client should finish request writes");
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("test client should read upstream response");
        let outcome = expect_intercepted_outcome(
            worker
                .await
                .expect("worker should join")
                .expect("plain HTTP flow should succeed"),
        );
        upstream.await.expect("upstream worker should join");

        assert!(
            response.starts_with(b"HTTP/1.1 200 OK"),
            "client should receive upstream response"
        );
        assert_eq!(outcome.protocol, TransparentProtocol::PlainHttp);
        assert_eq!(outcome.first_request.method(), http::Method::GET);
        assert_eq!(outcome.first_request.uri(), "/hello");
        assert_eq!(outcome.first_response.status(), http::StatusCode::OK);
    }

    #[tokio::test]
    async fn injected_hook_observes_complete_plain_http_exchange() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test upstream should bind");
        let upstream_addr = upstream_listener
            .local_addr()
            .expect("test upstream should expose listen address");
        let upstream = tokio::spawn(async move {
            let (mut stream, _peer_addr) = upstream_listener
                .accept()
                .await
                .expect("test upstream should accept one connection");
            let mut request = [0_u8; 1024];
            let read_len = stream
                .read(&mut request)
                .await
                .expect("test upstream should read request");
            assert!(
                request[..read_len].starts_with(b"POST /capture HTTP/1.1"),
                "upstream should receive the captured request"
            );
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n{\"ok\":true}")
                .await
                .expect("test upstream response should write");
        });
        let hook = RecordingHook::default();
        let observations = hook.observations.clone();

        let (mut client, server) = connected_pair().await;
        let flow = AcceptedTcpFlow::new(
            server,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 50002)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 18092)),
            OriginalDestination::from(upstream_addr),
        );
        let mitm = MitmEngine::from_ca(&test_ca())
            .expect("test CA should build MITM engine")
            .with_hook(hook);
        let worker = tokio::spawn(async move { Box::pin(mitm.handle_flow(flow)).await });

        client
            .write_all(
                b"POST /capture HTTP/1.1\r\nHost: example.test\r\nContent-Length: 9\r\n\r\n{\"n\":123}",
            )
            .await
            .expect("test client request should write");
        let mut response = [0_u8; 256];
        let read_len = client
            .read(&mut response)
            .await
            .expect("test client should read response");
        assert!(
            response[..read_len].starts_with(b"HTTP/1.1 200 OK"),
            "client should receive upstream response"
        );

        let outcome = expect_intercepted_outcome(
            worker
                .await
                .expect("worker should join")
                .expect("plain HTTP flow should succeed"),
        );
        upstream.await.expect("upstream worker should join");
        let observations = wait_for_hook_observations(&observations, 1).await;

        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].method, "POST");
        assert_eq!(observations[0].request_json_n, Some(123));
        assert_eq!(observations[0].response_json_ok, Some(true));
        assert_eq!(observations[0].original_destination, upstream_addr);
        assert_eq!(
            outcome
                .first_request
                .body()
                .json()
                .and_then(|json| json.get("n"))
                .and_then(serde_json::Value::as_i64),
            Some(123)
        );
    }

    #[tokio::test]
    async fn oversized_content_length_body_is_relayed_with_truncated_capture() {
        // The body is larger than the MITM capture budget below. The upstream
        // assertion verifies the budget does not truncate a Content-Length
        // request while the hook/outcome assertions verify capture keeps only
        // the configured prefix.
        let request_body = vec![b'x'; 32];
        let mut expected_request = format!(
            "POST /large HTTP/1.1\r\nHost: example.test\r\nContent-Length: {}\r\n\r\n",
            request_body.len()
        )
        .into_bytes();
        expected_request.extend_from_slice(&request_body);

        let upstream_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test upstream should bind");
        let upstream_addr = upstream_listener
            .local_addr()
            .expect("test upstream should expose listen address");
        let upstream = tokio::spawn({
            let expected_request = expected_request.clone();
            async move {
                let (mut stream, _peer_addr) = upstream_listener
                    .accept()
                    .await
                    .expect("test upstream should accept one connection");
                let mut request = vec![0_u8; expected_request.len()];
                stream
                    .read_exact(&mut request)
                    .await
                    .expect("test upstream should read full oversized request");
                assert_eq!(
                    request, expected_request,
                    "upstream should receive the full request even when hook capture is truncated"
                );
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n{\"ok\":true}")
                    .await
                    .expect("test upstream response should write");
            }
        });
        let hook = RecordingHook::default();
        let observations = hook.observations.clone();

        let (mut client, server) = connected_pair().await;
        let flow = AcceptedTcpFlow::new(
            server,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 50006)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 18096)),
            OriginalDestination::from(upstream_addr),
        );
        let mitm = MitmEngine::from_ca(&test_ca())
            .expect("test CA should build MITM engine")
            .with_max_http1_body_bytes(16)
            .with_hook(hook);
        let worker = tokio::spawn(async move { Box::pin(mitm.handle_flow(flow)).await });

        client
            .write_all(&expected_request)
            .await
            .expect("test client oversized request should write");
        let mut response = [0_u8; 256];
        let read_len = client
            .read(&mut response)
            .await
            .expect("test client should read response");
        assert!(
            response[..read_len].starts_with(b"HTTP/1.1 200 OK"),
            "client should receive upstream response after oversized body relay"
        );

        let outcome = expect_intercepted_outcome(
            worker
                .await
                .expect("worker should join")
                .expect("plain HTTP flow should succeed"),
        );
        upstream.await.expect("upstream worker should join");
        let observations = wait_for_hook_observations(&observations, 1).await;

        assert_eq!(observations[0].method, "POST");
        assert_eq!(
            observations[0].request_body_len, 16,
            "oversized request body capture should retain the configured prefix"
        );
        assert_eq!(observations[0].response_json_ok, Some(true));
        assert_eq!(outcome.first_request.body().bytes(), vec![b'x'; 16]);
        assert!(outcome.first_request.body().truncated());
        assert_eq!(outcome.first_response.body().bytes(), b"{\"ok\":true}");
        assert!(!outcome.first_response.body().truncated());
    }

    #[tokio::test]
    async fn oversized_chunked_response_is_relayed_with_truncated_capture() {
        // Chunked bodies must be relayed in their original wire form even when
        // decoded payload capture is truncated after crossing the budget.
        let upstream_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test upstream should bind");
        let upstream_addr = upstream_listener
            .local_addr()
            .expect("test upstream should expose listen address");
        let upstream = tokio::spawn(async move {
            let (mut stream, _peer_addr) = upstream_listener
                .accept()
                .await
                .expect("test upstream should accept one connection");
            let mut request = [0_u8; 1024];
            let read_len = stream
                .read(&mut request)
                .await
                .expect("test upstream should read request");
            assert!(
                request[..read_len].starts_with(b"GET /chunked HTTP/1.1"),
                "upstream should receive the chunked response test request"
            );
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n20\r\nxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\r\n0\r\n\r\n",
                )
                .await
                .expect("test upstream chunked response should write");
        });

        let (mut client, server) = connected_pair().await;
        let flow = AcceptedTcpFlow::new(
            server,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 50007)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 18097)),
            OriginalDestination::from(upstream_addr),
        );
        let mitm = MitmEngine::from_ca(&test_ca())
            .expect("test CA should build MITM engine")
            .with_max_http1_body_bytes(16);
        let worker = tokio::spawn(async move { Box::pin(mitm.handle_flow(flow)).await });

        client
            .write_all(b"GET /chunked HTTP/1.1\r\nHost: example.test\r\n\r\n")
            .await
            .expect("test client request should write");
        client
            .shutdown()
            .await
            .expect("test client should finish request writes");
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("test client should read full oversized chunked response");

        let outcome = expect_intercepted_outcome(
            worker
                .await
                .expect("worker should join")
                .expect("plain HTTP flow should succeed"),
        );
        upstream.await.expect("upstream worker should join");

        assert!(
            response.ends_with(b"0\r\n\r\n"),
            "client should receive the complete chunked terminator"
        );
        assert!(
            response
                .windows(32)
                .any(|window| window == b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
            "client should receive the full oversized chunk payload"
        );
        assert_eq!(
            outcome.first_response.body().bytes(),
            vec![b'x'; 16],
            "oversized chunked response capture should retain the configured prefix"
        );
        assert!(outcome.first_response.body().truncated());
    }

    #[tokio::test]
    async fn oversized_eof_response_is_relayed_with_truncated_capture() {
        // EOF-delimited responses have no advertised size, so capture is
        // truncated only after the budget is crossed. Relay must continue until
        // upstream EOF so the client receives the full response.
        let upstream_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test upstream should bind");
        let upstream_addr = upstream_listener
            .local_addr()
            .expect("test upstream should expose listen address");
        let upstream = tokio::spawn(async move {
            let (mut stream, _peer_addr) = upstream_listener
                .accept()
                .await
                .expect("test upstream should accept one connection");
            let mut request = [0_u8; 1024];
            let read_len = stream
                .read(&mut request)
                .await
                .expect("test upstream should read request");
            assert!(
                request[..read_len].starts_with(b"GET /eof HTTP/1.1"),
                "upstream should receive the EOF response test request"
            );
            stream
                .write_all(b"HTTP/1.1 200 OK\r\n\r\nxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
                .await
                .expect("test upstream EOF response should write");
            stream
                .shutdown()
                .await
                .expect("test upstream should close the EOF-delimited response");
        });

        let (mut client, server) = connected_pair().await;
        let flow = AcceptedTcpFlow::new(
            server,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 50008)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 18098)),
            OriginalDestination::from(upstream_addr),
        );
        let mitm = MitmEngine::from_ca(&test_ca())
            .expect("test CA should build MITM engine")
            .with_max_http1_body_bytes(16);
        let worker = tokio::spawn(async move { Box::pin(mitm.handle_flow(flow)).await });

        client
            .write_all(b"GET /eof HTTP/1.1\r\nHost: example.test\r\n\r\n")
            .await
            .expect("test client request should write");
        client
            .shutdown()
            .await
            .expect("test client should finish request writes");
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("test client should read full oversized EOF response");

        let outcome = expect_intercepted_outcome(
            worker
                .await
                .expect("worker should join")
                .expect("plain HTTP flow should succeed"),
        );
        upstream.await.expect("upstream worker should join");

        assert!(
            response.ends_with(b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
            "client should receive the full EOF-delimited response body"
        );
        assert_eq!(
            outcome.first_response.body().bytes(),
            vec![b'x'; 16],
            "oversized EOF-delimited response capture should retain the configured prefix"
        );
        assert!(outcome.first_response.body().truncated());
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "integration-style WebSocket relay test needs client, MITM, and upstream setup in one scenario."
    )]
    async fn injected_hook_observes_websocket_messages_after_upgrade() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test upstream should bind");
        let upstream_addr = upstream_listener
            .local_addr()
            .expect("test upstream should expose listen address");
        let upstream = tokio::spawn(async move {
            let (mut stream, _peer_addr) = upstream_listener
                .accept()
                .await
                .expect("test upstream should accept one connection");
            let request_head = read_http_head(&mut stream).await;
            assert!(
                request_head.starts_with("GET /socket HTTP/1.1"),
                "upstream should receive WebSocket upgrade request"
            );
            assert!(
                !request_head
                    .to_ascii_lowercase()
                    .contains("sec-websocket-extensions"),
                "MITM should strip WebSocket compression negotiation"
            );
            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: test\r\n\r\n",
                )
                .await
                .expect("test upstream should write upgrade response");
            let mut upstream_ws = WebSocketStream::from_raw_socket(
                stream,
                Role::Server,
                Some(WebSocketConfig::default()),
            )
            .await;
            let received = upstream_ws
                .next()
                .await
                .expect("upstream should receive client WebSocket message")
                .expect("client WebSocket message should decode");
            assert_eq!(
                received.to_text().expect("client message should be text"),
                "client hello"
            );
            upstream_ws
                .send(Message::text("upstream hello"))
                .await
                .expect("upstream should send WebSocket response");
            let close = upstream_ws
                .next()
                .await
                .expect("upstream should receive client close")
                .expect("client close should decode");
            assert!(close.is_close(), "client should close the WebSocket");
        });
        let hook = WebSocketRecordingHook::default();
        let observations = hook.observations.clone();

        let (mut client, server) = connected_pair().await;
        let flow_id = FlowId::generate();
        let flow = AcceptedTcpFlow::new(
            server,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 50003)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 18093)),
            OriginalDestination::from(upstream_addr),
        )
        .with_flow_id(flow_id.clone());
        let mitm = MitmEngine::from_ca(&test_ca())
            .expect("test CA should build MITM engine")
            .with_hook(hook);
        let worker = tokio::spawn(async move { Box::pin(mitm.handle_flow(flow)).await });

        client
            .write_all(
                b"GET /socket HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: abc\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n",
            )
            .await
            .expect("test client upgrade request should write");
        let response_head = read_http_head(&mut client).await;
        assert!(
            response_head.starts_with("HTTP/1.1 101 Switching Protocols"),
            "client should receive upstream upgrade response"
        );
        let mut client_ws = WebSocketStream::from_raw_socket(
            client,
            Role::Client,
            Some(WebSocketConfig::default()),
        )
        .await;
        client_ws
            .send(Message::text("client hello"))
            .await
            .expect("client should send WebSocket message");
        let response = client_ws
            .next()
            .await
            .expect("client should receive upstream WebSocket message")
            .expect("upstream WebSocket message should decode");
        assert_eq!(
            response.to_text().expect("upstream message should be text"),
            "upstream hello"
        );
        client_ws
            .close(None)
            .await
            .expect("client should close WebSocket cleanly");

        let outcome = expect_intercepted_outcome(
            worker
                .await
                .expect("worker should join")
                .expect("WebSocket flow should succeed"),
        );
        upstream.await.expect("upstream worker should join");
        let observations = wait_for_websocket_observations(&observations, 2).await;

        assert_eq!(
            outcome.first_response.status(),
            http::StatusCode::SWITCHING_PROTOCOLS
        );
        assert!(
            observations
                .iter()
                .any(|observation| observation.text == "client hello"),
            "hook should observe client-to-upstream WebSocket text"
        );
        assert!(
            observations
                .iter()
                .any(|observation| observation.text == "upstream hello"),
            "hook should observe upstream-to-client WebSocket text"
        );
        assert!(
            observations
                .iter()
                .all(|observation| observation.flow_id == flow_id),
            "the ingress flow id should survive WebSocket decoding"
        );
    }

    #[tokio::test]
    async fn handles_tls_http_flow_against_original_destination() {
        let ca = test_ca();
        let server_name = "example.test";
        let upstream_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test TLS upstream should bind");
        let upstream_addr = upstream_listener
            .local_addr()
            .expect("test TLS upstream should expose listen address");
        let upstream_acceptor = TlsAcceptor::from(
            MitmTlsAuthority::from_ca(&ca)
                .expect("test CA should parse as upstream issuer")
                .server_config_for_sni(server_name)
                .await
                .expect("upstream TLS config should build"),
        );
        let upstream = tokio::spawn(async move {
            let (stream, _peer_addr) = upstream_listener
                .accept()
                .await
                .expect("test TLS upstream should accept one connection");
            let mut stream = upstream_acceptor
                .accept(stream)
                .await
                .expect("test TLS upstream handshake should complete");
            let mut request = [0_u8; 1024];
            let read_len = stream
                .read(&mut request)
                .await
                .expect("test TLS upstream should read request");
            assert!(
                request[..read_len].starts_with(b"GET /secure HTTP/1.1"),
                "upstream should receive the decrypted HTTP/1 request"
            );
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecure")
                .await
                .expect("test TLS upstream response should write");
            stream
                .shutdown()
                .await
                .expect("test TLS upstream should send close notify");
        });

        let (client_tcp, server) = connected_pair().await;
        let flow = AcceptedTcpFlow::new(
            server,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 50001)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 18091)),
            OriginalDestination::from(upstream_addr),
        );
        let mitm = test_mitm_engine_trusting(&ca)
            .with_tls_decryption_policy(TlsDecryptionPolicy {
                default_action: TlsDecryptionAction::Intercept,
                missing_sni_action: None,
                rules: Vec::new(),
            })
            .expect("intercept policy should validate");
        let worker = tokio::spawn(async move { Box::pin(mitm.handle_flow(flow)).await });
        let mut client = TlsConnector::from(test_client_config_trusting(&ca))
            .connect(
                ServerName::try_from(server_name)
                    .expect("test server name should be valid")
                    .to_owned(),
                client_tcp,
            )
            .await
            .expect("client TLS handshake with MITM should complete");

        client
            .write_all(b"GET /secure HTTP/1.1\r\nHost: example.test\r\n\r\n")
            .await
            .expect("test TLS client request should write");
        client
            .shutdown()
            .await
            .expect("test TLS client should finish request writes");
        let mut response = [0_u8; 128];
        let read_len = client
            .read(&mut response)
            .await
            .expect("test TLS client should read upstream response");
        let outcome = expect_intercepted_outcome(
            worker
                .await
                .expect("worker should join")
                .expect("TLS HTTP flow should succeed"),
        );
        upstream.await.expect("upstream worker should join");

        assert!(
            response[..read_len].starts_with(b"HTTP/1.1 200 OK"),
            "client should receive upstream TLS response through MITM"
        );
        assert_eq!(
            outcome.protocol,
            TransparentProtocol::TlsHttp {
                server_name: server_name.to_owned()
            }
        );
        assert_eq!(outcome.first_request.method(), http::Method::GET);
        assert_eq!(outcome.first_request.uri(), "/secure");
        assert_eq!(outcome.first_response.status(), http::StatusCode::OK);
    }

    #[tokio::test]
    async fn intercept_rule_continues_tls_after_client_hello_inspection() {
        let ca = test_ca();
        let server_name = "api.openai.com";
        let upstream_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test TLS upstream should bind");
        let upstream_addr = upstream_listener
            .local_addr()
            .expect("test TLS upstream should expose listen address");
        let upstream_acceptor = TlsAcceptor::from(
            MitmTlsAuthority::from_ca(&ca)
                .expect("test CA should parse as upstream issuer")
                .server_config_for_sni(server_name)
                .await
                .expect("upstream TLS config should build"),
        );
        let upstream = tokio::spawn(async move {
            let (stream, _peer_addr) = upstream_listener
                .accept()
                .await
                .expect("test TLS upstream should accept one connection");
            let mut stream = upstream_acceptor
                .accept(stream)
                .await
                .expect("test TLS upstream handshake should complete");
            let request_head = read_http_head(&mut stream).await;
            assert!(
                request_head.starts_with("GET /policy HTTP/1.1"),
                "upstream should receive request after inspected MITM TLS"
            );
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\npolicy")
                .await
                .expect("test TLS upstream response should write");
            stream
                .shutdown()
                .await
                .expect("test TLS upstream should send close notify");
        });

        let (client_tcp, server) = connected_pair().await;
        let flow = codex_flow(server, OriginalDestination::from(upstream_addr));
        let mitm = test_mitm_engine_trusting(&ca)
            .with_tls_decryption_policy(sni_precedence_policy())
            .expect("intercept policy should validate");
        let worker = tokio::spawn(async move { Box::pin(mitm.handle_flow(flow)).await });
        let mut client = TlsConnector::from(test_client_config_trusting(&ca))
            .connect(
                ServerName::try_from(server_name)
                    .expect("test server name should be valid")
                    .to_owned(),
                client_tcp,
            )
            .await
            .expect("client TLS handshake with inspected MITM should complete");

        client
            .write_all(b"GET /policy HTTP/1.1\r\nHost: api.openai.com\r\n\r\n")
            .await
            .expect("test TLS client request should write");
        client
            .shutdown()
            .await
            .expect("test TLS client should finish request writes");
        let mut response = [0_u8; 128];
        let read_len = client
            .read(&mut response)
            .await
            .expect("test TLS client should read upstream response");
        let outcome = expect_intercepted_outcome(
            worker
                .await
                .expect("worker should join")
                .expect("inspected TLS HTTP flow should succeed"),
        );
        upstream.await.expect("upstream worker should join");

        assert!(
            response[..read_len].starts_with(b"HTTP/1.1 200 OK"),
            "client should receive upstream TLS response through inspected MITM"
        );
        assert_eq!(
            outcome.protocol,
            TransparentProtocol::TlsHttp {
                server_name: server_name.to_owned()
            }
        );
        assert_eq!(outcome.first_request.uri(), "/policy");
        assert_eq!(outcome.first_response.status(), http::StatusCode::OK);
    }

    #[tokio::test]
    async fn passthrough_policy_relays_tls_without_decryption() {
        let ca = test_ca();
        let server_name = "bypass.test";
        let upstream_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test TLS upstream should bind");
        let upstream_addr = upstream_listener
            .local_addr()
            .expect("test TLS upstream should expose listen address");
        let upstream_acceptor = TlsAcceptor::from(
            MitmTlsAuthority::from_ca(&ca)
                .expect("test CA should parse as upstream issuer")
                .server_config_for_sni(server_name)
                .await
                .expect("upstream TLS config should build"),
        );
        let upstream = tokio::spawn(async move {
            let (stream, _peer_addr) = upstream_listener
                .accept()
                .await
                .expect("test TLS upstream should accept one connection");
            let mut stream = upstream_acceptor
                .accept(stream)
                .await
                .expect("client should handshake directly with upstream through passthrough");
            let mut request = [0_u8; 1024];
            let read_len = stream
                .read(&mut request)
                .await
                .expect("test TLS upstream should read request");
            assert!(
                request[..read_len].starts_with(b"GET /opaque HTTP/1.1"),
                "upstream should receive request through the original TLS session"
            );
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nopaque")
                .await
                .expect("test TLS upstream response should write");
            stream
                .shutdown()
                .await
                .expect("test TLS upstream should send close notify");
        });

        let (client_tcp, server) = connected_pair().await;
        let flow = AcceptedTcpFlow::new(
            server,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 50003)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 18093)),
            OriginalDestination::from(upstream_addr),
        );
        let mitm = test_mitm_engine_trusting(&ca)
            .with_tls_decryption_policy(TlsDecryptionPolicy {
                default_action: TlsDecryptionAction::Passthrough,
                missing_sni_action: Some(TlsDecryptionAction::Passthrough),
                rules: Vec::new(),
            })
            .expect("passthrough policy should validate");
        let worker = tokio::spawn(async move { Box::pin(mitm.handle_flow(flow)).await });
        let mut client = TlsConnector::from(test_client_config_trusting(&ca))
            .connect(
                ServerName::try_from(server_name)
                    .expect("test server name should be valid")
                    .to_owned(),
                client_tcp,
            )
            .await
            .expect("client TLS handshake should complete with upstream");

        client
            .write_all(b"GET /opaque HTTP/1.1\r\nHost: bypass.test\r\n\r\n")
            .await
            .expect("test TLS client request should write");
        client
            .shutdown()
            .await
            .expect("test TLS client should finish request writes");
        let mut response = [0_u8; 128];
        let read_len = client
            .read(&mut response)
            .await
            .expect("test TLS client should read upstream response");
        let outcome = expect_passthrough_outcome(
            worker
                .await
                .expect("worker should join")
                .expect("TLS passthrough flow should succeed"),
        );
        upstream.await.expect("upstream worker should join");

        assert!(
            response[..read_len].starts_with(b"HTTP/1.1 200 OK"),
            "client should receive upstream TLS response without MITM decryption"
        );
        assert_eq!(
            outcome.protocol,
            TransparentPassthroughProtocol::Tls {
                server_name: Some(server_name.to_owned())
            }
        );
        assert!(outcome.client_to_upstream_bytes > 0);
        assert!(outcome.upstream_to_client_bytes > 0);
    }

    async fn connected_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener should bind");
        let listener_addr = listener
            .local_addr()
            .expect("test listener should expose its address");
        let client = TcpStream::connect(listener_addr);
        let server = listener.accept();
        let (client, accepted) = tokio::join!(client, server);
        (
            client.expect("test client should connect"),
            accepted.expect("test server should accept").0,
        )
    }

    fn codex_flow(stream: TcpStream, original_destination: OriginalDestination) -> AcceptedTcpFlow {
        AcceptedTcpFlow::from_boxed_parts(
            Box::new(stream),
            Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 50004))),
            Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 18094))),
            original_destination,
            Some(
                SourceProcess::new(None, Some("codex".to_owned()), None)
                    .with_application_id(Some("com.openai.codex".to_owned())),
            ),
        )
        .with_destination_host(Some("platform-fallback.example".to_owned()))
    }

    fn sni_precedence_policy() -> TlsDecryptionPolicy {
        TlsDecryptionPolicy {
            default_action: TlsDecryptionAction::Passthrough,
            missing_sni_action: Some(TlsDecryptionAction::Passthrough),
            rules: vec![
                TlsDecryptionRule {
                    id: "pass-platform-host".to_owned(),
                    enabled: true,
                    action: TlsDecryptionAction::Passthrough,
                    process_names: vec!["codex".to_owned()],
                    application_ids: vec!["com.openai.codex".to_owned()],
                    destination_hosts: vec!["platform-fallback.example".to_owned()],
                },
                TlsDecryptionRule {
                    id: "decrypt-openai".to_owned(),
                    enabled: true,
                    action: TlsDecryptionAction::Intercept,
                    process_names: vec!["codex".to_owned()],
                    application_ids: vec!["com.openai.codex".to_owned()],
                    destination_hosts: vec!["*.openai.com".to_owned()],
                },
            ],
        }
    }

    fn expect_intercepted_outcome(outcome: TransparentFlowOutcome) -> InterceptedHttpOutcome {
        match outcome {
            TransparentFlowOutcome::Intercepted(outcome) => *outcome,
            TransparentFlowOutcome::Passthrough(outcome) => {
                panic!("expected intercepted outcome, got passthrough: {outcome:?}");
            }
        }
    }

    fn expect_passthrough_outcome(
        outcome: TransparentFlowOutcome,
    ) -> TransparentPassthroughOutcome {
        match outcome {
            TransparentFlowOutcome::Passthrough(outcome) => outcome,
            TransparentFlowOutcome::Intercepted(outcome) => {
                panic!("expected passthrough outcome, got intercepted: {outcome:?}");
            }
        }
    }

    async fn wait_for_hook_observations(
        observations: &Arc<Mutex<Vec<HookObservation>>>,
        expected_count: usize,
    ) -> Vec<HookObservation> {
        timeout(Duration::from_secs(1), async {
            loop {
                let snapshot = observations.lock().clone();
                if snapshot.len() >= expected_count {
                    return snapshot;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("background hook worker should observe exchange")
    }

    async fn wait_for_websocket_observations(
        observations: &Arc<Mutex<Vec<WebSocketObservation>>>,
        expected_count: usize,
    ) -> Vec<WebSocketObservation> {
        timeout(Duration::from_secs(1), async {
            loop {
                let snapshot = observations.lock().clone();
                if snapshot.len() >= expected_count {
                    return snapshot;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("background hook worker should observe WebSocket messages")
    }

    async fn read_http_head<S>(stream: &mut S) -> String
    where
        S: tokio::io::AsyncRead + Unpin,
    {
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 256];
        loop {
            let read_len = stream
                .read(&mut buffer)
                .await
                .expect("test stream should read HTTP head");
            assert!(read_len > 0, "test peer should send a complete HTTP head");
            bytes.extend_from_slice(&buffer[..read_len]);
            if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                return String::from_utf8(bytes)
                    .expect("test HTTP head should be UTF-8 compatible");
            }
        }
    }

    fn test_mitm_engine_trusting(ca: &crate::CertificateAuthority) -> MitmEngine {
        let mut mitm = MitmEngine::from_ca(ca).expect("test CA should build MITM engine");
        mitm.upstream_tls_config = test_client_config_trusting(ca);
        mitm
    }

    fn test_ca() -> crate::CertificateAuthority {
        // Transparent-flow tests generate CA material directly, bypassing
        // CaStore's provider setup, so install it before rcgen key generation.
        crate::install_default_crypto_provider();
        let key_pair = KeyPair::generate().expect("test CA key should generate");
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, "Abyss Transparent Test Root CA");
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
        crate::CertificateAuthority::from_parts(
            certificate.der().to_vec(),
            certificate.pem(),
            key_pair.serialize_pem(),
        )
    }

    fn test_client_config_trusting(
        ca: &crate::CertificateAuthority,
    ) -> std::sync::Arc<ClientConfig> {
        let mut root_store = RootCertStore::empty();
        root_store
            .add(CertificateDer::from(ca.certificate_der().to_vec()))
            .expect("test root CA should be accepted by rustls");
        std::sync::Arc::new(
            ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth(),
        )
    }

    #[tokio::test]
    async fn connecting_upstream_uses_original_destination() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test upstream should bind");
        let original_destination = OriginalDestination::from(
            listener
                .local_addr()
                .expect("test upstream should expose listen address"),
        );
        let accept = listener.accept();
        let connect = connect_upstream_with_observer(
            UpstreamConnection::Deferred,
            &original_destination,
            MitmTimeouts::default().upstream_connect,
            None,
        );
        let (accepted, connected) = tokio::join!(accept, connect);

        assert!(
            accepted.is_ok(),
            "test upstream should accept connection from MITM connector"
        );
        assert!(
            connected.is_ok(),
            "MITM connector should connect to original destination"
        );
    }

    #[derive(Clone, Default)]
    struct RecordingHook {
        observations: Arc<Mutex<Vec<HookObservation>>>,
    }

    #[derive(Clone, Debug)]
    struct HookObservation {
        method: String,
        request_body_len: usize,
        request_json_n: Option<i64>,
        response_json_ok: Option<bool>,
        original_destination: SocketAddr,
    }

    impl MitmHook for RecordingHook {
        fn on_http_exchange<'a>(&'a self, exchange: &'a HttpExchange) -> HookFuture<'a> {
            self.observations.lock().push(HookObservation {
                method: exchange.request.method().to_string(),
                request_body_len: exchange.request.body().bytes().len(),
                request_json_n: exchange
                    .request
                    .body()
                    .json()
                    .and_then(|json| json.get("n"))
                    .and_then(serde_json::Value::as_i64),
                response_json_ok: exchange
                    .response
                    .body()
                    .json()
                    .and_then(|json| json.get("ok"))
                    .and_then(serde_json::Value::as_bool),
                original_destination: exchange.flow.original_destination.socket_addr(),
            });
            Box::pin(future::ready(Ok(())))
        }
    }

    #[derive(Clone, Default)]
    struct WebSocketRecordingHook {
        observations: Arc<Mutex<Vec<WebSocketObservation>>>,
    }

    #[derive(Clone, Debug)]
    struct WebSocketObservation {
        flow_id: FlowId,
        text: String,
    }

    impl MitmHook for WebSocketRecordingHook {
        fn on_websocket_message<'a>(&'a self, message: &'a WebSocketMessage) -> HookFuture<'a> {
            if let Some(text) = &message.text {
                self.observations.lock().push(WebSocketObservation {
                    flow_id: message.flow.flow_id.clone(),
                    text: text.clone(),
                });
            }
            Box::pin(future::ready(Ok(())))
        }
    }
}
