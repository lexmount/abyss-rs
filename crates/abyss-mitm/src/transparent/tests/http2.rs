//! Real TCP/TLS HTTP/2 coverage through the complete MITM engine.

use bytes::Bytes;
use h2::client::SendRequest;
use http::{HeaderMap, Request, Response, StatusCode, Version};
use parking_lot::Mutex;
use std::{future, sync::Arc, time::Duration};
use tokio::{net::TcpListener, time::timeout};
use tokio_rustls::{TlsAcceptor, TlsConnector, rustls::pki_types::ServerName};

use super::{connected_pair, test_ca, test_client_config_trusting, test_mitm_engine_trusting};
use crate::{
    tls::MitmTlsAuthority,
    transparent::{
        AcceptedTcpFlow, HookFuture, HttpExchange, LocalRejection, MitmHook, OriginalDestination,
        RequestEditor, RequestForwardingControl, RequestForwardingResult, RequestView,
    },
};

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<HttpExchange>>>);
impl MitmHook for Capture {
    fn on_http_exchange<'a>(&'a self, exchange: &'a HttpExchange) -> HookFuture<'a> {
        self.0.lock().push(exchange.clone());
        Box::pin(future::ready(Ok(())))
    }
}

type ObservedRequests = Arc<Mutex<Vec<(Request<()>, Vec<u8>, Option<HeaderMap>)>>>;

struct Fixture {
    sender: SendRequest<Bytes>,
    client: tokio::task::JoinHandle<()>,
    origin: tokio::task::JoinHandle<()>,
    relay: tokio::task::JoinHandle<
        Result<
            crate::transparent::TransparentFlowOutcome,
            crate::transparent::TransparentFlowError,
        >,
    >,
    capture: Capture,
    requests: ObservedRequests,
    authority: String,
}

impl Fixture {
    async fn start<C: RequestForwardingControl + 'static>(
        control: C,
        capture_limit: usize,
    ) -> Self {
        Self::start_routed(control, capture_limit, false).await
    }

    async fn start_routed<C: RequestForwardingControl + 'static>(
        control: C,
        capture_limit: usize,
        redirect: bool,
    ) -> Self {
        let ca = test_ca();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let authority = format!("http2.test:{}", address.port());
        let config =
            origin_config_for_name(&ca, if redirect { "localhost" } else { "http2.test" }).await;
        let requests = Arc::new(Mutex::new(Vec::new()));
        let observed = requests.clone();
        let origin = spawn_origin(listener, config, observed);
        let capture = Capture::default();
        let engine = test_mitm_engine_trusting(&ca)
            .with_tls_decryption_policy(crate::transparent::TlsDecryptionPolicy {
                default_action: crate::transparent::TlsDecryptionAction::Intercept,
                missing_sni_action: None,
                rules: if redirect { vec![serde_json::from_value(serde_json::json!({
                    "id": "h2-redirect", "action": "redirect", "destination_hosts": ["http2.test"], "target": "localhost",
                })).unwrap()] } else { Vec::new() },
            })
            .unwrap()
            .with_hook(capture.clone())
            .with_max_http1_body_bytes(capture_limit);
        let (client, server) = connected_pair().await;
        let flow = AcceptedTcpFlow::new(
            server,
            "127.0.0.1:10001".parse().unwrap(),
            "127.0.0.1:10002".parse().unwrap(),
            OriginalDestination::from(address),
        );
        let relay =
            tokio::spawn(async move { engine.handle_flow_with_control(flow, &control).await });
        let mut config = (*test_client_config_trusting(&ca)).clone();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let tls = TlsConnector::from(Arc::new(config))
            .connect(ServerName::try_from("http2.test").unwrap(), client)
            .await
            .unwrap();
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
        let (sender, connection) = h2::client::handshake(tls).await.unwrap();
        let client = tokio::spawn(async move {
            connection.await.unwrap();
        });
        Self {
            sender,
            client,
            origin,
            relay,
            capture,
            requests,
            authority,
        }
    }

    async fn call(&self, path: &str, bytes: Bytes) -> (StatusCode, Vec<u8>, Option<HeaderMap>) {
        let mut sender = self.sender.clone().ready().await.unwrap();
        let request = Request::builder()
            .method("POST")
            .version(Version::HTTP_2)
            .uri(format!("https://{}{path}", self.authority))
            .body(())
            .unwrap();
        let (response, mut upload) = sender.send_request(request, false).unwrap();
        crate::transparent::http2::body::send_data(&mut upload, bytes)
            .await
            .unwrap();
        let mut trailers = HeaderMap::new();
        trailers.insert("x-request-trailer", "complete".parse().unwrap());
        upload.send_trailers(trailers).unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.version(), Version::HTTP_2);
        let status = response.status();
        let mut body = response.into_body();
        let mut bytes = Vec::new();
        while let Some(chunk) = body.data().await {
            let chunk = chunk.unwrap();
            bytes.extend_from_slice(&chunk);
            body.flow_control().release_capacity(chunk.len()).unwrap();
        }
        (status, bytes, body.trailers().await.unwrap())
    }

    async fn captured(&self, count: usize) -> Vec<HttpExchange> {
        timeout(Duration::from_secs(2), async {
            loop {
                let captured = self.capture.0.lock().clone();
                if captured.len() >= count {
                    return captured;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap()
    }

    async fn close(self) {
        drop(self.sender);
        self.client.abort();
        // Aborting the client driver closes its socket. The relay must release all
        // origin handles without leaving detached stream workers behind.
        let _outcome = timeout(Duration::from_secs(2), self.relay)
            .await
            .unwrap()
            .unwrap();
        timeout(Duration::from_secs(2), self.origin)
            .await
            .unwrap()
            .unwrap();
    }
}

#[tokio::test]
async fn multiplexes_streams_and_preserves_large_bodies_and_trailers() {
    let fixture = Fixture::start(crate::transparent::UncontrolledForwarding, 1024).await;
    let large = Bytes::from(vec![b'x'; 256 * 1024]);
    let (slow, fast) = timeout(Duration::from_secs(5), async {
        tokio::join!(
            fixture.call("/slow", large.clone()),
            fixture.call("/fast", Bytes::from_static(b"fast"))
        )
    })
    .await
    .unwrap();
    assert_eq!(slow.0, StatusCode::OK);
    assert_eq!(slow.1, large);
    assert_eq!(fast.1, b"fast");
    assert_eq!(slow.2.unwrap()["x-response-trailer"], "complete");
    let captured = fixture.captured(2).await;
    assert_eq!(captured[0].request.uri().path(), "/fast");
    let slow = captured
        .iter()
        .find(|exchange| exchange.request.uri().path() == "/slow")
        .unwrap();
    assert_eq!(slow.request.version(), Version::HTTP_2);
    assert_eq!(slow.request.body().raw_bytes().len(), 1024);
    assert!(
        slow.request.body().raw_truncated(),
        "large request capture must be bounded"
    );
    assert!(
        slow.response.body().raw_truncated(),
        "large response capture must be bounded"
    );
    let requests = fixture.requests.lock().clone();
    assert_eq!(requests.len(), 2);
    assert!(
        requests
            .iter()
            .all(|(_, _, trailers)| trailers.as_ref().unwrap()["x-request-trailer"] == "complete"),
        "request trailers must reach origin"
    );
    fixture.close().await;
}

struct Inspect;
impl RequestForwardingControl for Inspect {
    type Plan = ();
    fn plan(&self) -> Option<()> {
        Some(())
    }
    fn before_forward(
        &self,
        (): (),
        request: RequestView<'_>,
    ) -> impl Future<Output = Result<RequestForwardingResult, LocalRejection>> + Send {
        if request.head.uri().path() == "/blocked" {
            return future::ready(Err(LocalRejection::new(
                StatusCode::FORBIDDEN,
                "test_block",
                "blocked",
                request.flow.flow_id.to_string(),
            )));
        }
        let mut editor = RequestEditor::new(request);
        editor.replace_body(Bytes::from_static(b"edited"));
        future::ready(Ok(editor.finish("inspected".to_owned())))
    }
}

#[tokio::test]
async fn inspects_each_stream_before_forwarding_and_preserves_other_streams() {
    let fixture = Fixture::start(Inspect, 1024).await;
    let (blocked, allowed) = tokio::join!(
        fixture.call("/blocked", Bytes::from_static(b"secret")),
        fixture.call("/allowed", Bytes::from_static(b"original"))
    );
    assert_eq!(blocked.0, StatusCode::FORBIDDEN);
    assert_eq!(allowed.1, b"edited");
    let captured = fixture.captured(1).await;
    assert_eq!(captured[0].request.body().bytes(), b"edited");
    assert_eq!(
        captured[0]
            .request
            .body()
            .extensions()
            .get::<String>()
            .unwrap(),
        "inspected"
    );
    assert_eq!(fixture.requests.lock().len(), 1);
    fixture.close().await;
}

#[tokio::test]
async fn cancellation_does_not_stall_later_streams() {
    let fixture = Fixture::start(crate::transparent::UncontrolledForwarding, 1024).await;
    let mut sender = fixture.sender.clone().ready().await.unwrap();
    let request = Request::builder()
        .uri(format!("https://{}/cancel", fixture.authority))
        .body(())
        .unwrap();
    let (response, mut upload) = sender.send_request(request, true).unwrap();
    timeout(Duration::from_secs(2), async {
        while fixture.requests.lock().is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    upload.send_reset(h2::Reason::CANCEL);
    drop(response);
    assert_eq!(
        fixture.call("/after", Bytes::from_static(b"after")).await.1,
        b"after"
    );
    fixture.captured(1).await;
    drop(sender);
    fixture.close().await;
}

async fn origin_config(ca: &crate::CertificateAuthority) -> tokio_rustls::rustls::ServerConfig {
    origin_config_for_name(ca, "http2.test").await
}

async fn origin_config_for_name(
    ca: &crate::CertificateAuthority,
    name: &str,
) -> tokio_rustls::rustls::ServerConfig {
    let mut config = (*MitmTlsAuthority::from_ca(ca)
        .unwrap()
        .server_config_for_sni(name)
        .await
        .unwrap())
    .clone();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config
}

#[tokio::test]
async fn rejects_cross_authority_stream_without_reusing_its_policy() {
    let fixture = Fixture::start(crate::transparent::UncontrolledForwarding, 1024).await;
    let mut sender = fixture.sender.clone().ready().await.unwrap();
    let request = Request::builder()
        .uri("https://different.test/secret")
        .body(())
        .unwrap();
    let (response, _) = sender.send_request(request, true).unwrap();
    assert_eq!(
        response.await.unwrap().status(),
        StatusCode::MISDIRECTED_REQUEST
    );
    assert!(
        fixture.requests.lock().is_empty(),
        "mismatched authority must never reach origin"
    );
    assert_eq!(
        fixture.call("/valid", Bytes::from_static(b"valid")).await.1,
        b"valid"
    );
    fixture.captured(1).await;
    drop(sender);
    fixture.close().await;
}

#[tokio::test]
async fn limits_inspected_bodies_before_forwarding() {
    let fixture = Fixture::start(Inspect, 32).await;
    let response = fixture
        .call("/large", Bytes::from_static(&[b'x'; 64]))
        .await;
    assert_eq!(response.0, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(
        fixture.requests.lock().is_empty(),
        "oversized inspected request must never reach origin"
    );
    assert_eq!(
        fixture.call("/valid", Bytes::from_static(b"valid")).await.1,
        b"edited"
    );
    fixture.captured(1).await;
    fixture.close().await;
}

#[tokio::test]
async fn negotiates_http1_fallback_when_the_origin_does_not_offer_h2() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let ca = test_ca();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut config = origin_config(&ca).await;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let origin = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = TlsAcceptor::from(Arc::new(config))
            .accept(tcp)
            .await
            .unwrap();
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));
        let head = super::read_http_head(&mut tls).await;
        assert!(
            head.starts_with("GET /fallback HTTP/1.1"),
            "HTTP/1 bytes must reach origin"
        );
        tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nfallback")
            .await
            .unwrap();
        tls.shutdown().await.unwrap();
    });
    let engine = test_mitm_engine_trusting(&ca)
        .with_tls_decryption_policy(crate::transparent::TlsDecryptionPolicy {
            default_action: crate::transparent::TlsDecryptionAction::Intercept,
            missing_sni_action: None,
            rules: Vec::new(),
        })
        .unwrap();
    let (client, server) = connected_pair().await;
    let flow = AcceptedTcpFlow::new(
        server,
        "127.0.0.1:10001".parse().unwrap(),
        "127.0.0.1:10002".parse().unwrap(),
        OriginalDestination::from(address),
    );
    let relay = tokio::spawn(async move { engine.handle_flow(flow).await.unwrap() });
    let mut config = (*test_client_config_trusting(&ca)).clone();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let mut client = TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("http2.test").unwrap(), client)
        .await
        .unwrap();
    assert_eq!(client.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));
    client
        .write_all(b"GET /fallback HTTP/1.1\r\nHost: http2.test\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    assert!(
        response.ends_with(b"fallback"),
        "fallback response must be forwarded"
    );
    relay.await.unwrap();
    origin.await.unwrap();
}

#[tokio::test]
async fn continues_before_inspection_and_forwards_informational_responses() {
    let fixture = Fixture::start(Inspect, 1024).await;
    let mut sender = fixture.sender.clone().ready().await.unwrap();
    let request = Request::builder()
        .method("POST")
        .uri(format!("https://{}/info", fixture.authority))
        .header("expect", "100-continue")
        .body(())
        .unwrap();
    let (mut response, mut upload) = sender.send_request(request, false).unwrap();
    let interim = timeout(
        Duration::from_secs(2),
        std::future::poll_fn(|cx| response.poll_informational(cx)),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap();
    assert_eq!(interim.status(), StatusCode::CONTINUE);
    upload
        .send_data(Bytes::from_static(b"original"), true)
        .unwrap();
    let interim = timeout(
        Duration::from_secs(2),
        std::future::poll_fn(|cx| response.poll_informational(cx)),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap();
    assert_eq!(interim.status(), StatusCode::EARLY_HINTS);
    let mut response = response.await.unwrap().into_body();
    let bytes = response.data().await.unwrap().unwrap();
    assert_eq!(bytes, b"edited"[..]);
    response
        .flow_control()
        .release_capacity(bytes.len())
        .unwrap();
    while let Some(chunk) = response.data().await {
        chunk.unwrap();
    }
    response.trailers().await.unwrap();
    fixture.captured(1).await;
    drop(sender);
    fixture.close().await;
}

#[tokio::test]
async fn cancellation_of_an_idle_response_releases_the_origin_stream() {
    let fixture = Fixture::start(crate::transparent::UncontrolledForwarding, 1024).await;
    let mut sender = fixture.sender.clone().ready().await.unwrap();
    let request = Request::builder()
        .uri(format!("https://{}/idle", fixture.authority))
        .body(())
        .unwrap();
    let (response, mut upload) = sender.send_request(request, true).unwrap();
    let response = response.await.unwrap();
    upload.send_reset(h2::Reason::CANCEL);
    drop(response);
    assert_eq!(
        fixture.call("/after", Bytes::from_static(b"after")).await.1,
        b"after"
    );
    fixture.captured(1).await;
    drop(sender);
    fixture.close().await;
}

fn spawn_origin(
    listener: TcpListener,
    config: tokio_rustls::rustls::ServerConfig,
    observed: ObservedRequests,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let tls = TlsAcceptor::from(Arc::new(config))
            .accept(tcp)
            .await
            .unwrap();
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
        let mut connection = h2::server::handshake(tls).await.unwrap();
        let mut workers = tokio::task::JoinSet::new();
        while let Some(incoming) = connection.accept().await {
            let (request, mut respond) = incoming.unwrap();
            let observed = observed.clone();
            workers.spawn(async move {
                let (parts, mut body) = request.into_parts();
                let head = Request::from_parts(parts, ());
                let mut bytes = Vec::new();
                while let Some(chunk) = body.data().await {
                    let chunk = chunk.unwrap();
                    bytes.extend_from_slice(&chunk);
                    body.flow_control().release_capacity(chunk.len()).unwrap();
                }
                let trailers = body.trailers().await.unwrap();
                let path = head.uri().path().to_owned();
                observed.lock().push((head, bytes.clone(), trailers));
                if path == "/refused" {
                    respond.send_reset(h2::Reason::REFUSED_STREAM);
                    return;
                }
                if path == "/slow" {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                if path == "/cancel" {
                    let reason = std::future::poll_fn(|cx| respond.poll_reset(cx))
                        .await
                        .unwrap();
                    assert_eq!(reason, h2::Reason::CANCEL);
                    return;
                }
                if path == "/info" {
                    respond
                        .send_informational(
                            Response::builder()
                                .status(StatusCode::EARLY_HINTS)
                                .body(())
                                .unwrap(),
                        )
                        .unwrap();
                }
                let response = Response::builder()
                    .version(Version::HTTP_2)
                    .header("content-type", "application/octet-stream")
                    .body(())
                    .unwrap();
                let mut stream = respond.send_response(response, false).unwrap();
                if path == "/idle" {
                    let reason = std::future::poll_fn(|cx| stream.poll_reset(cx))
                        .await
                        .unwrap();
                    assert_eq!(reason, h2::Reason::CANCEL);
                    return;
                }
                crate::transparent::http2::body::send_data(&mut stream, Bytes::from(bytes))
                    .await
                    .unwrap();
                let mut trailers = HeaderMap::new();
                trailers.insert("x-response-trailer", "complete".parse().unwrap());
                stream.send_trailers(trailers).unwrap();
            });
        }
        while let Some(result) = workers.join_next().await {
            result.unwrap();
        }
    })
}

#[tokio::test]
async fn redirects_http2_authority_and_tls_identity_without_changing_path_or_body() {
    let fixture =
        Fixture::start_routed(crate::transparent::UncontrolledForwarding, 1024, true).await;
    let response = fixture
        .call("/path%2Fpart?q=a%2Bb", Bytes::from_static(b"unchanged"))
        .await;
    assert_eq!(response.1, b"unchanged");
    let requests = fixture.requests.lock().clone();
    assert_eq!(requests.len(), 1);
    let request = &requests[0].0;
    assert_eq!(request.uri().host(), Some("localhost"));
    assert_eq!(
        request.uri().path_and_query().unwrap().as_str(),
        "/path%2Fpart?q=a%2Bb"
    );
    assert_eq!(
        request.headers()["host"].to_str().unwrap(),
        request.uri().authority().unwrap().as_str()
    );
    fixture.captured(1).await;
    fixture.close().await;
}

#[tokio::test]
async fn preserves_the_origin_reset_reason_for_retryable_streams() {
    let fixture = Fixture::start(crate::transparent::UncontrolledForwarding, 1024).await;
    let mut sender = fixture.sender.clone().ready().await.unwrap();
    let request = Request::builder()
        .uri(format!("https://{}/refused", fixture.authority))
        .body(())
        .unwrap();
    let (response, _) = sender.send_request(request, true).unwrap();
    assert_eq!(
        response.await.unwrap_err().reason(),
        Some(h2::Reason::REFUSED_STREAM)
    );
    assert_eq!(
        fixture.call("/after", Bytes::from_static(b"after")).await.1,
        b"after"
    );
    fixture.captured(1).await;
    drop(sender);
    fixture.close().await;
}
