//! Real TCP/TLS HTTP/2 coverage through the complete MITM engine.

mod observation;

use bytes::Bytes;
use h2::client::SendRequest;
use http::{HeaderMap, Request, Response, StatusCode, Version, request::Builder};
use parking_lot::Mutex;
use std::{future, sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::Notify, time::timeout};
use tokio_rustls::{TlsAcceptor, TlsConnector, rustls::pki_types::ServerName};

use self::observation::Capture;
use super::{connected_pair, test_ca, test_client_config_trusting, test_mitm_engine_trusting};
use crate::{
    tls::MitmTlsAuthority,
    transparent::{
        AcceptedTcpFlow, HttpExchange, LocalRejection, OriginalDestination, RequestEditor,
        RequestForwardingControl, RequestForwardingResult, RequestView,
    },
};

/// Origin view of each request: head, body, trailers, and whether the request
/// ended on its HEADERS frame.
type ObservedRequests = Arc<Mutex<Vec<(Request<()>, Vec<u8>, Option<HeaderMap>, bool)>>>;

#[derive(Clone, Copy)]
enum Routing {
    Original,
    DomainRedirect,
    PerStream,
    PerRequestProxies,
}

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
    finish_gzip: Arc<Notify>,
    requests: ObservedRequests,
    authority: String,
}

impl Fixture {
    async fn start<C: RequestForwardingControl + 'static>(
        control: C,
        capture_limit: usize,
    ) -> Self {
        Self::start_routed(control, capture_limit, Routing::Original).await
    }

    async fn start_routed<C: RequestForwardingControl + 'static>(
        control: C,
        capture_limit: usize,
        routing: Routing,
    ) -> Self {
        Self::start_with_capture(control, capture_limit, routing, Capture::default()).await
    }

    async fn start_with_capture<C: RequestForwardingControl + 'static>(
        control: C,
        capture_limit: usize,
        routing: Routing,
        capture: Capture,
    ) -> Self {
        let ca = test_ca();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let authority = format!("http2.test:{}", address.port());
        let config = origin_config_for_name(
            &ca,
            if matches!(routing, Routing::DomainRedirect) {
                "localhost"
            } else {
                "http2.test"
            },
        )
        .await;
        let requests = Arc::new(Mutex::new(Vec::new()));
        let observed = requests.clone();
        let mut origins = vec![config];
        if matches!(routing, Routing::PerStream) {
            origins.push(origin_config_for_name(&ca, "localhost").await);
        }
        if matches!(routing, Routing::PerRequestProxies) {
            origins.extend([origins[0].clone(), origins[0].clone()]);
        }
        let finish_gzip = Arc::new(Notify::new());
        let origin = spawn_origin(listener, origins, observed, finish_gzip.clone());
        let engine = test_mitm_engine_trusting(&ca)
            .with_tls_decryption_policy(crate::transparent::TlsDecryptionPolicy {
                default_action: crate::transparent::TlsDecryptionAction::Intercept,
                missing_sni_action: None,
                rules: if matches!(routing, Routing::DomainRedirect) { vec![serde_json::from_value(serde_json::json!({
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
            finish_gzip,
            requests,
            authority,
        }
    }

    fn request(&self, path: &str) -> Builder {
        Request::builder()
            .version(Version::HTTP_2)
            .uri(format!("https://{}{path}", self.authority))
    }

    async fn call(&self, path: &str, bytes: Bytes) -> (StatusCode, Vec<u8>, Option<HeaderMap>) {
        let mut sender = self.sender.clone().ready().await.unwrap();
        let request = self.request(path).method("POST").body(()).unwrap();
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
        read_body(&mut body, &mut bytes).await;
        (status, bytes, body.trailers().await.unwrap())
    }

    /// Sends a bodiless GET, ending it on HEADERS or on a separate empty DATA frame.
    async fn get(&self, path: &str, end_on_headers: bool) -> (StatusCode, Vec<u8>) {
        let mut sender = self.sender.clone().ready().await.unwrap();
        let request = self.request(path).body(()).unwrap();
        let (response, mut upload) = sender.send_request(request, end_on_headers).unwrap();
        if !end_on_headers {
            upload.send_data(Bytes::new(), true).unwrap();
        }
        let response = response.await.unwrap();
        let status = response.status();
        let mut body = response.into_body();
        let mut bytes = Vec::new();
        read_body(&mut body, &mut bytes).await;
        body.trailers().await.unwrap();
        (status, bytes)
    }

    /// Whether the origin saw the request for `path` end on its HEADERS frame.
    fn origin_ended_on_headers(&self, path: &str) -> bool {
        self.requests
            .lock()
            .iter()
            .find(|(request, _, _, _)| request.uri().path() == path)
            .unwrap()
            .3
    }

    async fn captured(&self, count: usize) -> Vec<HttpExchange> {
        timeout(Duration::from_secs(2), async {
            loop {
                let captured = self.capture.exchanges.lock().clone();
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

async fn read_body(body: &mut h2::RecvStream, bytes: &mut Vec<u8>) {
    while let Some(chunk) = body.data().await {
        let chunk = chunk.unwrap();
        bytes.extend_from_slice(&chunk);
        body.flow_control().release_capacity(chunk.len()).unwrap();
    }
}

#[tokio::test]
async fn observes_decoded_gzip_body_before_http2_end_stream() {
    observation::check_live_gzip_observation().await;
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
    assert!(
        slow.response_ended_at
            .duration_since(slow.request_sent_at)
            .unwrap()
            >= Duration::from_millis(50),
        "the origin's delay must be included between the two wire timestamps"
    );
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
        requests.iter().all(
            |(_, _, trailers, _)| trailers.as_ref().unwrap()["x-request-trailer"] == "complete"
        ),
        "request trailers must reach origin"
    );
    fixture.close().await;
}

#[tokio::test]
async fn forwards_authority_once_while_retaining_host_for_observers() {
    let fixture = Fixture::start(crate::transparent::UncontrolledForwarding, 1024).await;
    for include_host in [false, true] {
        let mut sender = fixture.sender.clone().ready().await.unwrap();
        let mut request = Request::builder()
            .version(Version::HTTP_2)
            .uri(format!("https://{}/authority", fixture.authority));
        if include_host {
            request = request.header("host", &fixture.authority);
        }
        let (response, _) = sender
            .send_request(request.body(()).unwrap(), true)
            .unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let mut body = response.into_body();
        while let Some(chunk) = body.data().await {
            let chunk = chunk.unwrap();
            body.flow_control().release_capacity(chunk.len()).unwrap();
        }
        body.trailers().await.unwrap();
    }
    let captured = fixture.captured(2).await;
    for exchange in captured {
        assert_eq!(exchange.request.headers()["host"], fixture.authority);
    }
    let requests = fixture.requests.lock().clone();
    for (request, _, _, _) in requests {
        assert_eq!(
            request.uri().authority().unwrap().as_str(),
            fixture.authority
        );
        assert!(
            !request.headers().contains_key("host"),
            "origins must not receive both :authority and the observer-only Host header"
        );
    }
    fixture.close().await;
}

#[tokio::test]
async fn forwards_the_client_end_of_stream_framing() {
    let fixture = Fixture::start(crate::transparent::UncontrolledForwarding, 1024).await;
    assert_eq!(fixture.get("/headers-only", true).await.0, StatusCode::OK);
    assert_eq!(fixture.get("/empty-data", false).await.0, StatusCode::OK);
    assert!(
        fixture.origin_ended_on_headers("/headers-only"),
        "a bodiless GET must not gain an empty DATA frame on the way to origin"
    );
    assert!(
        !fixture.origin_ended_on_headers("/empty-data"),
        "a client's own empty DATA frame is forwarded as sent"
    );
    let captured = fixture.captured(2).await;
    let bodiless = captured
        .iter()
        .find(|exchange| exchange.request.uri().path() == "/headers-only")
        .unwrap();
    assert!(bodiless.request.body().raw_bytes().is_empty());
    assert!(!bodiless.request.body().raw_truncated());
    fixture.close().await;
}

#[tokio::test]
async fn forwards_headers_only_responses_without_an_empty_data_frame() {
    let fixture = Fixture::start(crate::transparent::UncontrolledForwarding, 1024).await;
    // An empty DATA frame after a 304 with Content-Length is a protocol error
    // for the client, so this call fails unless the response ends on HEADERS.
    let (status, body) = fixture.get("/not-modified", true).await;
    assert_eq!(status, StatusCode::NOT_MODIFIED);
    assert!(body.is_empty());
    let captured = fixture.captured(1).await;
    assert_eq!(captured[0].response.status(), StatusCode::NOT_MODIFIED);
    assert!(captured[0].response.body().raw_bytes().is_empty());
    assert!(!captured[0].response.body().raw_truncated());
    fixture.close().await;
}

#[tokio::test]
async fn inspected_bodiless_requests_end_on_headers_unless_a_body_is_added() {
    // The model route also moves this stream to its own origin connection.
    let unchanged = Fixture::start_routed(RouteModel, 1024, Routing::PerStream).await;
    assert_eq!(
        unchanged.get("/backend-api/codex/responses", true).await.0,
        StatusCode::OK
    );
    assert!(
        unchanged.origin_ended_on_headers("/compatible-mode/v1/responses"),
        "inspection without a body edit keeps the bodiless framing"
    );
    unchanged.captured(1).await;
    unchanged.close().await;

    let edited = Fixture::start(Inspect, 1024).await;
    assert_eq!(edited.get("/headers-only", true).await.1, b"edited");
    assert!(
        !edited.origin_ended_on_headers("/headers-only"),
        "a body added by inspection must still reach origin"
    );
    edited.captured(1).await;
    edited.close().await;
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

struct RouteModel;

impl RequestForwardingControl for RouteModel {
    type Plan = ();
    fn plan(&self) -> Option<()> {
        Some(())
    }
    fn before_forward(
        &self,
        (): (),
        request: RequestView<'_>,
    ) -> impl Future<Output = Result<RequestForwardingResult, LocalRejection>> + Send {
        let mut editor = RequestEditor::new(request);
        if editor.view().head.uri().path() == "/backend-api/codex/responses" {
            editor.set_upstream_host("localhost").unwrap();
            editor
                .set_request_path("/compatible-mode/v1/responses")
                .unwrap();
        }
        future::ready(Ok(editor.finish(())))
    }
}

#[tokio::test]
async fn model_and_catalog_streams_share_client_tls_but_use_distinct_verified_origins() {
    let fixture = Fixture::start_routed(RouteModel, 1024, Routing::PerStream).await;
    let (model, catalog) = tokio::join!(
        fixture.call(
            "/backend-api/codex/responses?stream=1",
            Bytes::from_static(b"model")
        ),
        fixture.call(
            "/backend-api/plugins/export/curated",
            Bytes::from_static(b"catalog")
        ),
    );
    assert_eq!((model.0, catalog.0), (StatusCode::OK, StatusCode::OK));
    assert_eq!(model.1, b"model");
    assert_eq!(catalog.1, b"catalog");
    let requests = fixture.requests.lock().clone();
    assert_eq!(requests.len(), 2);
    for (request, body, trailers, _) in requests {
        if body == b"model" {
            assert_eq!(request.uri().host(), Some("localhost"));
            assert_eq!(
                request.uri().path_and_query().unwrap(),
                "/compatible-mode/v1/responses?stream=1"
            );
            assert!(trailers.is_none());
        } else {
            assert_eq!(request.uri().host(), Some("http2.test"));
            assert_eq!(request.uri().path(), "/backend-api/plugins/export/curated");
            assert!(trailers.is_some());
        }
    }
    fixture.close().await;
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
    let requests = fixture.requests.lock().clone();
    assert_eq!(requests.len(), 1);
    assert!(!requests[0].0.headers().contains_key("host"));
    assert_eq!(captured[0].request.headers()["host"], fixture.authority);
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

#[tokio::test]
async fn cancellation_retains_observed_response_bytes_as_incomplete() {
    let fixture = Fixture::start(crate::transparent::UncontrolledForwarding, 1024).await;
    let mut sender = fixture.sender.clone().ready().await.unwrap();
    let request = Request::builder()
        .method("POST")
        .uri(format!("https://{}/cancel-after-data", fixture.authority))
        .body(())
        .unwrap();
    let (response, mut upload) = sender.send_request(request, false).unwrap();
    upload
        .send_data(Bytes::from_static(b"observed"), true)
        .unwrap();
    let mut body = response.await.unwrap().into_body();
    let bytes = body.data().await.unwrap().unwrap();
    assert_eq!(bytes, b"observed"[..]);
    body.flow_control().release_capacity(bytes.len()).unwrap();
    // Streaming API clients can stop after an application-level terminal event
    // without waiting for the origin's HTTP/2 END_STREAM frame.
    upload.send_reset(h2::Reason::CANCEL);
    drop(body);
    let captured = fixture.captured(1).await;
    assert_eq!(captured[0].request.body().raw_bytes(), b"observed");
    assert!(!captured[0].request.body().raw_truncated());
    assert_eq!(captured[0].response.body().raw_bytes(), b"observed");
    assert!(captured[0].response.body().raw_truncated());
    assert_eq!(
        fixture.call("/after", Bytes::from_static(b"after")).await.1,
        b"after"
    );
    fixture.captured(2).await;
    drop(sender);
    fixture.close().await;
}

#[tokio::test]
async fn disconnect_retains_observed_response_bytes_as_incomplete() {
    let fixture = Fixture::start(crate::transparent::UncontrolledForwarding, 1024).await;
    let mut sender = fixture.sender.clone().ready().await.unwrap();
    let request = Request::builder()
        .method("POST")
        .uri(format!(
            "https://{}/disconnect-after-data",
            fixture.authority
        ))
        .body(())
        .unwrap();
    let (response, mut upload) = sender.send_request(request, false).unwrap();
    upload
        .send_data(Bytes::from_static(b"observed"), true)
        .unwrap();
    let mut body = response.await.unwrap().into_body();
    let bytes = body.data().await.unwrap().unwrap();
    assert_eq!(bytes, b"observed"[..]);
    body.flow_control().release_capacity(bytes.len()).unwrap();
    // Streaming API clients can stop after an application-level terminal event
    // without waiting for the origin's HTTP/2 END_STREAM frame.
    fixture.client.abort();
    drop(body);
    let captured = fixture.captured(1).await;
    assert_eq!(captured[0].request.body().raw_bytes(), b"observed");
    assert!(!captured[0].request.body().raw_truncated());
    assert_eq!(captured[0].response.body().raw_bytes(), b"observed");
    assert!(captured[0].response.body().raw_truncated());
    drop(sender);
    fixture.close().await;
}

fn spawn_origin(
    listener: TcpListener,
    configs: Vec<tokio_rustls::rustls::ServerConfig>,
    observed: ObservedRequests,
    finish_gzip: Arc<Notify>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        for config in configs {
            let (tcp, _) = listener.accept().await.unwrap();
            connections.spawn(serve_origin(
                tcp,
                config,
                observed.clone(),
                finish_gzip.clone(),
            ));
        }
        while let Some(result) = connections.join_next().await {
            result.unwrap();
        }
    })
}

async fn serve_origin(
    tcp: tokio::net::TcpStream,
    config: tokio_rustls::rustls::ServerConfig,
    observed: ObservedRequests,
    finish_gzip: Arc<Notify>,
) {
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
        let finish_gzip = finish_gzip.clone();
        workers.spawn(async move {
            let (parts, mut body) = request.into_parts();
            let ended_on_headers = body.is_end_stream();
            let head = Request::from_parts(parts, ());
            let mut bytes = Vec::new();
            while let Some(chunk) = body.data().await {
                let chunk = chunk.unwrap();
                bytes.extend_from_slice(&chunk);
                body.flow_control().release_capacity(chunk.len()).unwrap();
            }
            let trailers = body.trailers().await.unwrap();
            let path = head.uri().path().to_owned();
            observed
                .lock()
                .push((head, bytes.clone(), trailers, ended_on_headers));
            if path == "/refused" {
                respond.send_reset(h2::Reason::REFUSED_STREAM);
                return;
            }
            if path == "/not-modified" {
                // A 304 keeps the representation's length while ending on HEADERS.
                let response = Response::builder()
                    .status(StatusCode::NOT_MODIFIED)
                    .header("content-length", "123")
                    .body(())
                    .unwrap();
                respond.send_response(response, true).unwrap();
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
            if path == observation::GZIP_PATH {
                observation::serve_gzip(respond, &finish_gzip).await;
                return;
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
            if matches!(
                path.as_str(),
                "/cancel-after-data" | "/disconnect-after-data"
            ) {
                let reason = std::future::poll_fn(|cx| stream.poll_reset(cx)).await;
                if path == "/cancel-after-data" {
                    assert_eq!(reason.unwrap(), h2::Reason::CANCEL);
                }
                return;
            }
            let mut trailers = HeaderMap::new();
            trailers.insert("x-response-trailer", "complete".parse().unwrap());
            stream.send_trailers(trailers).unwrap();
        });
    }
    while let Some(result) = workers.join_next().await {
        result.unwrap();
    }
}

#[tokio::test]
async fn redirects_http2_authority_and_tls_identity_without_changing_path_or_body() {
    let fixture = Fixture::start_routed(
        crate::transparent::UncontrolledForwarding,
        1024,
        Routing::DomainRedirect,
    )
    .await;
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
    assert!(!request.headers().contains_key("host"));
    let captured = fixture.captured(1).await;
    assert_eq!(
        captured[0].request.headers()["host"].to_str().unwrap(),
        request.uri().authority().unwrap().as_str()
    );
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

struct ProxyPerPath {
    first: u16,
    second: u16,
}

impl RequestForwardingControl for ProxyPerPath {
    type Plan = ();
    fn plan(&self) -> Option<()> {
        Some(())
    }
    fn before_forward(
        &self,
        (): (),
        request: RequestView<'_>,
    ) -> impl Future<Output = Result<RequestForwardingResult, LocalRejection>> + Send {
        let port = if request.head.uri().path() == "/one" {
            self.first
        } else {
            self.second
        };
        let proxy = crate::outbound::UpstreamProxy::from_endpoint(
            format!("http://127.0.0.1:{port}"),
            Some(("alice".into(), "abc".into())),
        )
        .unwrap();
        let mut editor = RequestEditor::new(request);
        editor.set_upstream_proxy(proxy).unwrap();
        future::ready(Ok(editor.finish(())))
    }
}

#[tokio::test]
async fn same_host_streams_use_and_record_their_own_authenticated_proxies() {
    use tokio::io::AsyncWriteExt as _;
    async fn proxy() -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let head = super::read_http_head(&mut socket).await;
            assert!(head.contains("Proxy-Authorization: Basic YWxpY2U6YWJj\r\n"));
            let authority = head.split_whitespace().nth(1).unwrap();
            let origin_port = authority
                .strip_prefix("http2.test:")
                .unwrap()
                .parse::<u16>()
                .unwrap();
            let mut origin = tokio::net::TcpStream::connect(("127.0.0.1", origin_port))
                .await
                .unwrap();
            socket.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
            let _closed = tokio::io::copy_bidirectional(&mut socket, &mut origin).await;
        });
        (port, handle)
    }
    timeout(Duration::from_secs(10), async {
        let ((first, first_task), (second, second_task)) = tokio::join!(proxy(), proxy());
        let fixture = Fixture::start_routed(
            ProxyPerPath { first, second },
            1024,
            Routing::PerRequestProxies,
        )
        .await;
        let (a, b) = tokio::join!(
            fixture.call("/one", Bytes::from_static(b"one")),
            fixture.call("/two", Bytes::from_static(b"two"))
        );
        assert_eq!((a.0, b.0), (StatusCode::OK, StatusCode::OK));
        assert_eq!(
            (a.1.as_slice(), b.1.as_slice()),
            (b"one".as_slice(), b"two".as_slice())
        );
        for exchange in fixture.captured(2).await {
            let hop = exchange
                .request
                .extensions()
                .get::<crate::RequestProxyHop>()
                .unwrap();
            let port = if exchange.request.uri().path() == "/one" {
                first
            } else {
                second
            };
            assert_eq!(hop.peer().unwrap().port(), port);
            assert_eq!(hop.endpoint, format!("127.0.0.1:{port}"));
            assert!(
                !exchange
                    .request
                    .headers()
                    .contains_key("proxy-authorization")
            );
        }
        fixture.close().await;
        first_task.await.unwrap();
        second_task.await.unwrap();
    })
    .await
    .unwrap();
}
