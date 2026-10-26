//! Exercise the public relay over real TCP: wire bytes stay encoded and hooks decode.

use std::{io::Write, sync::Arc, time::Duration};

use abyss_mitm::{
    AcceptedTcpFlow, BodyDecodingStatus, CertificateAuthority, HookFuture, HttpExchange,
    MitmEngine, MitmHook, OriginalDestination,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::mpsc,
    time::timeout,
};

struct Observer(mpsc::UnboundedSender<HttpExchange>);

impl MitmHook for Observer {
    fn on_http_exchange<'a>(&'a self, exchange: &'a HttpExchange) -> HookFuture<'a> {
        self.0.send(exchange.clone()).unwrap();
        Box::pin(std::future::ready(Ok(())))
    }
}

struct Fixture {
    coding: &'static str,
    raw: Vec<u8>,
    decoded: Vec<u8>,
    status: BodyDecodingStatus,
    limit: usize,
}

impl Fixture {
    fn encoded(coding: &'static str, bytes: &[u8]) -> Self {
        let raw = match coding {
            "gzip" => {
                let mut writer =
                    flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                writer.write_all(bytes).unwrap();
                writer.finish().unwrap()
            }
            "deflate" => {
                let mut writer =
                    flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
                writer.write_all(bytes).unwrap();
                writer.finish().unwrap()
            }
            "br" => {
                let mut writer = brotli::CompressorWriter::new(Vec::new(), 4096, 5, 22);
                writer.write_all(bytes).unwrap();
                writer.into_inner()
            }
            "zstd" => zstd::stream::encode_all(bytes, 1).unwrap(),
            _ => bytes.to_vec(),
        };
        Self {
            coding,
            raw,
            decoded: bytes.to_vec(),
            status: BodyDecodingStatus::Complete,
            limit: 4096,
        }
    }

    async fn roundtrip(self, framing: &str) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        let mut request = format!("POST /arbitrary HTTP/1.1\r\nHost: gateway.test\r\naCcEpT-EnCoDiNg: gzip, br\r\nAccept-Encoding: zstd\r\nContent-Encoding: {}\r\nContent-Length: {}\r\n\r\n", self.coding, self.raw.len()).into_bytes();
        request.extend_from_slice(&self.raw);
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Encoding: {}\r\n",
            self.coding
        )
        .into_bytes();
        match framing {
            "chunked" => {
                response.extend_from_slice(b"Transfer-Encoding: chunked\r\n\r\n");
                for chunk in self.raw.chunks(7) {
                    response.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
                    response.extend_from_slice(chunk);
                    response.extend_from_slice(b"\r\n");
                }
                response.extend_from_slice(b"0\r\nX-Trailer: kept\r\n\r\n");
            }
            "eof" => {
                response.extend_from_slice(b"Connection: close\r\n\r\n");
                response.extend_from_slice(&self.raw);
            }
            _ => {
                response.extend_from_slice(
                    format!("Content-Length: {}\r\n\r\n", self.raw.len()).as_bytes(),
                );
                response.extend_from_slice(&self.raw);
            }
        }
        let expected_request = request.clone();
        let upstream_response = response.clone();
        let upstream = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut received = vec![0; expected_request.len()];
            stream.read_exact(&mut received).await.unwrap();
            assert_eq!(
                received, expected_request,
                "upstream must receive original headers and bytes"
            );
            for chunk in upstream_response.chunks(13) {
                stream.write_all(chunk).await.unwrap();
            }
        });
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = tokio::net::TcpStream::connect(proxy.local_addr().unwrap())
            .await
            .unwrap();
        let (server, peer) = proxy.accept().await.unwrap();
        let flow = AcceptedTcpFlow::new(
            server,
            peer,
            proxy.local_addr().unwrap(),
            OriginalDestination::from(target),
        );
        let (sender, mut observed) = mpsc::unbounded_channel();
        let engine = Arc::new(
            MitmEngine::from_ca(&test_ca())
                .unwrap()
                .with_max_http1_body_bytes(self.limit)
                .with_hook(Observer(sender)),
        );
        let relay_engine = engine.clone();
        let relay = tokio::spawn(async move { relay_engine.handle_flow(flow).await.unwrap() });
        client.write_all(&request).await.unwrap();
        let mut received = Vec::new();
        client.read_to_end(&mut received).await.unwrap();
        assert_eq!(
            received, response,
            "client must receive original response headers and bytes"
        );
        relay.await.unwrap();
        upstream.await.unwrap();
        let exchange = observed.recv().await.unwrap();
        for body in [exchange.request.body(), exchange.response.body()] {
            assert_eq!(
                body.raw_bytes(),
                &self.raw[..self.raw.len().min(self.limit)],
                "raw capture must stay encoded"
            );
            assert_eq!(
                body.bytes(),
                self.decoded,
                "observation bytes should be decoded"
            );
            assert_eq!(
                body.decoding_status(),
                self.status,
                "explicit decoding status"
            );
        }
        assert_eq!(
            exchange.response.headers()["content-encoding"],
            self.coding,
            "headers describe raw capture"
        );
    }
}

#[tokio::test]
async fn codecs_and_framing_preserve_wire_and_decode_hooks() {
    timeout(Duration::from_secs(15), async {
        for coding in ["gzip", "deflate", "br", "zstd", "identity"] {
            for framing in ["length", "chunked", "eof"] {
                Fixture::encoded(coding, b"data: {\"answer\":\"hello\"}\n\ndata: [DONE]\n\n")
                    .roundtrip(framing)
                    .await;
            }
        }
    })
    .await
    .expect("all codec roundtrips must complete");
}

#[tokio::test]
async fn observer_failures_and_limits_do_not_change_forwarding() {
    timeout(Duration::from_secs(10), async {
        for coding in ["gzip", "deflate", "br", "zstd"] {
            let mut fixture = Fixture::encoded(coding, &vec![b'x'; 16 * 1024]);
            fixture.limit = 1024;
            fixture.decoded.truncate(1024);
            fixture.status = BodyDecodingStatus::Truncated;
            fixture.roundtrip("chunked").await;
        }
        for (coding, status) in [
            ("future", BodyDecodingStatus::UnsupportedEncoding),
            ("gzip", BodyDecodingStatus::InvalidData),
        ] {
            Fixture {
                coding,
                raw: b"opaque invalid body".to_vec(),
                decoded: Vec::new(),
                status,
                limit: 4096,
            }
            .roundtrip("length")
            .await;
        }
    })
    .await
    .expect("invalid content must not stop forwarding");
}

fn test_ca() -> CertificateAuthority {
    abyss_mitm::install_default_crypto_provider();
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let cert = params.self_signed(&key).unwrap();
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("abyss-root-ca.der"), cert.der()).unwrap();
    std::fs::write(directory.path().join("abyss-root-ca.pem"), cert.pem()).unwrap();
    std::fs::write(
        directory.path().join("abyss-root-ca-key.pem"),
        key.serialize_pem(),
    )
    .unwrap();
    abyss_mitm::CaStore::at(directory.path())
        .load_required()
        .unwrap()
}
