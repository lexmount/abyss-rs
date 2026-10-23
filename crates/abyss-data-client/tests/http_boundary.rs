//! Transport boundary tests using real TCP and TLS servers.

use abyss_data_client::{DataClientError, HttpTransport};
use reqwest::Url;
use serde_json::{Value, json};
use std::{
    io::{BufRead as _, BufReader, Read as _, Write as _},
    net::TcpListener,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

struct Fixture {
    url: Url,
    worker: thread::JoinHandle<()>,
}
impl Fixture {
    fn plain(responses: Vec<(String, Duration)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let url = Url::parse(&format!(
            "http://{}/query",
            listener.local_addr().expect("address")
        ))
        .expect("url");
        let worker = thread::spawn(move || {
            for (response, delay) in responses {
                let deadline = Instant::now()
                    .checked_add(Duration::from_secs(5))
                    .expect("deadline");
                let mut socket = loop {
                    match listener.accept() {
                        Ok((socket, _)) => break socket,
                        Err(error)
                            if error.kind() == std::io::ErrorKind::WouldBlock
                                && Instant::now() < deadline =>
                        {
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(error) => panic!("accept: {error}"),
                    }
                };
                socket
                    .set_nonblocking(false)
                    .expect("blocking accepted socket");
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .expect("read timeout");
                let mut reader = BufReader::new(&mut socket);
                loop {
                    let mut line = String::new();
                    assert!(
                        reader.read_line(&mut line).expect("header") > 0,
                        "request ended before its headers"
                    );
                    if line == "\r\n" {
                        break;
                    }
                }
                thread::sleep(delay);
                // Timeout/size tests deliberately close their side of the socket.
                let _result = socket.write_all(response.as_bytes());
            }
        });
        Self { url, worker }
    }
    fn finish(self) {
        self.worker.join().expect("fixture completed");
    }
}
fn transport(timeout: Duration, retries: u8) -> HttpTransport {
    HttpTransport::new(timeout, 1024, None, retries).expect("transport")
}

#[test]
fn limits_content_length_and_chunked_bodies() {
    for response in [
        "HTTP/1.1 200 OK\r\nContent-Length: 2048\r\n\r\n".to_owned(),
        format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n800\r\n{}\r\n0\r\n\r\n",
            "x".repeat(2048)
        ),
    ] {
        let server = Fixture::plain(vec![(response, Duration::ZERO)]);
        assert!(
            matches!(
                transport(Duration::from_secs(2), 0).get::<Value>(&server.url, None),
                Err(DataClientError::ResponseTooLarge { .. })
            ),
            "both declared and streaming bodies must respect the size budget"
        );
        server.finish();
    }
}

#[test]
fn retries_transient_gets_but_not_auth_posts() {
    let unavailable = "HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\nRetry-After: 0\r\n\r\n";
    let success = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";
    let server = Fixture::plain(vec![
        (unavailable.into(), Duration::ZERO),
        (success.into(), Duration::ZERO),
    ]);
    assert_eq!(
        transport(Duration::from_secs(2), 1)
            .get::<Value>(&server.url, None)
            .expect("retried GET"),
        json!({}),
        "GET retries"
    );
    server.finish();
    let server = Fixture::plain(vec![(unavailable.into(), Duration::ZERO)]);
    assert!(
        matches!(
            transport(Duration::from_secs(2), 3).post::<Value, _>(&server.url, None, &json!({})),
            Err(DataClientError::Http { status: 503 })
        ),
        "never replay token exchange or other POSTs"
    );
    server.finish();
}

#[test]
fn request_deadline_includes_waiting_for_response() {
    let server = Fixture::plain(vec![(
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}".into(),
        Duration::from_millis(400),
    )]);
    let started = Instant::now();
    assert!(
        matches!(
            transport(Duration::from_millis(100), 0).get::<Value>(&server.url, None),
            Err(DataClientError::Transport(_))
        ),
        "request deadline enforced"
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "bounded execution"
    );
    server.finish();
}

#[test]
fn private_ca_is_trusted_only_when_explicitly_configured() {
    let certificate =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("certificate");
    let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("TLS versions")
    .with_no_client_auth()
    .with_single_cert(
        vec![certificate.cert.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.signing_key.serialize_der()).into(),
    )
    .expect("TLS configuration");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind TLS");
    listener.set_nonblocking(true).expect("nonblocking TLS");
    let url = Url::parse(&format!(
        "https://localhost:{}/",
        listener.local_addr().expect("address").port()
    ))
    .expect("url");
    let worker = thread::spawn(move || {
        let config = Arc::new(server_config);
        for _attempt in 0..2_u8 {
            let deadline = Instant::now()
                .checked_add(Duration::from_secs(5))
                .expect("deadline");
            let socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("TLS accept: {error}"),
                }
            };
            socket
                .set_nonblocking(false)
                .expect("blocking accepted TLS socket");
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .expect("TLS read deadline");
            let mut tls = rustls::StreamOwned::new(
                rustls::ServerConnection::new(Arc::clone(&config)).expect("TLS connection"),
                socket,
            );
            let mut bytes = [0; 1024];
            if tls.read(&mut bytes).is_ok() {
                tls.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                )
                .expect("TLS response");
            }
        }
    });
    assert!(
        transport(Duration::from_secs(2), 0)
            .get::<Value>(&url, None)
            .is_err(),
        "untrusted private certificate rejected"
    );
    let trusted = HttpTransport::new(
        Duration::from_secs(2),
        1024,
        Some(certificate.cert.pem().as_bytes()),
        0,
    )
    .expect("custom CA");
    assert_eq!(
        trusted.get::<Value>(&url, None).expect("trusted TLS"),
        json!({}),
        "explicit CA trust works"
    );
    worker.join().expect("TLS fixture completed");
}
