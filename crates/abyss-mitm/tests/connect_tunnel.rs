use std::{
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

use abyss_mitm::{
    ExplicitProxyErrorCategory, ExplicitProxyProtocol, ExplicitRequestDecoder,
    ExplicitRequestError, TargetHost,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

#[tokio::test]
async fn public_decoder_preserves_connect_bytes_for_the_mitm_client_stream() {
    let (mut client, mut accepted) = tokio::io::duplex(4096);
    client
        .write_all(
            concat!(
                "CONNECT api.example.test:443 HTTP/1.1\r\n",
                "Host: api.example.test:443\r\n",
                "Proxy-Authorization: Basic local-only\r\n",
                "\r\n",
                "prefetched-client-hello"
            )
            .as_bytes(),
        )
        .await
        .expect("explicit client request should write");

    let decoded = ExplicitRequestDecoder::default()
        .decode(&mut accepted)
        .await
        .expect("CONNECT request should decode");

    assert_eq!(decoded.protocol(), ExplicitProxyProtocol::HttpConnect);
    assert_eq!(decoded.target().authority(), "api.example.test:443");
    assert_eq!(decoded.client_prefix(), b"prefetched-client-hello");
}

#[tokio::test]
async fn public_decoder_normalizes_absolute_http_for_origin_upstream() {
    let (mut client, mut accepted) = tokio::io::duplex(4096);
    client
        .write_all(
            concat!(
                "POST http://127.0.0.1:18080/v1/events?source=test HTTP/1.1\r\n",
                "Host: 127.0.0.1:18080\r\n",
                "Proxy-Connection: keep-alive\r\n",
                "Proxy-Authorization: Bearer proxy-secret\r\n",
                "Content-Length: 7\r\n",
                "Content-Type: application/json\r\n",
                "\r\n",
                "payload"
            )
            .as_bytes(),
        )
        .await
        .expect("absolute-form request should write");

    let decoded = ExplicitRequestDecoder::default()
        .decode(&mut accepted)
        .await
        .expect("absolute-form request should decode");
    let prefix = std::str::from_utf8(decoded.client_prefix())
        .expect("normalized test request should remain UTF-8");

    assert_eq!(decoded.protocol(), ExplicitProxyProtocol::HttpAbsoluteForm);
    assert_eq!(
        decoded.target().host(),
        &TargetHost::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))
    );
    assert_eq!(decoded.target().port(), 18_080);
    assert!(
        prefix.starts_with("POST /v1/events?source=test HTTP/1.1\r\nHost: 127.0.0.1:18080\r\n")
    );
    assert!(!prefix.to_ascii_lowercase().contains("proxy-"));
    assert!(prefix.ends_with("\r\npayload"));
}

#[tokio::test]
async fn public_decoder_timeout_covers_the_whole_header_operation() {
    let (mut client, mut accepted) = tokio::io::duplex(128);
    client
        .write_all(b"CONNECT api.example.test:443 HTTP/1.1\r\n")
        .await
        .expect("partial request should write");

    let error = ExplicitRequestDecoder::new(Duration::from_millis(10))
        .decode(&mut accepted)
        .await
        .err()
        .expect("incomplete open connection should time out");

    assert!(matches!(error, ExplicitRequestError::HeaderTimeout { .. }));
    assert_eq!(error.category(), ExplicitProxyErrorCategory::RequestTimeout);
}

#[tokio::test]
async fn public_decoder_leaves_unread_client_bytes_on_the_stream() {
    let (mut client, mut accepted) = tokio::io::duplex(8192);
    let request_head = concat!(
        "CONNECT api.example.test:443 HTTP/1.1\r\n",
        "Host: api.example.test:443\r\n",
        "\r\n"
    );
    let payload = vec![0x16_u8; 4096];
    client
        .write_all(request_head.as_bytes())
        .await
        .expect("CONNECT head should write");
    client
        .write_all(&payload)
        .await
        .expect("tunnel payload should write");

    let decoded = ExplicitRequestDecoder::default()
        .decode(&mut accepted)
        .await
        .expect("CONNECT request should decode");
    let buffered = decoded.client_prefix().len();
    let mut remaining = vec![0_u8; payload.len() - buffered];
    accepted
        .read_exact(&mut remaining)
        .await
        .expect("unread tunnel payload should remain on the stream");

    assert_eq!(decoded.client_prefix(), &payload[..buffered]);
    assert_eq!(remaining, payload[buffered..]);
}
