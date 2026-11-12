//! HTTP transport tests for credential boundaries and upgrade validation.

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::connect_http;

#[tokio::test]
async fn rejects_nonlocal_or_nonorigin_urls_without_exposing_credentials() {
    for origin in [
        "https://localhost/",
        "http://example.invalid/",
        "http://127.0.0.1/path",
        "http://secret@localhost/",
        "http://localhost/?secret=value",
        "http://localhost/#secret",
    ] {
        let result = connect_http(origin, "secret-bearer").await;
        let error = result.err().expect("invalid origin must fail").to_string();
        assert!(!error.contains("secret"));
    }
}

#[tokio::test]
async fn authenticates_upgrade_and_carries_bidirectional_protocol_bytes() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(stream.read_u8().await.unwrap());
        }
        let head = String::from_utf8(head).unwrap().to_ascii_lowercase();
        assert!(head.starts_with("post /v1/plugins/connect http/1.1\r\n"));
        assert!(head.contains("\r\nauthorization: bearer test-bearer\r\n"));
        assert!(head.contains("\r\nupgrade: abyss-plugin-v1\r\n"));
        stream.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: abyss-plugin-v1\r\n\r\nhello").await.unwrap();
        let mut message = [0_u8; 5];
        stream.read_exact(&mut message).await.unwrap();
        assert_eq!(&message, b"reply");
    });
    let mut stream = connect_http(&origin, "test-bearer").await.unwrap();
    let mut message = [0_u8; 5];
    stream.read_exact(&mut message).await.unwrap();
    assert_eq!(&message, b"hello");
    stream.write_all(b"reply").await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn rejects_redirects_auth_errors_and_wrong_protocol() {
    for response in [
        "HTTP/1.1 302 Found\r\nLocation: http://example.invalid/secret\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: wrong\r\n\r\n",
    ] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(stream.read_u8().await.unwrap());
            }
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        let error = connect_http(&origin, "private-token").await.err().unwrap();
        assert_eq!(error.to_string(), "plugin API upgrade rejected");
        server.await.unwrap();
    }
}
