//! SOCKS5 wire regressions and real-socket deadline/configuration coverage.

use std::time::Duration;

use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpListener,
};

use super::{
    ProxyConnectStage, UpstreamProxy, UpstreamProxyConfig, UpstreamProxyError,
    UpstreamProxyProtocol, config::ProxyCredentials, socks5::Socks5Handshake,
};
use crate::{BoxedDuplexStream, TargetAuthority};

fn config() -> UpstreamProxyConfig {
    UpstreamProxyConfig {
        protocol: UpstreamProxyProtocol::Socks5,
        endpoint: "socks5://127.0.0.1:1080".into(),
        ca_file: None,
        credentials_file: None,
        connect_timeout_ms: 1000,
        handshake_timeout_ms: 1000,
    }
}

#[test]
fn configuration_matches_protocol_and_round_trips() {
    let mut config = config();
    for endpoint in ["socks5://proxy.invalid:1080/", "socks5://[::1]:1080"] {
        config.endpoint = endpoint.into();
        config.validate().unwrap();
        let json = serde_json::to_string(&config).unwrap();
        assert_eq!(
            serde_json::from_str::<UpstreamProxyConfig>(&json).unwrap(),
            config
        );
    }
    for endpoint in [
        "http://proxy.invalid:1080",
        "https://proxy.invalid:1080",
        "socks5h://proxy.invalid:1080",
        "socks5://user:secret@proxy.invalid:1080",
        "socks5://proxy.invalid",
        "socks5://proxy.invalid:0",
        "socks5://proxy.invalid:1080/path",
        "socks5://proxy.invalid:1080?q=secret",
    ] {
        config.endpoint = endpoint.into();
        let error = config.validate().unwrap_err().to_string();
        assert!(!error.contains("secret"));
    }
    config.endpoint = "socks5://proxy.invalid:1080".into();
    config.ca_file = Some(std::env::temp_dir().join("ca.pem"));
    assert!(config.validate().is_err());
}

#[test]
fn credentials_use_utf8_byte_limits_and_are_loaded_at_configuration_time() {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("credentials.json");
    let mut config = config();
    config.credentials_file = Some(file.clone());
    for (username, password, valid) in [
        ("user:name".into(), "password".into(), true),
        ("u".repeat(255), "p".repeat(255), true),
        ("\u{00e9}".repeat(127), "password".into(), true),
        ("\u{00e9}".repeat(128), "password".into(), false),
        (String::new(), "password".into(), false),
        ("username".into(), String::new(), false),
        ("u".repeat(256), "password".into(), false),
        ("username".into(), "p".repeat(256), false),
    ] {
        std::fs::write(
            &file,
            serde_json::to_vec(&serde_json::json!({"username": username, "password": password}))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(UpstreamProxy::new(&config).is_ok(), valid);
    }
    std::fs::write(&file, b"not-json-secret").unwrap();
    assert!(
        !UpstreamProxy::new(&config)
            .err()
            .unwrap()
            .to_string()
            .contains("not-json-secret")
    );
}

#[tokio::test]
async fn address_encodings_reply_families_and_early_bytes_are_preserved() {
    for (target, address) in [
        ("198.51.100.7:443", vec![1, 198, 51, 100, 7]),
        (
            "[2001:db8::1]:443",
            vec![4, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        ),
        (
            "unresolvable.invalid:443",
            [vec![3, 20], b"unresolvable.invalid".to_vec()].concat(),
        ),
    ] {
        for reply_address in [
            vec![1, 0, 0, 0, 0],
            vec![4; 17],
            vec![3, 3, b'd', b'n', b's'],
        ] {
            let (client, mut server) = tokio::io::duplex(1024);
            let mut client: BoxedDuplexStream = Box::new(client);
            let expected = [vec![5, 1, 0], address.clone(), vec![1, 187]].concat();
            let server = tokio::spawn(async move {
                let mut greeting = [0; 3];
                server.read_exact(&mut greeting).await.unwrap();
                assert_eq!(greeting, [5, 1, 0]);
                server.write_all(&[5, 0]).await.unwrap();
                let mut request = vec![0; expected.len()];
                server.read_exact(&mut request).await.unwrap();
                assert_eq!(request, expected);
                let reply = [vec![5, 0, 0], reply_address, vec![0, 0], b"early".to_vec()].concat();
                // Fragment every byte to exercise exact-length reads, including port bytes.
                for byte in reply {
                    server.write_all(&[byte]).await.unwrap();
                    tokio::task::yield_now().await;
                }
            });
            Socks5Handshake::new(None)
                .unwrap()
                .negotiate(&mut client, &TargetAuthority::parse(target).unwrap())
                .await
                .unwrap();
            let mut early = [0; 5];
            client.read_exact(&mut early).await.unwrap();
            assert_eq!(&early, b"early");
            server.await.unwrap();
        }
    }
}

#[tokio::test]
async fn credentials_are_used_only_for_proxy_authentication() {
    let (client, mut server) = tokio::io::duplex(1024);
    let mut client: BoxedDuplexStream = Box::new(client);
    let server = tokio::spawn(async move {
        let mut greeting = [0; 3];
        server.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 1, 2]);
        server.write_all(&[5, 2]).await.unwrap();
        let mut authentication = [0; 11];
        server.read_exact(&mut authentication).await.unwrap();
        assert_eq!(&authentication, b"\x01\x04user\x04pass");
        server.write_all(&[1, 0]).await.unwrap();
        let mut request = [0; 10];
        server.read_exact(&mut request).await.unwrap();
        assert_eq!(request, [5, 1, 0, 1, 198, 51, 100, 7, 1, 187]);
        server
            .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
    });
    let handshake = Socks5Handshake::new(Some(&ProxyCredentials {
        username: "user".into(),
        password: "pass".into(),
    }))
    .unwrap();
    handshake
        .negotiate(
            &mut client,
            &TargetAuthority::parse("198.51.100.7:443").unwrap(),
        )
        .await
        .unwrap();
    server.await.unwrap();
}

async fn failure(reply: Vec<u8>, authenticated: bool) -> UpstreamProxyError {
    let (client, mut server) = tokio::io::duplex(1024);
    let mut client: BoxedDuplexStream = Box::new(client);
    let server = tokio::spawn(async move {
        // Preload scripted server responses and keep the read side open until negotiation ends.
        server.write_all(&reply).await.unwrap();
        server.shutdown().await.unwrap();
        let mut request = Vec::new();
        server.read_to_end(&mut request).await.unwrap();
    });
    let credentials = authenticated.then(|| ProxyCredentials {
        username: "user".into(),
        password: "pass".into(),
    });
    let result = Socks5Handshake::new(credentials.as_ref())
        .unwrap()
        .negotiate(
            &mut client,
            &TargetAuthority::parse("target.invalid:443").unwrap(),
        )
        .await;
    drop(client);
    server.await.unwrap();
    result.unwrap_err()
}

#[tokio::test]
async fn rejects_authentication_downgrade_and_bad_credentials() {
    for (reply, authenticated) in [
        (vec![5, 0], true),
        (vec![5, 2], false),
        (vec![5, 255], false),
        (vec![5, 1], false),
        (vec![5, 2, 1, 1], true),
    ] {
        assert!(matches!(
            failure(reply, authenticated).await,
            UpstreamProxyError::Authentication
        ));
    }
    assert!(matches!(
        failure(vec![5, 2, 2, 0], true).await,
        UpstreamProxyError::Protocol { .. }
    ));
}

#[tokio::test]
async fn rejects_invalid_framing_eof_and_socks_reply_codes() {
    for reply in [
        vec![4, 0],
        vec![5, 0, 4, 0, 0, 1],
        vec![5, 0, 5, 0, 1, 1],
        vec![5, 0, 5, 0, 0, 2],
        vec![5, 0, 5, 0, 0, 3, 0],
    ] {
        assert!(matches!(
            failure(reply, false).await,
            UpstreamProxyError::Protocol { .. }
        ));
    }
    for reply in [
        vec![],
        vec![5],
        vec![5, 0, 5, 0, 0, 1, 0],
        vec![5, 0, 5, 0, 0, 3, 3, b'd'],
    ] {
        assert!(matches!(
            failure(reply, false).await,
            UpstreamProxyError::Io {
                stage: ProxyConnectStage::Handshake,
                ..
            }
        ));
    }
    for reply in 1..=8 {
        assert!(
            matches!(failure(vec![5, 0, 5, reply, 0, 1], false).await, UpstreamProxyError::Socks5Rejected { reply: code } if code == reply)
        );
    }
}

#[tokio::test]
async fn method_authentication_and_connect_share_one_deadline() {
    for responses in [vec![], vec![5, 2], vec![5, 2, 1, 0]] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = config();
        config.endpoint = format!("socks5://{}", listener.local_addr().unwrap());
        config.handshake_timeout_ms = 30;
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("credentials.json");
        std::fs::write(&file, br#"{"username":"user","password":"pass"}"#).unwrap();
        config.credentials_file = Some(file);
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(&responses).await.unwrap();
            tokio::time::sleep(Duration::from_secs(2)).await;
        });
        let result = UpstreamProxy::new(&config)
            .unwrap()
            .connect_tunnel(&TargetAuthority::parse("target.invalid:443").unwrap(), &[])
            .await;
        assert!(matches!(
            result,
            Err(UpstreamProxyError::Timeout {
                stage: ProxyConnectStage::Handshake,
                ..
            })
        ));
        task.abort();
    }
}
