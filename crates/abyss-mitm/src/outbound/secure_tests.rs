//! Real TLS proxy tests covering identity, trust, credentials and bounded negotiation.

use std::{path::PathBuf, sync::Arc, time::Duration};

use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpListener,
    task::JoinHandle,
    time::timeout,
};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{ServerConfig, pki_types::PrivatePkcs8KeyDer},
};

use super::{HttpConnectProxy, ProxyConnectStage, UpstreamProxyConfig, UpstreamProxyError};
use crate::TargetAuthority;

struct TlsProxy {
    config: UpstreamProxyConfig,
    directory: tempfile::TempDir,
    task: JoinHandle<Option<String>>,
}

impl TlsProxy {
    async fn start(names: Vec<String>, expired: bool) -> Self {
        crate::install_default_crypto_provider();
        let directory = tempfile::tempdir().unwrap();
        let key = KeyPair::generate().unwrap();
        let mut root = CertificateParams::default();
        root.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let root_certificate = root.self_signed(&key).unwrap();
        let ca_file = directory.path().join("proxy-ca.pem");
        std::fs::write(&ca_file, root_certificate.pem()).unwrap();
        let issuer = Issuer::new(root, key);
        let leaf_key = KeyPair::generate().unwrap();
        let mut leaf = CertificateParams::new(names).unwrap();
        if expired {
            leaf.not_before = time::OffsetDateTime::now_utc()
                .checked_sub(time::Duration::days(2))
                .unwrap();
            leaf.not_after = time::OffsetDateTime::now_utc()
                .checked_sub(time::Duration::days(1))
                .unwrap();
        }
        let leaf = leaf.signed_by(&leaf_key, &issuer).unwrap();
        let mut tls = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.der().clone()],
                PrivatePkcs8KeyDer::from(leaf_key.serialize_der()).into(),
            )
            .unwrap();
        tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(tls));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let config = UpstreamProxyConfig {
            protocol: super::UpstreamProxyProtocol::HttpConnect,
            endpoint: format!(
                "https://localhost:{}",
                listener.local_addr().unwrap().port()
            ),
            ca_file: Some(ca_file),
            credentials_file: None,
            connect_timeout_ms: 1000,
            handshake_timeout_ms: 1000,
        };
        let task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let Ok(mut stream) = acceptor.accept(socket).await else {
                return None;
            };
            assert_eq!(stream.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(stream.read_u8().await.unwrap());
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\n\r\nprefix")
                .await
                .unwrap();
            stream.flush().await.unwrap();
            let (mut reader, mut writer) = tokio::io::split(stream);
            let _copied = tokio::io::copy(&mut reader, &mut writer).await;
            let _closed = writer.shutdown().await;
            Some(String::from_utf8(request).unwrap())
        });
        Self {
            config,
            directory,
            task,
        }
    }

    fn credentials(&mut self, json: &[u8]) -> PathBuf {
        let path = self.directory.path().join("credentials.json");
        std::fs::write(&path, json).unwrap();
        self.config.credentials_file = Some(path.clone());
        path
    }
}

#[tokio::test]
async fn authenticated_https_tunnel_validates_proxy_and_keeps_target_unresolved() {
    for host in ["localhost", "127.0.0.1"] {
        let mut fixture = TlsProxy::start(vec![host.to_owned()], false).await;
        fixture.config.endpoint = fixture.config.endpoint.replace("localhost", host);
        let path = fixture.credentials(br#"{"username":"user","password":"pass:word"}"#);
        let proxy = HttpConnectProxy::new(&fixture.config).unwrap();
        // Material belongs to the validated snapshot, not to per-flow file reads.
        std::fs::write(path, b"invalid credentials").unwrap();
        let mut tunnel = proxy
            .connect_tunnel(&TargetAuthority::parse("target.invalid:443").unwrap(), &[])
            .await
            .unwrap();
        let mut prefix = [0; 6];
        tunnel.stream.read_exact(&mut prefix).await.unwrap();
        assert_eq!(&prefix, b"prefix");
        tunnel.stream.write_all(b"target bytes").await.unwrap();
        tunnel.stream.flush().await.unwrap();
        let mut echoed = [0; 12];
        tunnel.stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"target bytes");
        tunnel.stream.shutdown().await.unwrap();
        let request = timeout(Duration::from_secs(2), fixture.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(
            request,
            "CONNECT target.invalid:443 HTTP/1.1\r\nHost: target.invalid:443\r\nProxy-Authorization: Basic dXNlcjpwYXNzOndvcmQ=\r\n\r\n"
        );
    }
}

#[tokio::test]
async fn invalid_proxy_certificates_fail_before_sending_credentials() {
    for (names, expired, trust) in [
        (vec!["localhost".into()], false, false),
        (vec!["wrong.invalid".into()], false, true),
        (vec!["localhost".into()], true, true),
    ] {
        let mut fixture = TlsProxy::start(names, expired).await;
        if !trust {
            fixture.config.ca_file = None;
        }
        fixture.credentials(br#"{"username":"user","password":"secret"}"#);
        let proxy = HttpConnectProxy::new(&fixture.config).unwrap();
        let result = proxy
            .connect_tunnel(&TargetAuthority::parse("target.invalid:443").unwrap(), &[])
            .await;
        assert!(matches!(
            result,
            Err(UpstreamProxyError::Io {
                stage: ProxyConnectStage::TlsHandshake,
                ..
            })
        ));
        assert!(
            timeout(Duration::from_secs(2), fixture.task)
                .await
                .unwrap()
                .unwrap()
                .is_none()
        );
    }
}

#[tokio::test]
async fn proxy_tls_has_a_deadline_and_cancellation_closes_the_socket() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let config: UpstreamProxyConfig = serde_json::from_value(serde_json::json!({
        "protocol": "http_connect", "endpoint": format!("https://{}", listener.local_addr().unwrap()),
        "handshake_timeout_ms": 30_u64
    })).unwrap();
    let proxy = HttpConnectProxy::new(&config).unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = Vec::new();
        timeout(Duration::from_secs(2), stream.read_to_end(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert!(!bytes.windows(7).any(|bytes| bytes == b"CONNECT"));
    });
    let result = proxy
        .connect_tunnel(&TargetAuthority::parse("target.invalid:443").unwrap(), &[])
        .await;
    assert!(matches!(
        result,
        Err(UpstreamProxyError::Timeout {
            stage: ProxyConnectStage::TlsHandshake,
            ..
        })
    ));
    task.await.unwrap();
}

#[test]
fn configuration_material_is_validated_without_exposing_secrets() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("credentials.json");
    let mut config: UpstreamProxyConfig = serde_json::from_value(serde_json::json!({
        "protocol":"http_connect", "endpoint":"https://proxy.test:443", "credentials_file":path
    }))
    .unwrap();
    for invalid in [
        br#"{"username":"secret:name","password":"secret"}"#.as_slice(),
        br#"{"username":"user","password":"secret\r\n"}"#,
        br#"{"username":"user","password":1}"#,
        br#"{"username":"user","password":"secret","extra":"secret"}"#,
        b"secret malformed JSON",
    ] {
        std::fs::write(&path, invalid).unwrap();
        let error = HttpConnectProxy::new(&config).err().unwrap();
        assert!(!error.to_string().contains("secret"));
    }
    std::fs::write(&path, br#"{"username":"","password":""}"#).unwrap();
    assert!(HttpConnectProxy::new(&config).is_ok());
    assert!(!serde_json::to_string(&config).unwrap().contains("password"));
    config.credentials_file = Some(PathBuf::from("relative.json"));
    assert!(config.validate().is_err());
    config.credentials_file = None;
    config.ca_file = Some(path.clone());
    assert!(HttpConnectProxy::new(&config).is_err());
    std::fs::write(
        &path,
        "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----",
    )
    .unwrap();
    assert!(HttpConnectProxy::new(&config).is_err());
    config.endpoint = "http://proxy.test:80".into();
    assert!(config.validate().is_err());
}
