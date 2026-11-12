//! Socket-level redirect checks for target selection and independent TLS identities.

use super::{connected_pair, read_http_head, test_ca, test_client_config_trusting};
use crate::{
    AcceptedTcpFlow, DestinationAddress, ExplicitProxyProtocol, FlowIngress, TargetAuthority,
    TransparentFlowOutcome, tls::MitmTlsAuthority,
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpListener,
    time::{Duration, timeout},
};
use tokio_rustls::{TlsAcceptor, TlsConnector, rustls::pki_types::ServerName};

#[tokio::test]
async fn redirects_before_connecting_and_validates_selected_tls_identity() {
    timeout(Duration::from_secs(15), async {
        for transparent in [false, true] {
            for client_tls in [false, true] {
                run_redirect(transparent, client_tls, false).await;
            }
        }
        run_redirect(false, true, true).await;
    })
    .await
    .expect("redirect must finish");
}

async fn run_redirect(transparent: bool, client_tls: bool, wrong_certificate: bool) {
    let ca = test_ca();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let cert_host = if wrong_certificate {
        "original.invalid"
    } else {
        "localhost"
    };
    let acceptor = TlsAcceptor::from(
        MitmTlsAuthority::from_ca(&ca)
            .unwrap()
            .server_config_for_sni(cert_host)
            .await
            .unwrap(),
    );
    let provider = tokio::spawn(serve_provider(listener, acceptor, wrong_certificate));
    let (client, server) = connected_pair().await;
    let mut flow = AcceptedTcpFlow::from_destination_parts(
        Box::new(server),
        None,
        None,
        if transparent {
            DestinationAddress::Known("127.0.0.1:1".parse().unwrap())
        } else {
            DestinationAddress::Unknown
        },
        None,
    )
    .with_destination_host(Some("original.invalid".into()));
    if !transparent {
        flow = flow.with_ingress(FlowIngress::ExplicitProxy {
            protocol: ExplicitProxyProtocol::HttpConnect,
            target: TargetAuthority::parse("original.invalid:443").unwrap(),
            upstream_proxy: None,
            proxy_endpoint: None,
        });
    }
    let engine = super::test_mitm_engine_trusting(&ca).with_tls_decryption_policy(
        serde_json::from_value(serde_json::json!({
            "default_action":"block",
            "rules":[{"id":"redirect", "action":"redirect", "destination_hosts":["original.invalid"], "target":format!("https://localhost:{port}")}]
        })).unwrap()
    ).unwrap();
    let worker = tokio::spawn(async move { engine.handle_flow(flow).await });
    let mut client: crate::BoxedDuplexStream = if client_tls {
        Box::new(
            TlsConnector::from(test_client_config_trusting(&ca))
                .connect(ServerName::try_from("original.invalid").unwrap(), client)
                .await
                .unwrap(),
        )
    } else {
        Box::new(client)
    };
    client.write_all(b"GET /custom/path%2Fpart?q=a%2Bb HTTP/1.1\r\nHost: original.invalid:443\r\nConnection: close\r\n\r\n").await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    let result = worker.await.unwrap();
    if wrong_certificate {
        assert!(response.starts_with(b"HTTP/1.1 502"));
        assert!(result.is_err());
    } else {
        assert!(
            response.ends_with(b"redirected"),
            "{}",
            String::from_utf8_lossy(&response)
        );
        assert!(matches!(
            result.unwrap(),
            TransparentFlowOutcome::Intercepted(_)
        ));
    }
    provider.await.unwrap();
}

async fn serve_provider(listener: TcpListener, acceptor: TlsAcceptor, wrong_certificate: bool) {
    let port = listener.local_addr().unwrap().port();
    let (tcp, _) = listener.accept().await.unwrap();
    let handshake = acceptor.accept(tcp).await;
    if wrong_certificate {
        assert!(
            handshake.is_err(),
            "original identity must not authenticate the redirect target"
        );
        return;
    }
    let mut stream = handshake.unwrap();
    assert_eq!(stream.get_ref().1.server_name(), Some("localhost"));
    let head = read_http_head(&mut stream).await;
    assert!(
        head.starts_with("GET /custom/path%2Fpart?q=a%2Bb HTTP/1.1\r\n"),
        "{head}"
    );
    assert!(
        head.to_lowercase()
            .contains(&format!("host: localhost:{port}\r\n")),
        "{head}"
    );
    stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nredirected")
        .await
        .unwrap();
    stream.shutdown().await.unwrap();
}
