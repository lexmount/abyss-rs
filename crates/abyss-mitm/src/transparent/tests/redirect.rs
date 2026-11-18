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
    let provider = tokio::spawn(serve_provider(
        listener,
        client_tls.then_some(acceptor),
        wrong_certificate,
    ));
    let (client, server) = connected_pair().await;
    let mut flow = AcceptedTcpFlow::from_destination_parts(
        Box::new(server),
        None,
        None,
        if transparent {
            DestinationAddress::Known(format!("127.0.0.2:{port}").parse().unwrap())
        } else {
            DestinationAddress::Unknown
        },
        None,
    )
    .with_destination_host(Some("original.invalid".into()));
    if !transparent {
        flow = flow.with_ingress(FlowIngress::ExplicitProxy {
            protocol: ExplicitProxyProtocol::HttpConnect,
            target: TargetAuthority::parse(&format!("original.invalid:{port}")).unwrap(),
            upstream_proxy: None,
            proxy_endpoint: None,
        });
    }
    let engine = super::test_mitm_engine_trusting(&ca).with_tls_decryption_policy(
        serde_json::from_value(serde_json::json!({
            "default_action":"block",
            "rules":[{"id":"redirect", "action":"redirect", "destination_hosts":["original.invalid"], "target":"localhost"}]
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
    client.write_all(format!("GET /custom/path%2Fpart?q=a%2Bb HTTP/1.1\r\nHost: original.invalid:{port}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
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

async fn serve_provider(
    listener: TcpListener,
    acceptor: Option<TlsAcceptor>,
    wrong_certificate: bool,
) {
    let port = listener.local_addr().unwrap().port();
    let (tcp, _) = listener.accept().await.unwrap();
    let mut stream: crate::BoxedDuplexStream = if let Some(acceptor) = acceptor {
        let handshake = acceptor.accept(tcp).await;
        if wrong_certificate {
            assert!(
                handshake.is_err(),
                "original identity must not authenticate the redirect target"
            );
            return;
        }
        let stream = handshake.unwrap();
        assert_eq!(stream.get_ref().1.server_name(), Some("localhost"));
        Box::new(stream)
    } else {
        Box::new(tcp)
    };
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

struct SelectProvider(String);

impl crate::RequestForwardingControl for SelectProvider {
    type Plan = ();

    fn plan(&self) -> Option<()> {
        Some(())
    }

    fn defers_provider(&self, _flow: &crate::FlowContext, _head: &http::Request<()>) -> bool {
        true
    }

    fn before_forward(
        &self,
        (): (),
        view: crate::RequestView<'_>,
    ) -> impl std::future::Future<
        Output = Result<crate::RequestForwardingResult, crate::LocalRejection>,
    > + Send {
        let mut editor = crate::RequestEditor::new(view);
        editor.route_provider(&self.0).unwrap();
        editor
            .headers_mut()
            .insert("x-team", "literal-value".parse().unwrap());
        editor.replace_body(bytes::Bytes::from_static(
            br#"{"model":"selected","input":"hello"}"#,
        ));
        std::future::ready(Ok(editor.finish(())))
    }
}

#[tokio::test]
async fn plugin_selects_https_authority_port_and_path_before_any_original_request() {
    let ca = test_ca();
    let selected = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let original = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let selected_port = selected.local_addr().unwrap().port();
    let acceptor = TlsAcceptor::from(
        MitmTlsAuthority::from_ca(&ca)
            .unwrap()
            .server_config_for_sni("localhost")
            .await
            .unwrap(),
    );
    let provider = tokio::spawn(async move {
        let (stream, _) = selected.accept().await.unwrap();
        let mut stream = acceptor.accept(stream).await.unwrap();
        let head = read_http_head(&mut stream).await.to_lowercase();
        assert!(
            head.starts_with("post /custom/v1/responses http/1.1"),
            "selected path must be used"
        );
        assert!(
            head.contains(&format!("host: localhost:{selected_port}")),
            "selected authority must be used"
        );
        assert!(
            head.contains("x-team: literal-value"),
            "selected credential must reach provider"
        );
        assert!(
            !head.contains("original-secret"),
            "only selected credentials reach the provider"
        );
        let expected = br#"{"model":"selected","input":"hello"}"#;
        let mut body = vec![0; expected.len()];
        stream.read_exact(&mut body).await.unwrap();
        assert_eq!(body, expected);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
    });
    let (mut client, server) = connected_pair().await;
    let flow = AcceptedTcpFlow::from_destination_parts(
        Box::new(server),
        None,
        None,
        DestinationAddress::Known(original.local_addr().unwrap()),
        None,
    );
    let control = SelectProvider(format!(
        "https://localhost:{selected_port}/custom/v1/responses"
    ));
    let engine = super::test_mitm_engine_trusting(&ca);
    let worker = tokio::spawn(async move { engine.handle_flow_with_control(flow, &control).await });
    client.write_all(b"POST /v1/responses HTTP/1.1\r\nHost: original.invalid\r\nAuthorization: Bearer original-secret\r\nContent-Length: 17\r\n\r\n{\"input\":\"hello\"}").await.unwrap();
    let mut response = Vec::new();
    timeout(Duration::from_secs(6), client.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(
        response.ends_with(b"ok"),
        "client receives chosen provider response"
    );
    worker.await.unwrap().unwrap();
    provider.await.unwrap();
    assert!(
        timeout(Duration::from_millis(50), original.accept())
            .await
            .is_err(),
        "unselected origin should receive no connection"
    );
}
