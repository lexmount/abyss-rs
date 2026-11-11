//! Provider selection changes upstream TLS identity without changing client TLS.

use http::Uri;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpListener,
};

use crate::{AcceptedTcpFlow, RequestEditor, RequestForwardingControl, RequestView};

struct SwitchProvider(Uri);

impl RequestForwardingControl for SwitchProvider {
    type Plan = ();

    fn plan(&self) -> Option<()> {
        Some(())
    }

    fn before_forward(
        &self,
        (): (),
        request: RequestView<'_>,
    ) -> impl std::future::Future<
        Output = Result<crate::RequestForwardingResult, crate::LocalRejection>,
    > + Send {
        let mut editor = RequestEditor::new(request);
        editor.set_upstream(
            self.0.clone(),
            self.0.authority().unwrap().as_str().parse().unwrap(),
        );
        std::future::ready(Ok(editor.finish(())))
    }
}

#[tokio::test]
async fn switched_provider_uses_its_own_sni_and_certificate_identity() {
    for certificate_name in ["localhost", "original.test"] {
        let ca = super::test_ca();
        let original = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_port = target.local_addr().unwrap().port();
        let acceptor = tokio_rustls::TlsAcceptor::from(
            crate::tls::MitmTlsAuthority::from_ca(&ca)
                .unwrap()
                .server_config_for_sni(certificate_name)
                .await
                .unwrap(),
        );
        let provider = tokio::spawn(async move {
            let (stream, _) = target.accept().await.unwrap();
            let stream = acceptor.accept(stream).await;
            if certificate_name != "localhost" {
                assert!(
                    stream.is_err(),
                    "original provider certificate must not authenticate the new target"
                );
                return;
            }
            let mut stream = stream.unwrap();
            assert_eq!(stream.get_ref().1.server_name(), Some("localhost"));
            let head = super::read_http_head(&mut stream).await;
            assert!(head.starts_with("POST /gateway/responses?keep=1 HTTP/1.1\r\n"));
            assert!(
                head.to_lowercase()
                    .contains(&format!("host: localhost:{target_port}\r\n"))
            );
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
        });
        let (client, server) = super::connected_pair().await;
        let flow = AcceptedTcpFlow::new(
            server,
            "127.0.0.1:50001".parse().unwrap(),
            "127.0.0.1:18091".parse().unwrap(),
            original.local_addr().unwrap().into(),
        );
        let engine = super::test_mitm_engine_trusting(&ca)
            .with_tls_decryption_policy(
                serde_json::from_value(serde_json::json!({"default_action":"intercept"})).unwrap(),
            )
            .unwrap();
        let control = SwitchProvider(
            format!("https://localhost:{target_port}/gateway/responses?keep=1")
                .parse()
                .unwrap(),
        );
        let relay =
            tokio::spawn(async move { engine.handle_flow_with_control(flow, &control).await });
        let mut client = tokio_rustls::TlsConnector::from(super::test_client_config_trusting(&ca))
            .connect(
                tokio_rustls::rustls::pki_types::ServerName::try_from("original.test").unwrap(),
                client,
            )
            .await
            .unwrap();
        client
            .write_all(
                b"POST /v1/responses HTTP/1.1\r\nHost: original.test\r\nContent-Length: 0\r\n\r\n",
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        let _closed = client.read_to_end(&mut response).await;
        let result = relay.await.unwrap();
        if certificate_name == "localhost" {
            assert!(result.is_ok(), "{result:?}");
            assert!(response.ends_with(b"ok"));
        } else {
            assert!(
                matches!(
                    result,
                    Err(crate::TransparentFlowError::Io {
                        operation: crate::FlowOperation::ConnectProviderTls,
                        ..
                    })
                ),
                "{result:?}"
            );
        }
        provider.await.unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(30), original.accept())
                .await
                .is_err()
        );
    }
}
