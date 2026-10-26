//! Target TLS and hook behavior over an actual HTTP CONNECT tunnel.

use super::{connected_pair, read_http_head, test_ca, test_client_config_trusting};
use std::{future, sync::Arc, time::Duration};

use parking_lot::Mutex;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tokio_rustls::{TlsAcceptor, TlsConnector, rustls::pki_types::ServerName};

use crate::{
    AcceptedTcpFlow, DestinationAddress, ExplicitProxyProtocol, FlowIngress, HookFuture,
    HttpExchange, MitmEngine, MitmHook, TargetAuthority, TlsDecryptionAction, TlsDecryptionPolicy,
    TransparentFlowOutcome,
    outbound::{HttpConnectProxy, UpstreamProxyConfig, UpstreamProxyProtocol},
    tls::MitmTlsAuthority,
};

#[derive(Clone)]
struct ObservedTarget {
    exchanges: Arc<Mutex<Vec<(String, bool)>>>,
}

impl MitmHook for ObservedTarget {
    fn on_http_exchange<'a>(&'a self, exchange: &'a HttpExchange) -> HookFuture<'a> {
        self.exchanges.lock().push((
            exchange
                .flow
                .ingress
                .proxy_target()
                .expect("explicit authority")
                .authority(),
            exchange.flow.original_destination.socket_addr().is_none(),
        ));
        Box::pin(future::ready(Ok(())))
    }
}

#[tokio::test]
async fn preserves_separate_client_and_target_trust_over_connect() {
    timeout(Duration::from_secs(10), async {
        for action in [
            TlsDecryptionAction::Intercept,
            TlsDecryptionAction::Passthrough,
        ] {
            run_tls_chain(action).await;
        }
    })
    .await
    .expect("TLS chain test must finish");
}

async fn run_tls_chain(action: TlsDecryptionAction) {
    let broker_ca = test_ca();
    let target_ca = test_ca();
    let host = "only-proxy-knows.invalid";
    let target = TargetAuthority::parse(&format!("{host}:443")).expect("target authority");
    let servers = TlsChainServers::start(&target_ca, host).await;
    let proxy_address = servers.proxy_address;
    let connector = HttpConnectProxy::new(&UpstreamProxyConfig {
        protocol: UpstreamProxyProtocol::HttpConnect,
        endpoint: format!("http://{proxy_address}"),
        connect_timeout_ms: 1000,
        handshake_timeout_ms: 1000,
    })
    .expect("proxy configuration");
    let tunnel = connector
        .connect(&target, "127.0.0.1:0".parse().expect("listener"))
        .await
        .expect("CONNECT tunnel");
    let (client_tcp, server) = connected_pair().await;
    let flow = AcceptedTcpFlow::from_destination_parts(
        Box::new(server),
        None,
        None,
        DestinationAddress::Unknown,
        None,
    )
    .with_ingress(FlowIngress::ExplicitProxy {
        protocol: ExplicitProxyProtocol::HttpConnect,
        target,
        upstream_proxy: Some(tunnel.proxy_peer),
        proxy_endpoint: Some(proxy_address.to_string()),
    })
    .with_prepared_stream(tunnel.stream);
    let observations = ObservedTarget {
        exchanges: Arc::default(),
    };
    let mut engine = MitmEngine::from_ca(&broker_ca).expect("existing broker CA");
    // Only the target trust store is configured for this private test origin.
    // Production keeps its existing WebPKI roots and has no proxy CA settings.
    engine.upstream_tls_config = test_client_config_trusting(&target_ca);
    let engine = engine
        .with_hook(observations.clone())
        .with_tls_decryption_policy(TlsDecryptionPolicy {
            default_action: action,
            missing_sni_action: None,
            rules: Vec::new(),
        })
        .expect("TLS policy");
    let worker = tokio::spawn(async move { engine.handle_flow(flow).await });
    let client_ca = if action == TlsDecryptionAction::Intercept {
        &broker_ca
    } else {
        &target_ca
    };
    let mut client = TlsConnector::from(test_client_config_trusting(client_ca))
        .connect(
            ServerName::try_from(host).expect("target SNI").to_owned(),
            client_tcp,
        )
        .await
        .expect("client trusts the appropriate existing CA");
    client.write_all(b"GET /secure HTTP/1.1\r\nHost: only-proxy-knows.invalid\r\nAuthorization: Bearer model-test\r\nConnection: close\r\n\r\n").await.expect("request");
    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .await
        .expect("TLS response");
    assert!(
        response.ends_with(b"secure"),
        "response crosses tunnel unchanged"
    );
    client.shutdown().await.expect("client shutdown");
    drop(client);
    let outcome = worker.await.expect("MITM worker").expect("flow completion");
    servers.finish().await;
    if action == TlsDecryptionAction::Intercept {
        assert!(
            matches!(outcome, TransparentFlowOutcome::Intercepted(_)),
            "intercept policy preserved"
        );
        for _ in 0_u16..100 {
            if !observations.exchanges.lock().is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(
            *observations.exchanges.lock(),
            vec![("only-proxy-knows.invalid:443".to_owned(), true)],
            "hook sees original target and unknown target IP"
        );
    } else {
        assert!(
            matches!(outcome, TransparentFlowOutcome::Passthrough(_)),
            "passthrough policy preserved"
        );
        assert!(
            observations.exchanges.lock().is_empty(),
            "passthrough does not emit content events"
        );
    }
}

struct TlsChainServers {
    proxy_address: std::net::SocketAddr,
    origin: tokio::task::JoinHandle<()>,
    proxy: tokio::task::JoinHandle<()>,
}

impl TlsChainServers {
    async fn start(target_ca: &crate::CertificateAuthority, host: &'static str) -> Self {
        let origin_listener = TcpListener::bind("127.0.0.1:0").await.expect("origin");
        let origin_address = origin_listener.local_addr().expect("origin address");
        let origin_acceptor = TlsAcceptor::from(
            MitmTlsAuthority::from_ca(target_ca)
                .expect("target issuer")
                .server_config_for_sni(host)
                .await
                .expect("target certificate"),
        );
        let origin = tokio::spawn(async move {
            let (stream, _) = origin_listener.accept().await.expect("origin accept");
            let mut stream = origin_acceptor.accept(stream).await.expect("target TLS");
            let request = read_http_head(&mut stream).await;
            assert!(
                request.starts_with("GET /secure HTTP/1.1"),
                "existing HTTP request survives tunnel"
            );
            assert!(
                request
                    .to_ascii_lowercase()
                    .contains("authorization: bearer model-test"),
                "model credential reaches only target TLS"
            );
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsecure",
                )
                .await
                .expect("response");
            stream.shutdown().await.expect("TLS close notify");
        });
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.expect("proxy");
        let proxy_address = proxy_listener.local_addr().expect("proxy address");
        let proxy = tokio::spawn(async move {
            let (mut client, _) = proxy_listener.accept().await.expect("proxy accept");
            let request = read_http_head(&mut client).await;
            assert_eq!(
                request,
                "CONNECT only-proxy-knows.invalid:443 HTTP/1.1\r\nHost: only-proxy-knows.invalid:443\r\n\r\n",
                "CONNECT has no model or agent proxy credentials"
            );
            let mut target = TcpStream::connect(origin_address)
                .await
                .expect("proxy resolves target");
            client
                .write_all(b"HTTP/1.1 200 Tunnel ready\r\n\r\n")
                .await
                .expect("CONNECT success");
            let _relayed = tokio::io::copy_bidirectional(&mut client, &mut target).await;
        });
        Self {
            proxy_address,
            origin,
            proxy,
        }
    }

    async fn finish(self) {
        self.origin.await.expect("origin worker");
        self.proxy.await.expect("proxy worker");
    }
}
