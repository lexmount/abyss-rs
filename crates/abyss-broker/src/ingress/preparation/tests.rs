//! Shared preparation contract for platform capability opt-in and route preservation.

use super::*;
use crate::ingress::{
    PlatformFlowMetadata,
    original_proxy::{OriginalProxyConnect, OriginalProxyConnector},
};
use abyss_mitm::{ExplicitProxyProtocol, SourceProcess, TargetAuthority, TransparentFlowSource};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _, duplex},
    net::{TcpListener, TcpStream},
};

#[tokio::test]
async fn normalizes_target_without_losing_route_identity_or_read_ahead() {
    for source in [
        TransparentFlowSource::MacosNetworkExtension,
        TransparentFlowSource::Unattributed,
    ] {
        let proxy = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("original proxy");
        let peer = proxy.local_addr().expect("proxy address");
        let proxy_worker = tokio::spawn(async move {
            let (mut stream, _) = proxy.accept().await.expect("proxy accept");
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(stream.read_u8().await.expect("CONNECT byte"));
            }
            assert_eq!(
                request, b"CONNECT target.invalid:443 HTTP/1.1\r\nHost: target.invalid:443\r\n\r\n",
                "original proxy receives CONNECT"
            );
            stream
                .write_all(b"HTTP/1.1 200 Ready\r\n\r\nserver-data")
                .await
                .expect("success");
        });
        let (mut agent, client) = duplex(4096);
        agent
            .write_all(
                b"NECT target.invalid:443 HTTP/1.1\r\nHost: target.invalid:443\r\n\r\nclient-data",
            )
            .await
            .expect("request suffix");
        let metadata = PlatformFlowMetadata::from_destination_parts(
            None,
            None,
            DestinationAddress::Known(peer),
            Some("original-proxy.invalid".to_owned()),
            Some(SourceProcess::new(
                Some(123),
                Some("agent".to_owned()),
                None,
            )),
        );
        let flow_id = metadata.flow_id.clone();
        let mut flow = PlatformFlow::new(client, metadata)
            .with_ingress(FlowIngress::transparent(source))
            .with_read_prefix(Box::from(&b"CON"[..]));
        flow.original_proxy_connector = Some(Box::new(TestTcpConnector));
        let mut prepared = flow.prepare().await.expect("prepare").expect("established");
        assert_eq!(prepared.metadata.flow_id, flow_id, "flow identity retained");
        assert_eq!(
            prepared.source_process().and_then(|process| process.pid),
            Some(123),
            "Agent identity retained"
        );
        assert_eq!(
            prepared.ingress.source_label(),
            FlowIngress::transparent(source).source_label(),
            "platform retained"
        );
        assert_eq!(
            prepared.ingress.upstream_proxy(),
            Some(peer),
            "captured proxy route retained"
        );
        assert_eq!(
            prepared.ingress.proxy_target().expect("target").authority(),
            "target.invalid:443",
            "logical target comes from CONNECT"
        );
        assert_eq!(
            prepared.original_destination().socket_addr(),
            None,
            "no local target DNS or proxy-address substitution"
        );
        assert_eq!(
            prepared.destination_host(),
            Some("target.invalid"),
            "TLS policy uses inner target"
        );
        let mut prefix = [0; 11];
        prepared
            .io
            .read_exact(&mut prefix)
            .await
            .expect("client prefix");
        assert_eq!(&prefix, b"client-data", "client prefix retained");
        prepared
            .prepared_upstream
            .as_mut()
            .expect("existing proxy socket")
            .read_exact(&mut prefix)
            .await
            .expect("proxy prefix");
        assert_eq!(&prefix, b"server-data", "proxy prefix retained");
        proxy_worker.await.expect("proxy worker");
    }
}

#[tokio::test]
async fn direct_and_configured_explicit_flows_keep_their_existing_path() {
    for explicit in [false, true] {
        let (mut agent, client) = duplex(1024);
        let bytes = if explicit {
            b"CONNECT nested.invalid:443 HTTP/1.1\r\n".as_slice()
        } else {
            b"GET / HTTP/1.1\r\n"
        };
        agent.write_all(bytes).await.expect("input");
        agent.shutdown().await.expect("EOF");
        let peer = "127.0.0.1:12345".parse().expect("peer");
        let metadata = PlatformFlowMetadata::from_destination_parts(
            None,
            None,
            DestinationAddress::Known(peer),
            None,
            None,
        );
        let mut flow = PlatformFlow::new(client, metadata);
        flow.original_proxy_connector = Some(Box::new(RejectConnector));
        if explicit {
            flow = flow.with_ingress(FlowIngress::ExplicitProxy {
                protocol: ExplicitProxyProtocol::HttpConnect,
                target: TargetAuthority::parse("target.invalid:443").expect("target"),
                upstream_proxy: None,
                proxy_endpoint: None,
            });
        }
        let mut flow = flow.prepare().await.expect("prepare").expect("flow");
        let mut actual = Vec::new();
        flow.io
            .read_to_end(&mut actual)
            .await
            .expect("input replay");
        assert_eq!(actual, bytes, "existing path sees the exact input");
        assert_eq!(
            flow.original_destination().socket_addr(),
            Some(peer),
            "existing target unchanged"
        );
        assert!(flow.prepared_upstream.is_none(), "no new upstream opened");
    }
}

struct TestTcpConnector;

impl OriginalProxyConnector for TestTcpConnector {
    fn connect(&self, peer: SocketAddr) -> OriginalProxyConnect<'_> {
        Box::pin(async move {
            let stream: abyss_mitm::BoxedDuplexStream = Box::new(TcpStream::connect(peer).await?);
            Ok(stream)
        })
    }
}

struct RejectConnector;

impl OriginalProxyConnector for RejectConnector {
    fn connect(&self, _peer: SocketAddr) -> OriginalProxyConnect<'_> {
        Box::pin(std::future::ready(Err(std::io::Error::other(
            "test platform cannot open this route",
        ))))
    }
}

#[tokio::test]
async fn missing_platform_capability_preserves_flow_without_probing() {
    for source in [
        TransparentFlowSource::WindowsWfp,
        TransparentFlowSource::LinuxTransparent,
        TransparentFlowSource::Unattributed,
    ] {
        let (mut agent, client) = duplex(1024);
        let peer = "127.0.0.1:12345".parse().expect("peer");
        let metadata = PlatformFlowMetadata::from_destination_parts(
            None,
            None,
            DestinationAddress::Known(peer),
            None,
            None,
        );
        let flow = PlatformFlow::new(client, metadata)
            .with_ingress(FlowIngress::transparent(source))
            .with_read_prefix(Box::from(&b"CON"[..]));
        // With no bytes available beyond the prefix, even a method probe would
        // block. An unfinished platform adapter must return immediately.
        let mut flow = timeout(Duration::from_millis(100), flow.prepare())
            .await
            .expect("no protocol probe without opt-in")
            .expect("unchanged flow")
            .expect("flow");
        assert_eq!(&*flow.read_prefix, b"CON", "prefix remains unconsumed");
        assert_eq!(
            flow.original_destination().socket_addr(),
            Some(peer),
            "original peer retained"
        );
        assert!(
            flow.ingress.proxy_target().is_none(),
            "no proxy negotiation claimed"
        );
        assert!(flow.prepared_upstream.is_none(), "no connection prepared");
        agent
            .write_all(b"NECT target.invalid:443 HTTP/1.1\r\n")
            .await
            .expect("input");
        agent.shutdown().await.expect("EOF");
        let mut actual = Vec::new();
        flow.io
            .read_to_end(&mut actual)
            .await
            .expect("unchanged stream");
        assert_eq!(
            actual, b"NECT target.invalid:443 HTTP/1.1\r\n",
            "original stream remains available"
        );
    }
}

#[tokio::test]
async fn platform_connector_failure_cannot_fall_back_to_plain_tcp() {
    let proxy = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("proxy listener");
    let peer = proxy.local_addr().expect("peer");
    let (mut agent, client) = duplex(1024);
    agent
        .write_all(b"CONNECT target.invalid:443 HTTP/1.1\r\nHost: target.invalid:443\r\n\r\n")
        .await
        .expect("CONNECT");
    let metadata = PlatformFlowMetadata::from_destination_parts(
        None,
        None,
        DestinationAddress::Known(peer),
        None,
        None,
    );
    let mut flow = PlatformFlow::new(client, metadata);
    flow.original_proxy_connector = Some(Box::new(RejectConnector));
    assert!(
        matches!(
            flow.prepare().await,
            Err(IngressError::OriginalProxy { .. })
        ),
        "platform connection failure is terminal"
    );
    assert!(
        timeout(Duration::from_millis(100), proxy.accept())
            .await
            .is_err(),
        "no direct TCP bypass of platform connector"
    );
}
