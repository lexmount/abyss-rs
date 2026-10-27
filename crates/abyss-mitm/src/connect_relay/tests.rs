//! Wire-level tests of Agent-owned CONNECT and authentication boundaries.

use super::*;
use tokio::io::{DuplexStream, duplex};

fn boxed(stream: DuplexStream) -> BoxedDuplexStream {
    Box::new(stream)
}

const REQUEST: &[u8] = b"CONNECT target.invalid:443 HTTP/1.1\r\nHost: target.invalid:443\r\nProxy-Authorization: Basic agent-secret\r\n\r\n";

#[tokio::test]
async fn probe_preserves_other_protocols_and_fragmented_connect() {
    for bytes in [
        b"GET / HTTP/1.1\r\n".as_slice(),
        b"\x16\x03\x03",
        b"CON",
        b"",
    ] {
        let (mut writer, reader) = duplex(1024);
        writer.write_all(bytes).await.expect("input");
        writer.shutdown().await.expect("EOF");
        let ConnectProbe::Other(mut reader) =
            ConnectProbe::read(boxed(reader), Duration::from_secs(1))
                .await
                .expect("probe")
        else {
            panic!("ordinary protocol");
        };
        let mut actual = Vec::new();
        reader.read_to_end(&mut actual).await.expect("replay");
        assert_eq!(actual, bytes, "every probe byte is replayed");
    }
    let (mut writer, reader) = duplex(1);
    let sender = tokio::spawn(async move {
        for byte in REQUEST {
            writer.write_all(&[*byte]).await.expect("fragment");
        }
    });
    let ConnectProbe::Connect(mut reader) =
        ConnectProbe::read(boxed(reader), Duration::from_secs(1))
            .await
            .expect("probe")
    else {
        panic!("CONNECT prefix");
    };
    let mut actual = Vec::new();
    reader
        .read_to_end(&mut actual)
        .await
        .expect("read fragmented input");
    assert_eq!(actual, REQUEST, "probe restores fragmented CONNECT");
    sender.await.expect("sender");
}

#[tokio::test]
async fn preserves_auth_and_both_optimistic_tunnel_prefixes() {
    let (mut agent, client) = duplex(4096);
    let (upstream, proxy) = duplex(4096);
    agent.write_all(REQUEST).await.expect("CONNECT");
    agent
        .write_all(b"client-tls-prefix")
        .await
        .expect("optimistic bytes");
    let proxy_worker = tokio::spawn(async move {
        let mut proxy = BufReader::new(boxed(proxy));
        assert_eq!(
            read_head(&mut proxy).await.expect("request"),
            REQUEST,
            "Agent request forwarded verbatim"
        );
        proxy.write_all(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 201 Tunnel\r\nContent-Length: 999\r\nTransfer-Encoding: chunked\r\n\r\nserver-prefix").await.expect("response");
    });
    let result = HttpConnectRelay::default()
        .relay(boxed(client), boxed(upstream))
        .await
        .expect("relay");
    let ConnectRelayOutcome::Established {
        mut client,
        mut upstream,
        target,
    } = result
    else {
        panic!("tunnel");
    };
    assert_eq!(
        target.authority(),
        "target.invalid:443",
        "target retained without local DNS"
    );
    let mut client_prefix = [0; 17];
    client
        .read_exact(&mut client_prefix)
        .await
        .expect("client prefix");
    assert_eq!(
        &client_prefix, b"client-tls-prefix",
        "client read-ahead preserved"
    );
    let mut server_prefix = [0; 13];
    upstream
        .read_exact(&mut server_prefix)
        .await
        .expect("server prefix");
    assert_eq!(
        &server_prefix, b"server-prefix",
        "success framing ignored inside tunnel"
    );
    let mut response = [0; 25];
    agent
        .read_exact(&mut response)
        .await
        .expect("informational response");
    assert_eq!(
        &response, b"HTTP/1.1 100 Continue\r\n\r\n",
        "informational response retained"
    );
    proxy_worker.await.expect("proxy");
}

#[tokio::test]
async fn authentication_retries_keep_same_connection_and_exact_challenge() {
    for challenge in [
        b"HTTP/1.1 407 Auth\r\nProxy-Authenticate: Negotiate challenge\r\nContent-Length: 4\r\n\r\nauth".as_slice(),
        b"HTTP/1.1 407 Auth\r\nProxy-Authenticate: Digest challenge\r\nTransfer-Encoding: chunked\r\n\r\n4;test=yes\r\nauth\r\n0\r\nX-Trailer: yes\r\n\r\n",
    ] {
        let (mut agent, client) = duplex(4096);
        let (upstream, proxy) = duplex(4096);
        let relay = tokio::spawn(async move { HttpConnectRelay::default().relay(boxed(client), boxed(upstream)).await });
        let proxy_worker = tokio::spawn(async move {
            let mut proxy = BufReader::new(boxed(proxy));
            assert_eq!(read_head(&mut proxy).await.expect("first CONNECT"), REQUEST, "first request");
            proxy.write_all(challenge).await.expect("407");
            assert_eq!(read_head(&mut proxy).await.expect("second CONNECT"), REQUEST, "retry is on the original socket");
            proxy.write_all(b"HTTP/1.1 200 Ready\r\n\r\n").await.expect("success");
        });
        agent.write_all(REQUEST).await.expect("first CONNECT");
        let mut received = vec![0; challenge.len()];
        agent.read_exact(&mut received).await.expect("full 407");
        assert_eq!(received, challenge, "challenge and body remain byte-identical");
        agent.write_all(REQUEST).await.expect("authenticated retry");
        assert!(matches!(relay.await.expect("worker").expect("relay"), ConnectRelayOutcome::Established { .. }), "retry establishes tunnel");
        proxy_worker.await.expect("proxy");
    }
}

#[tokio::test]
async fn failures_forward_bodies_and_close_without_establishing_a_tunnel() {
    for response in [
        b"HTTP/1.1 403 Denied\r\nConnection: close\r\nContent-Length: 4\r\n\r\nnope".as_slice(),
        b"HTTP/1.0 407 Auth\r\nProxy-Authenticate: Basic test\r\n\r\nsecret challenge body",
    ] {
        let (mut agent, client) = duplex(4096);
        let (upstream, mut proxy) = duplex(4096);
        agent.write_all(REQUEST).await.expect("request");
        proxy.write_all(response).await.expect("response");
        proxy.shutdown().await.expect("proxy EOF");
        assert!(
            matches!(
                HttpConnectRelay::default()
                    .relay(boxed(client), boxed(upstream))
                    .await
                    .expect("relay"),
                ConnectRelayOutcome::Closed
            ),
            "no tunnel on non-2xx"
        );
        let mut actual = Vec::new();
        agent
            .read_to_end(&mut actual)
            .await
            .expect("response and EOF");
        assert_eq!(
            actual, response,
            "no synthetic success or replacement response"
        );
    }
}

#[tokio::test]
async fn invalid_responses_and_requests_fail_closed() {
    for response in [
        b"HTTP/1.1 101 Upgrade\r\n\r\n".as_slice(),
        b"HTTP/1.1 407 Auth\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
        b"HTTP/1.1 407 Auth\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 407 Auth\r\nContent-Length: 10\r\n\r\nshort",
        b"HTTP/1.1 407 Auth\r\nTransfer-Encoding: chunked\r\n\r\nxyz\r\n",
        b"HTTP/1.1 000 Broken\r\n\r\n",
        b"not http\r\n\r\n",
    ] {
        let (mut agent, client) = duplex(4096);
        let (upstream, mut proxy) = duplex(4096);
        agent.write_all(REQUEST).await.expect("request");
        proxy.write_all(response).await.expect("response");
        proxy.shutdown().await.expect("EOF");
        assert!(
            HttpConnectRelay::default()
                .relay(boxed(client), boxed(upstream))
                .await
                .is_err(),
            "malformed or truncated response must fail"
        );
    }
    let (mut agent, client) = duplex(4096);
    let (upstream, mut proxy) = duplex(4096);
    agent
        .write_all(b"CONNECT target.invalid:443 HTTP/1.1\r\nHost: wrong.invalid\r\n\r\n")
        .await
        .expect("invalid request");
    assert!(
        HttpConnectRelay::default()
            .relay(boxed(client), boxed(upstream))
            .await
            .is_err(),
        "ambiguous request fails"
    );
    let mut leaked = Vec::new();
    proxy
        .read_to_end(&mut leaked)
        .await
        .expect("closed upstream");
    assert!(leaked.is_empty(), "invalid request never reaches proxy");
}

#[tokio::test]
async fn bounds_negotiation_time_header_size_and_rounds() {
    let (_agent, client) = duplex(1024);
    let (_proxy, upstream) = duplex(1024);
    assert!(
        matches!(
            HttpConnectRelay::new(Duration::from_millis(10))
                .relay(boxed(client), boxed(upstream))
                .await,
            Err(ConnectRelayError::Timeout)
        ),
        "whole handshake has a timeout"
    );
    let (mut agent, client) = duplex(MAX_HEAD_BYTES * 2);
    let (_proxy, upstream) = duplex(1024);
    agent
        .write_all(&vec![b'A'; MAX_HEAD_BYTES + 1])
        .await
        .expect("oversized head");
    assert!(
        matches!(
            HttpConnectRelay::default()
                .relay(boxed(client), boxed(upstream))
                .await,
            Err(ConnectRelayError::Protocol(_))
        ),
        "header size bounded"
    );
    let (mut agent, client) = duplex(4096);
    let (upstream, mut proxy) = duplex(4096);
    for _ in 0..MAX_NEGOTIATIONS {
        agent.write_all(REQUEST).await.expect("retry");
        proxy
            .write_all(b"HTTP/1.1 407 Auth\r\nContent-Length: 0\r\n\r\n")
            .await
            .expect("challenge");
    }
    assert!(
        matches!(
            HttpConnectRelay::default()
                .relay(boxed(client), boxed(upstream))
                .await,
            Err(ConnectRelayError::Protocol(_))
        ),
        "round count bounded"
    );
}
