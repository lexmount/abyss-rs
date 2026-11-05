//! Real broker coverage for wildcard listeners, forwarding, and loop rejection.

use std::{
    io::{Read as _, Write as _},
    net::{SocketAddr, TcpListener, TcpStream},
    thread,
};

use super::{BrokerProcess, HTTP_TIMEOUT, loopback_ephemeral_addr, reserve_api_loopback_addr};

#[test]
fn explicit_wildcard_listeners_forward_http_and_connect_and_reject_self_targets() {
    for (bind, local_ip) in [("0.0.0.0:0", "127.0.0.1"), ("[::]:0", "::1")] {
        let mut broker = BrokerProcess::spawn_explicit(
            reserve_api_loopback_addr(),
            bind.parse().expect("bind address"),
        );
        let status = broker.wait_for_running();
        let bound = status.listen_addr.expect("listener address");
        assert!(
            bound.ip().is_unspecified(),
            "status must retain wildcard bind address"
        );
        assert_ne!(bound.port(), 0);
        let proxy = SocketAddr::new(local_ip.parse().expect("local address"), bound.port());
        let upstream = TcpListener::bind(loopback_ephemeral_addr()).expect("origin");
        let origin = upstream.local_addr().expect("origin address");
        let worker = thread::spawn(move || {
            for _ in 0_u8..2 {
                let (mut stream, _) = upstream.accept().expect("origin connection");
                stream
                    .set_read_timeout(Some(HTTP_TIMEOUT))
                    .expect("read timeout");
                let request = read_head(&mut stream);
                assert!(request.starts_with(b"GET /bound HTTP/1.1\r\n"));
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .expect("origin response");
            }
        });

        let mut direct = connect(proxy);
        write!(
            direct,
            "GET http://{origin}/bound HTTP/1.1\r\nHost: {origin}\r\nConnection: close\r\n\r\n"
        )
        .expect("absolute request");
        assert_ok(&mut direct);

        let mut tunnel = connect(proxy);
        write!(
            tunnel,
            "CONNECT {origin} HTTP/1.1\r\nHost: {origin}\r\n\r\n"
        )
        .expect("CONNECT");
        assert!(read_head(&mut tunnel).starts_with(b"HTTP/1.1 200"));
        write!(
            tunnel,
            "GET /bound HTTP/1.1\r\nHost: {origin}\r\nConnection: close\r\n\r\n"
        )
        .expect("tunneled request");
        assert_ok(&mut tunnel);
        worker.join().expect("origin worker");

        for target in [
            proxy.to_string(),
            format!("localhost:{}", proxy.port()),
            bound.to_string(),
        ] {
            let mut client = connect(proxy);
            write!(
                client,
                "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n"
            )
            .expect("self target");
            assert!(
                read_head(&mut client).starts_with(b"HTTP/1.1 403"),
                "must reject self target {target}"
            );
        }
        broker.shutdown();
        broker.wait_for_exit();
    }
}

fn connect(address: SocketAddr) -> TcpStream {
    let stream = TcpStream::connect_timeout(&address, HTTP_TIMEOUT).expect("proxy connection");
    stream
        .set_read_timeout(Some(HTTP_TIMEOUT))
        .expect("read timeout");
    stream
        .set_write_timeout(Some(HTTP_TIMEOUT))
        .expect("write timeout");
    stream
}

fn read_head(stream: &mut TcpStream) -> Vec<u8> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        stream.read_exact(&mut byte).expect("HTTP header");
        head.push(byte[0]);
        assert!(head.len() <= 4096, "bounded HTTP header");
    }
    head
}

fn assert_ok(stream: &mut TcpStream) {
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .expect("forwarded response");
    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "origin status must be forwarded"
    );
    assert!(response.ends_with(b"ok"), "origin body must be forwarded");
}
