#!/usr/bin/env python3
"""Verify SOCKS5 routing through the real broker REST and ingress boundaries."""

import http.client
import json
import select
import socket
import socketserver
import ssl
import sys
import tempfile
import time
from pathlib import Path

from blackbox_abyss_broker_upstream import (
    Broker,
    LocalServer,
    Origin,
    explicit_request,
    read_all,
    read_head,
)


def exact(stream, length):
    result = bytearray()
    while len(result) < length:
        chunk = stream.recv(length - len(result))
        if not chunk:
            raise EOFError("incomplete SOCKS5 frame")
        result.extend(chunk)
    return bytes(result)


class SocksProxy(socketserver.BaseRequestHandler):
    """Independent wire peer: domains map here, never through broker DNS."""

    def handle(self):
        stream = self.request
        version, count = exact(stream, 2)
        assert version == 5
        methods = exact(stream, count)
        expected = getattr(self.server, "credentials", None)
        method = 2 if expected is not None else 0
        if method not in methods:
            stream.sendall(b"\x05\xff")
            return
        stream.sendall(bytes([5, method]))
        if method == 2:
            assert exact(stream, 1) == b"\x01"
            username = exact(stream, exact(stream, 1)[0])
            password = exact(stream, exact(stream, 1)[0])
            valid = (username, password) == expected
            stream.sendall(bytes([1, 0 if valid else 1]))
            if not valid:
                return
        version, command, reserved, address_type = exact(stream, 4)
        assert (version, command, reserved) == (5, 1, 0)
        if address_type == 1:
            host = socket.inet_ntop(socket.AF_INET, exact(stream, 4))
        elif address_type == 4:
            host = socket.inet_ntop(socket.AF_INET6, exact(stream, 16))
        else:
            assert address_type == 3
            host = exact(stream, exact(stream, 1)[0]).decode("ascii")
        port = int.from_bytes(exact(stream, 2), "big")
        self.server.requests.append((host, port, address_type))
        if self.server.reject or host == "denied.invalid":
            stream.sendall(b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")
            return
        if host == "slow.invalid":
            time.sleep(0.7)
            return
        if host == "broken.invalid":
            stream.sendall(b"\x04\x00\x00\x01")
            return
        if host == "eof.invalid":
            return
        destination = (
            self.server.tls_origin.server_address
            if host == "tls.invalid"
            else self.server.origin.server_address
        )
        with socket.create_connection(destination, timeout=5) as target:
            stream.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
            readers = [stream, target]
            while readers:
                ready, _, _ = select.select(readers, [], [], 5)
                if not ready:
                    return
                for source in ready:
                    other = target if source is stream else stream
                    chunk = source.recv(8192)
                    if chunk:
                        other.sendall(chunk)
                    else:
                        readers.remove(source)
                        other.shutdown(socket.SHUT_WR)


def network(proxy, credentials=None):
    upstream = {
        "protocol": "socks5",
        "endpoint": f"socks5://127.0.0.1:{proxy.server_address[1]}",
        "connect_timeout_ms": 1000,
        "handshake_timeout_ms": 200,
    }
    if credentials:
        upstream["credentials_file"] = str(credentials)
    return {"upstream": upstream}


def configure(broker, config):
    assert broker.request("PUT", "/v1/network/config", config) == config
    assert broker.request("GET", "/v1/network/config") == config


def invalid_config_keeps_route(broker, valid):
    for changes in [
        {"endpoint": "http://127.0.0.1:1080"},
        {"ca_file": "/nonexistent/ca.pem"},
    ]:
        candidate = {"upstream": dict(valid["upstream"], **changes)}
        connection = http.client.HTTPConnection(broker.api, timeout=5)
        try:
            connection.request(
                "PUT",
                "/v1/network/config",
                json.dumps(candidate),
                {
                    "Authorization": f"Bearer {broker.token}",
                    "Content-Type": "application/json",
                },
            )
            response = connection.getresponse()
            response.read()
            assert response.status == 400
        finally:
            connection.close()
        assert broker.request("GET", "/v1/network/config") == valid


def run_explicit(broker, proxy, directory):
    route = network(proxy)
    configure(broker, route)
    invalid_config_keeps_route(broker, route)
    for host, address_type in [
        ("plain.invalid", 3),
        ("198.51.100.7", 1),
        ("[2001:db8::1]", 4),
    ]:
        for connect in (False, True):
            explicit_request(broker, f"{host}:80", connect)
            assert proxy.requests[-1] == (host.strip("[]"), 80, address_type)
    assert all(
        b"proxy-authorization" not in request.lower()
        for request in proxy.origin.requests
    )
    context = ssl.create_default_context(cafile=str(broker.ca_file))
    with (
        broker.connect("tls.invalid:443") as raw,
        context.wrap_socket(raw, server_hostname="tls.invalid") as stream,
    ):
        assert stream.getpeercert(binary_form=True) == ssl.PEM_cert_to_DER_cert(
            broker.origin_cert.read_text()
        )
        stream.sendall(
            b"GET /probe HTTP/1.1\r\nHost: tls.invalid\r\nConnection: close\r\n\r\n"
        )
        assert read_all(stream).endswith(b"secure")
    with broker.connect("plain.invalid:80") as stream:
        stream.sendall(
            b"GET /sse HTTP/1.1\r\nHost: plain.invalid\r\nConnection: close\r\n\r\n"
        )
        read_head(stream)
        assert b"data: first" in exact(stream, len(b"data: first\n\n"))
        configure(broker, {"upstream": None})
        time.sleep(0.3)
        proxy.origin.release_sse.set()
        assert b"data: second" in read_all(stream), (
            "live update interrupted existing tunnel"
        )
    configure(broker, route)
    with broker.connect("plain.invalid:80") as stream:
        stream.sendall(
            b"GET /ws HTTP/1.1\r\nHost: plain.invalid\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
        )
        assert read_head(stream).startswith(b"HTTP/1.1 101")
        assert exact(stream, 7) == b"\x81\x05hello"
        stream.sendall(b"\x88\x80\x00\x00\x00\x00")
    broker.restart()
    assert broker.request("GET", "/v1/network/config") == route
    explicit_request(broker)
    for host, status in [
        ("denied.invalid", 502),
        ("broken.invalid", 502),
        ("eof.invalid", 502),
        ("slow.invalid", 504),
    ]:
        with broker.connect(f"{host}:443", status):
            pass
    proxy.reject = True
    before = proxy.origin.accepted
    with broker.connect(f"127.0.0.1:{proxy.origin.server_address[1]}", 502):
        pass
    assert proxy.origin.accepted == before, "SOCKS rejection fell back to direct"
    proxy.reject = False
    failures = broker.observations(
        lambda row: row.get("target_authority") == "denied.invalid:443"
    )
    assert failures[0]["technical_error_code"] == "upstream_proxy_connect_error"
    assert failures[0]["proxy_status"] is None, (
        "SOCKS reply was exposed as an HTTP status"
    )
    assert failures[0]["hop"] == "abyss_to_upstream_proxy"
    credentials = directory / "credentials.json"
    credentials.write_text(
        json.dumps({"username": "user:name", "password": "private-test-password"})
    )
    proxy.credentials = (b"user:name", b"private-test-password")
    with broker.connect("auth.invalid:80", 502):
        pass
    configure(broker, network(proxy, credentials))
    # Snapshot owns credentials even if the file changes after successful application.
    credentials.write_text("invalid secret")
    explicit_request(broker)
    credentials.write_text(
        json.dumps({"username": "user:name", "password": "wrong-test-password"})
    )
    configure(broker, network(proxy, credentials))
    with broker.connect("auth.invalid:80", 502):
        pass
    rows = broker.observations(
        lambda row: row.get("technical_error_code") == "upstream_proxy_auth_required"
    )
    assert all(row["proxy_status"] is None for row in rows)
    assert "test-password" not in json.dumps(rows)
    configure(broker, {"upstream": None})
    before = len(proxy.requests)
    explicit_request(broker, f"127.0.0.1:{proxy.origin.server_address[1]}")
    assert len(proxy.requests) == before
    proxy.credentials = None


def main():
    origin, tls_origin, proxy = (
        LocalServer(Origin),
        LocalServer(Origin),
        LocalServer(SocksProxy),
    )
    proxy.origin, proxy.tls_origin = origin, tls_origin
    broker = None
    try:
        with tempfile.TemporaryDirectory(prefix="abyss-socks5-") as temporary:
            directory = Path(temporary)
            broker = Broker(directory, proxy)
            try:
                run_explicit(broker, proxy, directory)
            finally:
                broker.close()
            if sys.platform == "darwin":
                from blackbox_abyss_broker_transparent_upstream import request

                native = directory / "native"
                native.mkdir()
                broker = Broker(native, proxy, transparent=True)
                try:
                    configure(broker, network(proxy))
                    assert request(broker).endswith(b"secure")
                    assert proxy.requests[-1] == ("plain.invalid", 80, 3)
                    broker.restart()
                    assert request(broker, "198.51.100.7", 80, "198.51.100.7").endswith(
                        b"secure"
                    )
                    assert proxy.requests[-1] == ("198.51.100.7", 80, 1)
                finally:
                    broker.close()
        print(
            "PASS: SOCKS5 DNS/IPv4/IPv6, HTTP/CONNECT, TLS passthrough, SSE, WebSocket, route snapshots, restart, authentication, failure diagnostics, no fallback, and supported transparent ingress"
        )
    finally:
        if broker and not broker.log.closed:
            broker.close()
        proxy.close()
        tls_origin.close()
        origin.close()


if __name__ == "__main__":
    main()
