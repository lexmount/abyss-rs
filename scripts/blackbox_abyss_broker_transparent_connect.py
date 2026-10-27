#!/usr/bin/env python3
"""Exercise Agent-owned CONNECT through the real macOS broker flow protocol.

Uses the public NE framing boundary; does not install or simulate an OS filter.
TLS MITM through both platform identities is covered by Rust socket tests.
"""

import json
from pathlib import Path
import select
import socket
import socketserver
import struct
import sys
import tempfile
import uuid

from blackbox_abyss_broker_upstream import (
    Broker,
    LocalServer,
    Origin,
    read_all,
    read_head,
)


class FramedStream:
    def __init__(self, broker, peer):
        self.stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.stream.settimeout(5)
        self.stream.connect(broker.socket_path)
        self.flow_id = uuid.uuid4()
        self.buffer = bytearray()
        self.eof = False
        self.frame(
            1,
            0,
            json.dumps(
                {
                    "flow_id": str(self.flow_id),
                    "platform": "macos",
                    "protocol": "tcp",
                    "source_pid": 123,
                    "source_process": "/test/agent",
                    "source_application_id": "test.agent",
                    "destination_ip": peer[0],
                    "destination_port": peer[1],
                }
            ).encode(),
        )

    def frame(self, kind, direction, payload):
        self.stream.sendall(
            struct.pack(
                "!4sBBH16sI",
                b"ABY1",
                kind,
                direction,
                0,
                self.flow_id.bytes,
                len(payload),
            )
            + payload
        )

    def sendall(self, data):
        self.frame(2, 1, data)

    def exact(self, count):
        data = bytearray()
        while len(data) < count:
            chunk = self.stream.recv(count - len(data))
            if not chunk:
                raise EOFError("broker closed without a directional close frame")
            data.extend(chunk)
        return bytes(data)

    def recv(self, count):
        while not self.buffer and not self.eof:
            magic, kind, direction, reserved, flow_id, length = struct.unpack(
                "!4sBBH16sI", self.exact(28)
            )
            assert (magic, direction, reserved, flow_id) == (
                b"ABY1",
                2,
                0,
                self.flow_id.bytes,
            )
            assert length <= 16 * 1024 * 1024
            payload = self.exact(length)
            if kind == 3:
                self.eof = True
            else:
                assert kind == 2
                self.buffer.extend(payload)
        result = bytes(self.buffer[:count])
        del self.buffer[:count]
        return result

    def __enter__(self):
        return self

    def __exit__(self, *_):
        try:
            self.frame(
                3,
                1,
                json.dumps(
                    {"flow_id": str(self.flow_id), "reason": "test EOF"}
                ).encode(),
            )
        except OSError:
            pass
        self.stream.close()


REQUEST = b"CONNECT plain.invalid:80 HTTP/1.1\r\nHost: plain.invalid:80\r\nProxy-Authorization: Basic agent-secret\r\n\r\n"
CHALLENGE = b"HTTP/1.1 407 Auth\r\nProxy-Authenticate: Negotiate original-challenge\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nauth\r\n0\r\n\r\n"
SUCCESS = b"HTTP/1.1 201 Tunnel ready\r\nContent-Length: 9999\r\n\r\n"


class OriginalProxy(socketserver.BaseRequestHandler):
    def handle(self):
        request = read_head(self.request)
        self.server.requests.append(request)
        if self.server.reject:
            self.request.sendall(
                b"HTTP/1.1 403 Denied\r\nConnection: close\r\nContent-Length: 4\r\n\r\nnope"
            )
            return
        if self.server.broken:
            self.request.sendall(b"HTTP/1.1 101 Invalid upgrade\r\n\r\n")
            return
        assert request == REQUEST, (
            "Agent CONNECT/auth changed before the original proxy"
        )
        self.request.sendall(CHALLENGE)
        retry = read_head(self.request)
        assert retry == REQUEST, (
            "authentication retry changed or used another connection"
        )
        self.server.requests.append(retry)
        with socket.create_connection(
            self.server.origin.server_address, timeout=5
        ) as target:
            self.request.sendall(SUCCESS)
            readers = [self.request, target]
            while readers:
                ready, _, _ = select.select(readers, [], [], 5)
                if not ready:
                    return
                for source in ready:
                    destination = target if source is self.request else self.request
                    data = source.recv(4096)
                    if data:
                        destination.sendall(data)
                    else:
                        readers.remove(source)
                        destination.shutdown(socket.SHUT_WR)


def negotiate(client, optimistic=b""):
    # Exercise method detection across distinct platform frames.
    client.sendall(REQUEST[:3])
    client.sendall(REQUEST[3:])
    challenge = bytearray()
    while len(challenge) < len(CHALLENGE):
        chunk = client.recv(len(CHALLENGE) - len(challenge))
        assert chunk, "407 response truncated"
        challenge.extend(chunk)
    assert challenge == CHALLENGE, "proxy challenge/body changed"
    client.sendall(REQUEST + optimistic)
    assert read_head(client) == SUCCESS, "proxy success was synthesized or changed"


def run_checks(broker, proxy):
    request = b"GET /probe HTTP/1.1\r\nHost: plain.invalid\r\nAuthorization: Bearer model-test\r\nConnection: close\r\n\r\n"
    with FramedStream(broker, proxy.server_address) as client:
        negotiate(client, request)
        assert read_all(client).endswith(b"secure"), "inner HTTP response missing"
    with FramedStream(broker, proxy.server_address) as client:
        negotiate(client)
        client.sendall(
            b"GET /sse HTTP/1.1\r\nHost: plain.invalid\r\nConnection: close\r\n\r\n"
        )
        read_head(client)
        first = bytearray()
        while b"data: first\n\n" not in first:
            chunk = client.recv(128)
            assert chunk, "SSE ended before first event"
            first.extend(chunk)
        proxy.origin.release_sse.set()
        assert b"data: second" in read_all(client), "SSE continuation missing"
    with FramedStream(broker, proxy.server_address) as client:
        negotiate(client)
        client.sendall(
            b"GET /ws HTTP/1.1\r\nHost: plain.invalid\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
        )
        assert read_head(client).startswith(b"HTTP/1.1 101"), "inner WebSocket failed"
        frame = bytearray()
        while len(frame) < 7:
            chunk = client.recv(7 - len(frame))
            assert chunk, "WebSocket frame truncated"
            frame.extend(chunk)
        assert frame == b"\x81\x05hello"
        client.sendall(b"\x88\x80\x00\x00\x00\x00")
    assert len(proxy.requests) == 6, (
        "each successful flow uses two authentication rounds"
    )
    assert all(
        b"Proxy-Authorization" not in request for request in proxy.origin.requests
    ), "proxy credentials reached target"
    rows = broker.observations(
        lambda row: (
            row.get("request_path") == "/probe" and row.get("outcome") == "succeeded"
        )
    )
    row = rows[0]
    assert (
        row["destination_host"] == "plain.invalid" and row["destination_addr"] is None
    ), row
    assert row["proxy_peer"] == f"127.0.0.1:{proxy.server_address[1]}", row
    assert (
        row["source_pid"] == 123 and row["ingress_source"] == "macos_network_extension"
    ), row
    assert "agent-secret" not in json.dumps(
        rows
    ) and "original-challenge" not in json.dumps(rows), rows
    before = proxy.origin.accepted
    proxy.reject = True
    with FramedStream(broker, proxy.server_address) as client:
        # A locally reachable target proves rejection cannot cause direct fallback.
        authority = f"127.0.0.1:{proxy.origin.server_address[1]}"
        client.sendall(
            f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode()
        )
        assert (
            read_all(client)
            == b"HTTP/1.1 403 Denied\r\nConnection: close\r\nContent-Length: 4\r\n\r\nnope"
        )
    assert proxy.origin.accepted == before, "rejection caused a direct connection"
    proxy.reject = False
    proxy.broken = True
    with FramedStream(broker, proxy.server_address) as client:
        client.sendall(REQUEST)
        assert read_all(client) == b"", "invalid response must produce a framed close"
    assert proxy.origin.accepted == before, "malformed response caused direct fallback"
    broker.log.flush()
    assert "agent-secret" not in Path(broker.log.name).read_text(), (
        "proxy credential logged"
    )
    with FramedStream(broker, proxy.origin.server_address) as client:
        client.sendall(request)
        assert read_all(client).endswith(b"secure"), (
            "ordinary transparent HTTP regressed"
        )


def main():
    if sys.platform != "darwin":
        raise SystemExit(
            "This black-box test requires the macOS framed-flow broker build."
        )
    origin = LocalServer(Origin)
    tls_origin = LocalServer(Origin)
    proxy = LocalServer(OriginalProxy)
    proxy.broken = False
    proxy.origin = origin
    proxy.tls_origin = tls_origin
    try:
        with tempfile.TemporaryDirectory(
            prefix="abyss-preserve-", dir="/tmp"
        ) as directory:
            path = Path(directory)
            broker = Broker(path, proxy, transparent_socket=path / "flow.sock")
            try:
                run_checks(broker, proxy)
                print(
                    "PASS: transparent CONNECT, Agent auth, HTTP/SSE/WebSocket, route metadata, rejection and direct-flow regression"
                )
            finally:
                broker.close()
    finally:
        proxy.close()
        origin.close()
        tls_origin.close()


if __name__ == "__main__":
    main()
