#!/usr/bin/env python3
"""Verify request blocking through the real broker, plugin socket and provider sockets."""

import base64
import concurrent.futures
import gzip
import hashlib
import json
import socket
import socketserver
import ssl
import struct
import sys
import tempfile
import threading
from pathlib import Path

from blackbox_abyss_broker_upstream import (
    Broker,
    LocalServer,
    NextHop,
    read_all,
    read_head,
)


def exact(stream, length):
    data = bytearray()
    while len(data) < length:
        chunk = stream.recv(length - len(data))
        if not chunk:
            raise EOFError("peer closed")
        data.extend(chunk)
    return bytes(data)


def read_frame(stream):
    return json.loads(exact(stream, struct.unpack(">I", exact(stream, 4))[0]))


def write_frame(stream, value):
    body = json.dumps(value).encode()
    stream.sendall(struct.pack(">I", len(body)) + body)


class Plugin:
    def __init__(self, endpoint, handler=None, capabilities=None):
        self.stream = socket.socket(socket.AF_UNIX)
        self.stream.settimeout(15)
        self.stream.connect(endpoint)
        write_frame(
            self.stream,
            {
                "type": "plugin_hello",
                "protocol_version": 1,
                "plugin_id": "blackbox",
                "capabilities": capabilities or ["agent_request"],
            },
        )
        assert read_frame(self.stream)["type"] == "broker_hello"
        self.contexts = []
        self.thread = None
        self.errors = []
        if handler:
            self.thread = threading.Thread(
                target=self.serve, args=(handler,), daemon=True
            )
            self.thread.start()

    def serve(self, handler):
        try:
            while True:
                frame = read_frame(self.stream)
                if frame["type"] == "broker_close":
                    return
                if frame["type"] == "agent_event":
                    continue
                assert frame["type"] == "inspect_request", frame
                context = frame["context"]
                self.contexts.append(context)
                allow = handler(context)
                self.reply(context, allow)
        except (EOFError, OSError):
            pass
        except BaseException as error:
            self.errors.append(error)

    def reply(self, context, allow):
        write_frame(
            self.stream,
            {
                "type": "inspect_response",
                "request_id": context["request_id"],
                "allow": allow,
                "reason": None if allow else "Private key detected",
            },
        )

    def close(self):
        self.stream.shutdown(socket.SHUT_RDWR)
        self.stream.close()
        if self.thread:
            self.thread.join(timeout=1)
        assert not self.errors, self.errors


def websocket_frame(payload, opcode=1, final=True):
    assert len(payload) < 126
    mask = b"test"
    return (
        bytes([(128 if final else 0) | opcode, 128 | len(payload)])
        + mask
        + bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    )


def websocket_send(stream, payload, opcode=1, final=True):
    stream.sendall(websocket_frame(payload, opcode, final))


def websocket_read(stream):
    first, second = exact(stream, 2)
    length = second & 127
    if length == 126:
        length = struct.unpack(">H", exact(stream, 2))[0]
    mask = exact(stream, 4) if second & 128 else None
    body = exact(stream, length)
    if mask:
        body = bytes(value ^ mask[index % 4] for index, value in enumerate(body))
    return first & 15, body


class Provider(socketserver.BaseRequestHandler):
    def handle(self):
        if self.server.tls:
            self.request = self.server.tls.wrap_socket(self.request, server_side=True)
        head = read_head(self.request)
        self.server.requests.append(head)
        self.server.head_received.set()
        headers = dict(
            line.lower().split(b":", 1)
            for line in head.split(b"\r\n")[1:]
            if b":" in line
        )
        if b"upgrade" in headers:
            key = headers[b"sec-websocket-key"].strip()
            accept = base64.b64encode(
                hashlib.sha1(key + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest()
            )
            self.request.sendall(
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "
                + accept
                + b"\r\n\r\n"
            )
            assert self.server.release_reverse.wait(3)
            self.request.sendall(b"\x81\x07reverse")
            self.server.messages.append(websocket_read(self.request))
            return
        body = bytearray()
        if b"transfer-encoding" in headers:
            while True:
                line = bytearray()
                while not line.endswith(b"\r\n"):
                    line.extend(exact(self.request, 1))
                body.extend(line)
                length = int(line.split(b";", 1)[0].strip(), 16)
                if length == 0:
                    trailers = bytearray()
                    while not trailers.endswith(b"\r\n") or (
                        trailers != b"\r\n" and not trailers.endswith(b"\r\n\r\n")
                    ):
                        trailers.extend(exact(self.request, 1))
                    body.extend(trailers)
                    break
                body.extend(exact(self.request, length + 2))
        else:
            body.extend(exact(self.request, int(headers.get(b"content-length", b"0"))))
        self.server.bodies.append(bytes(body))
        self.request.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
        )


def request(broker, body, headers=b"", path="/v1/responses", chunked=False):
    with socket.create_connection(broker.address, timeout=12) as stream:
        framing = (
            b"Transfer-Encoding: chunked\r\n"
            if chunked
            else f"Content-Length: {len(body)}\r\n".encode()
        )
        stream.sendall(
            f"POST http://plain.invalid:80{path} HTTP/1.1\r\nHost: plain.invalid\r\nOriginator: codex_cli_rs\r\nAuthorization: Bearer private\r\nCookie: private\r\n".encode()
            + headers
            + framing
            + b"\r\n"
            + body
        )
        return read_all(stream)


def checks(broker, origin, endpoint):
    private = b'{"model":"test-model","instructions":"PRIVATE KEY","input":"hello"}'
    harmless = b'{"model":"test-model","input":"hello","extra":"preserve me"}'
    initial = len(origin.requests)
    broker.request(
        "PUT",
        "/v1/mitm/config",
        {
            "tls_decryption": {
                "default_action": "passthrough",
                "missing_sni_action": "block",
                "rules": [
                    {
                        "id": "deny-host",
                        "enabled": True,
                        "action": "block",
                        "destination_hosts": ["plain.invalid"],
                    }
                ],
            }
        },
    )
    plugin = Plugin(endpoint, lambda _: False)
    try:
        response = request(broker, private)
        assert (
            b"403" in response.split(b"\r\n", 1)[0] and b"network_blocked" in response
        ), response
        assert b"deny-host" in response and b"abyss-broker" in response
        assert len(origin.requests) == initial and not plugin.contexts
        with broker.connect("tls.invalid:443") as raw:
            with ssl.create_default_context(cafile=str(broker.ca_file)).wrap_socket(
                raw, server_hostname="tls.invalid"
            ) as stream:
                stream.sendall(
                    b"POST /v1/responses HTTP/1.1\r\nHost: tls.invalid\r\nContent-Length: "
                    + str(len(private)).encode()
                    + b"\r\n\r\n"
                    + private
                )
                assert read_all(stream).startswith(b"HTTP/1.1 200"), (
                    "opaque TLS must retain passthrough despite connected inspection plugins"
                )
        assert not plugin.contexts, "passthrough must not enter Agent inspection"
        broker.request(
            "PUT",
            "/v1/mitm/config",
            {
                "tls_decryption": {
                    "default_action": "intercept",
                    "missing_sni_action": None,
                    "rules": [],
                }
            },
        )
        for body, headers, chunked in [
            (private, b"", False),
            (gzip.compress(private), b"Content-Encoding: gzip\r\n", False),
            (
                f"{len(private):x};tag=test\r\n".encode()
                + private
                + b"\r\n0\r\nX-End: complete\r\n\r\n",
                b"",
                True,
            ),
        ]:
            response = request(broker, body, headers, chunked=chunked)
            assert (
                response.startswith(b"HTTP/1.1 403")
                and b"agent_request_blocked" in response
            ), response
            context = plugin.contexts[-1]
            assert context["json"]["instructions"] == "PRIVATE KEY"
            assert any(
                entry["role"] == "developer" and entry["text"] == "PRIVATE KEY"
                for entry in context["agent"]["conversation"]["entries"]
            )
            assert (
                context["harness"]["id"] == "codex"
                and context["source_process"] is None
            )
            assert all(
                name not in ("authorization", "cookie")
                for name, _ in context["headers"]
            )
            assert len(origin.requests) == initial, (
                "rejected request header reached provider"
            )
        response = request(broker, b"opaque private content", path="/unknown")
        assert response.startswith(b"HTTP/1.1 403")
        assert plugin.contexts[-1]["parsing_status"] == "unknown_protocol"
        assert plugin.contexts[-1]["body"]["content"] == "opaque private content"
        with socket.create_connection(broker.address, timeout=5) as stream:
            stream.sendall(
                b"POST http://plain.invalid:80/v1/responses HTTP/1.1\r\nHost: plain.invalid\r\nExpect: 100-continue\r\nContent-Length: "
                + str(len(private)).encode()
                + b"\r\n\r\n"
            )
            assert read_head(stream).startswith(b"HTTP/1.1 100"), (
                "client must be allowed to supply its body locally"
            )
            assert len(origin.requests) == initial, (
                "Expect must not release the request head"
            )
            stream.sendall(private)
            assert read_all(stream).startswith(b"HTTP/1.1 403")
        calls = len(plugin.contexts)
        with socket.create_connection(broker.address, timeout=5) as stream:
            stream.sendall(
                b"POST http://plain.invalid:80/v1/responses HTTP/1.1\r\nHost: plain.invalid\r\nContent-Length: 16777217\r\n\r\n"
            )
            assert read_all(stream).startswith(b"HTTP/1.1 413"), (
                "known oversized bodies must be rejected before waiting for content"
            )
        oversized_decoded = gzip.compress(b"x" * 16777217)
        assert request(
            broker, oversized_decoded, b"Content-Encoding: gzip\r\n"
        ).startswith(b"HTTP/1.1 413")
        assert len(plugin.contexts) == calls and len(origin.requests) == initial
        response = request(broker, private, b"Content-Encoding: unsupported\r\n")
        assert response.startswith(b"HTTP/1.1 415") and len(plugin.contexts) == calls
        response = request(broker, b"broken", b"Content-Encoding: gzip\r\n")
        assert response.startswith(b"HTTP/1.1 400") and len(plugin.contexts) == calls
        # JSON escaping can exceed the IPC limit even when the wire body fits.
        # Reject locally and keep the inspector connected for the next request.
        response = request(broker, b"\0" * (12 * 1024 * 1024), path="/unknown")
        assert response.startswith(b"HTTP/1.1 413") and len(plugin.contexts) == calls
        assert request(broker, private).startswith(b"HTTP/1.1 403"), (
            "oversized context must not disconnect the inspection plugin"
        )
        with broker.connect("plain.invalid:80") as stream:
            stream.sendall(
                b"GET /v1/responses HTTP/1.1\r\nHost: plain.invalid\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
            )
            assert read_all(stream).startswith(b"HTTP/1.1 403"), (
                "upgrade itself must be inspected before forwarding"
            )
            assert (
                not plugin.contexts[-1]["websocket"] and len(origin.requests) == initial
            )
    finally:
        plugin.close()

    # Disconnect is observed before the next request; the barrier is a complete
    # request through a newly registered plugin on the same broker.
    allow = Plugin(endpoint, lambda _: True)
    try:
        for body, headers, chunked in [
            (harmless, b"", False),
            (gzip.compress(harmless), b"Content-Encoding: gzip\r\n", False),
            (
                f"{len(harmless):x}\r\n".encode() + harmless + b"\r\n0\r\n\r\n",
                b"",
                True,
            ),
        ]:
            response = request(broker, body, headers, chunked=chunked)
            assert response.startswith(b"HTTP/1.1 200"), response
            assert origin.bodies[-1] == body, "allow changed original body bytes"
        deny = Plugin(endpoint, lambda _: False)
        try:
            count = len(origin.requests)
            assert request(broker, private).startswith(b"HTTP/1.1 403")
            assert len(origin.requests) == count and deny.contexts
        finally:
            deny.close()
    finally:
        allow.close()

    with concurrent.futures.ThreadPoolExecutor() as pool:
        disconnected = Plugin(endpoint)
        pending = pool.submit(request, broker, private)
        assert read_frame(disconnected.stream)["type"] == "inspect_request"
        disconnected.close()
        assert pending.result().startswith(b"HTTP/1.1 503"), (
            "selected disconnect must fail current request"
        )
        assert request(broker, harmless).startswith(b"HTTP/1.1 200"), (
            "no remaining inspectors must restore streaming"
        )
        event_only = Plugin(endpoint, lambda _: False, capabilities=["agent_events"])
        try:
            origin.head_received.clear()
            with socket.create_connection(broker.address, timeout=8) as stream:
                size = 16777217
                stream.sendall(
                    b"POST http://plain.invalid:80/large HTTP/1.1\r\nHost: plain.invalid\r\nContent-Length: "
                    + str(size).encode()
                    + b"\r\n\r\nx"
                )
                assert origin.head_received.wait(2), (
                    "event-only plugins must preserve streaming before the full body arrives"
                )
                stream.sendall(b"x" * (size - 1))
                assert read_all(stream).startswith(b"HTTP/1.1 200"), (
                    "audit capture truncation must not apply the inspection body limit"
                )
            assert not event_only.contexts
        finally:
            event_only.close()
        silent = Plugin(endpoint)
        try:
            pending = pool.submit(request, broker, private)
            context = read_frame(silent.stream)["context"]
            assert pending.result().startswith(b"HTTP/1.1 503"), (
                "silent plugin must hit finite deadline"
            )
            silent.reply(context, True)  # A late reply must not affect a later request.
            pending = pool.submit(request, broker, harmless)
            current = read_frame(silent.stream)["context"]
            assert current["request_id"] != context["request_id"]
            silent.reply(current, True)
            assert pending.result().startswith(b"HTTP/1.1 200")
        finally:
            silent.close()

        # Pending decisions must not serialize unrelated requests or stop the
        # PluginServer from accepting another connection. Replies may arrive
        # out of order, and a new session cannot join an existing request plan.
        concurrent_plugin = Plugin(endpoint)
        later = None
        try:
            count = len(origin.requests)
            first = pool.submit(request, broker, harmless)
            first_context = read_frame(concurrent_plugin.stream)["context"]
            second = pool.submit(request, broker, private)
            second_context = read_frame(concurrent_plugin.stream)["context"]
            assert first_context["request_id"] != second_context["request_id"]
            assert len(origin.requests) == count and not first.done()
            later = Plugin(endpoint)
            concurrent_plugin.reply(second_context, False)
            assert second.result(timeout=3).startswith(b"HTTP/1.1 403")
            assert not first.done() and len(origin.requests) == count
            concurrent_plugin.reply(first_context, True)
            assert first.result(timeout=3).startswith(b"HTTP/1.1 200")
            assert origin.bodies[-1] == harmless
            assert len(origin.requests) == count + 1
        finally:
            concurrent_plugin.close()
            if later:
                later.close()

    inspected, release = threading.Event(), threading.Event()

    def hold(context):
        if not context["websocket"]:
            return True  # Permit the HTTP upgrade, then inspect individual messages.
        assert context["websocket"] and context["json"]["input"] == "PRIVATE KEY"
        assert context["sequence"] == 1 and context["message_type"] == "text"
        inspected.set()
        assert release.wait(3)
        return False

    ws = Plugin(endpoint, hold)
    try:
        with broker.connect("plain.invalid:80") as stream:
            stream.sendall(
                b"GET /v1/responses HTTP/1.1\r\nHost: plain.invalid\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
                + websocket_frame(b'{"input":', final=False)
            )
            assert b"101" in read_head(stream)
            websocket_send(stream, b'"PRIVATE KEY"}', opcode=0)
            assert inspected.wait(2), "complete fragmented message must be inspected"
            origin.release_reverse.set()
            stream.settimeout(2)
            assert websocket_read(stream) == (1, b"reverse"), (
                "reverse traffic stalled behind inspection"
            )
            release.set()
            opcode, body = websocket_read(stream)
            assert opcode == 8 and struct.unpack(">H", body[:2])[0] == 1008
            assert b"abyss-broker" in body and not origin.messages
    finally:
        release.set()
        ws.close()

    # Exercise the public Python callback API against this real broker.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sdks/python"))
    from abyss_sdk.plugin import BrokerPlugin, RequestDecision

    seen = []

    def sdk_decision(context):
        seen.append(context)
        return RequestDecision(False, "SDK policy")

    sdk_stream = BrokerPlugin(
        "python-inspector", endpoint, on_agent_request=sdk_decision, agent_events=False
    ).connect()
    with concurrent.futures.ThreadPoolExecutor() as pool:
        receiving = pool.submit(next, sdk_stream, None)
        assert request(broker, private).startswith(b"HTTP/1.1 403")
        assert seen[0].agent.model == "test-model"
        broker.close()
        receiving.result(timeout=5)


def main():
    origin, tls_origin, proxy = (
        LocalServer(Provider),
        LocalServer(Provider),
        LocalServer(NextHop),
    )
    for server in (origin, tls_origin):
        server.bodies, server.messages = [], []
        server.head_received, server.release_reverse = (
            threading.Event(),
            threading.Event(),
        )
    proxy.origin, proxy.tls_origin = origin, tls_origin
    broker = None
    try:
        with tempfile.TemporaryDirectory(prefix="abyss-block-") as temporary:
            directory = Path(temporary)
            try:
                broker = Broker(directory, proxy)
                endpoint = json.loads((directory / "startup.json").read_text())[
                    "plugin_endpoint"
                ]
                checks(broker, origin, endpoint)
            except BaseException:
                if broker and not broker.log.closed:
                    broker.close()
                print((directory / "broker.log").read_text()[-12000:])
                raise
        print(
            "PASS: network policy, full-body decisions, raw-byte allow, compressed/chunked bodies, unknown requests, concurrent plugin decisions, connection snapshots, disconnect, timeout, fragmented WebSocket and Python SDK"
        )
    finally:
        if broker and not broker.log.closed:
            broker.close()
        proxy.close()
        origin.close()
        tls_origin.close()


if __name__ == "__main__":
    main()
