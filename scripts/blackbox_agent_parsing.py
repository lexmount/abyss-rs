#!/usr/bin/env python3
"""Compare streaming and inspected Agent events through real broker/plugin sockets."""

import base64
import concurrent.futures
import gzip
import hashlib
import json
import socket
import socketserver
import struct
import tempfile
from pathlib import Path

from blackbox_abyss_broker_upstream import Broker, LocalServer, NextHop, read_head
from blackbox_request_blocking import (
    exact,
    read_frame,
    request,
    websocket_read,
    websocket_send,
    write_frame,
)


class Provider(socketserver.BaseRequestHandler):
    def handle(self):
        head = read_head(self.request)
        headers = dict(
            line.lower().split(b":", 1)
            for line in head.split(b"\r\n")[1:]
            if b":" in line
        )
        if b"upgrade" in headers:
            accept = base64.b64encode(
                hashlib.sha1(
                    headers[b"sec-websocket-key"].strip()
                    + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
                ).digest()
            )
            self.request.sendall(
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "
                + accept
                + b"\r\n\r\n"
            )
            for _ in range(2):
                opcode, data = websocket_read(self.request)
                assert opcode == 1
                payload = json.loads(data)
                self.server.messages.append(payload)
                response = json.dumps(
                    {
                        "type": "response.completed",
                        "response": response_for(
                            "/v1/responses",
                            payload["input"],
                            getattr(self.server, "response_model", "provider-model"),
                        ),
                    }
                ).encode()
                self.request.sendall(
                    b"\x81\x7e" + struct.pack(">H", len(response)) + response
                )
            return
        data = exact(self.request, int(headers.get(b"content-length", b"0")))
        self.server.bodies.append(data)
        path = head.split(b" ", 2)[1].decode()
        response = json.dumps(
            response_for(
                path, "answer", getattr(self.server, "response_model", "provider-model")
            )
        ).encode()
        coding = b""
        if b"content-encoding" in headers:
            assert json.loads(gzip.decompress(data))
            response = gzip.compress(response)
            coding = b"Content-Encoding: gzip\r\n"
        self.request.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            + coding
            + f"Content-Length: {len(response)}\r\nConnection: close\r\n\r\n".encode()
            + response
        )


def response_for(path, text, model="provider-model"):
    common = {"id": f"response-{text}", "model": model}
    if path.endswith("responses"):
        common.update(
            output=[
                {
                    "type": "message",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": text}],
                }
            ],
            usage={"input_tokens": 3, "output_tokens": 2},
        )
    elif path.endswith("chat/completions"):
        common.update(
            choices=[{"message": {"role": "assistant", "content": text}}],
            usage={"prompt_tokens": 3, "completion_tokens": 2},
        )
    else:
        common.update(
            content=[{"type": "text", "text": text}],
            usage={"input_tokens": 3, "output_tokens": 2},
        )
    return common


class Plugin:
    def __init__(self, endpoint, inspect):
        self.inspect = inspect
        self.contexts = []
        self.stream = socket.socket(socket.AF_UNIX)
        self.stream.settimeout(10)
        self.stream.connect(endpoint)
        write_frame(
            self.stream,
            {
                "type": "plugin_hello",
                "protocol_version": 1,
                "plugin_id": "parsing-parity",
                "capabilities": ["agent_events"]
                + (["agent_request"] if inspect else []),
            },
        )
        assert read_frame(self.stream)["type"] == "broker_hello"

    def observe(self, send, count):
        events = []
        with concurrent.futures.ThreadPoolExecutor() as pool:
            pending = pool.submit(send)
            while len(events) < count:
                message = read_frame(self.stream)
                if message["type"] == "inspect_request":
                    assert self.inspect
                    context = message["context"]
                    self.contexts.append(context)
                    write_frame(
                        self.stream,
                        {
                            "type": "inspect_response",
                            "request_id": context["request_id"],
                            "decision": {"action": "allow"},
                        },
                    )
                else:
                    assert message["type"] == "agent_event", message
                    event = message["event"]
                    event.pop("observed_at")
                    events.append(event)
            pending.result(timeout=5)
        return events

    def close(self):
        self.stream.close()


def websocket_turns(broker):
    with broker.connect("plain.invalid:80") as stream:
        stream.sendall(
            b"GET /v1/responses HTTP/1.1\r\nHost: plain.invalid\r\nOriginator: codex_cli_rs\r\nSession-Id: parsing-parity\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
        )
        assert b"101" in read_head(stream)
        for text in ["first", "second"]:
            websocket_send(
                stream,
                json.dumps(
                    {"type": "response.create", "model": "requested", "input": text}
                ).encode(),
            )
            opcode, data = websocket_read(stream)
            assert opcode == 1 and json.loads(data)["type"] == "response.completed"
        websocket_send(stream, b"", opcode=8)


def checks(broker, origin, endpoint):
    policy = broker.request("GET", "/v1/hooks/config")
    policy["harness_usage"]["enabled"] = True
    broker.request("PUT", "/v1/hooks/config", policy)
    cases = [
        ("/v1/responses", {"input": "hello", "previous_response_id": "prior"}),
        (
            "/v1/chat/completions",
            {"messages": [{"role": "user", "content": "hello"}]},
        ),
        (
            "/v1/messages",
            {
                "messages": [{"role": "user", "content": "hello"}],
                "thread": {"type": "continue", "previous_message_id": "prior"},
            },
        ),
        (
            "/api/organizations/org/chat_conversations/conversation-1/completion",
            {"prompt": "hello"},
        ),
    ]
    baseline = []
    for inspected in [False, True]:
        plugin = Plugin(endpoint, inspected)
        try:
            current = []
            for path, content in cases:
                content = dict(content, model=" requested ")
                for compressed in [False, True]:
                    wire = json.dumps(content).encode()
                    headers = b"Session-Id: parsing-parity\r\n"
                    if compressed:
                        wire = gzip.compress(wire)
                        headers += b"Content-Encoding: gzip\r\n"

                    def send():
                        response = request(broker, wire, headers, path)
                        assert response.startswith(b"HTTP/1.1 200"), response
                        assert origin.bodies[-1] == wire

                    events = plugin.observe(send, 2)
                    assert [event["side"] for event in events] == [
                        "request",
                        "response",
                    ]
                    current.append(events)
                    if inspected:
                        context = plugin.contexts[-1]
                        assert context["agent"]["model"] == "requested"
                        assert context["json"] == content
            current.append(plugin.observe(lambda: websocket_turns(broker), 4))
            if inspected:
                messages = [
                    context for context in plugin.contexts if context["websocket"]
                ]
                assert [context["sequence"] for context in messages] == [1, 2]
                assert [
                    context["agent"]["conversation"]["entries"][0]["text"]
                    for context in messages
                ] == ["first", "second"]
                assert current == baseline, "inspection changed normalized Agent events"
            else:
                assert not plugin.contexts
                baseline = current
        finally:
            plugin.close()


def main():
    origin, tls_origin, proxy = (
        LocalServer(Provider),
        LocalServer(Provider),
        LocalServer(NextHop),
    )
    origin.bodies, origin.messages = [], []
    proxy.origin, proxy.tls_origin = origin, tls_origin
    try:
        with tempfile.TemporaryDirectory(prefix="abyss-parsing-") as temporary:
            directory = Path(temporary)
            broker = Broker(directory, proxy)
            try:
                endpoint = json.loads((directory / "startup.json").read_text())[
                    "plugin_endpoint"
                ]
                checks(broker, origin, endpoint)
            except BaseException:
                print((directory / "broker.log").read_text()[-12000:])
                raise
            finally:
                broker.close()
        print(
            "PASS: inspected/streaming event parity across four HTTP dialects, gzip requests/responses and two WebSocket turns"
        )
    finally:
        proxy.close()
        origin.close()
        tls_origin.close()


if __name__ == "__main__":
    main()
