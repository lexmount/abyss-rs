#!/usr/bin/env python3
"""Verify plugin provider selection using real broker, proxy and provider sockets."""

import json
import ssl
import struct
import tempfile
import threading
from pathlib import Path

from blackbox_request_blocking import (
    Broker,
    LocalServer,
    NextHop,
    Plugin,
    Provider,
    read_all,
    read_head,
    websocket_frame,
    websocket_read,
)
from blackbox_request_modification import modify


def send(broker, host="api.openai.com", port=80, tls=False):
    body = b'{ "model": "original", "input": "hello", "extra": 42 }'
    with broker.connect(f"{host}:{port}") as raw:
        stream = (
            ssl.create_default_context(cafile=str(broker.ca_file)).wrap_socket(
                raw, server_hostname=host
            )
            if tls
            else raw
        )
        with stream:
            stream.sendall(
                f"POST /backend-api/codex/responses?keep=1 HTTP/1.1\r\nHost: {host}:{port}\r\n"
                "Originator: codex_cli_rs\r\nAuthorization: Bearer placeholder\r\n"
                f"Content-Length: {len(body)}\r\n\r\n".encode()
                + body
            )
            return read_all(stream)


def checks(broker, original, target, endpoint, proxy):
    first = Plugin(
        endpoint,
        lambda _: modify(
            {"op": "set_base_url", "value": "http://unused.invalid/first"},
            {"op": "set_auth_token", "value": "provider-secret"},
            {"op": "set_model", "value": "provider-model"},
        ),
    )

    def second_handler(context):
        assert context["base_url"] == "http://unused.invalid/first"
        assert context["base_url_writable"]
        assert context["auth_token"] == "provider-secret"
        assert context["agent"]["model"] == "provider-model"
        assert context["authority"] == "unused.invalid"
        return modify(
            {"op": "set_base_url", "value": "http://provider.invalid/gateway/"}
        )

    second = Plugin(endpoint, second_handler)
    try:
        # Different client/server TLS identities: original HTTPS -> selected HTTP.
        broker.request(
            "PUT",
            "/v1/mitm/config",
            {
                "tls_decryption": {"default_action": "intercept", "rules": []},
            },
        )
        assert send(broker, tls=True).startswith(b"HTTP/1.1 200")
        assert send(broker).startswith(b"HTTP/1.1 200")
        assert not original.requests
        assert len(target.requests) == 2
        for head, body in zip(target.requests, target.bodies):
            assert head.startswith(b"POST /gateway/responses?keep=1 HTTP/1.1\r\n")
            assert b"host: provider.invalid\r\n" in head.lower()
            assert b"authorization: bearer provider-secret\r\n" in head.lower()
            assert json.loads(body) == {
                "model": "provider-model",
                "input": "hello",
                "extra": 42,
            }
        assert any(
            head.startswith(b"CONNECT provider.invalid:80 ") for head in proxy.requests
        )
        assert not any(b"unused.invalid" in head for head in proxy.requests)
    finally:
        first.close()
        second.close()

    # Later rejection and target network rules must both prevent forwarding.
    first = Plugin(
        endpoint,
        lambda _: modify({"op": "set_base_url", "value": "http://provider.invalid"}),
    )
    before = len(target.requests)
    second = Plugin(endpoint, lambda _: False)
    try:
        assert send(broker).startswith(b"HTTP/1.1 403")
    finally:
        second.close()
    try:
        broker.request(
            "PUT",
            "/v1/mitm/config",
            {
                "tls_decryption": {
                    "default_action": "intercept",
                    "rules": [
                        {
                            "id": "deny-selected",
                            "action": "block",
                            "destination_hosts": ["provider.invalid"],
                        }
                    ],
                }
            },
        )
        response = send(broker)
        assert response.startswith(b"HTTP/1.1 403") and b"network_blocked" in response
        assert b"deny-selected" in response
        assert len(target.requests) == before
    finally:
        first.close()
    broker.request(
        "PUT",
        "/v1/mitm/config",
        {"tls_decryption": {"default_action": "intercept", "rules": []}},
    )

    # A selected next-hop failure must never fall back to a direct target socket.
    first = Plugin(
        endpoint,
        lambda _: modify(
            {
                "op": "set_base_url",
                "value": f"http://127.0.0.1:{target.server_address[1]}",
            }
        ),
    )
    proxy.routes["127.0.0.1"] = ("127.0.0.1", 1)
    try:
        assert not send(broker).startswith(b"HTTP/1.1 200")
        assert len(target.requests) == before
    finally:
        first.close()

    # The upgrade selects a provider; an established WebSocket cannot change it.
    def websocket_handler(context):
        if context["websocket"]:
            assert context["base_url"] == "http://provider.invalid"
            assert not context["base_url_writable"]
        return modify({"op": "set_base_url", "value": "http://provider.invalid"})

    first = Plugin(endpoint, websocket_handler)
    target.release_reverse.set()
    try:
        with broker.connect("api.openai.com:80") as stream:
            stream.sendall(
                b"GET /v1/responses HTTP/1.1\r\nHost: api.openai.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
            )
            assert b"101" in read_head(stream)
            assert websocket_read(stream) == (1, b"reverse")
            stream.sendall(
                websocket_frame(b'{"type":"response.create","model":"old","input":[]}')
            )
            opcode, body = websocket_read(stream)
            assert opcode == 8 and struct.unpack(">H", body[:2])[0] == 1011
        assert target.requests[-1].startswith(b"GET /responses HTTP/1.1")
    finally:
        first.close()

    # No configured proxy: resolve and connect the selected URL directly.
    broker.request("PUT", "/v1/network/config", {"upstream": None})
    first = Plugin(
        endpoint,
        lambda _: modify(
            {
                "op": "set_base_url",
                "value": f"http://127.0.0.1:{target.server_address[1]}/direct",
            }
        ),
    )
    proxy_count = len(proxy.requests)
    try:
        assert send(broker, "127.0.0.1", original.server_address[1]).startswith(
            b"HTTP/1.1 200"
        )
        assert target.requests[-1].startswith(b"POST /direct/responses?keep=1 HTTP/1.1")
        assert len(proxy.requests) == proxy_count and not original.requests
    finally:
        first.close()


def main():
    original, target, proxy = (
        LocalServer(Provider),
        LocalServer(Provider),
        LocalServer(NextHop),
    )
    for server in (original, target):
        server.bodies, server.messages = [], []
        server.head_received, server.release_reverse = (
            threading.Event(),
            threading.Event(),
        )
    proxy.origin, proxy.tls_origin = original, original
    proxy.routes = {
        "api.openai.com": original.server_address,
        "provider.invalid": target.server_address,
    }
    try:
        with tempfile.TemporaryDirectory(prefix="abyss-provider-") as temporary:
            directory = Path(temporary)
            broker = Broker(directory, proxy)
            # Broker's shared fixture installs a TLS server; original receives no request.
            original.tls = None
            try:
                endpoint = json.loads((directory / "startup.json").read_text())[
                    "plugin_endpoint"
                ]
                checks(broker, original, target, endpoint, proxy)
                assert "provider-secret" not in (directory / "broker.log").read_text()
            except BaseException:
                print((directory / "broker.log").read_text()[-10000:])
                raise
            finally:
                broker.close()
        print(
            "PASS: provider routing, TLS client, path/query/Host, ordered edits, target block, next-hop routing, no direct fallback, WebSocket binding and direct mode"
        )
    finally:
        proxy.close()
        original.close()
        target.close()


if __name__ == "__main__":
    main()
