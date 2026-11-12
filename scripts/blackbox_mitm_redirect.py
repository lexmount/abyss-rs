#!/usr/bin/env python3
"""Verify configured redirects through real broker, proxy and provider sockets."""

import base64
import gzip
import http.client
import json
import socket
import ssl
import tempfile
import threading
from pathlib import Path

from blackbox_abyss_broker_https_upstream import proxy_tls
from blackbox_abyss_broker_upstream import network
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


def configure(broker, target):
    return broker.request(
        "PUT",
        "/v1/mitm/config",
        {
            "tls_decryption": {
                "default_action": "block",
                "rules": [
                    {
                        "id": "redirect",
                        "action": "redirect",
                        "destination_hosts": ["original.invalid"],
                        "target": target,
                    },
                ],
            },
        },
    )


def send(
    broker,
    body=b"",
    headers=b"",
    tls=False,
    path="/custom/path%2Fpart?q=a%2Bb",
    chunked=False,
    port=None,
):
    port = port or broker.redirect_port
    authority = f"original.invalid:{port}"
    raw = (
        broker.connect(authority)
        if tls
        else socket.create_connection(broker.address, timeout=5)
    )
    stream = (
        ssl.create_default_context(cafile=str(broker.ca_file)).wrap_socket(
            raw, server_hostname="original.invalid"
        )
        if tls
        else raw
    )
    with stream:
        uri = path if tls else f"http://{authority}{path}"
        framing = (
            b"Transfer-Encoding: chunked\r\n"
            if chunked
            else f"Content-Length: {len(body)}\r\n".encode()
        )
        stream.sendall(
            f"POST {uri} HTTP/1.1\r\nHost: {authority}\r\nOriginator: codex_cli_rs\r\nConnection: close\r\n".encode()
            + headers
            + framing
            + b"\r\n"
            + body
        )
        return read_all(stream)


def rejected_update(broker, target):
    previous = broker.request("GET", "/v1/mitm/config")
    invalid = json.loads(json.dumps(previous))
    invalid["tls_decryption"]["rules"][0]["target"] = target
    api = http.client.HTTPConnection(broker.api, timeout=5)
    try:
        api.request(
            "PUT",
            "/v1/mitm/config",
            json.dumps(invalid),
            {
                "Authorization": f"Bearer {broker.token}",
                "Content-Type": "application/json",
            },
        )
        response = api.getresponse()
        assert response.status == 422, response.read()
        response.read()
    finally:
        api.close()
    assert broker.request("GET", "/v1/mitm/config") == previous


def check(broker, origin, proxy):
    target = "localhost"
    broker.redirect_port = origin.server_address[1]
    proxy.plain_hosts = ("localhost",)
    configure(broker, target)
    # The next hop knows only the selected target; original.invalid is never resolved.
    assert send(broker, b"opaque-body").startswith(b"HTTP/1.1 200")
    assert origin.requests[-1].startswith(
        b"POST /custom/path%2Fpart?q=a%2Bb HTTP/1.1\r\n"
    )
    assert (
        f"host: localhost:{broker.redirect_port}\r\n".encode()
        in origin.requests[-1].lower()
    )
    assert origin.bodies[-1] == b"opaque-body"
    assert proxy.requests[-1].startswith(
        f"CONNECT localhost:{broker.redirect_port} HTTP/1.1".encode()
    )
    # Explicit nondefault ports remain the CONNECT target even with proxy-owned DNS.
    assert send(broker, port=8080).startswith(b"HTTP/1.1 200")
    assert proxy.requests[-1].startswith(b"CONNECT localhost:8080 HTTP/1.1")
    assert b"host: localhost:8080\r\n" in origin.requests[-1].lower()

    # HTTPS stays HTTPS. The local fixture's private certificate must fail the
    # broker's provider trust check, never be bypassed by a plaintext connection.
    configure(broker, "tls.invalid")
    assert send(broker, tls=True, port=8443).startswith(b"HTTP/1.1 502")
    assert proxy.requests[-1].startswith(b"CONNECT tls.invalid:8443 HTTP/1.1")
    broker.observations(
        lambda row: row.get("technical_error_code") == "provider_tls_error"
    )
    assert not proxy.tls_origin.requests
    configure(broker, target)

    compressed = gzip.compress(b'{ "model": "before", "input": "hello" }')
    wire = (
        f"{len(compressed):x};keep=yes\r\n".encode()
        + compressed
        + b"\r\n0\r\nX-End: yes\r\n\r\n"
    )
    assert send(
        broker, wire, b"Content-Encoding: gzip\r\nTrailer: X-End\r\n", chunked=True
    ).startswith(b"HTTP/1.1 200")
    assert origin.bodies[-1] == wire, "routing changed body framing"

    endpoint = json.loads((broker.directory / "startup.json").read_text())[
        "plugin_endpoint"
    ]

    def modify(context):
        assert context["authority"] == "localhost"
        assert context["harness"]["id"] == "codex"
        return {
            "action": "modify",
            "actions": [
                {"op": "set_auth_token", "value": "redirect-test-secret"},
                {"op": "set_model", "value": "after"},
            ],
        }

    plugin = Plugin(endpoint, modify)
    try:
        assert send(
            broker,
            b'{"model":"before","input":"hello"}',
            b"Authorization: Bearer placeholder\r\n",
            path="/v1/responses",
        ).startswith(b"HTTP/1.1 200")
        assert json.loads(origin.bodies[-1])["model"] == "after"
        assert (
            b"authorization: bearer redirect-test-secret\r\n"
            in origin.requests[-1].lower()
        )
        assert len(plugin.contexts) == 1
    finally:
        plugin.close()

    # Upgraded streams keep the selected target; subsequent frames need no reroute.
    origin.release_reverse.set()
    with socket.create_connection(broker.address, timeout=5) as stream:
        stream.sendall(
            f"GET http://original.invalid:{broker.redirect_port}/ws HTTP/1.1\r\nHost: original.invalid:{broker.redirect_port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n".encode()
        )
        assert read_head(stream).startswith(b"HTTP/1.1 101")
        assert websocket_read(stream) == (1, b"reverse")
        stream.sendall(websocket_frame(b"hello"))
        assert stream.recv(1024) == b""
    assert origin.messages[-1] == (1, b"hello")

    # Configuration persists and is validated before publication.
    rejected_update(broker, "https://example.com")
    rejected_update(broker, "example.com:443")
    rejected_update(broker, "example.com/path")
    rejected_update(broker, "https://user:password@example.com")
    broker.restart()
    assert send(broker).startswith(b"HTTP/1.1 200")

    # Direct mode also resolves only the new target.
    broker.request("PUT", "/v1/network/config", {"upstream": None})
    count = len(proxy.requests)
    assert send(broker).startswith(b"HTTP/1.1 200")
    assert len(proxy.requests) == count
    before = origin.accepted
    broker.request(
        "PUT",
        "/v1/mitm/config",
        {"tls_decryption": {"default_action": "block", "rules": []}},
    )
    assert send(broker).startswith(b"HTTP/1.1 403")
    assert origin.accepted == before
    configure(broker, "localhost")
    assert send(broker, port=broker.address[1]).startswith(b"HTTP/1.1 403"), (
        "redirect loop was not rejected"
    )
    configure(broker, target)

    # A redirect retains the configured authenticated HTTPS next hop.
    proxy.tls = proxy_tls(broker, "localhost")
    proxy.proxy_authorization = b"Basic " + base64.b64encode(
        b"redirect-user:redirect-password"
    )
    credentials = broker.directory / "proxy-auth.json"
    credentials.write_text(
        json.dumps({"username": "redirect-user", "password": "redirect-password"})
    )
    credentials.chmod(0o600)
    config = network(proxy)
    config["upstream"].update(
        endpoint=f"https://localhost:{proxy.server_address[1]}",
        ca_file=str(broker.ca_file),
        credentials_file=str(credentials),
    )
    broker.request("PUT", "/v1/network/config", config)
    assert send(broker).startswith(b"HTTP/1.1 200")
    assert proxy.requests[-1].startswith(
        f"CONNECT localhost:{origin.server_address[1]}".encode()
    )
    assert b"proxy-authorization:" not in origin.requests[-1].lower()
    count = len(proxy.requests)
    configure(broker, "localhost")
    assert send(broker, port=broker.address[1]).startswith(b"HTTP/1.1 403")
    assert len(proxy.requests) == count, "self target reached next hop"
    configure(broker, target)
    proxy.reject = True
    before = origin.accepted
    assert send(broker).startswith(b"HTTP/1.1 502")
    assert origin.accepted == before, "redirect fell back to direct after proxy failure"
    assert "redirect-test-secret" not in (broker.directory / "broker.log").read_text()
    assert "redirect-password" not in (broker.directory / "broker.log").read_text()


def main():
    origin, tls_origin, proxy = (
        LocalServer(Provider),
        LocalServer(Provider),
        LocalServer(NextHop),
    )
    for server in [origin, tls_origin]:
        server.bodies, server.messages = [], []
        server.head_received, server.release_reverse = (
            threading.Event(),
            threading.Event(),
        )
    proxy.origin, proxy.tls_origin = origin, tls_origin
    broker = None
    try:
        with tempfile.TemporaryDirectory(prefix="abyss-redirect-") as temporary:
            directory = Path(temporary)
            try:
                broker = Broker(directory, proxy)
                check(broker, origin, proxy)
            except BaseException:
                print((directory / "broker.log").read_text()[-10000:])
                raise
            finally:
                if broker:
                    broker.close()
        print(
            "PASS: redirect before DNS/connect, preserved protocol/ports/paths/body framing, auth/model plugins, WebSocket, persistence, validation, direct routing and authenticated HTTPS next hop"
        )
    finally:
        proxy.close()
        origin.close()
        tls_origin.close()


if __name__ == "__main__":
    main()
