#!/usr/bin/env python3
"""Exercise configured routing through the real macOS framed-flow/API boundary."""

import json
import os
import http.client
import subprocess
import time
from pathlib import Path
import select
import socket
import ssl
import struct
import sys
import tempfile
import threading
import uuid

from blackbox_abyss_broker_upstream import (
    Broker,
    LocalServer,
    NextHop,
    Origin,
    read_all,
    read_head,
)


def exact(stream, length):
    result = bytearray()
    while len(result) < length:
        chunk = stream.recv(length - len(result))
        if not chunk:
            raise EOFError("framed flow closed")
        result.extend(chunk)
    return bytes(result)


def framed_connection(broker, host, port, destination_ip=None):
    """Adapt a socket pair to the published framed-flow wire contract."""
    transport = socket.socket(socket.AF_UNIX)
    transport.settimeout(5)
    transport.connect(str(broker.flow_socket))
    flow_id = uuid.uuid4()

    def frame(kind, direction, payload):
        transport.sendall(
            b"ABY1"
            + bytes([kind, direction, 0, 0])
            + flow_id.bytes
            + struct.pack("!I", len(payload))
            + payload
        )

    frame(
        1,
        0,
        json.dumps(
            {
                "flow_id": str(flow_id),
                "platform": "macos",
                "protocol": "tcp",
                "source_process": "codex",
                "destination_host": host,
                "destination_ip": destination_ip,
                "destination_port": port,
            }
        ).encode(),
    )
    client, relay = socket.socketpair()
    client.settimeout(5)

    def bridge():
        try:
            readers = [transport, relay]
            while readers:
                ready, _, _ = select.select(readers, [], [], 8)
                if not ready:
                    raise TimeoutError("framed bridge timed out")
                for source in ready:
                    if source is relay:
                        chunk = relay.recv(16384)
                        if chunk:
                            frame(2, 1, chunk)
                        else:
                            frame(
                                3,
                                1,
                                json.dumps(
                                    {"flow_id": str(flow_id), "reason": "eof"}
                                ).encode(),
                            )
                            readers.remove(relay)
                    else:
                        header = exact(transport, 28)
                        assert header[:4] == b"ABY1" and header[8:24] == flow_id.bytes
                        length = struct.unpack("!I", header[24:])[0]
                        assert length <= 16 * 1024 * 1024
                        payload = exact(transport, length)
                        if header[4:6] == bytes([2, 2]):
                            relay.sendall(payload)
                        elif header[4] in (3, 4):
                            return
        except (OSError, EOFError):
            # A failed upstream closes the accepted flow without direct fallback.
            pass
        finally:
            transport.close()
            relay.close()

    thread = threading.Thread(target=bridge, daemon=True)
    thread.start()
    return client


def request(broker, host="plain.invalid", port=80, destination_ip=None):
    with framed_connection(broker, host, port, destination_ip) as stream:
        stream.sendall(
            f"GET /probe HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
        )
        return read_all(stream)


def network(proxy):
    return {
        "upstream": {
            "protocol": "http_connect",
            "endpoint": f"http://127.0.0.1:{proxy.server_address[1]}",
            "connect_timeout_ms": 1000,
            "handshake_timeout_ms": 200,
        }
    }


def restart(broker):
    command = broker.process.args
    broker.close()
    startup = broker.directory / "startup.json"
    startup.unlink()
    broker.log = (broker.directory / "broker.log").open("a+")
    broker.process = subprocess.Popen(
        command,
        env=dict(os.environ, ABYSS_HOME=str(broker.home)),
        stdout=broker.log,
        stderr=subprocess.STDOUT,
    )
    for _ in range(200):
        if broker.process.poll() is not None:
            raise AssertionError("restarted broker exited")
        if startup.exists():
            broker.api = json.loads(startup.read_text())["api_addr"]
            broker.token = broker.token_file.read_text().strip()
            return
        time.sleep(0.05)
    raise AssertionError("broker restart timed out")


def run_checks(broker, proxy, replacement):
    api = http.client.HTTPConnection(broker.api, timeout=5)
    try:
        api.request(
            "PUT",
            "/v1/network/config",
            body='{"upstream":null}',
            headers={"Content-Type": "application/json"},
        )
        assert api.getresponse().status == 401, (
            "route updates must require local bearer authentication"
        )
    finally:
        api.close()
    assert broker.request("GET", "/v1/network/config") == network(proxy)
    assert request(broker).endswith(b"secure"), "proxy must resolve a DNS-only target"
    assert proxy.requests[-1].startswith(b"CONNECT plain.invalid:80 HTTP/1.1")
    assert request(broker, "127.0.0.1", 8081, "127.0.0.1").endswith(b"secure")
    assert proxy.requests[-1].startswith(b"CONNECT 127.0.0.1:8081")

    # Real TLS travels through the proxy with target validation at the client.
    context = ssl.create_default_context(cafile=str(broker.ca_file))
    with framed_connection(broker, "198.18.0.1", 443, "198.18.0.1") as raw:
        with context.wrap_socket(raw, server_hostname="tls.invalid") as secure:
            secure.sendall(
                b"GET /secure HTTP/1.1\r\nHost: tls.invalid\r\nConnection: close\r\n\r\n"
            )
            assert read_all(secure).endswith(b"secure")
    assert proxy.requests[-1].startswith(b"CONNECT tls.invalid:443"), (
        "SNI must replace fake IP for proxy routing"
    )

    # Keep an active SSE connection across a configuration update.
    with framed_connection(broker, "plain.invalid", 80) as stream:
        stream.sendall(
            b"GET /sse HTTP/1.1\r\nHost: plain.invalid\r\nConnection: close\r\n\r\n"
        )
        assert b"200 OK" in read_head(stream)
        assert exact(stream, len(b"data: first\n\n")) == b"data: first\n\n"
        assert broker.request(
            "PUT", "/v1/network/config", network(replacement)
        ) == network(replacement)
        assert request(broker).endswith(b"secure")
        assert replacement.requests[-1].startswith(b"CONNECT plain.invalid:80")
        proxy.origin.release_sse.set()
        assert read_all(stream) == b"data: second\n\n", (
            "existing stream must retain its route"
        )

    replacement.reject = True
    before = proxy.origin.accepted
    assert (
        request(broker, "127.0.0.1", proxy.origin.server_address[1], "127.0.0.1") == b""
    )
    assert proxy.origin.accepted == before, (
        "rejected proxy must never fall back to direct"
    )
    replacement.reject = False
    assert request(broker, "auth.invalid") == b""
    broker.observations(
        lambda row: (
            row.get("proxy_status") == 407
            and row.get("hop") == "abyss_to_upstream_proxy"
        )
    )

    assert broker.request("PUT", "/v1/network/config", {"upstream": None}) == {
        "upstream": None
    }
    before = len(replacement.requests)
    assert request(
        broker, "127.0.0.1", proxy.origin.server_address[1], "127.0.0.1"
    ).endswith(b"secure")
    assert len(replacement.requests) == before, (
        "disabled proxy must restore direct routing"
    )
    stored = (broker.home / "runtime-policy.toml").read_text()
    assert "[network]" in stored, "direct override must be durable, not absent"
    restart(broker)
    assert broker.request("GET", "/v1/network/config") == {"upstream": None}
    assert request(
        broker, "127.0.0.1", proxy.origin.server_address[1], "127.0.0.1"
    ).endswith(b"secure")
    assert len(replacement.requests) == before, (
        "restart must not resurrect startup proxy"
    )

    broker.request("PUT", "/v1/network/config", network(replacement))
    assert request(broker).endswith(b"secure"), "enabling a proxy must affect new flows"
    restart(broker)
    assert broker.request("GET", "/v1/network/config") == network(replacement)
    assert request(broker).endswith(b"secure"), (
        "enabled route must survive broker restart"
    )


def main():
    if sys.platform != "darwin":
        raise SystemExit("macOS Network Extension ingress is required")
    origin, tls_origin = LocalServer(Origin), LocalServer(Origin)
    proxy, replacement = LocalServer(NextHop), LocalServer(NextHop)
    for server in (proxy, replacement):
        server.origin, server.tls_origin = origin, tls_origin
    broker = None
    try:
        with tempfile.TemporaryDirectory(prefix="abyss-ne-upstream-") as temporary:
            directory = Path(temporary)
            try:
                broker = Broker(directory, proxy, transparent=True)
                run_checks(broker, proxy, replacement)
                broker.close()
            except BaseException:
                if broker:
                    broker.close()
                log = directory / "broker.log"
                if log.exists():
                    print(log.read_text()[-18000:])
                raise
        print(
            "PASS: macOS framed ingress, proxy DNS, fake-IP/SNI, TLS, streaming, live route updates, direct mode, no fallback, proxy diagnostics"
        )
    finally:
        if broker and not broker.log.closed:
            broker.close()
        for server in (proxy, replacement, tls_origin, origin):
            server.close()


if __name__ == "__main__":
    main()
