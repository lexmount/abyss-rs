#!/usr/bin/env python3
"""Verify a real broker against an independent Linux-kernel WireGuard peer.

Requires Docker with NET_ADMIN inside the isolated container. Host routes and
interfaces are never changed. All randomly generated keys stay in temporary files.
"""

import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import time
import uuid

from blackbox_abyss_broker_upstream import (
    Broker,
    LocalServer,
    NextHop,
    Origin,
    ROOT,
    explicit_request,
    read_all,
    read_head,
)
from blackbox_abyss_broker_socks5_upstream import configure, exact


def keypair():
    private = subprocess.check_output(
        ["openssl", "genpkey", "-algorithm", "X25519", "-outform", "DER"]
    )
    public = subprocess.check_output(
        ["openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"],
        input=private,
    )
    return base64.b64encode(private[-32:]).decode(), base64.b64encode(
        public[-32:]
    ).decode()


class WireguardPeer:
    """Task-owned container; reusable by the real-provider validation runner."""

    def __init__(self, directory):
        self.directory = directory
        self.name = "abyss-wg-" + uuid.uuid4().hex[:12]
        self.started = False
        private, public = keypair()
        server_private, server_public = keypair()
        preshared = base64.b64encode(os.urandom(32)).decode()
        self.material = {
            "private_key": private,
            "public_key": server_public,
            "preshared_key": preshared,
            "addresses": ["10.77.0.2", "fd77::2"],
            "allowed_ips": ["0.0.0.0/0", "::/0"],
            "persistent_keepalive_secs": 15,
        }
        self.file = directory / "wireguard.json"
        self.file.write_text(json.dumps(self.material))
        self.file.chmod(0o600)
        peer = directory / "peer.json"
        peer.write_text(
            json.dumps(
                {
                    "private_key": server_private,
                    "client_public_key": public,
                    "preshared_key": preshared,
                }
            )
        )
        peer.chmod(0o600)

    def start(self):
        subprocess.run(
            [
                "docker",
                "build",
                "-q",
                "-t",
                "abyss-wireguard-test",
                str(ROOT / "scripts/fixtures/wireguard"),
            ],
            check=True,
        )
        subprocess.run(
            [
                "docker",
                "run",
                "--detach",
                "--rm",
                "--name",
                self.name,
                "--cap-add",
                "NET_ADMIN",
                "--sysctl",
                "net.ipv4.ip_forward=1",
                "--sysctl",
                "net.ipv6.conf.all.disable_ipv6=0",
                "--publish",
                "127.0.0.1::51820/udp",
                "--mount",
                f"type=bind,src={self.directory},dst=/config,readonly",
                "abyss-wireguard-test",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        self.started = True
        for _ in range(100):
            logs = subprocess.check_output(
                ["docker", "logs", self.name], stderr=subprocess.STDOUT
            )
            if b"READY" in logs:
                self.endpoint = subprocess.check_output(
                    ["docker", "port", self.name, "51820/udp"], text=True
                ).strip()
                return
            time.sleep(0.1)
        raise AssertionError("WireGuard peer did not become ready: " + logs.decode())

    def network(self, timeout=3000):
        return {
            "upstream": {
                "protocol": "wireguard",
                "endpoint": "wireguard://" + self.endpoint,
                "wireguard_file": str(self.file),
                "connect_timeout_ms": 1000,
                "handshake_timeout_ms": timeout,
            }
        }

    def stats(self):
        output = subprocess.check_output(
            ["docker", "exec", self.name, "wg", "show", "wg0", "transfer"], text=True
        ).split()
        return {"received": int(output[-2]), "sent": int(output[-1])}

    def close(self):
        if self.started:
            subprocess.run(
                ["docker", "rm", "--force", self.name],
                check=True,
                stdout=subprocess.DEVNULL,
            )
            self.started = False


def assert_invalid(broker, candidate, expected):
    connection = http.client.HTTPConnection(broker.api, timeout=5)
    connection.request(
        "PUT",
        "/v1/network/config",
        json.dumps(candidate),
        {
            "Authorization": "Bearer " + broker.token,
            "Content-Type": "application/json",
        },
    )
    response = connection.getresponse()
    body = response.read()
    connection.close()
    assert response.status == 400, (response.status, body)
    assert broker.request("GET", "/v1/network/config") == expected


def exercise(broker, peer, origin):
    route = peer.network()
    configure(broker, route)
    for host in ["10.77.0.1", "[fd77::1]"]:
        for connect in (False, True):
            print(f"Checking {host}:80 CONNECT={connect}", flush=True)
            explicit_request(broker, host + ":80", connect)
    with broker.connect("10.77.0.1:80") as stream:
        stream.sendall(
            b"GET /large HTTP/1.1\r\nHost: plain.invalid\r\nConnection: close\r\n\r\n"
        )
        read_head(stream)
        assert (
            hashlib.sha256(read_all(stream)).digest()
            == hashlib.sha256(bytes(range(256)) * 4096).digest()
        )
    context = ssl.create_default_context(cafile=str(broker.ca_file))
    with (
        broker.connect("10.77.0.1:443") as raw,
        context.wrap_socket(raw, server_hostname="tls.invalid") as stream,
    ):
        assert stream.getpeercert(binary_form=True) == ssl.PEM_cert_to_DER_cert(
            broker.origin_cert.read_text()
        )
        stream.sendall(
            b"GET /probe HTTP/1.1\r\nHost: tls.invalid\r\nConnection: close\r\n\r\n"
        )
        assert read_all(stream).endswith(b"secure")
    with broker.connect("10.77.0.1:80") as stream:
        stream.sendall(
            b"GET /sse HTTP/1.1\r\nHost: plain.invalid\r\nConnection: close\r\n\r\n"
        )
        read_head(stream)
        assert exact(stream, len(b"data: first\n\n")) == b"data: first\n\n"
        configure(broker, route)
        explicit_request(broker, "10.77.0.1:80")
        # Changing identity-owned settings must not interrupt this live stream.
        peer.file.write_text(json.dumps(dict(peer.material, mtu=1300)))
        assert_invalid(broker, route, route)
        peer.file.write_text(json.dumps(peer.material))
        configure(broker, {"upstream": None})
        subprocess.run(
            [
                "docker",
                "exec",
                peer.name,
                "python3",
                "-c",
                'import urllib.request; urllib.request.urlopen("http://10.77.0.1/release").read()',
            ],
            check=True,
        )
        assert b"data: second" in read_all(stream)
    configure(broker, route)
    peer.file.write_text("secret-invalid-json")
    explicit_request(broker, "10.77.0.1:80")
    assert_invalid(broker, route, route)
    peer.file.write_text(json.dumps(peer.material))
    before = origin.accepted
    with broker.connect(f"127.0.0.1:{origin.server_address[1]}", 502):
        pass
    with broker.connect(f"localhost:{origin.server_address[1]}", 502):
        pass
    assert origin.accepted == before, "WireGuard failure fell back to direct"
    broker.restart()
    assert broker.request("GET", "/v1/network/config") == route
    explicit_request(broker, "10.77.0.1:80")
    stats = peer.stats()
    assert stats["received"] > 0 and stats["sent"] > 1_048_576, stats
    # Change the peer PSK independently: the broker must time out, then recover
    # after the correct peer is restored and its route is reapplied.
    bad = dict(peer.material, preshared_key=base64.b64encode(os.urandom(32)).decode())
    configure(broker, {"upstream": None})
    time.sleep(0.3)
    peer.file.write_text(json.dumps(bad))
    configure(broker, peer.network(timeout=300))
    with broker.connect("10.77.0.1:80", 504):
        pass
    peer.file.write_text(json.dumps(peer.material))
    configure(broker, {"upstream": None})
    time.sleep(0.3)
    configure(broker, route)
    explicit_request(broker, "10.77.0.1:80")
    rows = broker.request("GET", "/v1/network/observations?limit=100")
    for key in ["private_key", "preshared_key"]:
        assert peer.material[key] not in json.dumps(rows)
        assert (
            peer.material[key] not in (broker.home / "runtime-policy.toml").read_text()
        )
    print(
        "PASS: kernel WireGuard interoperability, PSK, system-resolved address policy, IPv4/IPv6, HTTP/CONNECT, TLS, 1 MiB transfer, route snapshots, restart, no fallback, timeout and secret-safe configuration"
    )
    return stats


def main():
    origin, tls_origin, proxy = (
        LocalServer(Origin),
        LocalServer(Origin),
        LocalServer(NextHop),
    )
    proxy.origin, proxy.tls_origin = origin, tls_origin
    try:
        with tempfile.TemporaryDirectory(prefix="abyss-wireguard-") as temporary:
            directory = Path(temporary)
            broker = Broker(directory, proxy)
            peer = WireguardPeer(directory)
            try:
                peer.start()
                stats = exercise(broker, peer, origin)
                print(json.dumps({"wireguard_transfer": stats}))
                if sys.platform == "darwin":
                    from blackbox_abyss_broker_transparent_upstream import request

                    broker.close()
                    native = directory / "native"
                    native.mkdir()
                    broker = Broker(native, proxy, transparent=True)
                    configure(broker, peer.network())
                    assert request(broker, "10.77.0.1", 80, "10.77.0.1").endswith(
                        b"secure"
                    )
                    assert request(broker, "fd77::1", 80, "fd77::1").endswith(b"secure")
                    broker.restart()
                    assert request(broker, "10.77.0.1", 80, "10.77.0.1").endswith(
                        b"secure"
                    )
                    print(
                        "PASS: macOS framed transparent ingress and restart through WireGuard"
                    )
            except BaseException:
                print(
                    json.dumps(
                        broker.request("GET", "/v1/network/observations?limit=20")
                    ),
                    flush=True,
                )
                print(json.dumps(peer.stats()), flush=True)
                raise
            finally:
                broker.close()
                peer.close()
    finally:
        for server in [proxy, tls_origin, origin]:
            server.close()


if __name__ == "__main__":
    main()
