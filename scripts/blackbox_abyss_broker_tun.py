#!/usr/bin/env python3
"""Exercise actual Linux TUN packets, broker control, and unprivileged TCP clients.

Run with blackbox_abyss_broker_tun.sh; every network change is confined to its
throwaway container. This test never uses HTTP_PROXY/CONNECT as its ingress.
"""

import http.client
import http.server
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from blackbox_abyss_broker_upstream import LocalServer, NextHop, network

BROKER_UID = 1000
CLIENT_UID = 2001
ROOT = Path(__file__).resolve().parents[1]


def command(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def request_client(host, port, ca, mode):
    payload = b"tun-payload" * 20000
    with socket.create_connection((host, int(port)), timeout=10) as stream:
        if mode == "tls":
            context = ssl.create_default_context(cafile=ca)
            stream = context.wrap_socket(stream, server_hostname="tun.test")
        stream.sendall(
            f"POST /tun-proof HTTP/1.1\r\nHost: tun.test\r\nContent-Length: {len(payload)}\r\nConnection: close\r\n\r\n".encode()
            + payload
        )
        if mode == "half-close":
            stream.shutdown(socket.SHUT_WR)
        data = bytearray()
        while chunk := stream.recv(65536):
            data.extend(chunk)
    head, body = data.split(b"\r\n\r\n", 1)
    assert head.startswith(b"HTTP/1.0 200"), head
    assert json.loads(body) == {"path": "/tun-proof", "payload_bytes": len(payload)}
    print(
        f"PASS {host} {mode}: exact 220000-byte request and response after routing through TUN"
    )


class Origin(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        payload = self.rfile.read(int(self.headers["Content-Length"]))
        assert payload == b"tun-payload" * 20000
        self.server.requests += 1
        body = json.dumps({"path": self.path, "payload_bytes": len(payload)}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


class Origin6(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6


def certificates(directory):
    ca = directory / "ca"
    ca.mkdir()
    command(
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "1",
        "-subj",
        "/CN=TUN Test CA",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
        "-keyout",
        str(ca / "abyss-root-ca-key.pem"),
        "-out",
        str(ca / "abyss-root-ca.pem"),
    )
    command(
        "openssl",
        "x509",
        "-in",
        str(ca / "abyss-root-ca.pem"),
        "-outform",
        "DER",
        "-out",
        str(ca / "abyss-root-ca.der"),
    )
    command(
        "openssl",
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-subj",
        "/CN=tun.test",
        "-keyout",
        str(directory / "origin.key"),
        "-out",
        str(directory / "origin.csr"),
    )
    extension = directory / "origin.ext"
    extension.write_text(
        "subjectAltName=DNS:tun.test\nbasicConstraints=critical,CA:FALSE\n"
    )
    command(
        "openssl",
        "x509",
        "-req",
        "-in",
        str(directory / "origin.csr"),
        "-CA",
        str(ca / "abyss-root-ca.pem"),
        "-CAkey",
        str(ca / "abyss-root-ca-key.pem"),
        "-CAcreateserial",
        "-days",
        "1",
        "-extfile",
        str(extension),
        "-out",
        str(directory / "origin.pem"),
    )
    os.chown(ca / "abyss-root-ca-key.pem", BROKER_UID, BROKER_UID)
    return ca


def configure():
    if not Path("/.dockerenv").exists() or os.getuid() != 0:
        raise RuntimeError(
            "run the Docker wrapper; network changes require an isolated container"
        )
    command(
        "ip", "tuntap", "add", "dev", "abyss0", "mode", "tun", "user", str(BROKER_UID)
    )
    command("ip", "addr", "add", "198.18.0.1/30", "dev", "abyss0")
    command("ip", "-6", "addr", "add", "fd00:100::1/128", "dev", "abyss0", "nodad")
    command("ip", "link", "set", "abyss0", "up")
    command("ip", "addr", "add", "10.200.0.1/32", "dev", "lo")
    command("ip", "-6", "addr", "add", "fd00:200::1/128", "dev", "lo", "nodad")
    # Local origins remove external dependencies. In this namespace only, move
    # local lookup after the test UID rule and accept replies from local IPs.
    for version in ("-4", "-6"):
        command("ip", version, "rule", "del", "pref", "0")
        command("ip", version, "rule", "add", "pref", "100", "lookup", "local")
        command(
            "ip", version, "route", "add", "table", "100", "default", "dev", "abyss0"
        )
        command(
            "ip",
            version,
            "rule",
            "add",
            "pref",
            "90",
            "uidrange",
            f"{CLIENT_UID}-{CLIENT_UID}",
            "ipproto",
            "tcp",
            "lookup",
            "100",
        )


def run():
    configure()
    with tempfile.TemporaryDirectory(prefix="abyss-tun-") as temporary:
        directory = Path(temporary)
        directory.chmod(0o755)
        ca = certificates(directory)
        home = directory / "home"
        home.mkdir()
        os.chown(home, BROKER_UID, BROKER_UID)
        (home / "runtime-policy.toml").write_text(
            'schema_version = 1\n[mitm.tls_decryption]\ndefault_action = "passthrough"\n'
        )
        config = directory / "broker.toml"
        config.write_text(
            f'schema_version = 1\n[ca]\npath = "{ca}"\n[proxy]\nmode = "linux_tun"\ndevice_name = "abyss0"\n'
        )
        startup = home / "startup.json"
        log = (directory / "broker.log").open("w+")
        servers = [
            http.server.ThreadingHTTPServer(("10.200.0.1", 0), Origin),
            Origin6(("fd00:200::1", 0), Origin),
            http.server.ThreadingHTTPServer(("10.200.0.1", 0), Origin),
        ]
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(directory / "origin.pem", directory / "origin.key")
        servers[-1].socket = context.wrap_socket(servers[-1].socket, server_side=True)
        for server in servers:
            server.requests = 0
            threading.Thread(target=server.serve_forever, daemon=True).start()
        process = subprocess.Popen(
            [
                str(ROOT / "target/debug/abyss-broker"),
                "--config",
                str(config),
                "--startup-info-file",
                str(startup),
            ],
            env={**os.environ, "ABYSS_HOME": str(home)},
            user=BROKER_UID,
            group=BROKER_UID,
            extra_groups=[],
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        try:
            for _ in range(200):
                if process.poll() is not None:
                    raise AssertionError("broker exited during startup")
                if startup.exists():
                    break
                time.sleep(0.05)
            else:
                raise AssertionError("TUN broker startup timeout")
            info = json.loads(startup.read_text())
            token = Path(info["auth_token_file"]).read_text().strip()

            def api(method, path, payload=None):
                connection = http.client.HTTPConnection(info["api_addr"], timeout=10)
                connection.request(
                    method,
                    path,
                    body=json.dumps(payload) if payload is not None else None,
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Content-Type": "application/json",
                    },
                )
                response = connection.getresponse()
                body = response.read()
                assert response.status == 200, (response.status, body)
                connection.close()
                return json.loads(body)

            status = api("GET", "/v1/proxy/status")
            assert status["mode"] == "transparent" and status["listen_addr"] is None, (
                status
            )
            assert status["ingresses"] == [
                {"source": "linux_tun", "listen_addr": None, "device_name": "abyss0"}
            ], status

            def exercise(server, mode):
                child = subprocess.run(
                    [
                        sys.executable,
                        __file__,
                        "--client",
                        server.server_address[0],
                        str(server.server_port),
                        str(ca / "abyss-root-ca.pem"),
                        mode,
                    ],
                    env={
                        key: value
                        for key, value in os.environ.items()
                        if "proxy" not in key.lower()
                    },
                    user=CLIENT_UID,
                    group=CLIENT_UID,
                    extra_groups=[],
                    capture_output=True,
                    check=False,
                    text=True,
                    timeout=20,
                )
                assert child.returncode == 0, child.stdout + child.stderr
                print(child.stdout.strip(), flush=True)

            for server, mode in [
                (servers[0], "http"),
                (servers[0], "half-close"),
                (servers[1], "http"),
                (servers[2], "tls"),
            ]:
                exercise(server, mode)
            assert [server.requests for server in servers] == [2, 1, 1]
            proxy = LocalServer(NextHop)
            proxy.origin = servers[0]
            proxy.tls_origin = servers[2]
            proxy.plain_hosts = ("10.200.0.1",)
            try:
                api("PUT", "/v1/network/config", network(proxy))
                exercise(servers[0], "http")
                assert len(proxy.requests) == 1
                expected = (
                    f"CONNECT 10.200.0.1:{servers[0].server_port} HTTP/1.1".encode()
                )
                assert proxy.requests[0].startswith(expected), proxy.requests[
                    0
                ].splitlines()[0]
                assert servers[0].requests == 3
                api("PUT", "/v1/network/config", {"upstream": None})
                print(
                    "PASS TUN flow uses the configured CONNECT next hop with its original target",
                    flush=True,
                )
            finally:
                proxy.close()
            process.terminate()
            assert process.wait(timeout=15) == 0
            command("ip", "link", "show", "abyss0")
            startup.unlink(missing_ok=True)
            process = subprocess.Popen(
                [
                    str(ROOT / "target/debug/abyss-broker"),
                    "--config",
                    str(config),
                    "--startup-info-file",
                    str(startup),
                ],
                env={**os.environ, "ABYSS_HOME": str(home)},
                user=BROKER_UID,
                group=BROKER_UID,
                extra_groups=[],
                stdout=log,
                stderr=subprocess.STDOUT,
            )
            for _ in range(200):
                assert process.poll() is None, "restarted broker exited"
                if startup.exists():
                    break
                time.sleep(0.05)
            else:
                raise AssertionError("restarted broker startup timeout")
            info = json.loads(startup.read_text())
            token = Path(info["auth_token_file"]).read_text().strip()
            assert (
                api("GET", "/v1/proxy/status")["ingresses"][0]["device_name"]
                == "abyss0"
            )
            print(
                "PASS stop/restart preserves the administrator-owned interface",
                flush=True,
            )
        finally:
            process.terminate()
            process.wait(timeout=15)
            for server in servers:
                server.shutdown()
                server.server_close()
            log.seek(0)
            print(log.read())
            log.close()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--client":
        request_client(*sys.argv[2:])
    else:
        run()
