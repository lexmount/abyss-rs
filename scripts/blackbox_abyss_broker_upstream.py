#!/usr/bin/env python3
"""Exercise upstream chaining through a real broker and local socket servers."""

import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import select
import socket
import socketserver
import sqlite3
import ssl
import subprocess
import tempfile
import threading
import time


ROOT = Path(__file__).resolve().parents[1]


def read_head(stream):
    result = bytearray()
    while not result.endswith(b"\r\n\r\n"):
        chunk = stream.recv(1)
        if not chunk:
            raise EOFError("connection closed before headers")
        result.extend(chunk)
        if len(result) > 32768:
            raise AssertionError("unbounded HTTP headers")
    return bytes(result)


def read_all(stream):
    result = bytearray()
    while True:
        chunk = stream.recv(4096)
        if not chunk:
            return bytes(result)
        result.extend(chunk)


def openssl(*args):
    subprocess.run(
        ["openssl", *map(str, args)],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


class LocalServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, handler):
        super().__init__(("127.0.0.1", 0), handler)
        self.requests = []
        self.accepted = 0
        self.release_sse = threading.Event()
        self.tls = None
        self.reject = False
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def get_request(self):
        stream, peer = super().get_request()
        self.accepted += 1
        stream.settimeout(5)
        return stream, peer

    def close(self):
        self.release_sse.set()
        self.shutdown()
        self.server_close()
        self.thread.join(timeout=5)

    def handle_error(self, request, client_address):
        # Peer closure is expected in rejection, TLS failure, and cancellation tests.
        pass


class Origin(socketserver.BaseRequestHandler):
    def handle(self):
        stream = self.request
        if self.server.tls:
            stream = self.server.tls.wrap_socket(stream, server_side=True)
        with stream:
            request = read_head(stream)
            self.server.requests.append(request)
            if b"GET /sse " in request:
                stream.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
                    b"Connection: close\r\n\r\ndata: first\n\n"
                )
                if not self.server.release_sse.wait(3):
                    raise AssertionError("broker buffered SSE instead of forwarding it")
                stream.sendall(b"data: second\n\n")
            elif b"GET /ws " in request:
                headers = {
                    name.lower(): value
                    for name, value in (
                        line.split(b":", 1)
                        for line in request.split(b"\r\n")[1:]
                        if b":" in line
                    )
                }
                key = headers[b"sec-websocket-key"].strip()
                accept = base64.b64encode(
                    hashlib.sha1(key + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest()
                )
                stream.sendall(
                    b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                    b"Connection: Upgrade\r\nSec-WebSocket-Accept: "
                    + accept
                    + b"\r\n\r\n"
                )
                stream.sendall(b"\x81\x05hello")
                stream.recv(32)
            else:
                stream.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsecure"
                )


class NextHop(socketserver.BaseRequestHandler):
    def handle(self):
        request = read_head(self.request)
        self.server.requests.append(request)
        method, authority, version = request.split(b"\r\n", 1)[0].split()
        assert method == b"CONNECT" and version == b"HTTP/1.1", request
        assert b"authorization" not in request.lower(), (
            "credentials escaped into CONNECT"
        )
        host, port = authority.decode("ascii").rsplit(":", 1)
        status = {"auth.invalid": 407, "denied.invalid": 403}.get(host)
        if self.server.reject:
            status = 403
        if status:
            self.request.sendall(
                f"HTTP/1.1 {status} Private reason\r\nProxy-Authenticate: Secret challenge\r\n\r\nSecret body".encode(
                    "ascii"
                )
            )
            return
        if host == "slow.invalid":
            time.sleep(0.7)
            return
        if host == "broken.invalid":
            self.request.sendall(b"invalid response\r\n\r\n")
            return
        if host == "eof.invalid":
            return
        if host == "tls.invalid":
            destination = self.server.tls_origin.server_address
        elif host == "plain.invalid" or host == "127.0.0.1":
            destination = self.server.origin.server_address
        else:
            raise AssertionError(f"unexpected test target: {host}:{port}")
        with socket.create_connection(destination, timeout=5) as target:
            # Use a legal non-200 response and a misleading body length.
            self.request.sendall(
                b"HTTP/1.1 201 Tunnel ready\r\nContent-Length: 9000\r\n\r\n"
            )
            readers = [self.request, target]
            while readers:
                ready, _, _ = select.select(readers, [], [], 5)
                if not ready:
                    return
                for source in ready:
                    destination_stream = (
                        target if source is self.request else self.request
                    )
                    chunk = source.recv(8192)
                    if chunk:
                        destination_stream.sendall(chunk)
                    else:
                        readers.remove(source)
                        destination_stream.shutdown(socket.SHUT_WR)


class Broker:
    def __init__(self, directory, proxy):
        self.directory = directory
        self.home = directory / "home"
        self.home.mkdir()
        ca = directory / "ca"
        ca.mkdir()
        self.ca_file = ca / "abyss-root-ca.pem"
        self.ca_key = ca / "abyss-root-ca-key.pem"
        openssl(
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=Abyss Chaining Test CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout",
            self.ca_key,
            "-out",
            self.ca_file,
        )
        openssl(
            "x509",
            "-in",
            self.ca_file,
            "-outform",
            "DER",
            "-out",
            ca / "abyss-root-ca.der",
        )
        origin_key = directory / "origin.key"
        origin_csr = directory / "origin.csr"
        self.origin_cert = directory / "origin.pem"
        openssl(
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=tls.invalid",
            "-keyout",
            origin_key,
            "-out",
            origin_csr,
        )
        extension = directory / "origin.ext"
        extension.write_text(
            "subjectAltName=DNS:tls.invalid\nbasicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n"
        )
        openssl(
            "x509",
            "-req",
            "-in",
            origin_csr,
            "-CA",
            self.ca_file,
            "-CAkey",
            self.ca_key,
            "-CAcreateserial",
            "-days",
            "1",
            "-extfile",
            extension,
            "-out",
            self.origin_cert,
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.origin_cert, origin_key)
        proxy.tls_origin.tls = context
        (self.home / "runtime-policy.toml").write_text(
            'schema_version = 1\n[mitm.tls_decryption]\ndefault_action = "passthrough"\n'
            "[hooks.harness_usage]\nenabled = false\n"
        )
        config = directory / "broker-config.toml"
        config.write_text(
            'schema_version = 1\n[ca]\npath = "ca"\n[proxy]\nmode = "explicit"\n'
            'listen_addr = "127.0.0.1:0"\n[proxy.upstream]\nprotocol = "http_connect"\n'
            f'endpoint = "http://127.0.0.1:{proxy.server_address[1]}"\n'
            "connect_timeout_ms = 1000\nhandshake_timeout_ms = 200\n"
        )
        self.token_file = directory / "token"
        startup = directory / "startup.json"
        self.log = (directory / "broker.log").open("w+")
        environment = dict(os.environ, ABYSS_HOME=str(self.home))
        binary_name = "abyss-broker.exe" if os.name == "nt" else "abyss-broker"
        binary = Path(
            os.environ.get("ABYSS_BROKER_BINARY", ROOT / "target/debug" / binary_name)
        )
        self.process = subprocess.Popen(
            [
                str(binary),
                "--api",
                "127.0.0.1:0",
                "--config",
                str(config),
                "--auth-token-file",
                str(self.token_file),
                "--startup-info-file",
                str(startup),
            ],
            env=environment,
            stdout=self.log,
            stderr=subprocess.STDOUT,
        )
        try:
            for _ in range(200):
                if self.process.poll() is not None:
                    self.log.seek(0)
                    raise AssertionError(self.log.read())
                if startup.exists():
                    self.api = json.loads(startup.read_text())["api_addr"]
                    self.token = self.token_file.read_text().strip()
                    status = self.request("GET", "/v1/proxy/status")
                    self.address = tuple(
                        status["ingresses"][0]["listen_addr"].rsplit(":", 1)
                    )
                    self.address = (self.address[0], int(self.address[1]))
                    return
                time.sleep(0.05)
            raise AssertionError("broker startup timed out")
        except BaseException:
            self.process.terminate()
            self.process.wait(timeout=5)
            self.log.close()
            raise

    def request(self, method, path, payload=None):
        connection = http.client.HTTPConnection(self.api, timeout=5)
        try:
            connection.request(
                method,
                path,
                body=json.dumps(payload) if payload is not None else None,
                headers={
                    "Authorization": f"Bearer {self.token}",
                    "Content-Type": "application/json",
                },
            )
            response = connection.getresponse()
            body = response.read()
            assert response.status == 200, (response.status, body)
            return json.loads(body)
        finally:
            connection.close()

    def connect(self, target, expected=200):
        stream = socket.create_connection(self.address, timeout=5)
        stream.sendall(
            f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Basic agent-secret\r\n\r\n".encode(
                "ascii"
            )
        )
        response = read_head(stream)
        assert int(response.split()[1]) == expected, response
        assert b"Secret" not in response and b"Proxy-Authenticate" not in response, (
            response
        )
        return stream

    def observations(self, predicate):
        for _ in range(100):
            rows = self.request("GET", "/v1/network/observations?limit=100")[
                "observations"
            ]
            matches = [row for row in rows if predicate(row)]
            if matches:
                return matches
            time.sleep(0.05)
        raise AssertionError(f"expected diagnostic observation missing: {rows}")

    def close(self):
        if self.process.poll() is None:
            try:
                self.request("POST", "/v1/shutdown")
                self.process.wait(timeout=5)
            except (OSError, AssertionError, subprocess.TimeoutExpired):
                self.process.terminate()
                self.process.wait(timeout=5)
        self.log.close()


def run_checks(broker, proxy):
    with socket.create_connection(broker.address, timeout=5) as client:
        client.sendall(
            b"GET http://plain.invalid:80/probe HTTP/1.1\r\nHost: plain.invalid\r\n"
            b"Authorization: Bearer model-test\r\nProxy-Authorization: Basic agent-secret\r\nConnection: close\r\n\r\n"
        )
        assert read_all(client).endswith(b"secure"), "plain HTTP forwarding failed"
    with broker.connect("plain.invalid:80") as client:
        client.sendall(
            b"GET /probe HTTP/1.1\r\nHost: plain.invalid\r\nConnection: close\r\n\r\n"
        )
        assert read_all(client).endswith(b"secure"), "HTTP inside CONNECT failed"
    assert all(request.startswith(b"GET /") for request in proxy.origin.requests), (
        "absolute-form was not normalized"
    )
    assert all(
        b"proxy-authorization" not in request.lower()
        for request in proxy.origin.requests
    ), "agent proxy credentials reached origin"
    with broker.connect("plain.invalid:80") as client:
        client.sendall(
            b"GET /sse HTTP/1.1\r\nHost: plain.invalid\r\nConnection: close\r\n\r\n"
        )
        read_head(client)
        first = bytearray()
        while b"data: first\n\n" not in first:
            chunk = client.recv(128)
            assert chunk, "SSE stream closed before the first event"
            first.extend(chunk)
        time.sleep(
            0.3
        )  # The established stream must outlive the 200 ms handshake budget.
        proxy.origin.release_sse.set()
        assert b"data: second" in read_all(client), "SSE continuation lost"
    with broker.connect("plain.invalid:80") as client:
        client.sendall(
            b"GET /ws HTTP/1.1\r\nHost: plain.invalid\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            b"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
        )
        assert read_head(client).startswith(b"HTTP/1.1 101"), "WebSocket upgrade failed"
        frame = bytearray()
        while len(frame) < 7:
            chunk = client.recv(7 - len(frame))
            assert chunk, "WebSocket closed before the complete frame"
            frame.extend(chunk)
        assert frame == b"\x81\x05hello", "WebSocket payload changed"
        client.sendall(b"\x88\x80\x00\x00\x00\x00")
    assert all(b"authorization" not in request.lower() for request in proxy.requests), (
        "CONNECT leaked credentials"
    )
    client_context = ssl.create_default_context(cafile=str(broker.ca_file))
    with broker.connect("tls.invalid:443") as raw:
        with client_context.wrap_socket(raw, server_hostname="tls.invalid") as client:
            expected_cert = ssl.PEM_cert_to_DER_cert(broker.origin_cert.read_text())
            assert client.getpeercert(binary_form=True) == expected_cert, (
                "passthrough substituted a certificate"
            )
            client.sendall(
                b"GET /probe HTTP/1.1\r\nHost: tls.invalid\r\nConnection: close\r\n\r\n"
            )
            assert read_all(client).endswith(b"secure"), "TLS passthrough failed"
    for target, status in [
        ("auth.invalid:443", 502),
        ("denied.invalid:443", 502),
        ("broken.invalid:443", 502),
        ("eof.invalid:443", 502),
        ("slow.invalid:443", 504),
    ]:
        with broker.connect(target, status):
            pass
    before = proxy.origin.accepted
    proxy.reject = True
    with broker.connect(f"127.0.0.1:{proxy.origin.server_address[1]}", 502):
        pass
    time.sleep(0.05)
    assert proxy.origin.accepted == before, (
        "broker bypassed a rejected proxy with a direct connection"
    )
    proxy.reject = False
    failures = broker.observations(
        lambda row: row.get("technical_error_code") == "upstream_proxy_auth_required"
    )
    assert failures[0]["hop"] == "abyss_to_upstream_proxy", failures
    assert failures[0]["proxy_status"] == 407 and failures[0]["http_status"] is None, (
        failures
    )
    assert failures[0]["destination_addr"] is None and failures[0]["flow_id"], failures
    assert failures[0]["target_authority"] == "auth.invalid:443", failures
    assert "Secret" not in json.dumps(failures), (
        "proxy response content leaked into diagnostics"
    )
    successes = broker.observations(
        lambda row: (
            row.get("destination_host") == "plain.invalid"
            and row.get("outcome") == "succeeded"
        )
    )
    assert successes[0]["destination_addr"] is None, successes
    assert successes[0]["proxy_peer"] == f"127.0.0.1:{proxy.server_address[1]}", (
        successes
    )
    broker.request(
        "PUT",
        "/v1/mitm/config",
        {"tls_decryption": {"default_action": "intercept", "rules": []}},
    )
    try:
        with broker.connect("tls.invalid:443") as raw:
            with client_context.wrap_socket(
                raw, server_hostname="tls.invalid"
            ) as client:
                client.sendall(b"GET /probe HTTP/1.1\r\nHost: tls.invalid\r\n\r\n")
                assert b"secure" not in read_all(client), (
                    "broker accepted an untrusted target certificate"
                )
    except (ssl.SSLError, OSError, EOFError):
        pass
    broker.observations(
        lambda row: (
            row.get("technical_error_code") == "provider_tls_error"
            and row.get("proxy_peer")
        )
    )


def main():
    origin = LocalServer(Origin)
    tls_origin = LocalServer(Origin)
    proxy = LocalServer(NextHop)
    proxy.origin = origin
    proxy.tls_origin = tls_origin
    broker = None
    try:
        with tempfile.TemporaryDirectory(prefix="abyss-upstream-") as temporary:
            directory = Path(temporary)
            try:
                broker = Broker(directory, proxy)
                run_checks(broker, proxy)
                broker.close()
                database = sqlite3.connect(broker.home / "data/abyss.sqlite3")
                try:
                    row = database.execute(
                        "SELECT hop, proxy_status, http_status, destination_addr FROM network_observations WHERE technical_error_code = 'upstream_proxy_auth_required'"
                    ).fetchone()
                    assert row == ("abyss_to_upstream_proxy", 407, None, None), row
                finally:
                    database.close()
            except BaseException:
                if broker:
                    broker.close()
                log = directory / "broker.log"
                if log.exists():
                    print(log.read_text()[-18000:])
                raise
        print(
            "PASS: HTTP, CONNECT, TLS passthrough, target certificate validation, SSE, WebSocket, failure isolation, no direct fallback, durable diagnostics"
        )
    finally:
        if broker and not broker.log.closed:
            broker.close()
        proxy.close()
        tls_origin.close()
        origin.close()


if __name__ == "__main__":
    main()
