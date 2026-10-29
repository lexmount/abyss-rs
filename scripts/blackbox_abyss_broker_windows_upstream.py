#!/usr/bin/env python3
"""Test a running WFP broker with an isolated Node executable and real CONNECT peers.

The Host must redirect only the supplied executable to this broker. This script
restores network and TLS policy. It does not install a driver or change services.
Local servers test routing without external dependencies; --trusted-tls-host adds
an optional public HTTPS interception check with normal certificate validation.
"""

import argparse
import json
import os
import select
import socket
import socketserver
import ssl
import subprocess
import tempfile
import time
from pathlib import Path

from blackbox_abyss_broker_upstream import (
    Broker,
    LocalServer,
    Origin,
    network,
    openssl,
    read_head,
)


class WindowsNextHop(socketserver.BaseRequestHandler):
    def handle(self):
        request = read_head(self.request)
        self.server.requests.append(request)
        assert b"authorization" not in request.lower(), (
            "CONNECT leaked application credentials"
        )
        method, authority, version = request.split(b"\r\n", 1)[0].split()
        assert method == b"CONNECT" and version == b"HTTP/1.1"
        host, _port = authority.decode().rsplit(":", 1)
        status = 403 if self.server.reject else 407 if host == "auth.invalid" else None
        if status:
            self.request.sendall(
                f"HTTP/1.1 {status} Rejected\r\n\r\nprivate-proxy-body".encode()
            )
            return
        if host == "tls.invalid":
            destination = self.server.tls_origin.server_address
        elif host == self.server.trusted_host:
            destination = (host, 443)
        else:
            destination = self.server.origin.server_address
        with socket.create_connection(destination, timeout=5) as upstream:
            self.request.sendall(b"HTTP/1.1 200 Tunnel ready\r\n\r\n")
            readers = [self.request, upstream]
            while readers:
                ready, _, _ = select.select(readers, [], [], 12)
                if not ready:
                    raise TimeoutError("tunnel relay timeout")
                for source in ready:
                    destination = upstream if source is self.request else self.request
                    data = source.recv(16384)
                    if data:
                        destination.sendall(data)
                    else:
                        destination.shutdown(socket.SHUT_WR)
                        readers.remove(source)


class WindowsChecks:
    def __init__(self, args, directory):
        self.args = args
        self.directory = directory
        startup = json.loads(args.startup.read_text(encoding="utf-8-sig"))
        self.broker = Broker.__new__(Broker)
        self.broker.api = startup["api_addr"]
        self.broker.token = Path(startup["auth_token_file"]).read_text().strip()
        self.results = []
        self.clients = []

    def start_client(self, host="plain.invalid", port=8443, **options):
        payload = {"ip": "203.0.113.9", "port": port, "host": host} | options
        environment = dict(os.environ)
        for name in (
            "NODE_OPTIONS",
            "NODE_TLS_REJECT_UNAUTHORIZED",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
        ):
            environment.pop(name, None)
        client = subprocess.Popen(
            [
                str(self.args.node),
                str(Path(__file__).parent / "tests/windows_upstream_client.cjs"),
                json.dumps(payload),
            ],
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        self.clients.append(client)
        return client

    @staticmethod
    def finish(client, success=True):
        stdout, stderr = client.communicate(timeout=15)
        events = [json.loads(line) for line in stdout.splitlines()]
        assert events, (client.returncode, stdout, stderr)
        if success:
            assert client.returncode == 0 and events, (stdout, stderr)
            assert events[-1]["response"].endswith("secure"), events
        else:
            assert all(not event.get("response") for event in events), events
            assert all("timed out" not in event.get("error", "") for event in events), (
                events
            )
        return events[-1] if events else {"pid": client.pid}

    def probe(self, label, host="plain.invalid", **options):
        result = self.finish(self.start_client(host, **options))
        self.results.append({"case": label, "passed": True, "pid": result["pid"]})
        return result

    def run(self):
        origin, tls_origin = LocalServer(Origin), LocalServer(Origin)
        proxy, replacement = LocalServer(WindowsNextHop), LocalServer(WindowsNextHop)
        original_network = self.broker.request("GET", "/v1/network/config")
        original_mitm = self.broker.request("GET", "/v1/mitm/config")
        for server in (proxy, replacement):
            server.origin, server.tls_origin = origin, tls_origin
            server.trusted_host = self.args.trusted_tls_host
        certificate, key = self.directory / "origin.pem", self.directory / "origin.key"
        try:
            openssl(
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=tls.invalid",
                "-addext",
                "subjectAltName=DNS:tls.invalid",
                "-keyout",
                key,
                "-out",
                certificate,
            )
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certificate, key)
            tls_origin.tls = context
            self.broker.request(
                "PUT",
                "/v1/mitm/config",
                {"tls_decryption": {"default_action": "passthrough"}},
            )
            proxy_config = network(proxy)
            proxy_config["upstream"]["handshake_timeout_ms"] = 5000
            self.broker.request("PUT", "/v1/network/config", proxy_config)
            self.probe("HTTP Host replaces OS IP; original port retained")
            assert proxy.requests[-1].startswith(b"CONNECT plain.invalid:8443 HTTP/1.1")
            self.probe("IP literal target", host="203.0.113.9")
            assert proxy.requests[-1].startswith(b"CONNECT 203.0.113.9:8443 HTTP/1.1")
            result = self.probe(
                "TLS passthrough and SNI",
                host="tls.invalid",
                tls=True,
                ca=str(certificate),
            )
            assert result["certificate"]["authorized"]
            assert proxy.requests[-1].startswith(b"CONNECT tls.invalid:8443 HTTP/1.1")

            streaming = self.start_client(path="/sse")
            first = json.loads(streaming.stdout.readline())
            assert first["event"] == "first", first
            replacement_config = network(replacement)
            replacement_config["upstream"]["handshake_timeout_ms"] = 5000
            self.broker.request("PUT", "/v1/network/config", replacement_config)
            self.probe("hot update routes new flows to replacement")
            assert replacement.requests[-1].startswith(b"CONNECT plain.invalid:8443")
            origin.release_sse.set()
            stdout, stderr = streaming.communicate(timeout=15)
            assert streaming.returncode == 0 and "data: second" in stdout, (
                stdout,
                stderr,
            )
            self.results.append(
                {
                    "case": "existing SSE survives route replacement",
                    "passed": True,
                    "pid": streaming.pid,
                }
            )

            for host, status in (("plain.invalid", 403), ("auth.invalid", 407)):
                replacement.reject = status == 403
                before = origin.accepted
                failed = self.finish(self.start_client(host), success=False)
                assert origin.accepted == before, "proxy rejection reached origin"
                self.broker.observations(
                    lambda row, expected=status: (
                        row.get("proxy_status") == expected
                        and row.get("ingress_source") == "windows_wfp"
                    )
                )
                self.results.append(
                    {
                        "case": f"CONNECT {status} closes flow",
                        "passed": True,
                        "pid": failed["pid"],
                    }
                )
            replacement.reject = False

            self.broker.request(
                "PUT",
                "/v1/mitm/config",
                {"tls_decryption": {"default_action": "intercept"}},
            )
            failed = self.finish(
                self.start_client("tls.invalid", tls=True, ca=str(self.args.broker_ca)),
                success=False,
            )
            self.results.append(
                {
                    "case": "interception rejects untrusted target certificate",
                    "passed": True,
                    "pid": failed["pid"],
                }
            )
            if self.args.trusted_tls_host:
                client = self.start_client(
                    self.args.trusted_tls_host,
                    port=443,
                    tls=True,
                    path="/",
                    ca=str(self.args.broker_ca),
                )
                stdout, stderr = client.communicate(timeout=15)
                event = json.loads(stdout)
                assert client.returncode == 0 and event["response"].startswith(
                    "HTTP/1.1 "
                ), (
                    event,
                    stderr,
                )
                assert event["certificate"]["authorized"]
                self.results.append(
                    {
                        "case": "interception through proxy with trusted target TLS",
                        "passed": True,
                        "pid": client.pid,
                    }
                )

            status = self.broker.request("GET", "/v1/proxy/status")
            listen_addr = status["ingresses"][0]["listen_addr"]
            self.broker.request(
                "PUT",
                "/v1/network/config",
                {
                    "upstream": {
                        "protocol": "http_connect",
                        "endpoint": f"http://{listen_addr}",
                    }
                },
            )
            self.finish(self.start_client(), success=False)
            self.results.append(
                {"case": "reject broker listener as next hop", "passed": True}
            )

            self.broker.request("PUT", "/v1/network/config", {"upstream": None})
            assert self.broker.request("GET", "/v1/network/config") == {
                "upstream": None
            }
            self.results.append({"case": "clear upstream through REST", "passed": True})
            if self.args.trusted_tls_host:
                before = (len(proxy.requests), len(replacement.requests))
                client = self.start_client(
                    self.args.trusted_tls_host,
                    port=443,
                    ip=socket.gethostbyname(self.args.trusted_tls_host),
                    tls=True,
                    path="/",
                    ca=str(self.args.broker_ca),
                )
                stdout, stderr = client.communicate(timeout=15)
                event = json.loads(stdout)
                assert client.returncode == 0 and event["response"].startswith(
                    "HTTP/1.1 "
                ), (
                    event,
                    stderr,
                )
                assert (len(proxy.requests), len(replacement.requests)) == before
                self.results.append(
                    {
                        "case": "clear upstream restores direct traffic",
                        "passed": True,
                        "pid": client.pid,
                    }
                )
            time.sleep(0.2)
            diagnostics = self.broker.request("GET", "/v1/support/diagnostics")
            for result in self.results[:4]:
                flow = next(
                    flow
                    for flow in diagnostics["flow"]["recent_flows"]
                    if (flow.get("source_process") or {}).get("pid") == result["pid"]
                )
                assert flow["ingress"]["source"] == "windows_wfp", flow
            return self.results
        finally:
            try:
                self.broker.request("PUT", "/v1/network/config", original_network)
            finally:
                try:
                    self.broker.request("PUT", "/v1/mitm/config", original_mitm)
                finally:
                    for client in self.clients:
                        if client.poll() is None:
                            client.kill()
                            client.communicate(timeout=5)
                    for server in (proxy, replacement, origin, tls_origin):
                        server.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--startup", type=Path, required=True)
    parser.add_argument("--node", type=Path, required=True)
    parser.add_argument("--broker-ca", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--trusted-tls-host")
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("Windows WFP ingress is required")
    with tempfile.TemporaryDirectory(prefix="abyss-wfp-upstream-") as temporary:
        results = WindowsChecks(args, Path(temporary)).run()
    args.output.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"PASS: {len(results)} Windows WFP upstream checks")


if __name__ == "__main__":
    main()
