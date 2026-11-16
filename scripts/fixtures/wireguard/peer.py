"""Independent Linux-kernel WireGuard peer for broker interoperability tests."""

import http.server
import json
from pathlib import Path
import socket
import ssl
import subprocess
import threading
import time


def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL)


config = json.loads(Path("/config/peer.json").read_text())
wireguard = Path("/tmp/wg.conf")
wireguard.write_text(
    "[Interface]\nListenPort = 51820\nPrivateKey = "
    + config["private_key"]
    + "\n[Peer]\nPublicKey = "
    + config["client_public_key"]
    + "\nPresharedKey = "
    + config["preshared_key"]
    + "\nAllowedIPs = 10.77.0.2/32, fd77::2/128\n"
)
wireguard.chmod(0o600)
run("ip", "link", "add", "wg0", "type", "wireguard")
run("wg", "setconf", "wg0", str(wireguard))
wireguard.unlink()
run("ip", "address", "add", "10.77.0.1/24", "dev", "wg0")
run("ip", "-6", "address", "add", "fd77::1/64", "dev", "wg0")
run("ip", "link", "set", "wg0", "up")
# Docker Desktop's userspace gateway may forward packets with checksum-offload
# placeholders. Compute a real inner TCP checksum before WireGuard encryption;
# the broker keeps full IP/TCP checksum validation enabled.
run("tc", "qdisc", "add", "dev", "wg0", "clsact")
run(
    "tc",
    "filter",
    "add",
    "dev",
    "wg0",
    "egress",
    "protocol",
    "ip",
    "u32",
    "match",
    "ip",
    "protocol",
    "6",
    "0xff",
    "action",
    "csum",
    "tcp",
)
run(
    "iptables",
    "-t",
    "nat",
    "-A",
    "POSTROUTING",
    "-s",
    "10.77.0.0/24",
    "-o",
    "eth0",
    "-j",
    "MASQUERADE",
)
dns = subprocess.Popen(
    [
        "dnsmasq",
        "--keep-in-foreground",
        "--bind-interfaces",
        "--listen-address=10.77.0.1",
        "--listen-address=fd77::1",
        "--address=/plain.invalid/tls.invalid/10.77.0.1",
        "--address=/plain.invalid/tls.invalid/fd77::1",
    ]
)
release = threading.Event()


class Origin(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path == "/release":
            release.set()
        if self.path == "/sse":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b"data: first\n\n")
            self.wfile.flush()
            if release.wait(20):
                self.wfile.write(b"data: second\n\n")
            self.close_connection = True
            return
        body = b"secure" if self.path != "/large" else bytes(range(256)) * 4096
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def log_message(self, *_):
        pass


class V6Server(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6


for address, cls in [
    ("10.77.0.1", http.server.ThreadingHTTPServer),
    ("fd77::1", V6Server),
]:
    for port in (80, 443):
        server = cls((address, port), Origin)
        if port == 443:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain("/config/origin.pem", "/config/origin.key")
            server.socket = context.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
print("READY", flush=True)
while dns.poll() is None:
    time.sleep(1)
raise RuntimeError("DNS service stopped")
