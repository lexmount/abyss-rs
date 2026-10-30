#!/usr/bin/env python3
"""Test independently installed proxy implementations without altering user config.

Reference versions: Mihomo v1.19.33 and Tinyproxy 1.11.3. Supply isolated binary
paths; this script does not download software or contact external target services.
"""

import argparse
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import time

from blackbox_abyss_broker_upstream import Broker, LocalServer, Origin, read_all


def reserve_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


class Endpoint:
    def __init__(self, port, tls_origin):
        self.server_address = ("127.0.0.1", port)
        self.tls_origin = tls_origin


class ProxyProcess:
    def __init__(self, command, port, directory):
        self.log = (directory / "process.log").open("w+")
        self.process = subprocess.Popen(
            command, stdout=self.log, stderr=subprocess.STDOUT
        )
        try:
            for _ in range(100):
                if self.process.poll() is not None:
                    raise RuntimeError("proxy exited before readiness")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        return
                except OSError:
                    time.sleep(0.05)
            raise RuntimeError("proxy did not bind its listener")
        except BaseException:
            self.log.seek(0)
            print(self.log.read())
            self.close()
            raise

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            self.process.wait(timeout=5)
        self.log.close()


def verify_endpoint(directory, label, port, origin, tls_origin):
    directory.mkdir()
    broker = Broker(directory, Endpoint(port, tls_origin))
    try:
        target = f"127.0.0.1:{origin.server_address[1]}"
        with broker.connect(target) as client:
            client.sendall(
                f"GET /probe HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n".encode(
                    "ascii"
                )
            )
            assert read_all(client).endswith(b"secure"), label
        target = f"127.0.0.1:{tls_origin.server_address[1]}"
        context = ssl.create_default_context(cafile=str(broker.ca_file))
        with broker.connect(target) as raw:
            with context.wrap_socket(raw, server_hostname="tls.invalid") as client:
                assert client.getpeercert(binary_form=True) == ssl.PEM_cert_to_DER_cert(
                    broker.origin_cert.read_text()
                ), label
                client.sendall(
                    f"GET /probe HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n".encode(
                        "ascii"
                    )
                )
                assert read_all(client).endswith(b"secure"), label
        rows = broker.observations(
            lambda row: (
                row.get("proxy_peer") == f"127.0.0.1:{port}"
                and row.get("outcome") == "succeeded"
            )
        )
        assert rows[0]["destination_addr"] == f"127.0.0.1:{origin.server_address[1]}", (
            rows
        )
        print(f"PASS: {label}, HTTP and TLS targets through CONNECT")
    finally:
        broker.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mihomo", required=True, type=Path)
    parser.add_argument("--tinyproxy", required=True, type=Path)
    args = parser.parse_args()
    origin = LocalServer(Origin)
    tls_origin = LocalServer(Origin)
    try:
        with tempfile.TemporaryDirectory(prefix="abyss-proxy-interop-") as temporary:
            directory = Path(temporary)
            mihomo_directory = directory / "mihomo"
            mihomo_directory.mkdir()
            http_port, mixed_port = reserve_port(), reserve_port()
            config = mihomo_directory / "config.yaml"
            config.write_text(
                f"port: {http_port}\nmixed-port: {mixed_port}\nallow-lan: false\n"
                "bind-address: 127.0.0.1\nmode: direct\nlog-level: warning\n"
                "ipv6: false\ndns:\n  enable: false\nrules:\n  - MATCH,DIRECT\n"
            )
            process = ProxyProcess(
                [
                    str(args.mihomo.resolve()),
                    "-d",
                    str(mihomo_directory),
                    "-f",
                    str(config),
                ],
                http_port,
                mihomo_directory,
            )
            try:
                verify_endpoint(
                    directory / "broker-mihomo-http",
                    "Mihomo HTTP",
                    http_port,
                    origin,
                    tls_origin,
                )
                verify_endpoint(
                    directory / "broker-mihomo-mixed",
                    "Mihomo mixed",
                    mixed_port,
                    origin,
                    tls_origin,
                )
            finally:
                process.close()
            tiny_directory = directory / "tinyproxy"
            tiny_directory.mkdir()
            tiny_port = reserve_port()
            config = tiny_directory / "tinyproxy.conf"
            config.write_text(
                f"Port {tiny_port}\nListen 127.0.0.1\nTimeout 10\n"
                f'LogFile "{tiny_directory / "tinyproxy.log"}"\nLogLevel Error\n'
                f'PidFile "{tiny_directory / "tinyproxy.pid"}"\nMaxClients 16\nAllow 127.0.0.1\n'
                f"ConnectPort {origin.server_address[1]}\nConnectPort {tls_origin.server_address[1]}\n"
            )
            process = ProxyProcess(
                [str(args.tinyproxy.resolve()), "-d", "-c", str(config)],
                tiny_port,
                tiny_directory,
            )
            try:
                verify_endpoint(
                    directory / "broker-tinyproxy",
                    "Tinyproxy HTTP",
                    tiny_port,
                    origin,
                    tls_origin,
                )
            finally:
                process.close()
    finally:
        tls_origin.close()
        origin.close()


if __name__ == "__main__":
    main()
