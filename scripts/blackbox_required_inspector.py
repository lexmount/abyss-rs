#!/usr/bin/env python3
"""Verify required inspectors through a real broker and upstream provider."""
import json
import tempfile
import threading
from pathlib import Path

from blackbox_abyss_broker_upstream import Broker, LocalServer, NextHop
from blackbox_request_blocking import Plugin, Provider, request


def main():
    origin, tls_origin, proxy = LocalServer(Provider), LocalServer(Provider), LocalServer(NextHop)
    origin.bodies, origin.messages = [], []
    origin.head_received, origin.release_reverse = threading.Event(), threading.Event()
    proxy.origin, proxy.tls_origin = origin, tls_origin
    broker = None
    try:
        with tempfile.TemporaryDirectory(prefix="abyss-required-") as directory:
            directory = Path(directory)
            broker = Broker(directory, proxy)
            config = directory / "broker-config.toml"
            config.write_text('required_inspectors = ["enterprise"]\n' + config.read_text())
            broker.restart()
            endpoint = json.loads((directory / "startup.json").read_text())["plugin_endpoint"]
            body = b'{"model":"test","input":"test"}'
            def denied():
                before = len(origin.requests)
                result = request(broker, body)
                assert b"503 Service Unavailable" in result, result
                assert len(origin.requests) == before, "request bytes reached provider without required inspector"
            denied()
            unrelated = Plugin(endpoint, lambda _: True)
            denied()
            required = Plugin(endpoint, lambda _: True, plugin_id="enterprise")
            assert b"200 OK" in request(broker, body)
            duplicate = Plugin(endpoint, lambda _: True, plugin_id="enterprise")
            denied()
            duplicate.close()
            assert b"200 OK" in request(broker, body)
            required.close()
            denied()
            unrelated.close()
            broker.close()
        print("PASS: absent, unrelated, duplicate and disconnected required inspector fail closed; connected inspector permits forwarding")
    finally:
        if broker and not broker.log.closed:
            broker.close()
        proxy.close()
        origin.close()
        tls_origin.close()


if __name__ == "__main__":
    main()
