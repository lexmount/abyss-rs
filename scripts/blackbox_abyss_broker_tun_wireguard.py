#!/usr/bin/env python3
"""Test TUN ingress and WireGuard egress against the shared kernel-peer fixture.

Both network paths run inside dedicated Docker namespaces. This orchestrator
never changes host routes and keeps temporary peer keys out of test evidence.
"""

import json
import subprocess
import tempfile
from pathlib import Path

from blackbox_abyss_broker_tun import certificates
from blackbox_abyss_broker_upstream import ROOT
from blackbox_abyss_broker_wireguard import WireguardPeer


def main():
    subprocess.run(
        ["cargo", "build", "--locked", "-p", "abyss-broker"], cwd=ROOT, check=True
    )
    subprocess.run(
        [
            "docker",
            "build",
            "-q",
            "-t",
            "abyss-tun-blackbox:local",
            str(ROOT / "scripts/testdata/linux-tun"),
        ],
        check=True,
    )
    with tempfile.TemporaryDirectory(prefix="abyss-tun-wireguard-") as temporary:
        directory = Path(temporary)
        ca = certificates(directory, owner=None)
        peer = WireguardPeer(directory)
        try:
            peer.start()
            address = subprocess.check_output(
                [
                    "docker",
                    "inspect",
                    "--format",
                    '{{(index .NetworkSettings.Networks "bridge").IPAddress}}',
                    peer.name,
                ],
                text=True,
            ).strip()
            assert address, "kernel peer must have an address on the Docker bridge"
            subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--add-host",
                    "tun.test:10.77.0.1",
                    "--cap-add",
                    "NET_ADMIN",
                    "--device",
                    "/dev/net/tun",
                    "--sysctl",
                    "net.ipv4.conf.all.accept_local=1",
                    "--sysctl",
                    "net.ipv4.conf.default.accept_local=1",
                    "--sysctl",
                    "net.ipv4.conf.all.rp_filter=0",
                    "--sysctl",
                    "net.ipv4.conf.default.rp_filter=0",
                    "-v",
                    str(ROOT) + ":/src:ro",
                    "-v",
                    str(peer.file) + ":/run/wireguard/material.json:ro",
                    "-v",
                    str(ca / "abyss-root-ca.pem") + ":/run/wireguard/ca.pem:ro",
                    "-e",
                    "ABYSS_TUN_TEST_WIREGUARD_ENDPOINT=wireguard://"
                    + address
                    + ":51820",
                    "-e",
                    "ABYSS_TUN_TEST_WIREGUARD_FILE=/run/wireguard/material.json",
                    "-e",
                    "ABYSS_TUN_TEST_WIREGUARD_CA=/run/wireguard/ca.pem",
                    "abyss-tun-blackbox:local",
                    "python3",
                    "/src/scripts/blackbox_abyss_broker_tun.py",
                ],
                check=True,
            )
            stats = peer.stats()
            assert stats["received"] > 0 and stats["sent"] >= 3 * 1024 * 1024
            print(
                "PASS kernel WireGuard peer confirms encrypted TUN workload transfer: "
                + json.dumps(stats)
            )
        finally:
            peer.close()


if __name__ == "__main__":
    main()
