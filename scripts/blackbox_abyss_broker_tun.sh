#!/usr/bin/env bash
# A dedicated Docker network namespace owns every test route and TUN device.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build --locked -p abyss-broker
docker build -t abyss-tun-blackbox:local scripts/testdata/linux-tun
docker run --rm --cap-add NET_ADMIN --device /dev/net/tun \
  --sysctl net.ipv4.conf.all.accept_local=1 \
  --sysctl net.ipv4.conf.default.accept_local=1 \
  --sysctl net.ipv4.conf.all.rp_filter=0 \
  --sysctl net.ipv4.conf.default.rp_filter=0 \
  -v "$PWD:/src:ro" abyss-tun-blackbox:local \
  python3 /src/scripts/blackbox_abyss_broker_tun.py
