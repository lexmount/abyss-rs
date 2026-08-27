#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SERVICE_FILE="${1:-${REPO_ROOT}/platform/linux/abyss-broker@.service}"

grep -F -- "--config /home/%i/.abyss/broker-config.toml" \
  "${SERVICE_FILE}" >/dev/null
grep -F -- "--api 127.0.0.1:0" "${SERVICE_FILE}" >/dev/null
grep -F -- \
  "--startup-info-file /home/%i/.abyss/runtime/startup-info.json" \
  "${SERVICE_FILE}" >/dev/null
grep -F -- \
  "ExecStartPre=/bin/rm -f /home/%i/.abyss/runtime/startup-info.json /home/%i/.abyss/runtime/broker.token" \
  "${SERVICE_FILE}" >/dev/null
grep -F -- \
  "ExecStopPost=/bin/rm -f /home/%i/.abyss/runtime/startup-info.json /home/%i/.abyss/runtime/broker.token" \
  "${SERVICE_FILE}" >/dev/null

if grep -F -- "--api 127.0.0.1:18190" "${SERVICE_FILE}" >/dev/null; then
  echo "Linux systemd unit must use a dynamic broker API port" >&2
  exit 1
fi
if grep -F -- "/home/%i/.abyss/config.json" "${SERVICE_FILE}" >/dev/null; then
  echo "Linux systemd unit must not read the retired config.json" >&2
  exit 1
fi

echo "Linux systemd service unit test passed"
