#!/usr/bin/env bash

set -euo pipefail

cargo_home="${CARGO_HOME:-${HOME}/.cargo}"
cargo_bin="${cargo_home}/bin"

if ! command -v rustup >/dev/null 2>&1 && [[ ! -x "${cargo_bin}/rustup" ]]; then
  curl --proto '=https' --tlsv1.2 --fail --silent --show-error \
    https://sh.rustup.rs | sh -s -- -y --default-toolchain none --profile minimal
fi

export PATH="${cargo_bin}:${PATH}"
command -v rustup >/dev/null 2>&1 || {
  echo "ensure_rustup: rustup is unavailable at ${cargo_bin}" >&2
  exit 1
}

if [[ -n "${GITHUB_PATH:-}" ]]; then
  echo "${cargo_bin}" >>"${GITHUB_PATH}"
fi
