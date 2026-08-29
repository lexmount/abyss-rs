#!/usr/bin/env bash

set -euo pipefail

fail() {
  printf 'install-local: %s\n' "$*" >&2
  exit 1
}

info() {
  printf 'install-local: %s\n' "$*"
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command is missing: $1"
}

run_privileged() {
  if [[ "$(id -u)" == "0" ]]; then
    "$@"
  else
    require_command sudo
    sudo "$@"
  fi
}

install_runtime_file() {
  local source="$1"
  local destination="$2"
  local mode="$3"
  local destination_directory
  destination_directory="$(dirname "${destination}")"
  if [[ ! -d "${destination_directory}" ]]; then
    if ! install -d -m 0755 "${destination_directory}" 2>/dev/null; then
      run_privileged install -d -m 0755 "${destination_directory}"
    fi
  fi
  if [[ -w "${destination_directory}" ]]; then
    install -m "${mode}" "${source}" "${destination}"
  else
    run_privileged install -m "${mode}" "${source}" "${destination}"
  fi
}

platform="$(uname -s)"
architecture="$(uname -m)"
case "${platform}/${architecture}" in
  Darwin/arm64|Linux/x86_64) ;;
  *) fail "supported platforms are macOS ARM64 and Linux x86_64; found ${platform}/${architecture}" ;;
esac

for required in cargo install; do
  require_command "${required}"
done

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
ABYSS_RS_SOURCE="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
[[ -f "${ABYSS_RS_SOURCE}/Cargo.toml" ]] \
  || fail "run this installer from an abyss-rs checkout: ${ABYSS_RS_SOURCE}"

if [[ "${platform}" == "Linux" ]]; then
  RUNTIME_BIN_DIR="${ABYSS_RUNTIME_BIN_DIR:-/usr/local/bin}"
  [[ "${RUNTIME_BIN_DIR}" == "/usr/local/bin" ]] \
    || fail "Linux runtime binaries must be installed in /usr/local/bin for the systemd service"
  current_user="$(id -un)"
  [[ "${HOME}" == "/home/${current_user}" ]] \
    || fail "Linux local installation requires HOME=/home/${current_user} for the systemd service"
  [[ -z "${ABYSS_HOME:-}" || "${ABYSS_HOME}" == "${HOME}/.abyss" ]] \
    || fail "Linux local installation requires ABYSS_HOME=${HOME}/.abyss for the systemd service"
else
  USER_INSTALL_ROOT="${ABYSS_INSTALL_ROOT:-${HOME}/.local}"
  RUNTIME_BIN_DIR="${ABYSS_RUNTIME_BIN_DIR:-${USER_INSTALL_ROOT}/bin}"
fi
case "${RUNTIME_BIN_DIR}" in
  /*) ;;
  *) fail "runtime binary directory must be absolute: ${RUNTIME_BIN_DIR}" ;;
esac
BUILD_TARGET_DIR="${ABYSS_LOCAL_BUILD_TARGET_DIR:-${ABYSS_RS_SOURCE}/target}"
case "${BUILD_TARGET_DIR}" in
  /*) ;;
  *) fail "build target directory must be absolute: ${BUILD_TARGET_DIR}" ;;
esac

info "building the Abyss CLI runtime"
CARGO_TARGET_DIR="${BUILD_TARGET_DIR}" cargo build \
  --release \
  --locked \
  --manifest-path "${ABYSS_RS_SOURCE}/Cargo.toml" \
  --package abyss-cli \
  --package abyss-broker \
  --package abyss-delivery-plugin

for binary in abyss abyss-broker abyss-delivery-plugin; do
  install_runtime_file \
    "${BUILD_TARGET_DIR}/release/${binary}" \
    "${RUNTIME_BIN_DIR}/${binary}" \
    0755
done

if [[ "${platform}" == "Linux" ]]; then
  require_command systemctl
  install_runtime_file \
    "${ABYSS_RS_SOURCE}/platform/linux/abyss-broker@.service" \
    "/etc/systemd/system/abyss-broker@.service" \
    0644
  run_privileged systemctl daemon-reload
fi

if [[ "${ABYSS_LOCAL_NO_START:-0}" != "1" ]]; then
  info "deploying the local SQLite+FTS backend and dashboard"
  "${RUNTIME_BIN_DIR}/abyss" deploy-local start
fi

info "installation complete"
if [[ ":${PATH}:" != *":${RUNTIME_BIN_DIR}:"* ]]; then
  info "add ${RUNTIME_BIN_DIR} to PATH before running abyss"
fi
info "manage the environment with: abyss deploy-local start|stop|status"
