#!/usr/bin/env bash

set -euo pipefail

readonly DEFAULT_ABYSS_RS_REPOSITORY="https://github.com/lexmount/abyss-rs.git"
readonly DEFAULT_ABYSS_RS_REF="main"
readonly DEFAULT_BACKEND_REPOSITORY="https://github.com/lexmount/abyss-backend.git"
readonly DEFAULT_BACKEND_REVISION="872c030f333e881fc25d452e73677a36090b69c6"
readonly DEFAULT_DASHBOARD_PACKAGE="@lexmount.com/abyss-dashboard@0.1.0"
readonly LOCAL_CONFIG_VERSION="1"

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

require_version_at_least() {
  local label="$1"
  local actual="$2"
  local minimum="$3"
  case "${actual}" in
    ''|*[!0-9]*) fail "could not determine ${label} major version" ;;
  esac
  [[ "${actual}" -ge "${minimum}" ]] \
    || fail "${label} ${minimum} or newer is required; found ${actual}"
}

require_safe_path_value() {
  local label="$1"
  local value="$2"
  case "${value}" in
    /*) ;;
    *) fail "${label} must be an absolute path: ${value}" ;;
  esac
  [[ "${value}" != *$'\n'* && "${value}" != *$'\r'* ]] \
    || fail "${label} must not contain newlines"
}

validate_port() {
  local label="$1"
  local value="$2"
  case "${value}" in
    ''|*[!0-9]*) fail "${label} must be a numeric TCP port" ;;
  esac
  [[ "${value}" -ge 1 && "${value}" -le 65535 ]] \
    || fail "${label} must be between 1 and 65535"
}

checkout_source() {
  local repository="$1"
  local revision="$2"
  local destination="$3"
  git init -q "${destination}"
  git -C "${destination}" remote add origin "${repository}"
  git -C "${destination}" fetch --depth 1 origin "${revision}"
  git -C "${destination}" checkout -q --detach FETCH_HEAD
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
  if [[ -d "${destination_directory}" && -w "${destination_directory}" ]]; then
    install -m "${mode}" "${source}" "${destination}"
  else
    run_privileged install -d -m 0755 "${destination_directory}"
    run_privileged install -m "${mode}" "${source}" "${destination}"
  fi
}

atomic_write_install_config() {
  local destination="$1"
  local temporary
  temporary="$(mktemp "${destination}.tmp.XXXXXX")"
  chmod 600 "${temporary}"
  cat >"${temporary}"
  mv -f "${temporary}" "${destination}"
}

platform="$(uname -s)"
architecture="$(uname -m)"
case "${platform}/${architecture}" in
  Darwin/arm64|Linux/x86_64) ;;
  *) fail "supported platforms are macOS ARM64 and Linux x86_64; found ${platform}/${architecture}" ;;
esac

for required in cargo curl git install mktemp node npm openssl; do
  require_command "${required}"
done
require_version_at_least "Node.js" "$(node -p 'process.versions.node.split(".")[0]')" 22
require_version_at_least "npm" "$(npm --version | cut -d. -f1)" 10

ABYSS_HOME="${ABYSS_HOME:-${HOME}/.abyss}"
USER_INSTALL_ROOT="${ABYSS_INSTALL_ROOT:-${HOME}/.local}"
USER_BIN_DIR="${USER_INSTALL_ROOT}/bin"
if [[ "${platform}" == "Linux" ]]; then
  RUNTIME_BIN_DIR="${ABYSS_RUNTIME_BIN_DIR:-/usr/local/bin}"
else
  RUNTIME_BIN_DIR="${ABYSS_RUNTIME_BIN_DIR:-${USER_BIN_DIR}}"
fi
BACKEND_PORT="${ABYSS_LOCAL_BACKEND_PORT:-8080}"
DASHBOARD_PORT="${ABYSS_LOCAL_DASHBOARD_PORT:-5173}"
ABYSS_RS_REPOSITORY="${ABYSS_RS_REPOSITORY:-${DEFAULT_ABYSS_RS_REPOSITORY}}"
ABYSS_RS_REF="${ABYSS_RS_REF:-${DEFAULT_ABYSS_RS_REF}}"
BACKEND_REPOSITORY="${ABYSS_BACKEND_REPOSITORY:-${DEFAULT_BACKEND_REPOSITORY}}"
BACKEND_REVISION="${ABYSS_BACKEND_REVISION:-${DEFAULT_BACKEND_REVISION}}"
DASHBOARD_PACKAGE="${ABYSS_DASHBOARD_PACKAGE:-${DEFAULT_DASHBOARD_PACKAGE}}"

require_safe_path_value "ABYSS_HOME" "${ABYSS_HOME}"
require_safe_path_value "user install root" "${USER_INSTALL_ROOT}"
require_safe_path_value "runtime binary directory" "${RUNTIME_BIN_DIR}"
validate_port "backend port" "${BACKEND_PORT}"
validate_port "dashboard port" "${DASHBOARD_PORT}"
[[ "${BACKEND_PORT}" != "${DASHBOARD_PORT}" ]] \
  || fail "backend and dashboard ports must differ"

if [[ "${platform}" == "Linux" ]]; then
  [[ "${RUNTIME_BIN_DIR}" == "/usr/local/bin" ]] \
    || fail "Linux runtime binaries must be installed in /usr/local/bin for the systemd service"
  current_user="$(id -un)"
  [[ "${HOME}" == "/home/${current_user}" ]] \
    || fail "Linux local installation currently requires HOME=/home/${current_user}"
  require_command systemctl
fi

existing_product_config="${ABYSS_HOME}/product-config.json"
if [[ -e "${existing_product_config}" ]]; then
  [[ -f "${existing_product_config}" && ! -L "${existing_product_config}" ]] \
    || fail "existing product configuration is not a regular file: ${existing_product_config}"
  grep -Fq '"plugin_id": "lexmount.abyss.local"' "${existing_product_config}" \
    || fail "${existing_product_config} belongs to another deployment; set ABYSS_HOME to a separate directory"
fi

install_workspace="$(mktemp -d "${TMPDIR:-/tmp}/abyss-local-install.XXXXXX")"
cleanup() {
  rm -rf "${install_workspace}"
}
trap cleanup EXIT

if [[ -n "${ABYSS_RS_SOURCE_DIR:-}" ]]; then
  ABYSS_RS_SOURCE="${ABYSS_RS_SOURCE_DIR}"
  [[ -f "${ABYSS_RS_SOURCE}/Cargo.toml" ]] \
    || fail "ABYSS_RS_SOURCE_DIR is not an abyss-rs checkout: ${ABYSS_RS_SOURCE}"
else
  ABYSS_RS_SOURCE="${install_workspace}/abyss-rs"
  info "fetching abyss-rs ${ABYSS_RS_REF}"
  checkout_source "${ABYSS_RS_REPOSITORY}" "${ABYSS_RS_REF}" "${ABYSS_RS_SOURCE}"
fi

if [[ -n "${ABYSS_BACKEND_SOURCE_DIR:-}" ]]; then
  BACKEND_SOURCE="${ABYSS_BACKEND_SOURCE_DIR}"
  [[ -f "${BACKEND_SOURCE}/Cargo.toml" ]] \
    || fail "ABYSS_BACKEND_SOURCE_DIR is not an abyss-backend checkout: ${BACKEND_SOURCE}"
else
  BACKEND_SOURCE="${install_workspace}/abyss-backend"
  info "fetching abyss-backend ${BACKEND_REVISION}"
  checkout_source "${BACKEND_REPOSITORY}" "${BACKEND_REVISION}" "${BACKEND_SOURCE}"
fi

ABYSS_TARGET_DIR="${install_workspace}/target-abyss"
BACKEND_TARGET_DIR="${install_workspace}/target-backend"

info "building Abyss CLI runtime"
CARGO_TARGET_DIR="${ABYSS_TARGET_DIR}" cargo build \
  --release \
  --locked \
  --manifest-path "${ABYSS_RS_SOURCE}/Cargo.toml" \
  --package abyss-cli \
  --package abyss-broker \
  --package abyss-delivery-plugin

info "building sqlite+fts backend"
CARGO_TARGET_DIR="${BACKEND_TARGET_DIR}" cargo build \
  --release \
  --locked \
  --manifest-path "${BACKEND_SOURCE}/Cargo.toml" \
  --package abyss-backend \
  --no-default-features \
  --features sqlite-fts

mkdir -p "${USER_BIN_DIR}"
chmod 755 "${USER_INSTALL_ROOT}" "${USER_BIN_DIR}"
for binary in abyss abyss-broker abyss-delivery-plugin; do
  install_runtime_file \
    "${ABYSS_TARGET_DIR}/release/${binary}" \
    "${RUNTIME_BIN_DIR}/${binary}" \
    0755
done
install_runtime_file \
  "${BACKEND_TARGET_DIR}/release/abyss-backend" \
  "${RUNTIME_BIN_DIR}/abyss-backend" \
  0755

if [[ "${platform}" == "Linux" ]]; then
  install_runtime_file \
    "${ABYSS_RS_SOURCE}/platform/linux/abyss-broker@.service" \
    "/etc/systemd/system/abyss-broker@.service" \
    0644
  run_privileged systemctl daemon-reload
fi

info "installing dashboard ${DASHBOARD_PACKAGE}"
npm install --global --prefix "${USER_INSTALL_ROOT}" "${DASHBOARD_PACKAGE}"
install -m 0755 "${ABYSS_RS_SOURCE}/scripts/abyss-local" "${USER_BIN_DIR}/abyss-local"

umask 077
mkdir -p "${ABYSS_HOME}/local"
chmod 700 "${ABYSS_HOME}" "${ABYSS_HOME}/local"
cat <<EOF | atomic_write_install_config "${ABYSS_HOME}/local/install.conf"
config_version=${LOCAL_CONFIG_VERSION}
runtime_bin_dir=${RUNTIME_BIN_DIR}
user_bin_dir=${USER_BIN_DIR}
backend_port=${BACKEND_PORT}
dashboard_port=${DASHBOARD_PORT}
EOF

ABYSS_HOME="${ABYSS_HOME}" "${USER_BIN_DIR}/abyss-local" init
if [[ "${ABYSS_LOCAL_NO_START:-0}" != "1" ]]; then
  ABYSS_HOME="${ABYSS_HOME}" "${USER_BIN_DIR}/abyss-local" start
fi

info "installation complete"
if [[ ":${PATH}:" != *":${USER_BIN_DIR}:"* ]]; then
  info "add ${USER_BIN_DIR} to PATH before running abyss-local"
fi
if [[ ":${PATH}:" != *":${RUNTIME_BIN_DIR}:"* ]]; then
  info "add ${RUNTIME_BIN_DIR} to PATH before running abyss"
fi
info "manage the environment with: abyss-local status|stop|start"
