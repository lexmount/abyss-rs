#!/usr/bin/env bash
# Build the native CLI runtime from this checkout and install its three binaries.

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: bash scripts/install-cli.sh [--prefix DIRECTORY]

Build and install abyss, abyss-broker, and abyss-delivery-plugin from source.
Supports macOS and Linux. Requires Rust and a native C/C++ build toolchain.

  --prefix DIRECTORY  Install binaries in DIRECTORY/bin (default: /usr/local).
  -h, --help          Show this help.

Linux also installs /etc/systemd/system/abyss-broker@.service and runs
systemctl daemon-reload. Run as your normal user; installation uses sudo
only when the destination requires it. Stop Abyss before upgrading.

DESTDIR stages files below an absolute directory without reloading systemd.
CARGO_TARGET_DIR selects the Cargo build directory.
EOF
}

fail() {
  printf 'install-cli: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command '$1' is missing. $2"
}

prefix=/usr/local
destdir="${DESTDIR:-}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix)
      [[ $# -ge 2 && -n "$2" ]] || fail '--prefix requires an absolute directory'
      prefix="$2"
      shift 2
      ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown argument: $1 (use --help)" ;;
  esac
done

[[ "$prefix" == /* && "$prefix" != *$'\n'* && "$prefix" != *$'\r'* && "$prefix" != *:* ]] \
  || fail '--prefix must be an absolute, single-line directory without a colon'
[[ -z "$destdir" || "$destdir" == /* ]] || fail 'DESTDIR must be an absolute directory'
prefix="${prefix%/}"
destdir="${destdir%/}"
bin_dir="${prefix}/bin"
install_bin_dir="${destdir}${bin_dir}"
service_dir="${destdir}/etc/systemd/system"
platform="$(uname -s)"
case "$platform" in
  Darwin) ;;
  Linux)
    # Keep the ExecStart path literal; systemd has its own quoting and expansion.
    [[ "$bin_dir" != *[!a-zA-Z0-9/_.-]* ]] \
      || fail 'Linux --prefix supports only letters, digits, slash, underscore, dot, and hyphen'
    if [[ -z "$destdir" ]]; then
      require_command systemctl 'Linux CLI lifecycle requires systemd.'
      systemctl show-environment >/dev/null \
        || fail 'systemd must be running to install the Linux CLI service'
    fi
    ;;
  *) fail "unsupported operating system: $platform (expected macOS or Linux)" ;;
esac

require_command cargo 'Install the Rust stable toolchain first.'
require_command rustc 'Install the Rust stable toolchain first.'
require_command cc 'Install Xcode Command Line Tools on macOS or a C/C++ toolchain on Linux.'

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
host_target="$(rustc -vV | sed -n 's/^host: //p')"
[[ -n "$host_target" && "$host_target" != *[!a-zA-Z0-9_.-]* ]] \
  || fail 'could not determine the native Rust target'
target_dir="${CARGO_TARGET_DIR:-${repo_root}/target}"
[[ "$target_dir" == /* ]] || target_dir="${repo_root}/${target_dir}"
artifact_dir="${target_dir}/${host_target}/release"
binaries=(abyss abyss-broker abyss-delivery-plugin)

printf 'Building the Abyss CLI runtime for %s...\n' "$host_target"
cargo build --release --locked \
  --manifest-path "${repo_root}/Cargo.toml" \
  --target "$host_target" --target-dir "$target_dir" \
  --package abyss-cli --package abyss-broker --package abyss-delivery-plugin

for binary in "${binaries[@]}"; do
  [[ -x "${artifact_dir}/${binary}" ]] || fail "build did not produce ${artifact_dir}/${binary}"
  "${artifact_dir}/${binary}" --help >/dev/null
done

# Installation is the only privileged phase. Stage replacements beside their
# destinations so an existing running executable can finish on its old inode.
use_sudo=false
needs_privilege() {
  local ancestor="$1"
  while [[ ! -e "$ancestor" ]]; do ancestor="$(dirname "$ancestor")"; done
  [[ ! -d "$ancestor" || ! -w "$ancestor" ]]
}
if needs_privilege "$install_bin_dir" \
  || { [[ "$platform" == Linux ]] && needs_privilege "$service_dir"; }; then
  if [[ "$EUID" -ne 0 ]]; then
    require_command sudo 'Administrator access is required for the installation directory.'
    use_sudo=true
  fi
fi
install_run() {
  if "$use_sudo"; then sudo "$@"; else "$@"; fi
}

bin_stage=''
service_stage=''
cleanup() {
  if [[ -n "$bin_stage" ]]; then install_run rm -rf "$bin_stage"; fi
  if [[ -n "$service_stage" ]]; then install_run rm -rf "$service_stage"; fi
}
trap cleanup EXIT

for binary in "${binaries[@]}"; do
  [[ ! -d "${install_bin_dir}/${binary}" ]] || fail "destination is a directory: ${install_bin_dir}/${binary}"
done
install_run mkdir -p "$install_bin_dir"
bin_stage="$(install_run mktemp -d "${install_bin_dir}/.abyss-install.XXXXXX")"
for binary in "${binaries[@]}"; do
  install_run install -m 0755 "${artifact_dir}/${binary}" "${bin_stage}/${binary}"
done

if [[ "$platform" == Linux ]]; then
  [[ ! -d "${service_dir}/abyss-broker@.service" ]] || fail 'systemd unit destination is a directory'
  install_run mkdir -p "$service_dir"
  service_stage="$(install_run mktemp -d "${service_dir}/.abyss-install.XXXXXX")"
  sed "s|^ExecStart=/usr/local/bin/abyss-broker |ExecStart=${bin_dir}/abyss-broker |" \
    "${repo_root}/platform/linux/abyss-broker@.service" \
    | install_run tee "${service_stage}/abyss-broker@.service" >/dev/null
  install_run chmod 0644 "${service_stage}/abyss-broker@.service"
fi

for binary in "${binaries[@]}"; do
  install_run mv -f "${bin_stage}/${binary}" "${install_bin_dir}/${binary}"
done
if [[ "$platform" == Linux ]]; then
  install_run mv -f "${service_stage}/abyss-broker@.service" "${service_dir}/abyss-broker@.service"
  if [[ -z "$destdir" ]]; then
    if [[ "$EUID" -eq 0 ]]; then
      systemctl daemon-reload
    else
      require_command sudo 'Administrator access is required to reload systemd.'
      sudo systemctl daemon-reload
    fi
  fi
fi

printf 'Installed the Abyss CLI runtime in %s\n' "$install_bin_dir"
if [[ -n "$destdir" ]]; then
  printf 'Staged installation complete; runtime prefix: %s\n' "${prefix:-/}"
else
  "${install_bin_dir}/abyss" version
  case ":${PATH}:" in
    *":${bin_dir}:"*) ;;
    *) printf '\nAdd the installation directory to your shell PATH:\n  export PATH=%q:"$PATH"\n' "$bin_dir" ;;
  esac
  printf '\nNext, with Node.js 22+ and npm 10+ installed:\n  abyss deploy-local start\n  abyss run -- codex\n'
fi
