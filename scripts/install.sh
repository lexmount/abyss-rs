#!/bin/sh
# Public CLI download installer. Release packaging replaces the version marker.
# Keep this entry point compatible with POSIX sh, including Debian dash.

set -eu

fail() { printf 'abyss installer: %s\n' "$*" >&2; exit 1; }
require() { command -v "$1" >/dev/null 2>&1 || fail "required command '$1' is missing"; }
run_install() { if [ "$use_sudo" = yes ]; then sudo "$@"; else "$@"; fi; }
needs_privilege() {
    ancestor=$1
    while [ ! -e "$ancestor" ]; do ancestor=$(dirname "$ancestor"); done
    [ ! -d "$ancestor" ] || [ ! -w "$ancestor" ]
}
cleanup() {
    if [ -n "$bin_stage" ]; then run_install rm -rf "$bin_stage"; fi
    if [ -n "$service_stage" ]; then run_install rm -rf "$service_stage"; fi
    if [ -n "$work" ]; then rm -rf "$work"; fi
}
download() {
    curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL \
        --retry 3 --connect-timeout 15 --max-time 300 -o "$2" "$1"
}
usage() {
    cat <<'EOF'
Usage: sh install.sh [--prefix DIRECTORY] [--version VERSION]

Download and install abyss, abyss-broker, and abyss-delivery-plugin.
Supports macOS ARM64 and Linux x86_64 with systemd. No Rust toolchain required.

  --prefix DIRECTORY  Binary installation prefix (default: /usr/local).
  --version VERSION   Install a particular release, for example 1.0.0.
  -h, --help          Show help.

Run as your normal user; privileged installation uses sudo when needed.
Stop Abyss before upgrading. Existing configuration and data are preserved.
DESTDIR stages files below an absolute directory without reloading systemd.
EOF
}

main() {
    version='@ABYSS_VERSION@'
    prefix=/usr/local
    destdir=${DESTDIR:-}
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --prefix|--version)
                [ "$#" -ge 2 ] && [ -n "$2" ] || fail "$1 requires a value"
                case "$1" in --prefix) prefix=$2 ;; --version) version=${2#v} ;; esac
                shift 2 ;;
            -h|--help) usage; return ;;
            *) fail "unknown argument: $1 (use --help)" ;;
        esac
    done
    # The downloaded installer is pinned to its release, avoiding latest races.
    printf '%s\n' "$version" | LC_ALL=C grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' \
        || fail 'expected a stable version such as 1.0.0; use the released install.sh'
    case "$prefix" in /*) ;; *) fail '--prefix must be absolute' ;; esac
    # Also keeps the Linux systemd ExecStart replacement literal.
    case "$prefix" in *[!a-zA-Z0-9/_.-]*) fail '--prefix supports letters, digits, slash, underscore, dot, and hyphen' ;; esac
    case "$destdir" in ''|/*) ;; *) fail 'DESTDIR must be absolute' ;; esac
    prefix=${prefix%/}
    destdir=${destdir%/}
    bin_dir=$prefix/bin
    install_bin_dir=$destdir$bin_dir
    service_dir=$destdir/etc/systemd/system

    platform=$(uname -s)
    architecture=$(uname -m)
    case "$platform/$architecture" in
        Darwin/arm64|Darwin/aarch64) target=aarch64-apple-darwin ;;
        Linux/x86_64|Linux/amd64) target=x86_64-unknown-linux-musl ;;
        *) fail "no prebuilt CLI for $platform/$architecture; use scripts/install-cli.sh from a source checkout" ;;
    esac
    if [ "$platform" = Linux ] && [ -z "$destdir" ]; then
        require systemctl
        systemctl show-environment >/dev/null || fail 'Linux installation requires a running systemd'
    fi
    for command in curl tar mktemp install; do require "$command"; done
    if command -v sha256sum >/dev/null 2>&1; then
        hash_command=sha256sum
    else
        require shasum
        hash_command=shasum
    fi

    use_sudo=no
    work=''
    bin_stage=''
    service_stage=''
    trap cleanup 0
    trap 'exit 1' 1 2 15
    work=$(mktemp -d "${TMPDIR:-/tmp}/abyss-download.XXXXXX")
    archive=abyss-cli-v$version-$target.tar.gz
    base=https://github.com/lexmount/abyss-rs/releases/download/v$version
    printf 'Downloading Abyss CLI %s for %s...\n' "$version" "$target"
    download "$base/SHA256SUMS" "$work/SHA256SUMS"
    download "$base/$archive" "$work/$archive"
    expected=$(awk -v name="$archive" '$2 == name { print $1 }' "$work/SHA256SUMS")
    [ "${#expected}" -eq 64 ] || fail "missing or duplicate SHA-256 for $archive"
    case "$expected" in *[!0-9a-f]*) fail 'invalid SHA-256 in release manifest' ;; esac
    if [ "$hash_command" = sha256sum ]; then
        actual=$(sha256sum "$work/$archive" | cut -d ' ' -f 1)
    else
        actual=$(shasum -a 256 "$work/$archive" | cut -d ' ' -f 1)
    fi
    [ "$actual" = "$expected" ] || fail "SHA-256 mismatch for $archive"

    # Extract only known files to stdout, never archive-supplied filesystem paths.
    mkdir "$work/runtime"
    for file in abyss abyss-broker abyss-delivery-plugin abyss-broker@.service VERSION LICENSE; do
        tar -xOzf "$work/$archive" "$file" > "$work/runtime/$file" \
            || fail "invalid release archive: missing $file"
        [ -s "$work/runtime/$file" ] || fail "empty release file: $file"
    done
    [ "$(cat "$work/runtime/VERSION")" = "$version" ] || fail 'archive version does not match the release'
    for binary in abyss abyss-broker abyss-delivery-plugin; do
        chmod 0755 "$work/runtime/$binary"
        "$work/runtime/$binary" --help >/dev/null || fail "$binary cannot run on this system"
        [ ! -d "$install_bin_dir/$binary" ] || fail "destination is a directory: $install_bin_dir/$binary"
    done
    [ "$("$work/runtime/abyss" version)" = "$version" ] || fail 'CLI version does not match the release'
    [ ! -d "$service_dir/abyss-broker@.service" ] || fail 'systemd unit destination is a directory'

    if needs_privilege "$install_bin_dir" || { [ "$platform" = Linux ] && needs_privilege "$service_dir"; }; then
        if [ "$(id -u)" -ne 0 ]; then require sudo; use_sudo=yes; fi
    fi
    if [ "$platform" = Linux ] && [ -z "$destdir" ] && [ "$(id -u)" -ne 0 ]; then
        require sudo
        use_sudo=yes
    fi
    # Authenticate through the controlling terminal, never through the piped script.
    if [ "$use_sudo" = yes ]; then sudo -v; fi
    run_install mkdir -p "$install_bin_dir"
    bin_stage=$(run_install mktemp -d "$install_bin_dir/.abyss-install.XXXXXX")
    for binary in abyss abyss-broker abyss-delivery-plugin; do
        run_install install -m 0755 "$work/runtime/$binary" "$bin_stage/$binary"
    done
    if [ "$platform" = Linux ]; then
        run_install mkdir -p "$service_dir"
        service_stage=$(run_install mktemp -d "$service_dir/.abyss-install.XXXXXX")
        sed "s|^ExecStart=/usr/local/bin/abyss-broker |ExecStart=$bin_dir/abyss-broker |" \
            "$work/runtime/abyss-broker@.service" > "$work/unit"
        run_install install -m 0644 "$work/unit" "$service_stage/abyss-broker@.service"
    fi
    for binary in abyss abyss-broker abyss-delivery-plugin; do
        run_install mv -f "$bin_stage/$binary" "$install_bin_dir/$binary"
    done
    if [ "$platform" = Linux ]; then
        run_install mv -f "$service_stage/abyss-broker@.service" "$service_dir/abyss-broker@.service"
        if [ -z "$destdir" ]; then run_install systemctl daemon-reload; fi
    fi
    printf 'Installed Abyss CLI %s in %s\n' "$version" "$install_bin_dir"
    if [ -z "$destdir" ]; then
        case ":$PATH:" in
            *":$bin_dir:"*) ;;
            *) printf "Add to your shell PATH: export PATH=\"%s:\$PATH\"\n" "$bin_dir" ;;
        esac
        printf '\nTo start a local environment (requires Node.js 22+ and npm 10+):\n  abyss deploy-local start\n  abyss run -- codex\n'
    fi
}

# Parse the complete function before running commands when installed with curl | sh.
main "$@"
