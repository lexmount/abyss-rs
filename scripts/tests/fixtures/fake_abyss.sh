#!/usr/bin/env bash

set -euo pipefail

state_file="${ABYSS_HOME:?ABYSS_HOME is required}/local/fake-proxy.running"
case "${1:-}" in
  proxy)
    case "${2:-}" in
      start)
        mkdir -p "$(dirname "${state_file}")"
        : >"${state_file}"
        printf 'Abyss proxy is running on http://127.0.0.1:28999.\n'
        ;;
      stop)
        rm -f "${state_file}"
        printf 'Abyss proxy stopped.\n'
        ;;
      *) exit 2 ;;
    esac
    ;;
  status)
    [[ -f "${state_file}" ]] || exit 1
    printf 'Abyss proxy: running\n'
    ;;
  --version|-V|version)
    printf '1.0.0\n'
    ;;
  *) exit 2 ;;
esac
