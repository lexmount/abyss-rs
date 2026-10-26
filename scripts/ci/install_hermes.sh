#!/usr/bin/env bash
# Install the real Hermes CLI into a job-owned checkout with its upstream lockfile.
set -euo pipefail
client_dir="${1:?Usage: install_hermes.sh EMPTY_CLIENT_DIRECTORY}"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
revision="$(cat "$script_dir/hermes-revision.txt")"
[[ "$revision" =~ ^[0-9a-f]{40}$ ]] || { echo 'Invalid Hermes revision' >&2; exit 1; }
[[ ! -e "$client_dir" ]] || { echo 'Hermes install directory already exists' >&2; exit 1; }
git init "$client_dir"
git -C "$client_dir" fetch --depth=1 https://github.com/NousResearch/hermes-agent.git "$revision"
git -C "$client_dir" checkout --detach FETCH_HEAD
uv sync --project "$client_dir" --locked --python 3.14 --no-dev --extra anthropic
if [[ -n "${GITHUB_PATH:-}" ]]; then
  echo "$client_dir/.venv/bin" >> "$GITHUB_PATH"
fi
