#!/usr/bin/env bash
# Exercise actual Codex command isolation without a model or API credential.
set -euo pipefail

probe_dir=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/abyss-codex-sandbox.XXXXXX")
trap 'rm -rf -- "$probe_dir"' EXIT
printf '%s\n' 'ABYSS_CODEX_SANDBOX_OK' > "$probe_dir/probe.txt"
cd "$probe_dir"

# Both paths use the same sandbox settings as the matrix and randomized E2E.
# A failed shell launch must fail this step, before any billable model calls.
codex sandbox -c 'sandbox_mode="read-only"' -- /bin/sh -eu -c '
  test "$(cat probe.txt)" = ABYSS_CODEX_SANDBOX_OK
  if (printf forbidden > forbidden.txt) 2>/dev/null; then
    echo "Codex read-only sandbox unexpectedly allowed a workspace write" >&2
    exit 1
  fi
'

codex sandbox -c 'sandbox_mode="workspace-write"' -- /bin/sh -eu -c '
  cat probe.txt > copied.txt
  cmp probe.txt copied.txt
'

echo 'Codex sandbox checks passed (read-only and workspace-write)'
