# Linux Codex capture through the explicit launcher

## Problem and observed behavior

Task: `fix-linux.md`. The installed Linux CLI and broker were version 1.6.0;
Codex was 0.169.0 and its shared app-server was 0.169.1. The task baseline is
`5552403` (endpoint 1.6.1).

`abyss run` gives its child the explicit-proxy environment. Interactive Codex
can instead submit work to a previously started shared app-server, whose
environment has no proxy variables. The model request then bypasses Abyss even
though the TUI inherited the proxy. A real interactive control returned its
marker with no matching persisted events. The same control with
`codex --no-daemon` returned its marker and produced three persisted events.
`codex exec` also successfully captured and uploaded its request and response.
This isolates the problem to the process that owns the model connection rather
than parsing or delivery.

The exact launcher also failed before spawning Codex in a noninteractive
terminal: Linux unconditionally invoked sudo to reinstall the already trusted
CA and enable/start the already healthy broker.

## Implementation

The CLI owns agent command preparation. For a directly invoked `codex`
executable, it detects support for `--no-daemon` from that executable's help
and adds the option before caller arguments. This keeps model traffic in a
process inheriting the launch environment without editing Codex configuration,
stopping shared servers, or changing the model/provider. Older versions lacking
the option keep their original arguments. Explicit remote-server operations,
queueing, and daemon management retain their requested behavior and are outside
the local capture guarantee. An explicit `--no-daemon` is preserved.
The argument scan skips option values and stops at `--`, so directory/model
values and prompt text cannot be mistaken for server-selection options.
Codex's [versioned CLI implementation](https://github.com/openai/codex/blob/rust-v0.169.0/codex-rs/cli/src/main.rs)
defines the foreground option and its explicit-remote incompatibility.

Linux checks the current CA fingerprint before requesting privileged
installation. Broker startup reuses an authenticated, healthy CLI-owned explicit
endpoint under the existing lifecycle lock when no restart or alternate service
user was requested. Missing trust and genuinely required service operations
still follow the installation/systemd path. Startup identity, token, mode, and
PID checks remain authoritative.

No event schema, ingestion API, storage, backend, SDK, or packaged native
dependency changes are needed. The fix belongs entirely in `abyss-rs`.

Real headless validation also exposed a pre-existing empty-prewarm case. Codex
sent an explicit `response.create` with `generate: false` and no conversation
content. The decoder discarded the client frame as irrelevant before recording
the generation flag; the later server usage was therefore emitted without its
prewarm purpose. This added two observed input tokens to inference accounting.
A read-only request inspector established the actual flag; no token-size or
event-position heuristic is used. Retain an explicitly disabled generation frame
as semantically relevant even when its input is empty, so the existing
accumulator, purpose contract, uploader, and backend preserve that distinction.
Missing, true, or nonboolean generation flags keep their existing semantics.

## Compatibility with Linux TUN ingress

The branch incorporates upstream `d8769be` (PR #93). TUN ingress is an opt-in
broker transport; the CLI continues to manage explicit ingress only. Upstream's
additive `linux_tun` source and optional `device_name` status field are retained
in the CLI client. Existing explicit status responses remain valid, and broker
reuse still checks explicit mode, PID, token ownership, and a TCP endpoint before
launching a proxied child.

Upstream worker supervision publishes lifecycle changes independently of status
reads and releases the state lock while connections drain. CLI reuse relies on
that public lifecycle contract without taking ownership of the worker or changing
its start/stop sequencing. The shared TUN/WireGuard network stack remains below
MITM and Agent Hook; foreground Codex selection and explicit empty-prewarm
classification apply unchanged above that transport boundary. The four task
patches rebase without textual conflicts or changes to their code.

Rebase verification includes workspace tests and Clippy, explicit-proxy and
combined TUN/WireGuard black-box checks, and real Codex/DSH capture through the
rebuilt broker. Revision-specific evidence is preserved in
`task-artifacts/fix-linux/sync-main-20261118T050917Z/` under the coordinator root.

## Validation

Unit tests cover Codex capability and argument handling, non-Codex preservation,
explicit remote/control operations, and supported/older help output. Public CLI
black-box checks exercise command preparation and runtime reuse. Required
verification also includes workspace tests, formatting, linting, broker black-box
tests, and real Codex interactive/headless and DSH traffic through the submitted
broker and delivery plugin into a dedicated local backend. Persisted session
markers, request/response content, usage, and spool state establish delivery.

The persistent HTML report and sanitized logs live under
`task-artifacts/fix-linux/` in the coordinator workspace. Final tested revisions,
commands, counts, and artifact links will be recorded there before handoff.

Run the interactive regression against a prepared environment with:

```sh
python3 scripts/blackbox_codex_launcher.py \
  --abyss /absolute/path/to/abyss \
  --state-root /absolute/path/to/cli-state \
  --backend-url http://127.0.0.1:BACKEND_PORT \
  --bearer-file /private/path/to/backend.bearer \
  --artifacts /private/path/to/interactive-evidence
```

This test deliberately avoids model/configuration/sandbox overrides that can
make Codex select an embedded server independently of the launcher. It checks
an actual completed terminal turn, persisted request and response markers,
Codex identification, and nonzero output usage. The private terminal trace is
kept separate from the credential-free JSON result. The exact-launch local
environment reuses this machine's existing CA without installing a test CA into
system trust; its backend database, bearer, broker, worker, and spool are isolated.
