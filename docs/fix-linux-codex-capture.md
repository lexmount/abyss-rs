# Linux explicit-proxy startup reuse

## Investigation and current scope

Task: `fix-linux.md`. The installed Linux CLI and broker were version 1.6.0;
Codex was 0.169.0 and its shared app-server was 0.169.1. The task baseline is
`5552403` (endpoint 1.6.1).

Two independent behaviors were observed while investigating missing Codex
events. First, interactive Codex can send model requests through a shared
app-server started without the proxy environment. Second, the Linux CLI can
fail before launching the child because it unconditionally requests sudo to
reinstall an unchanged CA and enable/start an already healthy broker.

The current implementation addresses the Linux startup operations. Automatic
Codex foreground selection and the unrelated empty-prewarm parsing change were
removed during review. Agent commands are passed through with their original
arguments. Shared app-server requests originating outside the proxy environment
remain outside this fix's capture guarantee.

## Implementation

Linux checks the current CA fingerprint before requesting privileged
installation. If the matching certificate is already installed, startup skips
that privileged installation command.

Broker startup reuses an authenticated, healthy CLI-owned explicit endpoint
under the existing lifecycle lock when no restart or alternate service user
was requested. Startup identity, token, mode, and PID checks remain authoritative.
Missing trust and required service operations follow the existing
installation/systemd path.

## Compatibility with Linux TUN ingress

The branch incorporates upstream `d8769be` (PR #93). TUN ingress is an opt-in
broker transport; the CLI continues to manage explicit ingress only. Upstream's
additive `linux_tun` source and optional `device_name` status field are retained
in the CLI client. Broker reuse checks explicit mode, PID, token ownership, and
a TCP endpoint before launching a proxied child.

Upstream worker supervision publishes lifecycle changes independently of status
reads and releases the state lock while connections drain. CLI reuse relies on
that public lifecycle contract without taking ownership of the worker or
changing its start/stop sequencing.

## Validation

The broker reuse regression verifies authenticated endpoint ownership and
startup without invoking service operations. Existing CLI tests cover lifecycle
locking, endpoint validation, and command execution.

Revision-specific reports and logs are preserved under
`task-artifacts/fix-linux/` in the coordinator workspace. Earlier native Codex
capture results include the now-removed automatic foreground behavior; those
historical results do not establish capture through an unproxied shared
app-server for the current implementation.
