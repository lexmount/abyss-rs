# Repository guidance

## Project overview

`abyss` is the open-source endpoint runtime for AI Agent network observation and
control. It owns shared Rust behavior: traffic ingress contracts, TLS MITM, Agent
protocol parsing, local policy, audit events, plugin delivery, the standalone
CLI, storage primitives, and SDKs.

Closed product applications and deployment details do not belong here. The
private `AbyssApp` repository owns macOS and Windows Host applications,
platform adapter implementations, the desktop dashboard, updater, packaging,
signing, release automation, and product-specific configuration. Backend,
services, dashboard, and frontend source live in their own repositories.

## Architecture and dependency direction

External adapters feed platform flow metadata and bytes into the common broker
ingress. The broker routes flows through shared MITM and Agent Hook logic, then
publishes normalized events through the plugin protocol. Delivery plugins own
remote destinations and authentication.

```text
private platform adapters / explicit proxy clients
                        |
                        v
            abyss-broker ingress contracts
                        |
                        v
              abyss-mitm + abyss-agent-hook
                        |
                        v
               abyss-plugin-protocol
                        |
                        v
              abyss-delivery-plugin / SDKs
```

Dependencies flow toward this open repository. Open crates must never import
private product code or embed private deployment endpoints, credentials,
artifact locations, signing identities, or release policy. Keep native interop
behind dedicated `sys/`, `ffi/`, or ingress modules.

## Workspace structure

The Rust workspace contains only active open crates:

- `crates/abyss-agent-hook/` — Agent traffic parsing and normalized events.
- `crates/abyss-broker/` — endpoint broker, REST control, and ingress contracts.
- `crates/abyss-cli/` — explicit-proxy CLI for Linux and macOS.
- `crates/abyss-delivery-plugin/` — official event delivery plugin.
- `crates/abyss-mitm/` — TLS interception and HTTP stream handling.
- `crates/abyss-plugin-protocol/` — broker/plugin wire protocol.
- `crates/abyss-sdk/` — Rust SDK.
- `crates/abyss-storage/` — durable endpoint storage primitives.
- `crates/abyss-terminal-auth/` — reusable terminal authentication.
- `sdks/` — TypeScript and Python SDKs.
- `specs/` — public protocol and API contracts.
- `platform/linux/` — Linux service integration.

The Windows callout ABI header lives under `crates/abyss-broker/include/`
because the broker consumes that public ingress contract. Driver and adapter
implementations remain outside this repository.

## Configuration boundary

The open CLI embeds only generic `broker-config.toml` and
`runtime-policy.toml` defaults from `crates/abyss-cli/defaults/`.
`product-config.json` is deployment-supplied and must never have an
environment-specific fallback compiled into the open binary.

This repository owns the generic, unsigned `install-local.sh` bootstrap for the
public SQLite+FTS backend and npm dashboard. Hosted or signed product installers,
private artifact origins, and product release lifecycles belong to the
distributing product and service repositories.

## Security boundaries

MITM proxying is a network observation and control point, not a complete Agent
sandbox. File operations, process execution, shell tools, and other local access
need separate controls.

Do not assume all HTTPS traffic can be decrypted. Certificate pinning, mTLS,
private CA bundles, QUIC/HTTP/3, and local model traffic may bypass or limit
inspection. Preserve explicit pass, block, metadata-only, and intercept outcomes.
Enterprise deployments must define authorization, notice, privacy scope,
retention, and data minimization.

The current Agent parser diagnostic capture is temporary pre-production
instrumentation. It uploads bounded raw HTTP and WebSocket content after
credential-header redaction independently of normalized audit controls and must
be removed before a production release.

## Code style

New Rust module files start with a `//!` module-level documentation comment
explaining responsibility and boundary.

Use typed enums for fixed state sets. Except for small module-local helpers,
organize logic around structs with `impl` blocks. Add derives only when required
by callers, serialization, collections, tests, or diagnostics. Do not derive
`Copy` for owning non-enum types.

All unsafe operations must be localized and documented. Every `unsafe fn` needs
a `# Safety` section, and every unsafe block needs a preceding `// SAFETY:`
comment stating its invariant.

Prefer durable, replayable state transitions. Endpoint behavior must remain
well-defined while the control plane is unavailable.

## Common commands

```bash
cargo +nightly fmt --all -- --check
cargo build --workspace
make lint
make test
make test-blackbox-broker-explicit
make test-sdks
```
