# Source-specific egress and required request inspectors

Task: `lexmount-vpn.md`. Baseline: `fe75e1501b5f73c5410e7047a93275c6e64a7a63`.

The generic broker now supports source-specific next hops, required request inspectors,
and authenticated plugin connections from a desktop user to a system broker. Company identity,
provider credentials and enrollment remain outside this public runtime.

## Source-specific network policy

`GET/PUT /v1/network/config` adds optional ordered `rules`. Each rule has a unique
nonempty `id`, at least one populated source selector, and an `upstream` value.
`process_names`, `application_ids`, `executable_paths` and `process_entry_points`
use AND between dimensions and OR within each dimension. Paths must be absolute.
Missing attribution cannot match a populated selector. The first matching rule
wins. Null upstream explicitly selects direct routing. Unmatched and explicit
proxy connections retain the existing top-level default.

All routes, credential files and TLS roots are validated before the durable
configuration transaction publishes a snapshot. macOS and Windows ingress retain
that snapshot at accept time, resolve native source attribution, and select the
route before destination DNS or connection. DNS-only destinations are resolved
by the selected CONNECT proxy. A failed selected next hop never falls back to
another rule or direct access. Existing accepted streams retain their snapshot
across policy changes. Runtime policy persistence and restart behavior are shared
with the existing default route. The macOS process resolver runs once per flow.

Rust, TypeScript and Python SDKs and the OpenAPI document expose the same optional
rules. Old JSON clients remain valid when they omit rules; policy editors must
preserve rules while editing the default route. Rust callers constructing the
public config struct explicitly must supply the new `rules` field.

## Required inspectors

The static broker config adds `required_inspectors`, defaulting to an empty list.
Each entry is a unique valid plugin identifier. Exactly one live session declaring
the `agent_request` capability must exist for every required identifier. An
unrelated observer does not satisfy the requirement; duplicate required names
fail closed. Empty requirements preserve the existing optional-inspection behavior.

The plugin server publishes immutable connection identities and names. Request
planning keeps retention enabled even if a required inspector is absent or the
plugin service is closed. Before parsing/forwarding, an unavailable plan returns
503 `inspection_unavailable`. Existing selected-session disconnect and deadline
handling also return unavailable. A newly connected replacement cannot join an
already planned request. Registration order and independent observation delivery
remain unchanged. Names identify trusted local plugins; this is not a separate
OS-user authentication boundary. TLS passthrough flows remain outside plaintext
inspection; products must install their intended intercept/redirect policy.

## Authenticated plugin transport

`POST /v1/plugins/connect` uses the existing local management bearer and HTTP/1.1
upgrade (`Connection: upgrade`, `Upgrade: abyss-plugin-v1`). Unauthorized requests
receive 401; missing or incompatible upgrade headers receive 400. A 101 response
switches to the unchanged length-prefixed v1 plugin handshake and stream.
Upgraded streams join the same registry, event fan-out, inspection deadlines,
disconnect cleanup and shutdown lifecycle as local IPC sessions.

This allows an authorized desktop user to reach a system-owned broker without
changing owner-only Unix socket or Windows Named Pipe permissions. The existing
management token remains a powerful local credential; this adds no remote or
per-plugin authority. Products retain responsibility for granting that credential.

Rust SDK `BrokerPlugin::with_api_endpoint` restricts the origin to loopback HTTP,
disables proxies and redirects, bounds the HTTP connection/upgrade wait, and keeps
the bearer out of URLs and diagnostics. `run_with_ready` publishes application
readiness after the broker accepts the plugin handshake. Socket/pipe discovery
remains the default. Other SDKs may use the documented transport directly.

Transport unit tests reject remote origins, redirects and incompatible upgrades.
`scripts/blackbox_plugin_http.py` checks authorization, unchanged socket permissions,
handshake rejection, observation, required-inspector loss/duplication and orderly
shutdown against the actual broker.

## Product composition and validation

AbyssApp's private plugin authenticates to the separate enterprise service,
installs source-scoped egress and hostname redirect rules, and injects approved
token/model values using the existing semantic mutation protocol. The broker
requires that plugin in the enterprise package profile. The normal release
configuration does not enable a company service or a required inspector.

Unit and CLI integration tests cover rule order, attribution, invalid policies,
snapshot immutability, required membership, duplication and plugin loss. Real
broker black-box scripts cover native framed routing, persisted policies, proxy
failure without fallback, and missing/duplicate/disconnected inspector denial.
The companion product black-box test composes the real broker, enterprise service,
plugin, local provider and real installed harnesses. Production provider/exit
credentials are separate deployment inputs; local validation was authorized.

`scripts/ci/prepare_review_runtime.py` builds only the broker and delivery worker
from a clean, explicitly selected commit. It records the host target, capabilities
and SHA-256 of each executable in `runtime-review.json`. Dependent development
packages verify this manifest against their own source pin. It is not a release
artifact and does not change the crates.io or production runtime version.

Local verification passed workspace tests/build/clippy, Rust formatting, all
three SDK unit and real-broker suites, source routing, HTTPS next hops, required
inspectors, request mutation, parser parity and MITM redirect black-box suites.
Installed Codex 0.167.0, Claude Code 2.1.206 and DSH 0.2.0-rc.2 completed against
the local provider through the product plugin. Actual delivery workers persisted
all ten observed events in both backends with unchanged model, conversation and
token fields (85 input and 15 output tokens), including the readiness request.
The local fixture is not production-provider or residential-exit evidence.

Evidence is maintained in `artifacts/lexmount-vpn` in the coordinator workspace.
Native Windows source routing and final installer consumption remain part of the
cross-repository acceptance work and are reported separately from local passes.
Companion designs: AbyssApp, abyss-services and abyss-backend
`docs/lexmount-vpn.md`. Exact tested revisions are recorded in the task report.

## Coordinated review

- [Endpoint PR 85](https://github.com/lexmount/abyss-rs/pull/85) and [runtime design](https://github.com/lexmount/abyss-rs/blob/task/lexmount-vpn/docs/lexmount-vpn.md).
- [Desktop PR 86](https://github.com/lexmount/AbyssApp/pull/86) and [product design](https://github.com/lexmount/AbyssApp/blob/task/lexmount-vpn/docs/lexmount-vpn.md).
- [Services PR 25](https://github.com/lexmount/abyss-services/pull/25) and [service design](https://github.com/lexmount/abyss-services/blob/task/lexmount-vpn/docs/lexmount-vpn.md).
- [Standalone PR 16](https://github.com/lexmount/abyss-backend/pull/16) and [persistence design](https://github.com/lexmount/abyss-backend/blob/task/lexmount-vpn/docs/lexmount-vpn.md).

The standalone verifier is independent. Integrate the public runtime primitives
before the product composition. The enterprise service is opt-in; production
packaging additionally requires a published endpoint release and normal release
pins. Review packages consume explicit immutable development artifacts only.
