# Source-specific egress and required request inspectors

Task: `lexmount-vpn.md`. Baseline: `fe75e1501b5f73c5410e7047a93275c6e64a7a63`.

The generic broker now supports two primitives needed by managed Agent access:
selecting different next hops for native source processes, and requiring a named
request inspector before plaintext requests may be forwarded. Company identity,
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
`docs/lexmount-vpn.md`. PR links and tested revisions will be added at handoff.
