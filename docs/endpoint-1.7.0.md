# Endpoint 1.7.0

Rust SDK request handlers can return `ModifyAction::SetUpstreamHost` and
`ModifyAction::SetRequestPath` to route a single model request. The broker
retains the port and configured proxy chain when switching hosts, and preserves
the query string when changing the path. Other requests on the same client
connection keep their own routes. See the [plugin protocol](../specs/broker-plugin-protocol/v1/README.md).

The delivery worker also reports readiness before replaying queued events,
so installation can finish while the worker drains the backlog.

The endpoint archives and Rust workspace crates use version 1.7.0. Distributors
can check archive digests against the release's `SHA256SUMS` and the source
revision in each archive's `endpoint-artifact.json`.
