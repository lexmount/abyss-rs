# Endpoint 1.8.0

The macOS, Linux and Windows endpoint archives now include the model-routing
worker. CLI users can import a catalog, list models, select a model for a
harness, and clear selections with `abyss model-route`. Desktop clients use
the same local HTTP API. The worker restores saved routes at startup and uses
the in-memory selection when handling an attributed request.

Distributors can verify the archive digests in `SHA256SUMS` and the source
revision in each archive's `endpoint-artifact.json`. The matching Rust
libraries and SDK manifests use version 1.8.0. See the
[model-routing protocol and CLI examples](optimize-model-route.md).
