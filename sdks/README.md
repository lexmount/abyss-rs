# Abyss SDKs

The public Abyss SDK is implemented in Rust, TypeScript/Node.js, and Python.
Each language exposes the same two local integration surfaces:

- a broker REST client for loopback management and diagnostics; and
- a plugin client for the versioned local Agent event stream.

The SDKs do not manage `abyss-broker`, upload events, or perform SSO. Product
launchers and plugin applications own those responsibilities.

Language-neutral contracts live under `specs/broker-rest-api/` and
`specs/broker-plugin-protocol/`.
