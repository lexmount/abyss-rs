# Endpoint 1.6.1 release

Version 1.6.1 publishes the merged WireGuard upstream transport in the existing
endpoint distribution. It accepts `wireguard://host:port` plus an absolute
`wireguard_file` reference through startup configuration and the network REST
API. The file holds key material and tunnel parameters; public responses contain
only its path. Target hostnames use system DNS. Route-manager ownership preserves
shared tunnels and existing connections across compatible route changes.

This release change only increments the workspace version, internal dependency
requirements and corresponding lockfile entries from 1.6.0 to 1.6.1. WireGuard's
implementation and regression coverage were merged in PR #91. The binary release
contains all five endpoint archives; the crates.io workflow publishes the broker,
its dependencies, the Rust SDK and query CLI in dependency order. SDK language
packages retain their compatible 1.6 major/minor versions.

Validate the version/tag contract, release packaging/installer tests, Rust build,
unit tests, lint and the independent kernel-peer WireGuard black-box before
publishing `v1.6.1`. The tag workflows verify native archives on macOS, Linux and
Windows before publication. Consumers must verify the published archive hashes,
source revision and payload metadata, and align their exact `abyss-mitm` registry
dependency. Do not replace released bytes or move the tag after publication.
