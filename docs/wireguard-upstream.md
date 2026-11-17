# WireGuard upstream routing

Task: `wireguard.md`.

The broker currently prepares target streams through HTTP CONNECT or SOCKS5.
This change adds a `wireguard` route to the same startup and runtime configuration
contract. Explicit and framed transparent ingress continue to use the common
MITM, passthrough, capture and inspection pipeline. The tunnel transports TCP
flows accepted by the broker; it does not change operating-system routes or
delivery-plugin traffic.

## Implementation

`UpstreamProxy` selects the WireGuard transport before TCP-proxy negotiation.
BoringTun owns encryption and handshake state. An asynchronous smoltcp stack
creates target TCP connections, carried as IP packets over one UDP peer socket.
The implementation uses bounded packet queues, WireGuard timers, explicit task
ownership and connection deadlines. A terminated UDP driver can be recreated for
new connections without retaining a permanently dead transport. It does not create a TUN device or require
administrator privileges.

The public configuration contains a `wireguard://host:port` endpoint and an
absolute `wireguard_file` path. The broker loads and validates the local JSON
file before publishing a route. The file carries keys, tunnel addresses,
AllowedIPs, MTU and keepalive settings. Private and preshared keys
must never appear in serialized configuration, errors or diagnostics. Existing
HTTP CONNECT and SOCKS5 configuration remains compatible.

Both the peer endpoint and target hostnames use the operating-system resolver
through Tokio's `lookup_host`. DNS follows the host's resolver configuration;
the broker does not send DNS queries through its WireGuard transport or maintain
a separate resolver. Target results are filtered by AllowedIPs and configured
address families before TCP connection attempts race through the tunnel. An
unusable IPv6 route cannot suppress a working IPv4 connection. Unsuccessful
resolution, authentication or connection setup fails closed. Target TLS identity
and certificate verification remain unchanged.

The earlier experimental `dns_servers` field is removed. Delete it from local
JSON configuration files; unknown fields are rejected when loading a route.

All connections of a route share its WireGuard identity and TCP/IP stacks.
Reapplying identical material must reuse the transport: creating competing UDP
endpoints with the same key would make the peer roam and disrupt existing flows.
Incompatible concurrent reuse of the same identity is rejected. Old streams
retain their transport until closed; key rotation uses a distinct identity.
The identity registry holds weak references, so the final route/stream owner
releases its key material, packet driver and stacks. This intentionally rejects
incompatible updates rather than disrupting an existing session. The UDP socket
accepts only the configured peer; endpoint roaming is outside this contract.

Fixed configuration collections and stack endpoints use boxed slices. Growable
collections remain for file reads and the live route registry; smoltcp packet APIs
also require `Vec`. The packet driver follows BoringTun's result variants directly
when draining pending datagrams.

The `connect_timeout_ms` budget bounds peer DNS; `handshake_timeout_ms` covers
UDP setup, WireGuard establishment, target DNS and target TCP. Failures use the
existing upstream handshake diagnostics, with no synthetic HTTP proxy status.
The first peer endpoint address remains selected until its transport is rebuilt.

The Rust, Python and TypeScript configuration contracts and OpenAPI schema change
together. TypeScript and Python SDK metadata is aligned with the broker 1.6
minor version; no SDK package is published by this task. No event schema or backend API changes are required. AbyssApp consumes
released endpoint binaries; exposing this option in its native settings and
updating its release pin are separate consumer work.

## Validation plan

- Unit tests: strict configuration, key validation, AllowedIPs, secret-safe
  errors, system-resolved address filtering, deadlines, and transport ownership.
- Black-box tests: a real broker and independent WireGuard peer, encrypted HTTP
  and TLS over IPv4/IPv6, system-resolved loopback rejection, PSK mismatch, no
  direct fallback, hot updates and persistence. Existing upstream and SDK
  regression suites remain required.
- Live validation: actual installed Codex and dsh provider traffic through the
  changed broker and WireGuard peer, using system-resolved provider hostnames,
  delivered to a real backend and correlated with stored events.
- Quality: workspace build and tests, nightly rustfmt, Clippy, SDK checks, CI,
  and an HTML report recording submitted revisions and actual outcomes.

The reproducible peer in `scripts/fixtures/wireguard/` uses Linux's independent
kernel WireGuard implementation, HTTP and TLS services, plus Internet NAT. It
does not run a DNS service. Deterministic transport tests use IP-literal targets;
the live provider runs cover successful system resolution and tunneled TCP.
It recalculates outgoing inner TCP checksums with `tc csum` before encryption:
Docker Desktop can forward checksum-offload placeholders that are invalid once
encrypted. This is confined to the test peer; production packet checksum and TLS
verification remain enabled. Container capabilities do not alter host networking.

`make test-blackbox-broker-wireguard` covers explicit ingress and, on macOS, the
published framed transparent ingress. GitHub's Linux job runs the kernel-peer
suite. Platform CI builds/tests the portable implementation on Linux, macOS and
Windows. No native installer changes are included; signed Network Extension and
WFP activation are outside the changed shared connector boundary.

The PR links the persistent HTML validation report and real Codex/dsh run
evidence. The report records tested source identities, dependency versions,
commands, observed outcomes and any remaining gaps.

Dependency references: [BoringTun](https://github.com/cloudflare/boringtun) and
[tokio-smoltcp](https://github.com/spacemeowx2/tokio-smoltcp).
