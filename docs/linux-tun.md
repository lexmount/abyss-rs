# Linux TUN ingress

Task: `tun.md`. Baseline: `55524031806d05509d94f9ad5b0081bfcfd54af5` (endpoint 1.6.1).

Linux currently accepts endpoint traffic only through an explicit HTTP proxy.
Add an opt-in `linux_tun` broker ingress so TCP clients can enter the existing
MITM, request policy, Agent Hook, diagnostics, and plugin pipeline without proxy
environment variables. Explicit ingress remains the Linux default.

## Boundary and implementation

An administrator provisions a named persistent Linux TUN device and narrowly
scoped TCP policy routing. The unprivileged broker attaches to that device using
`tun-rs`, preserving its addresses, MTU, enable state, and persistence. It never
changes host routes, DNS, firewall rules, or capabilities. Running the broker as
an unrelated dedicated user keeps its provider, backend, and proxy connections
outside the captured source-UID policy. Remove policy routing before stopping
the broker; device and route ownership remain with the administrator.

TUN ingress and WireGuard egress share `tokio-smoltcp` 0.7 and the bounded
asynchronous `PacketDevice` in `abyss-mitm::netstack`. The broker no longer owns
smoltcp RX/TX tokens, a periodic polling loop, or a manually polled byte pump.
`tokio-smoltcp` supplies asynchronous TCP streams, TCP reassembly, retransmission,
flow control, and half-close handling. The shared `OwnedStream` retains each
transport's resources until its last application stream is dropped; WireGuard
retains its route/tunnel and TUN retains its stack/connection permit.

A TUN packet router validates opening SYNs and demultiplexes packets by the
source/destination socket pair. Each admitted flow owns one `Net` with the
original destination as its local IP and listening endpoint. This preserves
arbitrary IPv4/IPv6 destinations without retaining an unbounded listener cache
or depending on private socket APIs. The tradeoff is one event-driven reactor
per live flow plus a Tokio duplex forwarding task. The same 256-permit limit
bounds pending and established connections together. Half-open connections expire after 30 seconds. Per-flow
input channels hold 32 packets, the shared output channel holds 256, and socket
buffers are 64 KiB per direction. Full input queues discard the packet so one
slow flow cannot block other flows or the output driver; TCP retransmission
recovers from congestion. The single-slot overwrite path is removed.

Established streams enter the existing `PlatformFlow` interface with their
original destination and the existing `LinuxTransparent` attribution. SNI-based
TLS policy and the shared next-hop runtime retain routing ownership, including
WireGuard identity reuse and snapshots. A standard `copy_bidirectional` adapter
preserves the broker IO drop contract:
closing the application-side duplex stream flushes TCP and sends FIN before the
`Net` owner is released. It also preserves independent half-closes.
All packet IO is event-driven; stopping the ingress cancels pending accepts and releases the TUN descriptor while the
administrator's persistent interface remains configured.

The status API reports `mode=transparent`, ingress `source=linux_tun`, a device
name, and no TCP listen address. Update all three SDKs and OpenAPI with this
additive ingress identity and optional device field. Existing consumers retain
their current explicit/macOS/Windows status shapes. TypeScript and Python SDK
manifest versions move to 1.6.0 to match the broker major/minor policy. Consumers
using typed ingress identities need the updated SDK before opting into TUN.
Publishing these packages remains a separate release operation.

## Compatibility and scope

This is a TCP ingress, matching the current MITM engine. Policy routing must
select TCP only: UDP DNS, QUIC, ICMP, and other traffic use their existing routes.
TLS trust still requires the existing Abyss CA; pinned certificates and private
trust stores retain their existing limitations. The explicit-only CLI lifecycle
is unchanged; this mode is provisioned and started through the broker directly.
No event schema, destination API, native package, or backend/UI change is needed.

## Validation and evidence

Unit coverage must verify config rejection, packet parsing and socket admission,
status serialization, bounded queues, flow identity, and shutdown behavior.
A Linux namespace/container black-box test must send actual TCP packets through
a real TUN device into the built broker, verify HTTP/TLS behavior and original
destinations, exercise runtime policy and stop/restart, and check explicit proxy
regressions. Final validation also requires workspace tests, formatter, Clippy,
SDK checks, and real installed `codex` and `dsh` provider traffic delivered to a
real backend. Synthetic provider traffic cannot replace those live harness runs.

Review and validation evidence: [PR #93](https://github.com/lexmount/abyss-rs/pull/93).
Persistent evidence: `task-artifacts/tun/` under the coordinator root. Record
actual tested commits and unavailable requirements in the HTML report. A PR and
passing CI are required before this task is ready for review.

## Operator setup

Use a dedicated unprivileged broker account and a different account for captured
clients. In the example below `1000` owns the broker and `2001` runs clients;
replace both with the actual account IDs. `iproute2` with `uidrange` and `ipproto`
policy-rule support and administrator access are required for provisioning.
Do not route the broker account, loopback control endpoints, or management
traffic into the TUN. This example captures nonlocal IPv4 TCP from one account:

```sh
sudo ip tuntap add dev abyss0 mode tun user 1000
sudo ip addr add 198.18.0.1/30 dev abyss0
sudo ip link set dev abyss0 mtu 1500 up
sudo ip route add table 190 default dev abyss0
sudo ip rule add priority 190 uidrange 2001-2001 ipproto tcp lookup 190
```

Reserve table/priority 190 for this deployment; choose unused values instead if
another policy already owns them. Leave the default local lookup rule intact.
For IPv6, provision an appropriate IPv6 address on the TUN and add the equivalent
`ip -6 route` and `ip -6 rule` entries. DNS and UDP retain the normal route.
Fragmented IP and IPv6 extension headers are outside this TCP adapter's initial
scope; ordinary TCP uses the configured MTU and MSS negotiation.

Provision the CA using the existing CA workflow and create a broker config:

```toml
schema_version = 1
[ca]
path = "/absolute/path/to/ca"
[proxy]
mode = "linux_tun"
device_name = "abyss0"
```

Run the built broker as the TUN owner, with a dedicated writable `ABYSS_HOME`:

```sh
ABYSS_HOME=/absolute/path/to/tun-home abyss-broker \
  --config /absolute/path/to/broker-config.toml \
  --startup-info-file /absolute/path/to/tun-home/startup.json
```

Configure the existing delivery plugin against that broker home as usual. Clients
run as account 2001 with the Abyss CA trusted and no proxy environment variables.
TLS policy and next-hop settings retain their existing broker REST interfaces.
A shared UID cannot distinguish client sockets from broker sockets; use separate
accounts rather than installing a capture-all default route.

For shutdown, first remove exactly the policy rule added above, then stop the
broker gracefully, then remove the task-owned route and persistent interface:

```sh
sudo ip rule del priority 190 uidrange 2001-2001 ipproto tcp lookup 190
# Stop the broker with SIGTERM and wait for it to exit.
sudo ip route del table 190 default dev abyss0
sudo ip tuntap del dev abyss0 mode tun
```

Apply the same teardown to any IPv6 rule/route added for this deployment. A broker
crash does not remove external routing: the administrator must remove its rules
before expecting captured clients to use the ordinary route again.

Run the actual TUN regression suite with `make test-blackbox-broker-tun`. Docker
provides the temporary network namespace and `NET_ADMIN`; the broker and client
processes inside it run under different unprivileged UIDs. The suite checks
IPv4/IPv6, large HTTP bodies, independent TCP half-close, TLS passthrough, status,
and process stop/restart while preserving the persistent interface. The combined
`make test-blackbox-broker-tun-wireguard` suite reuses the upstream kernel
WireGuard peer fixture and verifies IPv4/IPv6 targets and a 1 MiB transfer through
TUN ingress and WireGuard egress together.
