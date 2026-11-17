# Linux TUN ingress

Task: `tun.md`. Baseline: `01639cbc10c2dcf705e24d3d75ee5552a15ec3f1`.

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

A bounded packet device and `smoltcp` provide IPv4/IPv6 TCP reassembly,
retransmission, flow control, and FIN handling. Established streams enter the
existing `PlatformFlow` interface with their original destination and the
existing `LinuxTransparent` attribution. There is no CONNECT preamble and no
process attribution. SNI-based TLS policy and the shared network next-hop policy
retain ownership of routing and TLS decisions.

The stack limits pending and established TCP sockets together to 256, bounds
packet queues and per-socket buffers, and owns its task until asynchronous
shutdown. A short bounded timer drives TCP retransmission and socket-to-async
stream progress. TCP stack implementation remains separate from broker policy.

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
and process stop/restart while preserving the persistent interface.
