# Configured upstream routing for transparent ingress

The broker owns the CONNECT exchange and its proxy configuration. This extends
configured-upstream mode; it does not relay an Agent's own proxy authentication
or intercept loopback connections to an Agent-configured proxy.

```mermaid
flowchart LR
    A[Agent HTTPS connection] --> NE[macOS Network Extension]
    W[Windows WFP adapter] -->|Redirect records| F
    NE --> F[Normalized PlatformFlow]
    F --> R[Snapshot of outbound route]
    R -->|Direct| D[OS destination socket]
    R -->|HTTP CONNECT| P[Configured next hop]
    P --> T[Target tunnel]
    D --> M[Shared TLS / HTTP pipeline]
    T --> M
    M --> C[Capture and hooks]
    M -->|Passthrough policy| B[Encrypted byte relay]
```

HTTP CONNECT clients of the explicit listener and macOS/Windows transparent flows
require the broker's shared `NetworkRuntime` and use `HttpConnectProxy`.
Listener plans contain only their binding endpoints. There is no optional
runtime, private ingress runtime, or static next-hop fallback.
The native extension remains a framing and metadata
adapter. All three ingress modes use the same `NetworkRuntime`. Windows retrieves
the opaque WFP redirect records from the accepted connection and associates them
with every candidate next-hop socket before TCP connect. These OS records differ
from the callout's original-destination context. Record-query or socket-setup
failure closes the flow; it never retries without records or falls back to direct.
The shared connector retains its DNS/connect deadlines and CONNECT framing rules.
Windows excludes its bound ingress endpoint, including mapped IPv6 equivalents,
from proxy candidates. The Host must exclude external proxy processes where
their outbound traffic would otherwise re-enter the configured chain.

For configured routes, a native hostname is preferred. If native metadata has
only an IP, TLS SNI (or an HTTP Host hostname) supplies the logical target.
The original destination port is retained. DNS-only destinations remain
unresolved locally. With no logical hostname, CONNECT uses the original IP,
including bracketed IPv6. Direct mode continues using the OS destination, and
TLS server identity remains the ClientHello SNI. Upstream TLS trust is unchanged.

The protocol is currently HTTP/1.1 CONNECT over TCP, with a configured HTTP URL
and bounded connection/handshake timeouts. A single next hop is configured;
additional hops belong to that proxy. There are no assumptions about proxy
software, vendor configuration files, or process names. Authentication, SOCKS,
and TLS to the proxy are outside the supported contract.

```mermaid
flowchart LR
    C[broker-config.toml] -->|Read at startup| S[Resolve initial configuration]
    P[runtime-policy.toml] -->|Read persisted override at startup| S
    S --> N[One shared NetworkRuntime]
    A[REST PUT /v1/network/config] --> V[Validate and persist]
    V -->|Publish hot update| N
    N --> E[Explicit ingress: snapshot at accept]
    N --> T[macOS ingress: snapshot at accept]
    N --> W[Windows WFP ingress: snapshot at accept]
```

Configuration files are startup inputs, not a watched source or a per-connection
fallback. Every supported proxy-chain field uses the same REST update path.

```mermaid
sequenceDiagram
    participant UI as Settings / Network
    participant Host as Native Host bridge
    participant API as Broker configuration API
    participant Disk as runtime-policy.toml
    participant Route as Shared route snapshots
    UI->>Host: updateNetworkConfig
    Host->>API: Authenticated PUT /v1/network/config
    API->>API: Validate proxy protocol and endpoint
    API->>Disk: Atomic durable replacement
    Disk-->>API: Committed
    API->>Route: Publish validated snapshot
    API-->>UI: Applied configuration
    Note over Route: Accepted connections retain their selected route
```

The broker serializes network, capture, and hook updates in the same transaction.
An absent network table inherits startup settings. An empty `[network]` table
explicitly selects direct routing, preventing a cleared startup proxy from
returning on restart. Persistence failure leaves the active route unchanged.
A committed update completes even if the HTTP request is cancelled. Old brokers
with strict policy decoding cannot read the new table; rollback requires backing
up the policy file and removing that table before starting the older binary.

CONNECT failure never falls back to direct routing. Proxy 407/403 diagnostics
remain separate from provider HTTP statuses and do not retain proxy response
bodies or authentication challenges. Existing SSE/WebSocket/TLS streams are not
migrated when settings change. Plugin delivery is outside this routing policy.

Validation includes MITM unit tests with a configured next hop and captured TLS
response bodies, durable configuration tests, and the real broker black-box
scripts `scripts/blackbox_abyss_broker_upstream.py` and
`scripts/blackbox_abyss_broker_transparent_upstream.py` using the explicit proxy
and published macOS framed-flow boundaries. They cover startup-only file reads,
hot route updates, stream continuity, direct mode, and restart persistence.
Live Network Extension activation still requires a
signed product build on macOS.

On Windows, `scripts/blackbox_abyss_broker_windows_upstream.py` exercises a real
WFP broker supplied by the Host, an isolated Node test executable, and local
CONNECT peers. It verifies HTTP Host and TLS SNI routing, nondefault target ports,
TLS passthrough, target-certificate rejection, SSE continuity during hot updates,
proxy rejection diagnostics, and self-loop rejection. `--trusted-tls-host` adds
interception and direct-route checks against a public HTTPS target. The script
restores network and TLS policy; service/driver setup remains Host-owned.
