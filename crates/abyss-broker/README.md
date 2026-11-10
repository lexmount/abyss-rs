# abyss-broker

The standalone broker for the [Abyss endpoint runtime](https://github.com/lexmount/abyss-rs).
It provides an HTTP/HTTPS explicit proxy, policy-controlled TLS interception,
AI agent protocol parsing, local diagnostics, a loopback REST API, and a local
plugin event stream. Platform adapters can feed the same shared ingress pipeline.

## Configure the explicit listener

`proxy.listen_addr` accepts an IPv4 or bracketed IPv6 address and port. For example:

```toml
[proxy]
mode = "explicit"
listen_addr = "0.0.0.0:8080"
```

Use `0.0.0.0:8080` for all IPv4 interfaces, `[::]:8080` for an IPv6 wildcard
listener, or a specific local interface address such as `192.168.1.10:8080`.
IPv6 wildcard acceptance of IPv4 connections depends on the operating system.
The operating system must be able to bind the selected address and port.
Omitting `listen_addr` uses `127.0.0.1:0` (an automatically assigned port).
Restart the broker after changing this startup configuration.

Remote clients use the broker machine's reachable IP address; local CLI commands
use loopback when the listener is a wildcard. HTTPS interception requires clients
to trust the broker's CA. Explicit proxy connections do not require authentication,
so use network access controls to restrict who can reach an exposed listener.
The REST control API retains its separate loopback-only listener and bearer token.

## Block network flows

Add ordered rules to the existing MITM policy in `runtime-policy.toml`, or update
the running policy with `PUT /v1/mitm/config`:

```toml
[mitm.tls_decryption]
default_action = "passthrough"

[[mitm.tls_decryption.rules]]
id = "deny-destination"
action = "block"
destination_hosts = ["blocked.example", "*.blocked.example"]

[[mitm.tls_decryption.rules]]
id = "deny-executable"
action = "block"
executable_paths = ["/opt/example/bin/client"]
```

The first enabled matching rule wins across `block`, `intercept` and `passthrough`.
Different selector dimensions are ANDed; values in one dimension are ORed.
`process_names`, `application_ids` and `process_entry_points` remain available.
Executable paths and entry points use exact native absolute-path matching.
Explicit proxy ingress has no process identity, so process-based selectors do not
match it. Destination rules and default actions still apply.

Plain HTTP receives a local `403 network_blocked`. TLS blocks close before
decryption, with `network_blocked` recorded in broker diagnostics. Existing CONNECT
setup remains unchanged: a TLS block decided from ClientHello occurs after CONNECT
acknowledgement and is visible to the client as a TLS/socket failure.

## Inspect Agent requests through plugins

A plugin connects to the existing local endpoint and declares `agent_request`.
The broker sends complete decoded content, a shared Agent request projection and
available flow metadata; the plugin replies with `allow` and a safe reason.
No inspector list or additional broker configuration is needed. Event-only plugins
continue observing without enabling request inspection.

The HTTP request, WebSocket upgrade, and each reassembled client WebSocket data
message are checked before forwarding. Provider TCP/TLS setup retains its existing
order. All selected plugins must allow; a block returns `403 agent_request_blocked`,
and a selected plugin's failure or five-second timeout returns `503 inspection_unavailable`.
WebSocket decisions close with 1008 or 1011 respectively. Without connected inspectors,
the existing streaming path is used. Network passthrough remains opaque and never
enters Agent inspection.

See the [plugin contract](../../specs/broker-plugin-protocol/v2/README.md) and
[Rust](../abyss-sdk/examples/request_inspection.rs),
[TypeScript](../../sdks/typescript/examples/request-inspection.ts), and
[Python](../../sdks/python/examples/request_inspection.py) callback examples.

## Forward through another explicit proxy

Add an upstream table to `broker-config.toml` when the broker should use a
next-hop HTTP proxy:

```toml
[proxy]
mode = "explicit"
listen_addr = "127.0.0.1:8080"

[proxy.upstream]
protocol = "http_connect"
endpoint = "http://127.0.0.1:3128"
connect_timeout_ms = 10000
handshake_timeout_ms = 10000
```

The broker reads this file at startup; editing it does not update a running
broker. The CLI preserves this table when it updates other startup settings.
Without an upstream or a persisted runtime override, the broker connects directly.
Use the REST API described below to update the running broker without restarting.

Abyss sends `CONNECT target.example:443` to the next hop, then runs its existing
target TLS and request processing over the resulting byte tunnel. Client trust
in the Abyss MITM CA and target certificate verification do not change. Target
hostnames are passed to the proxy without local resolution. Both intercepted
and passthrough traffic use the configured proxy, with no direct fallback on
failure. This setting does not route delivery-plugin or CLI download traffic.

The initial implementation supports unauthenticated HTTP/1.1 CONNECT over TCP.
It does not require a new CA or credential file. HTTPS proxy endpoints, proxy
authentication and SOCKS5 are not yet supported.
The next hop must permit CONNECT to each required target port, including port
80 for plaintext HTTP. Avoid routing the next hop back into Abyss.

Proxy preparation failures appear in authenticated network diagnostics under
`abyss_to_upstream_proxy`. `proxy_status` records a rejected CONNECT status
separately from provider `http_status`; unresolved target addresses stay null.

See [the design and API compatibility notes](../../docs/upstream-proxy-design.md)
for the flow model and validation plan.

## macOS transparent routing

`[proxy.upstream]` also applies to `mode = "macos_network_extension"`.
Keep its existing `socket_path`; do not add a TCP `listen_addr`.
The Network Extension continues delivering normalized flows. The broker owns
CONNECT negotiation and uses the same MITM/capture pipeline inside the tunnel.
No loopback interception or proxy-vendor integration is needed.

## Windows transparent routing

`[proxy.upstream]` also applies to `mode = "windows_wfp"`. Keep the dynamic
loopback endpoint supplied by the Host; do not configure `listen_addr` or
`socket_path`. The broker transfers the accepted connection's opaque WFP redirect
records to each next-hop socket before connecting. Query or association failures
close that flow without attempting an untracked connection or direct fallback.

The original destination port is retained. TLS SNI or an HTTP Host hostname
supplies the CONNECT target when WFP provides only an IP address. Without a
hostname, the original IP is sent to the proxy. Direct mode retains the OS
destination. The next hop cannot point back to the broker's bound listener.
External proxy processes must be excluded from the Host's interception policy
when their own outbound connections would otherwise re-enter this proxy chain.

With a test Host redirecting an isolated Node executable, run
`scripts/blackbox_abyss_broker_windows_upstream.py --help` for native WFP checks.
It uses local CONNECT peers and restores TLS/network policy after testing.
An optional `--trusted-tls-host` adds a public HTTPS interception check.

## Live proxy-chain configuration

Explicit ingress and both macOS and Windows transparent ingress require the same shared
`NetworkRuntime`. Startup files initialize it once, and authenticated REST
updates replace its validated snapshot. Listener plans contain only endpoints;
they do not carry a second upstream configuration or a static fallback.

Authenticated `GET /v1/network/config` returns the effective route. A `PUT` to
the same endpoint accepts `{ "upstream": { "protocol": "http_connect",
"endpoint": "http://127.0.0.1:3128" } }`. Set `upstream` to `null` to restore
direct routing. Updates are validated, atomically persisted to
`runtime-policy.toml`, and applied to new connections without interrupting
existing streams. Endpoint, protocol, and both timeout fields use this same
update path, subject to the supported protocol and platform capabilities.
An explicit direct override survives restarts even when startup TOML contains
an upstream. At startup, a persisted override takes precedence over
`[proxy.upstream]`; neither file is watched or reread when accepting connections.
This schema extension requires an updated broker;
older brokers reject the new `network` policy table.

See [transparent routing and platform boundaries](../../docs/transparent-upstream-routing.md).

## Install

```bash
cargo install --locked abyss-broker
abyss-broker --version
abyss-broker --help
```

Cargo builds from source and installs the command into `~/.cargo/bin` by default;
ensure that directory is on `PATH`. The four supporting Abyss libraries are
compiled automatically. This package installs only `abyss-broker`. The `abyss`
management CLI, event delivery plugin, backend, dashboard, and platform adapters
are separate components.

Use a current stable Rust toolchain (releases are verified with Rust 1.98.0).
Native compilation requires a C/C++ toolchain and CMake for TLS dependencies:

- Linux: install the distribution's build tools and CMake, for example
  `sudo apt-get install build-essential cmake` on Ubuntu/Debian.
- macOS: install Xcode Command Line Tools (`xcode-select --install`) and CMake.
- Windows: use the MSVC Rust toolchain, Visual Studio C++ Build Tools, CMake,
  and LLVM/libclang. Set `LIBCLANG_PATH` to the LLVM `bin` directory if needed.

SQLite is bundled; no separate SQLite installation is needed.

## Run an explicit proxy on Linux or macOS

The following example uses a new, user-owned state directory and OpenSSL.
For an existing deployment, reuse its CA material and configuration instead of
replacing them. No system service installation is required for a foreground run.

```bash
export ABYSS_HOME="$HOME/.abyss-broker"
umask 077
mkdir -p "$ABYSS_HOME/ca"
```

The broker requires an existing CA even when HTTPS is passed through. Supply
`abyss-root-ca.pem`, `abyss-root-ca.der`, and `abyss-root-ca-key.pem` under `ca/`.
For a new local CA, generate all three files:

```bash
cat > "$ABYSS_HOME/ca/openssl.cnf" <<'EOF'
[req]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no
[dn]
CN = Abyss Local Proxy CA
[v3_ca]
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOF

openssl req -x509 -newkey rsa:2048 -nodes -days 365 -sha256 \
  -config "$ABYSS_HOME/ca/openssl.cnf" \
  -keyout "$ABYSS_HOME/ca/abyss-root-ca-key.pem" \
  -out "$ABYSS_HOME/ca/abyss-root-ca.pem"
openssl x509 -in "$ABYSS_HOME/ca/abyss-root-ca.pem" -outform DER \
  -out "$ABYSS_HOME/ca/abyss-root-ca.der"
```

Keep the private key in the protected state directory. Create the startup config;
the relative CA path is resolved against this file's directory:

```bash
cat > "$ABYSS_HOME/broker-config.toml" <<'EOF'
schema_version = 1

[ca]
path = "ca"

[proxy]
mode = "explicit"
listen_addr = "127.0.0.1:8080"
EOF

abyss-broker --config "$ABYSS_HOME/broker-config.toml" \
  --startup-info-file "$ABYSS_HOME/runtime/startup-info.json"
```

Select `explicit` explicitly: macOS and Windows otherwise default to ingress
modes that require separately supplied platform adapters. The same TOML works
on Windows with `ABYSS_HOME` set to an absolute user-owned Windows directory.
The REST API binds an available loopback port and writes its address, bearer
token file path, plugin endpoint, and PID to the startup JSON. Stop a foreground
broker with Ctrl-C.

In another terminal, configure clients to use the proxy:

```bash
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
curl --noproxy '' --proxy http://127.0.0.1:8080 https://example.com
```

## HTTPS policy and events

HTTPS defaults to pass-through. To decrypt selected traffic, configure
`$ABYSS_HOME/runtime-policy.toml` before startup or update the runtime policy
through the REST API. Clients must trust `ca/abyss-root-ca.pem` for intercepted
hosts. For example, curl accepts `--cacert /absolute/path/to/abyss-root-ca.pem`;
other clients may use their own trust store. Installing this crate does not
modify system trust.

See [endpoint configuration](https://github.com/lexmount/abyss-rs/blob/main/docs/configuration.md)
for TLS rules, content controls, and REST updates, and the
[REST API specification](https://github.com/lexmount/abyss-rs/blob/main/specs/broker-rest-api/openapi.yaml)
for broker control. Certificate pinning, mTLS, QUIC/HTTP/3, and application trust
settings can limit interception. Network observation is not a filesystem or
process sandbox.

Normalized Agent events are streamed to connected local plugins. Remote upload
and authentication require a separate consumer, such as `abyss-delivery-plugin`;
the broker does not require `product-config.json` or an upload endpoint. The
plugin stream has no offline replay; local network diagnostics are a separate
store. See the [plugin protocol](https://github.com/lexmount/abyss-rs/tree/main/specs/broker-plugin-protocol/v2)
to implement a consumer.

Licensed under GPL-3.0; see the included `LICENSE` file.
