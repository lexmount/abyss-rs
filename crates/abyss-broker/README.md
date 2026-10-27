# abyss-broker

The standalone broker for the [Abyss endpoint runtime](https://github.com/lexmount/abyss-rs).
It provides an HTTP/HTTPS explicit proxy, policy-controlled TLS interception,
AI agent protocol parsing, local diagnostics, a loopback REST API, and a local
plugin event stream. Platform adapters can feed the same shared ingress pipeline.

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

Use the address and port of your actual proxy, then restart the broker. The CLI
preserves this table when it updates other startup settings. Without the table,
the broker connects directly as before.

Abyss sends `CONNECT target.example:443` to the next hop, then runs its existing
target TLS and request processing over the resulting byte tunnel. Client trust
in the Abyss MITM CA and target certificate verification do not change. Target
hostnames are passed to the proxy without local resolution. Both intercepted
and passthrough traffic use the configured proxy, with no direct fallback on
failure. This setting does not route delivery-plugin or CLI download traffic.

The initial implementation supports unauthenticated HTTP/1.1 CONNECT over TCP.
It does not require a new CA or credential file. HTTPS proxy endpoints, proxy
authentication and SOCKS5 are not yet supported. Windows WFP upstream routing
is reserved but not enabled.
The next hop must permit CONNECT to each required target port, including port
80 for plaintext HTTP. Avoid routing the next hop back into Abyss.

Proxy preparation failures appear in authenticated network diagnostics under
`abyss_to_upstream_proxy`. `proxy_status` records a rejected CONNECT status
separately from provider `http_status`; unresolved target addresses stay null.

See [the design and API compatibility notes](../../docs/upstream-proxy-design.md)
for the flow model and validation plan.

## macOS transparent routing and live configuration

`[proxy.upstream]` also applies to `mode = "macos_network_extension"`.
Keep its existing `socket_path`; do not add a TCP `listen_addr`.
The Network Extension continues delivering normalized flows. The broker owns
CONNECT negotiation and uses the same MITM/capture pipeline inside the tunnel.
No loopback interception or proxy-vendor integration is needed.

Authenticated `GET /v1/network/config` returns the effective route. A `PUT` to
the same endpoint accepts `{ "upstream": { "protocol": "http_connect",
"endpoint": "http://127.0.0.1:3128" } }`. Set `upstream` to `null` to restore
direct routing. Updates are validated, atomically persisted to
`runtime-policy.toml`, and applied to new connections without interrupting
existing streams. An explicit direct override survives restarts even when
startup TOML contains an upstream. In the absence of a runtime override, startup
settings remain the default. This schema extension requires an updated broker;
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
store. See the [plugin protocol](https://github.com/lexmount/abyss-rs/tree/main/specs/broker-plugin-protocol/v1)
to implement a consumer.

Licensed under GPL-3.0; see the included `LICENSE` file.
