# Linux CLI integration

Linux uses the public `abyss` CLI and explicit HTTP/HTTPS proxy mode. The CLI
owns CA trust, broker lifecycle, local policy, and proxy environment setup; no
transparent Linux interception is currently provided.

## Distribution boundary

This repository provides the generic systemd service template. A product
distributor is responsible for publishing an x86_64 musl archive containing:

- `abyss`;
- `abyss-broker`;
- `abyss-delivery-plugin`;
- `abyss-broker@.service`;
- `broker-config.toml`;
- `runtime-policy.toml`;
- a deployment-specific `product-config.json`;
- `LICENSE`.

Installer implementation, artifact hosting, checksum publication, and
configuration seeding behavior for hosted distributions are owned outside this
open runtime repository. Development builds are produced directly from the
repository with Cargo.

For a source build, install the compiled runtime and service template before
starting the local environment:

```bash
cargo build --release --locked \
  --package abyss-cli \
  --package abyss-broker \
  --package abyss-delivery-plugin
sudo install -m 0755 target/release/abyss /usr/local/bin/abyss
sudo install -m 0755 target/release/abyss-broker /usr/local/bin/abyss-broker
sudo install -m 0755 target/release/abyss-delivery-plugin /usr/local/bin/abyss-delivery-plugin
sudo install -m 0644 platform/linux/abyss-broker@.service /etc/systemd/system/abyss-broker@.service
sudo systemctl daemon-reload
abyss deploy-local start
```

## User workflow

```bash
abyss status
abyss run -- codex
abyss run -- claude
abyss proxy start
eval "$(abyss proxy env)"
abyss proxy stop
abyss log dump --file /tmp/abyss-support.zip
abyss logout
```

With `delivery_worker.authentication.mode = "none"` or a static header-file
mode, no login or control-plane configuration is required. `managed_bearer`
requires `product.control_plane`; in those deployments, run `abyss login` before
the commands above. `abyss login` reads the control-plane URL from the
deployment-supplied `product-config.json`. `abyss run` starts the explicit
broker, ensures that its CA is trusted, and scopes proxy environment variables
to the launched command.

## Runtime layout

```text
~/.abyss/
├── ca/                    MITM certificate and private key
├── broker-config.toml     static broker settings
├── product-config.json    deployment and delivery settings
├── runtime-policy.toml    broker-owned MITM and hook policy
├── auth/                  owner-only terminal credential
├── logs/                  broker logs and support bundles
├── runtime/               control token and startup-info.json
└── delivery/              delivery-plugin state and failed events
```

The systemd template starts `/usr/local/bin/abyss-broker` for the endpoint user
and reads `/home/%i/.abyss/broker-config.toml`. The broker publishes its dynamic
REST and explicit-proxy endpoints through runtime state instead of requiring
fixed ports.

The retired `~/.abyss/config.json` is not read, migrated, rewritten, or deleted.

## Non-goals

- Linux transparent routing, TProxy, nftables, TUN, or eBPF interception.
- A separate Linux event extraction pipeline.
- Product-specific release origins, control-plane endpoints, or credentials.
