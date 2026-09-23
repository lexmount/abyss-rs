# Linux CLI integration

Linux uses the public `abyss` CLI and explicit HTTP/HTTPS proxy mode. The CLI
owns CA trust, broker lifecycle, local policy, and proxy environment setup; no
transparent Linux interception is currently provided.

## Distribution boundary

This repository publishes the public x86_64 musl CLI archive and generic
systemd service template. The archive contains:

- `abyss`;
- `abyss-broker`;
- `abyss-delivery-plugin`;
- `abyss-broker@.service`;
- `VERSION`;
- `LICENSE`.

The public `scripts/install.sh` downloads a checksummed release archive; the
release workflow publishes it as `install.sh` in GitHub Releases. The CLI owns
generic broker and policy defaults, and `abyss deploy-local start` creates the
local deployment configuration. Private product configuration and signed
desktop installers remain outside this repository. See the
[CLI release guide](../../docs/cli-release.md).

This repository's `scripts/install-cli.sh` also builds and installs the CLI
runtime directly from a source checkout.

For a source build, install the compiled runtime and service template before
starting the local environment:

```bash
bash scripts/install-cli.sh
abyss version
abyss deploy-local start
```

Run the script as your normal user with Rust stable, a C/C++ toolchain, CMake,
pkg-config, and systemd available. It builds all three release binaries before
installing them into `/usr/local/bin`, installs the service template, and runs
`systemctl daemon-reload`. Only installation uses `sudo`. Service enablement,
startup, configuration, and CA trust remain owned by the CLI.

`--prefix /opt/abyss` selects another installation prefix and updates the
installed unit's executable path. Linux prefixes must use only letters,
digits, slash, underscore, dot, and hyphen, and must be accessible to the
service user. Ensure `PREFIX/bin` is on `PATH`. `DESTDIR=/absolute/staging`
stages both binaries and the unit without contacting systemd. Stop the local
environment before reinstalling an updated checkout.

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

The systemd template starts `/usr/local/bin/abyss-broker` (or the selected
prefix's binary) for the endpoint user and reads
`/home/%i/.abyss/broker-config.toml`. It currently assumes a `/home/<user>` home
directory and the default `~/.abyss` state root. The broker publishes its dynamic
REST and explicit-proxy endpoints through runtime state instead of requiring
fixed ports.

The retired `~/.abyss/config.json` is not read, migrated, rewritten, or deleted.

## Non-goals

- Linux transparent routing, TProxy, nftables, TUN, or eBPF interception.
- A separate Linux event extraction pipeline.
- Product-specific release origins, control-plane endpoints, or credentials.
