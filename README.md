# Abyss

## About Abyss

Abyss is an open-source endpoint runtime for observing and controlling AI agent
network traffic. It provides an explicit HTTP/HTTPS proxy, TLS interception,
AI agent and provider protocol parsing, local capture policy, normalized audit
events, pluggable event delivery, and Rust, TypeScript, and Python SDKs.

The shared runtime is implemented in Rust. Platform integrations feed traffic
into stable broker ingress contracts while policy, interception, parsing, and
event production remain platform independent.

## Quick Start

For the standalone broker, install it from crates.io:

```bash
cargo install --locked abyss-broker
```

Follow the [broker setup guide](crates/abyss-broker/README.md) to prepare its CA,
select explicit-proxy mode, and start it. For maintainers, the
[crates.io release guide](docs/crates-io-release.md) describes version tags and
the GitHub Actions publication workflow.

### Complete local environment from source

The local environment supports Linux x86_64 and macOS ARM64 without Docker.
Install the Rust stable toolchain and a native C/C++ build toolchain first
(Xcode Command Line Tools on macOS; on Linux, also install CMake and pkg-config).
Clone the repository and build and install the complete CLI runtime:

```bash
git clone https://github.com/lexmount/abyss-rs.git
cd abyss-rs
bash scripts/install-cli.sh
abyss version
abyss --help
```

The script builds `abyss`, `abyss-broker`, and `abyss-delivery-plugin` together
with `cargo build --release --locked`, checks that all three programs run, and
installs them into `/usr/local/bin`. Run it as your normal user; it requests
`sudo` only for installation when needed. Linux requires a running systemd and
also installs the broker service template and reloads systemd. See the
[Linux integration notes](platform/linux/README.md) for its user-home layout.

Use `bash scripts/install-cli.sh --prefix "$HOME/.local"` for a user-writable
macOS installation, or another absolute prefix on either platform. Add the
printed `PREFIX/bin` directory to `PATH` if needed. Keep all three binaries
together because the CLI discovers its delivery worker, and its macOS broker,
beside its own executable. Stop the local environment before rerunning the
script to upgrade it. The script supports `CARGO_TARGET_DIR` and stages packages
under `DESTDIR` without reloading systemd when that variable is set.

Installation prepares the executables and Linux service template. Configuration,
CA trust, backend, and dashboard setup happen when you start the runtime. With
Node.js 22 or newer and npm 10 or newer installed, run:

```bash
abyss deploy-local start
```

The first start downloads the checksummed native backend from the public
`lexmount/abyss-backend` GitHub Release and installs the pinned public dashboard
package below the private Abyss state directory. Neither component is added to
`PATH`; `abyss` remains the only management command.

The CLI keeps all services on IPv4 loopback and stores downloaded runtimes, the
SQLite database, logs, and private bearer files under
`~/Library/Application Support/Abyss/cli/local` on macOS or `~/.abyss/local` on
Linux. It automatically selects and persists available backend and dashboard
ports. `abyss status` and `abyss proxy start` also print the selected dashboard
URL. Inspect the complete local environment and run an agent through it:

```bash
abyss deploy-local status
abyss run -- codex
```

Manage the environment without reinstalling it:

```bash
abyss deploy-local stop
abyss deploy-local start
```

`deploy-local` refuses to replace an unrelated existing `product-config.json`
in the platform state directory; set `ABYSS_HOME` to another absolute directory
when the machine already has a different deployment. Linux proxy startup uses
the existing systemd broker integration; CA trust changes may request `sudo`.

The CLI requires a deployment-supplied `product-config.json` for proxy and agent
commands. `abyss deploy-local start` creates a local profile that delivers
events to its authenticated backend. Other distributions can provide their own
delivery destination and authentication mode; `managed_bearer` deployments
also require a control plane and `abyss login`.

Run another AI agent without changing the parent shell:

```bash
abyss run -- claude
```

Alternatively, export the proxy variables into the current shell:

```bash
eval "$(abyss proxy env)"
```

Common operational commands are:

```bash
abyss status
abyss diagnostics
abyss config context off
abyss config harness enable codex
abyss log dump
abyss proxy stop
abyss logout
```

See [Endpoint configuration](docs/configuration.md) for the complete runtime and
deployment configuration boundary.

## Architecture

```mermaid
flowchart LR
    Agent[AI agents, IDEs, CLIs, and SDKs]
    Provider[AI providers]
    EventAPI[Agent event API]

    subgraph Endpoint[Abyss endpoint runtime]
        CLI[abyss CLI]
        Ingress[abyss-broker ingress]
        MITM[abyss-mitm<br/>TLS and HTTP relay]
        Hook[abyss-agent-hook<br/>protocol parsing]
        Protocol[abyss-plugin-protocol<br/>normalized AgentEvent]
        Delivery[abyss-delivery-plugin]
        State[(Policy, CA, diagnostics,<br/>and durable local state)]

        CLI -->|lifecycle, auth, and policy| Ingress
        CLI -->|delivery credentials| Delivery
        Ingress <--> MITM
        MITM --> Hook
        Hook --> Protocol
        Protocol --> Delivery
        Ingress <--> State
        MITM <--> State
        Delivery <--> State
    end

    Agent <-->|HTTP, HTTPS, and WebSocket| Ingress
    MITM <-->|upstream traffic| Provider
    Delivery -->|authenticated event upload| EventAPI
```

Explicit-proxy clients connect directly to `abyss-broker`. External macOS and
Windows platform adapters can use the same broker ingress contracts to attach
process identity and transparently redirect traffic. The broker and shared Rust
crates do not depend on those platform implementations.

## License

Abyss is licensed under the [GNU General Public License, version 3](LICENSE).
