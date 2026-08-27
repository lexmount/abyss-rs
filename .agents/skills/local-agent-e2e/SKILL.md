---
name: local-agent-e2e
description: Deploy, operate, verify, and troubleshoot a persistent local Abyss endpoint end-to-end environment consisting of Docker PostgreSQL plus the published abyss-backend image, abyss-broker in explicit-proxy mode, and abyss-delivery-plugin. Use when asked to run Codex or Claude Code through Abyss locally, validate Agent Hook parsing and delivery, or inspect locally ingested events.
---

# Local Agent E2E

Run a persistent endpoint stack against the published Backend contract:

```text
Codex or Claude Code -> explicit abyss-broker proxy -> provider
                              |
                              v
                    abyss-delivery-plugin
                              |
                              v
              published abyss-backend -> PostgreSQL
```

Backend source, migrations, frontend behavior, and service deployment are owned
by the `abyss-backend` and `abyss-services` repositories. Do not recreate or
patch those concerns in this endpoint repository.

## Protect Existing Tests

- Do not reuse resources owned by `scripts/blackbox_*.sh` or
  `scripts.agent_e2e_ci`.
- Keep persistent state under `/tmp/abyss-local-agent-e2e` by default and prefix
  Docker resources with `abyss-local-agent-e2e`.
- Do not install the E2E CA in the system trust store. Pass its PEM only to the
  Agent process under test.
- Never print the deployment bearer, broker token, or CA private key.
- Reuse only a healthy stack proven to belong to this skill. Do not kill an
  unrelated process to claim a port.

## Backend Stack

1. Read the immutable image reference from
   `scripts/ci/abyss-backend-image.txt`. Pull it as `linux/amd64` unless an
   intentionally selected compatible image declares another platform.
2. Create a random raw bearer and store it mode `0600` under the runtime root.
   Compute its lowercase SHA-256 hex digest without printing either value.
3. Create a dedicated Docker network and start `postgres:16` with an empty
   `abyss` database. Wait for `pg_isready`.
4. Start the published Backend image on the same network and expose it only on
   a loopback host port. Configure:

```text
ABYSS_BACKEND_ADDR=0.0.0.0:8080
ABYSS_BACKEND_ENV=blackbox
ABYSS_BACKEND_BLACKBOX_ALLOW_NON_LOOPBACK=true
ABYSS_BACKEND_API_TOKEN_SHA256=<sha256-of-raw-bearer>
ABYSS_BACKEND_DATABASE_URL=postgres://abyss:abyss@abyss-local-agent-e2e-postgres:5432/abyss?sslmode=disable
ABYSS_BACKEND_RUN_MIGRATIONS=true
```

5. Wait for `/readyz`. Do not seed `app_users`, `native_auth_sessions`, or any
   other Backend-owned database table; standalone authentication is the
   deployment bearer configured at process startup.

## Broker and Delivery

Build current endpoint binaries:

```bash
cargo build --locked --package abyss-broker --package abyss-delivery-plugin
```

Generate a short-lived CA under the runtime root with the filenames required by
`abyss-mitm`:

```text
abyss-root-ca.pem
abyss-root-ca.der
abyss-root-ca-key.pem
```

Write runtime-only `broker-config.toml`, `runtime-policy.toml`, and
`product-config.json` files using the public broker and policy defaults in
`crates/abyss-cli/defaults` plus a deployment-local product profile following
`docs/configuration.md`. Select explicit proxy mode, intercept only the provider
domains being tested, enable the desired Harness, and configure the delivery
plugin endpoint as:

```text
http://127.0.0.1:<backend-port>/v1/agent-usage/events
```

Store `Bearer <raw-bearer>` in a mode `0600` authorization file referenced by
the delivery configuration. Start the Broker first, discover its automatically
selected REST API from `startup-info.json`, then start the delivery plugin.
Require Broker health, proxy status, and a running delivery process before
sending provider traffic.

## Run and Verify an Agent

Set proxy and CA variables only for the Agent child process. Keep Backend and
Broker loopback addresses in `NO_PROXY` and clear unrelated proxy values.

For Codex:

```bash
HTTP_PROXY=http://127.0.0.1:<proxy-port> \
HTTPS_PROXY=http://127.0.0.1:<proxy-port> \
NO_PROXY=localhost,127.0.0.1,::1 \
CODEX_CA_CERTIFICATE=<runtime-root>/ca/abyss-root-ca.pem \
SSL_CERT_FILE=<runtime-root>/ca/abyss-root-ca.pem \
codex exec <arguments>
```

For Claude Code, also set `NODE_EXTRA_CA_CERTS` to the same PEM. Use a
disposable workspace and a prompt that triggers the content being validated.

Verify every boundary:

1. The real Agent request succeeds through the explicit proxy.
2. Broker and delivery logs contain no parse, upload, or spool failures.
3. An authenticated `GET /v1/agent-usage/events` using the deployment bearer
   contains the matching session and event markers.
4. Tool call/result identifiers, turn identifiers, content policy, and provider
   usage fields match the captured exchange.
5. The delivery spool is empty after successful upload.

## Stop or Preserve

Keep the stack running unless the user asks to stop it. On stop, resolve exact
PIDs and Docker resource names first, stop only this skill's processes and
containers, remove only its dedicated network, and preserve the runtime root by
default for diagnostics.
