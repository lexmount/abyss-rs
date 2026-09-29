# Endpoint configuration

The open endpoint runtime uses three configuration files with deliberately
different owners.

| File | Format | Owner | Contents |
| --- | --- | --- | --- |
| `broker-config.toml` | TOML | Open runtime | Static diagnostics, CA store, and proxy ingress. |
| `runtime-policy.toml` | TOML | Open runtime | Dynamic TLS-decryption and Agent Hook policy. |
| `product-config.json` | JSON | Product distributor | Delivery destination, authentication mode, optional control-plane URL, and optional product integration. |

The open CLI defaults for the first two files live in
`crates/abyss-cli/defaults/`. They contain no deployment endpoints. The CLI can
seed these public defaults when the files are missing and preserves existing
files during subsequent starts.

`abyss config context off` retains token usage and the identifying metadata
needed to associate it with a device, Harness, model, and session. It disables
conversation text, tool calls and results, and image attachments in both the
global content policy and existing per-Harness overrides.
`abyss config context on` enables all of these content categories again. Both commands retain token
usage and preserve Harness enablement and matching rules. The broker persists
the policy and applies it to subsequent event processing; previously captured
events, including pending delivery retries, are not rewritten or deleted.

`product-config.json` has no embedded default in this repository. A deployment
or package must supply it. The CLI validates `schema_version = 1`, requires
`product.kind = "cli"`, rejects platform-adapter configuration, and passes the
same file to `abyss-delivery-plugin`. When
`delivery_worker.authentication.mode` is `none`, `authorization_header_file`,
or `cookie_header_file`, `product.control_plane` may be omitted and proxy
commands do not require terminal login. Static credential files are resolved
relative to `product-config.json`. The `managed_bearer` mode requires
`product.control_plane` and preserves the terminal login flow. An optional
`product.dashboard.url` is shown by `abyss status` and `abyss proxy start`, and
opened in the default browser by `abyss dashboard`.
Product URLs, SSO settings, update settings, and managed credentials belong in
the distributing repository.

`abyss deploy-local start` creates a narrowly scoped local `product-config.json`
for the SQLite+FTS backend and refuses to replace a file owned by another
deployment. Product deployment packages should include all three configuration
files and preserve existing files byte-for-byte. Hosted or signed product
installers, artifact origins, and release lifecycles remain outside this open
runtime repository.

The broker REST API binds a dynamic loopback endpoint and publishes its address,
PID, and token path in `runtime/startup-info.json`. Temporary files such as
control tokens, startup records, delivery control records, spool files, locks,
and logs are runtime state and must not be added to a configuration schema.

Closed Host packages may apply a different ownership lifecycle, but those
profiles, installers, platform adapter settings, and product update rules are
owned by the product distribution and service repositories rather than this
project.
