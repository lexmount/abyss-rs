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

The CLI's packaged policy enables DeepSeek Harness and intercepts
`api.deepseek.com`. DSH Web (`dsh web`), headless launchers (including
`dsh-headless`), and
[dsh-tui](https://github.com/ccch1mneyyy/dsh-TUI) using the DSH backend share
the same request identity and use the existing protocol parsers. Run an
installed client through the proxy with:

```bash
abyss run -- dsh web
abyss run -- dsh-headless <arguments>
abyss run -- dsh-tui
abyss config harness disable deepseek-harness
abyss config harness enable deepseek-harness
```

`abyss run` and `abyss proxy env` for the managed proxy supply
`NODE_EXTRA_CA_CERTS` so Node clients trust the Abyss CA. An inherited extra
CA file is preserved in a combined bundle, without changing the original.
API credentials and model selection remain the client's configuration.

For the Web UI, start the local Abyss environment with `abyss deploy-local start`
if no deployment is configured, then run `abyss run -- dsh web` from the intended
workspace directory. DSH opens its browser interface or prints a full login URL
to open manually. Keep the terminal running while using the Web UI, and open
`abyss dashboard` from another terminal to review captured activity.

The proxy and CA environment belongs to the DSH server process that sends model
requests; the browser connects directly to the local Web UI and needs no proxy
configuration. Restart an already-running Web server through `abyss run` to
apply that environment. DSH flags are forwarded unchanged, for example:

```bash
abyss run -- dsh web --no-open --host 127.0.0.1 --port 3080
```

Existing runtime-policy files are preserved on upgrade. To enable DSH in an
older policy, add the following tables (or update matching existing entries):

```toml
[[mitm.tls_decryption.rules]]
id = "decrypt-deepseek-api"
enabled = true
action = "intercept"
destination_hosts = ["api.deepseek.com"]
```

Custom Harnesses reuse protocol parsers by declaring identity matchers in
`runtime-policy.toml`. The packaged DSH matcher recognizes its request
User-Agent without source process metadata:

```toml
[hooks.harness_usage.config.harnesses."deepseek-harness"]
enabled = true

[[hooks.harness_usage.config.harnesses."deepseek-harness".matchers]]
user_agent_prefixes = ["deepseek-harness/"]
```

`user_agent_prefixes` uses literal, case-sensitive prefixes. `process_names` and
`application_ids` use exact matches against platform-supplied source metadata.
Populated fields in one matcher must all match; values within a field and
separate matchers are alternatives. Exactly one enabled Harness must match.
Request headers provide attribution, not authenticated process identity.
TLS traffic must also be selected for interception by the MITM policy.
For intercepted POST requests ending in `/responses`, `/chat/completions`, or
`/messages`, the HTTP relay removes `Accept-Encoding` so compatible providers
return plaintext JSON/SSE for capture, regardless of their hostname.

Harness matching does not select or customize a protocol parser. Recognized
traffic is parsed using its existing wire protocol, such as OpenAI Responses
or Chat Completions. Configuring a new Harness does not add support for extra
provider fields or supply session/turn identifiers absent from its requests.

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
