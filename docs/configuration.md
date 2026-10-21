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
`api.deepseek.com`, `open.bigmodel.cn`, `api.z.ai`, `api.moonshot.cn`, and
`api.moonshot.ai`, and the Qwen API hosts listed below. DSH Web (`dsh web`),
headless launchers (including `dsh-headless`), and
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

For Node-based clients such as DSH, configure `NODE_EXTRA_CA_CERTS` yourself before
launching the client. Point it at the `abyss-root-ca.pem` in your configured CA directory,
or a PEM bundle containing that certificate and any other extra CAs you need:

```bash
export NODE_EXTRA_CA_CERTS='/absolute/path/to/abyss-root-ca.pem'
abyss run -- dsh web
```

You can place the export in your shell profile for future sessions. `abyss run`
inherits this variable unchanged, and `abyss proxy env` prints only proxy
variables. API credentials and model selection remain the client's configuration.

Claude Code also supports persistent certificate setup through
`abyss config harness enable claude-code`. This command backs up
`~/.claude/settings.json`, merges the Abyss root certificate with any existing
CA bundle referenced by its `env.NODE_EXTRA_CA_CERTS`, and writes
`~/.claude/abyss-ca-bundle.pem`. It updates that settings entry to point to the
managed bundle while preserving other settings. Disabling capture leaves this
certificate configuration in place. This setup is scoped to Claude Code;
it does not change the shell environment.

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

Existing runtime-policy files are preserved on upgrade. DSH identification is
built in and enabled by default, including with policies that have no DSH entry.
To observe DeepSeek API traffic with an older policy, add the following TLS rule
(or update its existing entry):

```toml
[[mitm.tls_decryption.rules]]
id = "decrypt-deepseek-api"
enabled = true
action = "intercept"
destination_hosts = ["api.deepseek.com"]
```

For GLM, add a separate rule for its official API hosts:

```toml
[[mitm.tls_decryption.rules]]
id = "decrypt-glm-api"
enabled = true
action = "intercept"
destination_hosts = ["open.bigmodel.cn", "api.z.ai"]
```

Both standard and Coding Plan Chat Completions paths use the shared parser.
Custom gateways require their own TLS rule. See [GLM with DSH](glm.md) for
model configuration and session attribution details.

For Kimi, add the official Moonshot API hosts:

```toml
[[mitm.tls_decryption.rules]]
id = "decrypt-kimi-api"
enabled = true
action = "intercept"
destination_hosts = ["api.moonshot.cn", "api.moonshot.ai"]
```

See [Kimi with DSH](kimi.md) for Responses, Chat Completions, and Messages
configuration. The rule selects only these API hosts, not the entire Moonshot domain.

For Qwen, add the Model Studio API hosts and regional workspace endpoints:

```toml
[[mitm.tls_decryption.rules]]
id = "decrypt-qwen-api"
enabled = true
action = "intercept"
destination_hosts = [
    "dashscope.aliyuncs.com",
    "dashscope-intl.aliyuncs.com",
    "dashscope-us.aliyuncs.com",
    "coding.dashscope.aliyuncs.com",
    "coding-intl.dashscope.aliyuncs.com",
    "*.cn-beijing.maas.aliyuncs.com",
    "*.ap-southeast-1.maas.aliyuncs.com",
    "*.us-east-1.maas.aliyuncs.com",
    "*.eu-central-1.maas.aliyuncs.com",
    "*.ap-northeast-1.maas.aliyuncs.com",
    "*.cn-hongkong.maas.aliyuncs.com",
]
```

These rules target Model Studio API endpoints, not the entire `aliyuncs.com`
domain. See [Qwen with DSH](qwen.md) for the three compatible APIs, client
configuration, and session attribution.

The built-in DSH detector recognizes the literal, case-sensitive
`deepseek-harness/` prefix in the model request's User-Agent without source
process metadata. Its optional policy entry controls enablement and content
capture, following the same format as other built-in Harnesses:

```toml
[hooks.harness_usage.config.harnesses."deepseek-harness"]
enabled = true
```

Custom Harnesses can declare `process_names` and `application_ids` matchers in
`runtime-policy.toml`; these use exact matches against platform-supplied source
metadata.
Populated fields in one matcher must all match; values within a field and
separate matchers are alternatives. Exactly one enabled Harness must match.
Hermes is also built in; see [client setup and session requirements](hermes.md).
Its explicit identity takes precedence over Codex/Claude Code compatibility
fingerprints, including when capture for that client is disabled. Other ambiguous
matches are skipped. Request headers provide attribution, not authenticated process identity.
TLS traffic must also be selected for interception by the MITM policy.
HTTP compression negotiation and forwarded bytes are preserved. The background
MITM hook worker decodes request/response `Content-Encoding` before Agent parsing
(gzip, deflate, Brotli, zstd, identity, and stacked codings), independent of
hostname and route. Encoded captures remain available separately; unsupported or
invalid encodings cannot be mistaken for plaintext. Capture and decoding limits
affect observation only; see [abyss-mitm](../crates/abyss-mitm/README.md).

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
