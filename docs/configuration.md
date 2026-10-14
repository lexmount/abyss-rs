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

The defaults intercept the official DeepSeek API at `api.deepseek.com`. Existing
installations can add the following rule to `runtime-policy.toml`, before any
matching passthrough rule, and restart the broker to load it:

```toml
[[mitm.tls_decryption.rules]]
id = "decrypt-deepseek-api"
enabled = true
action = "intercept"
destination_hosts = ["api.deepseek.com"]
```

Events from this host use `llm.provider = "deepseek"` independently of the wire
protocol. Agent Hook processing still requires an enabled, recognized Harness.

DeepSeek Harness is recognized by the `deepseek-harness/<version>` product token
in its User-Agent, including when using a gateway or another LLM provider. Its
stable Harness ID and event `agent.name` are `deepseek-harness`; client profiles
such as headless, Web, and Desktop are not distinguished. Recognition is enabled
by default and does not require process metadata or custom matchers.

For recognized DeepSeek Harness traffic, session grouping first uses explicit
request headers (`x-deepseek-harness-session-id`, `session-id`, `thread-id`,
`session_id`, or `x-session-id`, in that order), then the version 1
`dsh_session_log.session.id` extension. On OpenAI Responses and Chat Completions
routes, dsh's `prompt_cache_key` is also accepted as a fallback because its
pi-ai adapter derives that value from the Harness session ID. This cache-key
convention is not applied to other Harnesses. These markers also work through
gateways and do not affect protocol selection.

Requests without these markers retain the existing protocol fallback; Abyss
cannot recover a session ID that the client does not send. In particular, dsh
`0.2.0-rc.2` using Chat Completions with its default cache settings against
DeepSeek sends no session marker, so its requests can still appear as separate
sessions. Responses and native DeepSeek Messages requests carry session markers.

Use `abyss config harness enable deepseek-harness` or
`abyss config harness disable deepseek-harness` to change capture enablement.
The existing per-Harness content policy also applies, for example:

```toml
[hooks.harness_usage.config.harnesses.deepseek-harness]
enabled = true

[hooks.harness_usage.config.harnesses.deepseek-harness.content]
token_usage = true
conversation_text = false
tool_calls = false
images = false
```

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
