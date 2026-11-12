# `abyss-sdk`

Synchronous Python SDK for the local `abyss-broker` REST API and plugin event
stream. It does not provide remote event upload or SSO handling.

```python
from abyss_sdk import BrokerClient

broker = BrokerClient(base_url="http://127.0.0.1:18190")
print(broker.get_proxy_status())
```

```python
from abyss_sdk.plugin import BrokerPlugin, AgentEvent

plugin = BrokerPlugin(plugin_id="company.security-exporter")
plugin.run(lambda event: print(event.event_id))
```

## Request inspection

A connected request handler enables `agent_request` inspection on the existing
plugin connection. See the [request inspection example](examples/request_inspection.py). No broker
inspector configuration is needed. Event observation is an independent capability.
Use the complete decoded body/JSON and parsing status as well as the normalized
Agent projection when implementing a policy; unknown protocols still reach the
handler. Credential headers are omitted and explicit proxy process fields are absent.
Return a safe block reason that does not contain the rejected content.

Plugins run in registration order, and each sees earlier accepted modifications.
Return Allow, Block with a safe reason, or Modify with explicit Set/Remove actions
for the selected auth token or model, or `SetProvider` for its provider endpoint.
`auth_token_writable`, `model_writable` and `provider_writable` indicate supported edits. See the [model override example](examples/request_modification.py). The SDK sends only the decision; it never diffs context.
Request handlers can read `auth_token`; event subscribers cannot.
See the [v1 wire contract](https://github.com/lexmount/abyss-rs/tree/main/specs/broker-plugin-protocol/v1).
Broker and SDKs share the updated v1 contract. A selected
plugin that fails or does not respond within five seconds fails that request.
Disconnecting the last inspection plugin restores normal streaming for future
requests. Network policy Block and opaque TLS Passthrough never invoke this callback.

The [Codex blocking example](examples/block_codex.py) rejects parsed model requests
whose `harness.id` is `codex`, including HTTP requests and WebSocket messages. It
allows setup requests, WebSocket upgrades, unknown payloads, and other Harnesses.
This uses Agent recognition; it does not require an OS process name and also
matches other clients recognized as the Codex Harness.

Run it from the repository root against an existing broker:

```bash
PYTHONPATH=sdks/python \
ABYSS_BROKER_STARTUP_INFO=/path/to/startup-info.json \
python3 sdks/python/examples/block_codex.py
```

Configure the broker's TLS policy to `intercept` the provider destinations. For a
Codex CLI test, pass the proxy through `HTTP_PROXY` and `HTTPS_PROXY`, and the
broker CA PEM through `CODEX_CA_CERTIFICATE` and `SSL_CERT_FILE`. Launch with
`codex --no-daemon` so an existing background server does not bypass the
per-command proxy environment. HTTP rejection returns `403 agent_request_blocked`
with the example's reason; WebSocket rejection closes with code `1008`. Codex may
retry WebSocket before falling back to HTTP and displaying the reason.

## Supply a DeepSeek key to Codex

The [Codex DeepSeek auth plugin](examples/codex_deepseek_auth.py) reads
`~/.deepseek/api.key` once at startup and returns `SetAuthToken` for Codex requests
to `api.deepseek.com`. It changes only authentication; Codex selects the provider
URL and model. Other destinations and Harnesses are left unchanged. The plugin
logs request IDs, never credentials, and does not subscribe to Agent events.

Start it against a broker that intercepts `api.deepseek.com`:

```bash
PYTHONPATH=sdks/python \
ABYSS_BROKER_STARTUP_INFO=/path/to/startup-info.json \
python3 sdks/python/examples/codex_deepseek_auth.py
```

Use `--key-file /path/to/api.key` to select a different credential file.
Then run Codex with a placeholder bearer token. The real key stays in the plugin;
the placeholder tells the broker which authentication header to replace:

```bash
ABYSS_CODEX_TOKEN=abyss-placeholder \
HTTP_PROXY=http://127.0.0.1:18080 \
HTTPS_PROXY=http://127.0.0.1:18080 \
NO_PROXY=localhost,127.0.0.1,::1 \
CODEX_CA_CERTIFICATE=/path/to/ca/abyss-root-ca.pem \
SSL_CERT_FILE=/path/to/ca/abyss-root-ca.pem \
codex --no-daemon exec --ignore-user-config --ephemeral \
  --skip-git-repo-check --sandbox read-only -m deepseek-flash \
  -c 'model_provider="abyss_deepseek"' \
  -c 'model_providers.abyss_deepseek={name="DeepSeek via Abyss",base_url="https://api.deepseek.com",env_key="ABYSS_CODEX_TOKEN",wire_api="responses",supports_websockets=false}' \
  -c 'features.enable_request_compression=false' \
  -c 'features.plugins=false' \
  'Do not use tools. Reply with exactly: ABYSS_AUTH_OK'
```

Use the actual broker proxy port and CA path. The
[DeepSeek Codex guide](https://api-docs.deepseek.com/quick_start/agent_integrations/codex/)
documents its Responses endpoint and model configuration. This example uses HTTP
streaming without request compression and disables Codex's own plugins for this
isolated test. For WebSocket providers, credentials can only change at the handshake.

## Route Codex to DeepSeek in the plugin

The [provider switching example](examples/codex_deepseek_provider.py) reads the
same local key file and returns three actions together: `SetProvider`,
`SetAuthToken`, and `SetModel`. Codex still targets OpenAI; Abyss selects DeepSeek.
This example handles HTTP model requests and requires compatible Responses APIs.

Start a broker that intercepts `api.openai.com`, then launch the plugin:

```bash
PYTHONPATH=sdks/python \
ABYSS_BROKER_STARTUP_INFO=/path/to/startup-info.json \
python3 sdks/python/examples/codex_deepseek_provider.py
```

With the proxy, CA and placeholder environment variables from the previous example,
run Codex using an OpenAI base URL and original model:

```bash
codex --no-daemon exec --ignore-user-config --ephemeral \
  --skip-git-repo-check --sandbox read-only -m gpt-5.4 \
  -c 'model_provider="abyss_original"' \
  -c 'model_providers.abyss_original={name="Original OpenAI endpoint",base_url="https://api.openai.com/v1",env_key="ABYSS_CODEX_TOKEN",wire_api="responses",supports_websockets=false}' \
  -c 'model_reasoning_effort="low"' \
  -c 'features.enable_request_compression=false' \
  -c 'features.plugins=false' \
  'Do not use tools. Reply with exactly: ABYSS_PROVIDER_OK'
```

The plugin sends the request to `https://api.deepseek.com/responses` with the local
DeepSeek key and `deepseek-flash` model. Use `--model` or `--key-file` on the plugin
to change those values. Client TLS remains associated with OpenAI; upstream TLS
and Host use DeepSeek. Explicit ingress currently prepares the original TCP
connection before inspection, so the original endpoint must be reachable.
