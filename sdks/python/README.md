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
for the selected auth token or model. `auth_token_writable` and `model_writable`
indicate supported edits. See the [model override example](examples/request_modification.py). The SDK sends only the decision; it never diffs context.
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
