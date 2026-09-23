# `abyss-sdk`

Synchronous Python SDK for the local broker REST API and plugin event stream.
It does not provide remote event upload or SSO handling.

```python
from abyss_sdk import BrokerClient

broker = BrokerClient(
    base_url="http://127.0.0.1:18190",
    plugin_endpoint="/path/to/runtime/broker-plugin-v1.sock",
    # bearer_token="...",  # Required for protected REST routes.
)
print(broker.get_proxy_status())
broker.plugin("company.security-exporter").run(lambda event: print(event.event_id))
```

`BrokerClient.from_startup_info(path)` loads both endpoints and the bearer token
from broker startup information. Windows callers provide the advertised Named
Pipe as `plugin_endpoint`.

`broker.plugin(id)` creates a `BrokerPlugin` without opening a connection.
`connect()` returns an `AgentEventStream` supporting iteration, `close_stream()`,
and the final `close` reason. Each plugin owns its connection independently.
Plugins never rediscover endpoints from environment variables; reconnection and
durable event storage belong to the consumer.

Migration: replace `AbyssPlugin(plugin_id, endpoint)` with
`BrokerClient(base_url, plugin_endpoint=endpoint).plugin(plugin_id)`.
`BrokerPluginError` replaces `AbyssPluginError`; the wire protocol is unchanged.
