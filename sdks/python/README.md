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

All selected plugins must allow before the broker forwards the request. A selected
plugin that fails or does not respond within five seconds fails that request.
Disconnecting the last inspection plugin restores normal streaming for future
requests. Network policy Block and opaque TLS Passthrough never invoke this callback.
