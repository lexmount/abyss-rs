# `abyss-sdk`

Synchronous Python SDK for the local `abyss-broker` REST API and plugin event
stream. It does not provide remote event upload or SSO handling.

```python
from abyss_sdk import BrokerClient

broker = BrokerClient(base_url="http://127.0.0.1:18190")
print(broker.get_proxy_status())
```

```python
from abyss_sdk.plugin import AbyssPlugin, AgentEvent

plugin = AbyssPlugin(plugin_id="company.security-exporter")
plugin.run(lambda event: print(event.event_id))
```
