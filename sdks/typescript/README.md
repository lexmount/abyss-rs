# `@lexmount/abyss-sdk`

Node.js SDK for the local broker REST API and plugin event stream.
It does not provide browser APIs, remote event upload, or SSO handling.

```typescript
import { BrokerClient } from "@lexmount/abyss-sdk";

const broker = new BrokerClient({
  baseUrl: "http://127.0.0.1:18190",
  pluginEndpoint: "/path/to/runtime/broker-plugin-v1.sock",
  // bearerToken: "...", // Required for protected REST routes.
});
console.log(await broker.getProxyStatus());

await broker.plugin("company.security-exporter").run(async (event) => {
  console.log(event.event_id);
});
```

`await BrokerClient.fromStartupInfo(path)` loads both endpoints and the bearer
token from broker startup information. Windows callers provide the advertised
Named Pipe as `pluginEndpoint`.

`broker.plugin(id)` returns a `BrokerPlugin` without opening a connection.
`connect()` returns a `PluginConnection` supporting `for await`, `nextEvent()`,
`closeConnection()`, and the final `close` reason. Multiple plugins are
independent. Plugins never rediscover endpoints from environment variables;
reconnection and durable event storage belong to the consumer.

Migration: replace `new AbyssPlugin({ consumerId, endpoint })` with
`new BrokerClient({ baseUrl, pluginEndpoint: endpoint }).plugin(consumerId)`.
The `BrokerPlugin` type is exported from `@lexmount/abyss-sdk/plugin`;
`BrokerPluginError` replaces `AbyssPluginError`. The wire protocol is unchanged.
