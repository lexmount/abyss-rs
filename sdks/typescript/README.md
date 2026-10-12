# `@lexmount/abyss-sdk`

Node.js SDK for the local `abyss-broker` REST API and plugin event stream.
It does not provide browser APIs, remote event upload, or SSO handling.

```typescript
import { BrokerClient } from "@lexmount/abyss-sdk";

const broker = new BrokerClient({ baseUrl: "http://127.0.0.1:18190" });
console.log(await broker.getProxyStatus());
```

```typescript
import { BrokerPlugin, type AgentEvent } from "@lexmount/abyss-sdk/plugin";

await new BrokerPlugin({ consumerId: "company.security-exporter" }).run(
  async (event: AgentEvent) => {
    console.log(event.event_id);
  },
);
```

For a long-lived subscriber, `connect({ signal, timeoutMs })` supports shutdown
and a connection/handshake deadline. The signal also closes the established
stream; the deadline stops once the handshake succeeds.

```typescript
const stop = new AbortController();
const connection = await new BrokerPlugin({
  consumerId: "example.subscriber",
}).connect({ signal: stop.signal, timeoutMs: 10_000 });
try {
  for await (const event of connection) console.log(event.event_id);
} finally {
  connection.closeConnection();
}
```

See [Codex to Telegram](../../examples/codex-to-telegram/README.md) for an
independent receiver/sender with durable delivery checkpoints and reconnection.
