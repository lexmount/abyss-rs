# `@lexmount/abyss-sdk`

Node.js SDK for the local `abyss-broker` REST API and plugin event stream.
It does not provide browser APIs, remote event upload, or SSO handling.

```typescript
import { BrokerClient } from "@lexmount/abyss-sdk";

const broker = new BrokerClient({ baseUrl: "http://127.0.0.1:18190" });
console.log(await broker.getProxyStatus());
```

```typescript
import { AbyssPlugin, type AgentEvent } from "@lexmount/abyss-sdk/plugin";

await new AbyssPlugin({ consumerId: "company.security-exporter" }).run(
  async (event: AgentEvent) => {
    console.log(event.event_id);
  },
);
```
