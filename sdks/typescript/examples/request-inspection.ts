import { BrokerPlugin } from "@lexmount.com/abyss-sdk/plugin";

// This marker check illustrates the callback, not a complete data-loss policy.
await new BrokerPlugin({
  consumerId: "example.typescript-policy",
  agentEvents: false,
  onAgentRequest(context) {
    const detected = context.agent?.conversation.entries.some((message) =>
      message.text.includes("PRIVATE KEY"),
    );
    return detected
      ? { allow: false, reason: "Private key detected" }
      : { allow: true };
  },
}).run();
