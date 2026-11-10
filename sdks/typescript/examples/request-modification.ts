import { BrokerPlugin } from "@lexmount.com/abyss-sdk/plugin";

const model = process.env.ABYSS_MODEL_OVERRIDE;
if (!model) throw new Error("Set ABYSS_MODEL_OVERRIDE to the requested model");

await new BrokerPlugin({
  consumerId: "example.model-override",
  agentEvents: false,
  onAgentRequest(context) {
    return context.model_writable
      ? { action: "modify", actions: [{ op: "set_model", value: model }] }
      : { action: "allow" };
  },
}).run();
