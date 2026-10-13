import { BrokerPlugin } from "@lexmount.com/abyss-sdk/plugin";

const close = await new BrokerPlugin({ consumerId: "example.typescript" }).run(
  async (event) => {
    process.stdout.write(`${event.event_id}\n`);
  },
);

process.stderr.write(
  `broker closed plugin stream: ${close.code} ${close.reason}\n`,
);
