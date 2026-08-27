import { AbyssPlugin } from "@lexmount/abyss-sdk/plugin";

const close = await new AbyssPlugin({ consumerId: "example.typescript" }).run(
  async (event) => {
    process.stdout.write(`${event.event_id}\n`);
  },
);

process.stderr.write(
  `broker closed plugin stream: ${close.code} ${close.reason}\n`,
);
