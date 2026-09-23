import { BrokerClient } from "@lexmount/abyss-sdk";

const startupInfo = process.argv[2];
if (!startupInfo) {
  throw new Error(
    "Pass the broker startup-info.json path as the first argument",
  );
}
const broker = await BrokerClient.fromStartupInfo(startupInfo);
const close = await broker.plugin("example.typescript").run(async (event) => {
  console.log(event.event_id, event.agent.name, event.side);
});
console.log("Broker closed:", close.code, close.reason);
