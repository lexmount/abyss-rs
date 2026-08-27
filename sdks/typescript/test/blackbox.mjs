import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

import { BrokerApiError, BrokerClient } from "../dist/index.js";
import { AbyssPlugin } from "../dist/plugin/index.js";

const startupInfo = process.env.ABYSS_BROKER_STARTUP_INFO;
if (!startupInfo) {
  throw new Error("ABYSS_BROKER_STARTUP_INFO must point to a real broker");
}

const client = await BrokerClient.fromStartupInfo(startupInfo);
const startup = JSON.parse(await readFile(startupInfo, "utf8"));
const unauthenticated = new BrokerClient({
  baseUrl: `http://${startup.api_addr}`,
});
const events = await new AbyssPlugin({
  consumerId: "blackbox.typescript-sdk",
}).connect();

assert.deepEqual(await client.getHealth(), {
  service: "abyss-broker",
  status: "ok",
});
await assert.rejects(
  unauthenticated.getMitmConfig(),
  (error) => error instanceof BrokerApiError && error.status === 401,
);
assert.equal((await client.getProxyStatus()).lifecycle, "running");

const mitm = await client.getMitmConfig();
assert.deepEqual(await client.updateMitmConfig(mitm), mitm);
const hooks = await client.getHooksConfig();
hooks.harness_usage.config.harnesses["typescript-sdk-custom"] = {
  enabled: true,
  matchers: [{ process_names: ["typescript-sdk-custom"] }],
};
const updatedHooks = await client.updateHooksConfig(hooks);
assert.deepEqual(
  updatedHooks.harness_usage.config.harnesses["typescript-sdk-custom"],
  hooks.harness_usage.config.harnesses["typescript-sdk-custom"],
);
await client.collectBrokerLogs({ max_bytes_per_file: 4096 });
assert.equal((await client.getDiagnostics()).schema_version, 1);
assert.equal((await client.getNetworkObservations(10)).schema_version, 1);
await client.getTrafficSnapshot();

assert.equal((await client.shutdown()).lifecycle, "stopped");
assert.equal(await events.nextEvent(), undefined);
assert.equal(events.close?.code, 100);

process.stdout.write("TypeScript SDK real-broker black-box: ok\n");
