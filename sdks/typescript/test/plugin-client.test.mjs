import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { BrokerClient } from "../dist/index.js";

const fixture = JSON.parse(
  await readFile(
    new URL(
      "../../../specs/broker-plugin-protocol/v1/fixtures/agent-event.json",
      import.meta.url,
    ),
    "utf8",
  ),
);

function frame(value) {
  const payload = Buffer.from(JSON.stringify(value));
  const header = Buffer.alloc(4);
  header.writeUInt32BE(payload.length);
  return Buffer.concat([header, payload]);
}

async function brokerPeer(t, endpoint, eventId) {
  const hellos = [];
  const sockets = new Set();
  const server = createServer((socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
    socket.setTimeout(3000, () => socket.destroy());
    let input = Buffer.alloc(0);
    socket.on("data", (chunk) => {
      input = Buffer.concat([input, chunk]);
      if (input.length < 4 || input.length < 4 + input.readUInt32BE()) return;
      hellos.push(
        JSON.parse(input.subarray(4, 4 + input.readUInt32BE()).toString()),
      );
      socket.removeAllListeners("data");
      socket.end(
        Buffer.concat([
          frame({ protocol_version: 1 }),
          frame({ ...fixture, event_id: eventId }),
          frame({ code: 100, reason: "complete" }),
        ]),
      );
    });
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(endpoint, resolve);
  });
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => server.close(resolve));
  });
  return hellos;
}

test("BrokerClient requires a usable plugin endpoint", () => {
  for (const pluginEndpoint of [undefined, null, "", "  ", "bad\0socket"]) {
    assert.throws(
      () => new BrokerClient({ baseUrl: "http://127.0.0.1:1", pluginEndpoint }),
      /pluginEndpoint/,
    );
  }
  const client = new BrokerClient({
    baseUrl: "http://127.0.0.1:1",
    pluginEndpoint: "/not/listening",
  });
  for (const id of ["", "bad id", "x".repeat(129)]) {
    assert.throws(() => client.plugin(id), /pluginId/);
  }
});

test("startup info requires plugin_endpoint", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "abyss-sdk-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, "startup.json");
  const token = join(directory, "token");
  await writeFile(token, "local-token\n");
  for (const plugin_endpoint of [undefined, null, "", " ", "bad\0socket"]) {
    await writeFile(
      path,
      JSON.stringify({
        api_addr: "127.0.0.1:1",
        auth_token_file: token,
        plugin_endpoint,
      }),
    );
    await assert.rejects(
      BrokerClient.fromStartupInfo(path),
      /connection fields|pluginEndpoint/,
    );
  }
});

test(
  "plugins retain their client's endpoint and independent lifecycle",
  { timeout: 10000 },
  async (t) => {
    const directory = await mkdtemp(join(tmpdir(), "abyss-sdk-"));
    t.after(() => rm(directory, { recursive: true, force: true }));
    const endpoint = (name) =>
      process.platform === "win32"
        ? `\\\\.\\pipe\\abyss-sdk-${process.pid}-${name}-${Date.now()}`
        : join(directory, name);
    const firstEndpoint = endpoint("first.sock");
    const secondEndpoint = endpoint("second.sock");
    const firstClient = new BrokerClient({
      baseUrl: "http://127.0.0.1:1",
      pluginEndpoint: firstEndpoint,
    });
    const firstPlugin = firstClient.plugin("first.consumer");
    // Creating a plugin must not perform network IO: listeners start afterwards.
    const firstHellos = await brokerPeer(t, firstEndpoint, "first-event");
    const secondHellos = await brokerPeer(t, secondEndpoint, "second-event");
    const path = join(directory, "startup.json");
    const token = join(directory, "token");
    await writeFile(token, "local-token\n");
    const startup = {
      api_addr: "127.0.0.1:1",
      auth_token_file: token,
      plugin_endpoint: secondEndpoint,
    };
    await writeFile(path, JSON.stringify(startup));
    const secondClient = await BrokerClient.fromStartupInfo(path);
    await writeFile(
      path,
      JSON.stringify({ ...startup, plugin_endpoint: "/wrong/socket" }),
    );
    const received = [];
    const closes = await Promise.all([
      firstPlugin.run((event) => received.push(event.event_id)),
      firstClient
        .plugin("another.consumer")
        .run((event) => received.push(event.event_id)),
      secondClient
        .plugin("second.consumer")
        .run((event) => received.push(event.event_id)),
    ]);
    assert.deepEqual(received.sort(), [
      "first-event",
      "first-event",
      "second-event",
    ]);
    assert.ok(closes.every((close) => close.code === 100));
    assert.deepEqual(firstHellos.map((hello) => hello.plugin_id).sort(), [
      "another.consumer",
      "first.consumer",
    ]);
    assert.deepEqual(secondHellos, [
      { protocol_version: 1, plugin_id: "second.consumer" },
    ]);
  },
);
