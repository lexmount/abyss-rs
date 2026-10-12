import assert from "node:assert/strict";
import { once } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:net";
import { join } from "node:path";
import test from "node:test";
import { BrokerPlugin } from "../dist/plugin/index.js";

async function server(t, handshake) {
  const dir = await mkdtemp("/tmp/abyss-sdk-abort-");
  const sockets = new Set();
  const listener = createServer((socket) => {
    sockets.add(socket);
    socket.on("error", () => {});
    socket.on("close", () => sockets.delete(socket));
    socket.on("data", () => {
      if (!handshake) return;
      handshake = false;
      const body = Buffer.from('{"protocol_version":1}');
      const header = Buffer.alloc(4);
      header.writeUInt32BE(body.length);
      socket.write(Buffer.concat([header, body]));
    });
  });
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => listener.close(resolve));
    await rm(dir, { recursive: true, force: true });
  });
  const endpoint = join(dir, "p.sock");
  listener.listen(endpoint);
  await once(listener, "listening");
  return new BrokerPlugin({ consumerId: "test.cancellation", endpoint });
}

test(
  "handshake timeout closes a stalled real socket",
  { timeout: 2000 },
  async (t) => {
    const plugin = await server(t, false);
    await assert.rejects(plugin.connect({ timeoutMs: 30 }));
  },
);

test(
  "abort interrupts both handshake and established stream",
  { timeout: 2000 },
  async (t) => {
    const stalled = await server(t, false);
    const setup = new AbortController();
    const pending = stalled.connect({ signal: setup.signal });
    setTimeout(() => setup.abort(), 30);
    await assert.rejects(pending);

    const plugin = await server(t, true);
    const lifetime = new AbortController();
    const connection = await plugin.connect({
      signal: lifetime.signal,
      timeoutMs: 1000,
    });
    const event = connection.nextEvent();
    lifetime.abort();
    await assert.rejects(event);
    connection.closeConnection();
  },
);

test("already aborted signal and invalid deadlines fail before connecting", async () => {
  const plugin = new BrokerPlugin({
    consumerId: "test.cancellation",
    endpoint: "/nonexistent",
  });
  await assert.rejects(plugin.connect({ signal: AbortSignal.abort() }));
  await assert.rejects(
    plugin.connect({ timeoutMs: 0 }),
    /positive safe integer/,
  );
});
