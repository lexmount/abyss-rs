import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { BrokerPlugin } from "../dist/plugin/index.js";
import { readJsonFrames, writeJsonFrame } from "../dist/plugin/framing.js";

test("request handler returns a correlated decision on the existing connection", async () => {
  const root = await mkdtemp(join(tmpdir(), "abyss-inspector-"));
  const endpoint =
    process.platform === "win32"
      ? `\\\\.\\pipe\\abyss-inspector-${process.pid}`
      : join(root, "plugin.sock");
  const request = JSON.parse(
    await readFile(
      new URL(
        "../../../specs/broker-plugin-protocol/v1/fixtures/inspect-request.json",
        import.meta.url,
      ),
      "utf8",
    ),
  );
  let resolveSession, rejectSession;
  const session = new Promise((resolve, reject) => {
    resolveSession = resolve;
    rejectSession = reject;
  });
  const server = createServer((socket) => {
    (async () => {
      const frames = readJsonFrames(socket)[Symbol.asyncIterator]();
      const hello = (await frames.next()).value;
      assert.equal(hello.type, "plugin_hello");
      assert.deepEqual(hello.capabilities, ["agent_request"]);
      await writeJsonFrame(socket, {
        type: "broker_hello",
        protocol_version: 1,
      });
      await writeJsonFrame(socket, request);
      assert.deepEqual((await frames.next()).value, {
        type: "inspect_response",
        request_id: "request-123",
        allow: false,
        reason: "test policy",
      });
      await writeJsonFrame(socket, {
        type: "broker_close",
        code: 100,
        reason: "test complete",
      });
      socket.end();
    })().then(resolveSession, rejectSession);
  });
  try {
    await new Promise((resolve) => server.listen(endpoint, resolve));
    const close = await new BrokerPlugin({
      consumerId: "sdk-inspector",
      endpoint,
      agentEvents: false,
      onAgentRequest(context) {
        assert.equal(context.agent.model, "gpt-test");
        return { allow: false, reason: "test policy" };
      },
    }).run();
    assert.equal(close.code, 100);
    await session;
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await rm(root, { recursive: true, force: true });
  }
});
