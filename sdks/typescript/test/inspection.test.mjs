import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { BrokerPlugin } from "../dist/plugin/index.js";
import { readJsonFrames, writeJsonFrame } from "../dist/plugin/framing.js";

for (const decision of [
  { action: "allow" },
  { action: "block", reason: "test policy" },
  {
    action: "modify",
    actions: [
      { op: "set_auth_token", value: "allocated" },
      { op: "remove_auth_token" },
      { op: "set_model", value: "new" },
      { op: "remove_model" },
      { op: "set_provider", value: "https://provider.example/v1" },
    ],
  },
])
  test(`request handler sends ${decision.action} without context comparison`, async () => {
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
          decision,
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
          context.agent.model = "local-only";
          return decision;
        },
      }).run();
      assert.equal(close.code, 100);
      await session;
    } finally {
      await new Promise((resolve) => server.close(resolve));
      await rm(root, { recursive: true, force: true });
    }
  });
