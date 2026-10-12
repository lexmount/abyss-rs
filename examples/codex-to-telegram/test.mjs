import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { createServer as httpServer } from "node:http";
import { createServer as socketServer } from "node:net";
import { join } from "node:path";
import test from "node:test";

const script = new URL("./main.mjs", import.meta.url).href;
const fixture = JSON.parse(
  await readFile(
    new URL(
      "../../specs/broker-plugin-protocol/v1/fixtures/agent-event.json",
      import.meta.url,
    ),
    "utf8",
  ),
);

function frame(value) {
  const body = Buffer.from(JSON.stringify(value));
  const header = Buffer.alloc(4);
  header.writeUInt32BE(body.length);
  return Buffer.concat([header, body]);
}

test(
  "forwards only Codex text and tools, splitting Unicode safely",
  { timeout: 10000 },
  async (t) => {
    const dir = await mkdtemp("/tmp/abyss-tg-");
    const endpoint = join(dir, "plugin.sock");
    const messages = [];
    const sockets = new Set();
    const context = "demo 🎉".repeat(500);
    const event = {
      ...fixture,
      agent: { name: "codex" },
      text: context,
      tool_results: [
        {
          call_id: "demo-call",
          output: "demo tool output",
          output_sha256: "sha",
        },
      ],
    };
    const broker = socketServer((socket) => {
      sockets.add(socket);
      socket.on("error", () => {});
      socket.once("data", () =>
        socket.end(
          Buffer.concat([
            frame({ protocol_version: 1 }),
            frame({
              ...event,
              agent: { name: "claude-code" },
              text: "SKIP_THIS",
            }),
            frame(event),
            frame({ code: 100, reason: "demo complete" }),
          ]),
        ),
      );
    });
    const api = httpServer(async (req, res) => {
      assert.equal(req.method, "POST");
      assert.equal(req.url, "/bot123:TEST/sendMessage");
      const body = [];
      for await (const chunk of req) body.push(chunk);
      messages.push(JSON.parse(Buffer.concat(body).toString()));
      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify({ ok: true, result: { message_id: messages.length } }),
      );
    });
    t.after(async () => {
      for (const socket of sockets) socket.destroy();
      api.closeAllConnections();
      await Promise.all([
        new Promise((resolve) => broker.close(resolve)),
        new Promise((resolve) => api.close(resolve)),
      ]);
      await rm(dir, { recursive: true, force: true });
    });
    broker.listen(endpoint);
    api.listen(0, "127.0.0.1");
    await Promise.all([once(broker, "listening"), once(api, "listening")]);
    // Redirect HTTP only inside the test process; production always calls Telegram.
    const code = `const request = globalThis.fetch;
    globalThis.fetch = (url, options) => request('http://127.0.0.1:${api.address().port}' + new URL(url).pathname, options);
    await import(${JSON.stringify(script)});`;
    const child = spawn(process.execPath, ["--input-type=module", "-e", code], {
      env: {
        ...process.env,
        TELEGRAM_BOT_TOKEN: "123:TEST",
        TELEGRAM_CHAT_ID: "42",
        ABYSS_BROKER_PLUGIN_ENDPOINT: endpoint,
      },
      stdio: ["ignore", "ignore", "pipe"],
    });
    t.after(() => {
      if (child.exitCode === null) child.kill();
    });
    let errors = "";
    child.stderr.on("data", (data) => {
      errors += data;
    });
    const [exitCode] = await once(child, "exit");
    assert.equal(exitCode, 0, errors);
    assert.ok(messages.length > 1);
    assert.ok(
      messages.every(
        (message) =>
          message.chat_id === "42" &&
          message.text.length <= 4096 &&
          !message.parse_mode,
      ),
    );
    const text = messages.map((message) => message.text).join("");
    assert.ok(text.includes(context));
    assert.ok(text.includes(event.tool_calls[0].input));
    assert.ok(text.includes(event.tool_results[0].output));
    assert.ok(!text.includes("SKIP_THIS"));
    assert.ok(
      messages.every(
        (message) => !/[\uD800-\uDBFF]$|^[\uDC00-\uDFFF]/u.test(message.text),
      ),
    );
  },
);

test("requires environment credentials", { timeout: 5000 }, async () => {
  const child = spawn(
    process.execPath,
    [new URL("./main.mjs", import.meta.url).pathname],
    {
      env: { ...process.env, TELEGRAM_BOT_TOKEN: "", TELEGRAM_CHAT_ID: "" },
      stdio: ["ignore", "ignore", "pipe"],
    },
  );
  let errors = "";
  child.stderr.on("data", (data) => {
    errors += data;
  });
  const [exitCode] = await once(child, "exit");
  assert.equal(exitCode, 1);
  assert.match(errors, /Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID/);
});
