import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { access, mkdtemp, rm, writeFile } from "node:fs/promises";
import { createServer as httpServer } from "node:http";
import { createServer as socketServer } from "node:net";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { Outbox } from "../dist/outbox.js";
import { TelegramClient, TelegramFailure } from "../dist/telegram.js";
import { event, frame } from "./fixtures.mjs";

const fakeToken = "123456:TEST_TOKEN_DO_NOT_LOG";
const cli = fileURLToPath(new URL("../dist/main.js", import.meta.url));

async function until(predicate, detail = "condition") {
  const end = Date.now() + 10000;
  while (Date.now() < end) {
    if (await predicate()) return;
    await delay(20);
  }
  assert.fail(`Timed out: ${detail}`);
}

async function harness(
  t,
  respond = () => ({
    status: 200,
    body: { ok: true, result: { message_id: 99 } },
  }),
) {
  const dir = await mkdtemp("/tmp/abyss-tg-");
  const endpoint = join(dir, "p.sock");
  const state = join(dir, "state");
  const clients = new Set();
  const ready = new Set();
  const children = [];
  const requests = [];
  const broker = socketServer((socket) => {
    clients.add(socket);
    socket.on("error", () => {});
    socket.on("close", () => {
      clients.delete(socket);
      ready.delete(socket);
    });
    let buffer = Buffer.alloc(0);
    socket.on("data", (data) => {
      buffer = Buffer.concat([buffer, data]);
      if (
        buffer.length < 4 ||
        buffer.length < 4 + buffer.readUInt32BE(0) ||
        ready.has(socket)
      )
        return;
      const hello = JSON.parse(
        buffer.subarray(4, 4 + buffer.readUInt32BE(0)).toString(),
      );
      assert.equal(hello.protocol_version, 1);
      assert.equal(hello.plugin_id, "example.codex-telegram");
      socket.write(frame({ protocol_version: 1 }));
      ready.add(socket);
    });
  });
  const api = httpServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const payload = JSON.parse(Buffer.concat(chunks).toString());
    requests.push({ path: req.url, payload, time: Date.now() });
    const response = respond(req.url, payload, requests.length);
    res.writeHead(response.status, {
      "content-type": "application/json",
      ...response.headers,
    });
    res.end(JSON.stringify(response.body));
  });
  broker.listen(endpoint);
  api.listen(0, "127.0.0.1");
  await Promise.all([once(broker, "listening"), once(api, "listening")]);
  const apiBase = `http://127.0.0.1:${api.address().port}`;
  t.after(async () => {
    for (const child of children) {
      if (child.process.exitCode === null && child.process.signalCode === null)
        child.process.kill("SIGKILL");
      await child.exited;
    }
    for (const socket of clients) socket.destroy();
    api.closeAllConnections();
    await Promise.all([
      new Promise((resolve) => broker.close(resolve)),
      new Promise((resolve) => api.close(resolve)),
    ]);
    await rm(dir, { recursive: true, force: true });
  });
  function launch(args = ["run"], extraEnv = {}) {
    const child = spawn(
      process.execPath,
      [cli, ...args, "--endpoint", endpoint, "--state-dir", state],
      {
        env: {
          ...process.env,
          TELEGRAM_BOT_TOKEN: fakeToken,
          TELEGRAM_CHAT_ID: "42",
          TELEGRAM_API_BASE_URL: apiBase,
          TELEGRAM_PROXY_URL: "",
          ABYSS_TELEGRAM_SESSION_ID: "",
          ...extraEnv,
        },
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    const result = {
      process: child,
      stdout: "",
      stderr: "",
      exited: once(child, "exit"),
    };
    child.stdout.on("data", (data) => {
      result.stdout += data;
    });
    child.stderr.on("data", (data) => {
      result.stderr += data;
    });
    children.push(result);
    return result;
  }
  function send(events) {
    const bytes = Buffer.concat(events.map(frame));
    for (const socket of ready) {
      // Split a length header and coalesce the remaining event frames.
      socket.write(bytes.subarray(0, 2));
      socket.write(bytes.subarray(2));
    }
  }
  return {
    dir,
    endpoint,
    state,
    apiBase,
    clients,
    ready,
    requests,
    launch,
    send,
  };
}

async function stop(child) {
  child.process.kill("SIGTERM");
  const [code, signal] = await child.exited;
  assert.equal(code, 0, child.stderr);
  assert.equal(signal, null);
}

test(
  "real CLI filters, deduplicates, retries 429, and reconnects to broker",
  { timeout: 15000 },
  async (t) => {
    const h = await harness(t, (_path, _payload, count) =>
      count === 1
        ? {
            status: 429,
            body: {
              ok: false,
              error_code: 429,
              parameters: { retry_after: 1 },
            },
          }
        : { status: 200, body: { ok: true, result: { message_id: count } } },
    );
    const child = h.launch(["run", "--session", "demo-session"]);
    await until(() => child.stderr.includes("broker_connected"));
    h.send([
      event({ agent: { name: "claude-code" } }),
      event({ session_id: "other" }),
      event(),
      event(),
    ]);
    await until(() => child.stderr.includes('"telegram_message_id":2'));
    assert.equal(h.requests.length, 2);
    assert.ok(h.requests[1].time - h.requests[0].time >= 1000);
    assert.equal(h.requests[1].payload.chat_id, "42");
    assert.equal(h.requests[1].payload.parse_mode, undefined);
    assert.deepEqual(h.requests[1].payload.link_preview_options, {
      is_disabled: true,
    });
    assert.equal(h.requests[1].payload.text, h.requests[0].payload.text);
    for (const socket of h.clients) socket.destroy();
    await until(
      () => (child.stderr.match(/broker_connected/g) ?? []).length === 2,
    );
    h.send([event(), event({ event_id: "event-2", text: "after reconnect" })]);
    await until(() => child.stderr.includes('"telegram_message_id":3'));
    await stop(child);
    assert.equal(h.requests.length, 3);
    assert.doesNotMatch(child.stderr, new RegExp(fakeToken));
  },
);

test(
  "chunk checkpoints survive process restart without resending acknowledged chunks",
  { timeout: 15000 },
  async (t) => {
    const h = await harness(t);
    let child = h.launch(["run", "--session", "demo-session"]);
    await until(() => child.stderr.includes("broker_connected"));
    h.send([event({ text: "🎉".repeat(2300) })]);
    await until(() => child.stderr.includes('"chunk":1,'));
    await stop(child);
    assert.equal(h.requests.length, 1);
    child = h.launch(["run", "--session", "demo-session"]);
    await until(() => child.stderr.includes('"chunk":2,'));
    await stop(child);
    assert.equal(h.requests.length, 2);
    assert.match(h.requests[0].payload.text, /Part 1\/2/);
    assert.match(h.requests[1].payload.text, /Part 2\/2/);
  },
);

test(
  "permanent Telegram failure keeps queue, exits, and hides server credentials",
  { timeout: 10000 },
  async (t) => {
    let reject = true;
    const h = await harness(t, () =>
      reject
        ? {
            status: 403,
            body: { ok: false, error_code: 403, description: fakeToken },
          }
        : { status: 200, body: { ok: true, result: { message_id: 7 } } },
    );
    const child = h.launch(["run", "--session", "demo-session"]);
    await until(() => child.stderr.includes("broker_connected"));
    h.send([event()]);
    const [code] = await child.exited;
    assert.equal(code, 1);
    assert.match(child.stderr, /Telegram API error 403/);
    assert.doesNotMatch(child.stderr, new RegExp(fakeToken));
    const box = new Outbox(
      h.state,
      JSON.stringify({ bot: "123456", chat: "42", api: h.apiBase }),
    );
    assert.match(box.peek().text, /Hello Telegram/);
    box.close();
    reject = false;
    const restarted = h.launch(["run", "--session", "demo-session"]);
    await until(() => restarted.stderr.includes('"telegram_message_id":7'));
    await stop(restarted);
  },
);

test(
  "dry-run needs no credentials, creates no queue, and makes no HTTP calls",
  { timeout: 10000 },
  async (t) => {
    const h = await harness(t);
    const child = h.launch(["run", "--dry-run", "--session", "demo-session"], {
      TELEGRAM_BOT_TOKEN: "",
      TELEGRAM_CHAT_ID: "",
    });
    await until(() => child.stderr.includes("broker_connected"));
    h.send([event()]);
    await until(() => child.stdout.includes("Hello Telegram"));
    await stop(child);
    assert.equal(h.requests.length, 0);
    await assert.rejects(access(h.state));
  },
);

test(
  "exclusive state lock rejects a second sender",
  { timeout: 10000 },
  async (t) => {
    const h = await harness(t);
    const first = h.launch();
    await until(() => first.stderr.includes("broker_connected"));
    const second = h.launch();
    const [code] = await second.exited;
    assert.equal(code, 1);
    assert.match(second.stderr, /locked by another relay/);
    await stop(first);
  },
);

test(
  "missing or blank credential variables fail before connecting, even with legacy files configured",
  { timeout: 10000 },
  async (t) => {
    const h = await harness(t);
    const tokenFile = join(h.dir, "telegram.token");
    const chatFile = join(h.dir, "chat-id");
    await writeFile(tokenFile, fakeToken);
    await writeFile(chatFile, "42");
    for (const [name, value] of [
      ["TELEGRAM_BOT_TOKEN", undefined],
      ["TELEGRAM_CHAT_ID", undefined],
      ["TELEGRAM_BOT_TOKEN", "  "],
      ["TELEGRAM_CHAT_ID", ""],
    ]) {
      const child = h.launch(["run"], {
        TELEGRAM_BOT_TOKEN_FILE: tokenFile,
        TELEGRAM_CHAT_ID_FILE: chatFile,
        [name]: value,
      });
      const [code] = await child.exited;
      assert.equal(code, 1, child.stderr);
      assert.match(
        child.stderr,
        new RegExp(`Set the ${name} environment variable`),
      );
      assert.doesNotMatch(child.stderr, new RegExp(fakeToken));
    }
    assert.equal(h.clients.size, 0);
    assert.equal(h.requests.length, 0);
    await assert.rejects(access(h.state));
  },
);

test(
  "chats discovers only private chats without consuming updates",
  { timeout: 10000 },
  async (t) => {
    const h = await harness(t, (path) => ({
      status: 200,
      body: {
        ok: true,
        result: path.endsWith("getMe")
          ? { id: 123456, username: "test_bot" }
          : [
              {
                message: {
                  chat: { id: -12, type: "group", title: "not private" },
                },
              },
              {
                message: {
                  chat: { id: 42, type: "private", first_name: "Demo" },
                },
              },
              {
                message: {
                  chat: { id: 42, type: "private", first_name: "Demo" },
                },
              },
            ],
      },
    }));
    const child = h.launch(["chats"], { TELEGRAM_CHAT_ID: undefined });
    const [code] = await child.exited;
    assert.equal(code, 0, child.stderr);
    assert.deepEqual(JSON.parse(child.stdout).chats, [
      { id: 42, first_name: "Demo" },
    ]);
    assert.equal(h.requests[1].payload.offset, undefined);
  },
);

test(
  "HTTP redirects are not followed; gateway errors and malformed responses retry",
  { timeout: 10000 },
  async (t) => {
    let status = 302;
    const h = await harness(t, () => ({
      status,
      headers: { location: "/leak" },
      body: { description: fakeToken },
    }));
    const client = new TelegramClient(fakeToken, h.apiBase);
    t.after(() => client.close());
    for (const [code, retryable] of [
      [302, false],
      [502, true],
      [200, true],
    ]) {
      status = code;
      await assert.rejects(
        client.send("42", "demo", new AbortController().signal),
        (error) => {
          assert.ok(error instanceof TelegramFailure);
          assert.equal(error.retryable, retryable);
          assert.doesNotMatch(error.message, new RegExp(fakeToken));
          return true;
        },
      );
    }
    assert.equal(h.requests.length, 3);
  },
);
