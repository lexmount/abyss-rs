import assert from "node:assert/strict";
import { mkdtemp, rm, stat } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";
import { accepts, formatEvent, splitText } from "../dist/format.js";
import { Outbox } from "../dist/outbox.js";
import { event } from "./fixtures.mjs";

test("filters Codex and optionally an exact session", () => {
  assert.equal(accepts(event()), true);
  assert.equal(
    accepts(event({ agent: { name: "Codex" } }), "demo-session"),
    true,
  );
  assert.equal(accepts(event({ agent: { name: "claude_code" } })), false);
  assert.equal(accepts(event(), "another-session"), false);
});

test("Unicode chunks preserve content and stay within Telegram's limit", () => {
  const text = "🎉中文𝄞 <unsafe>& markdown_".repeat(1000);
  assert.equal(splitText(text, 7).join(""), text);
  assert.ok(
    splitText(text, 7).every((part) => part.isWellFormed() && part.length <= 7),
  );
  assert.throws(() => splitText(text, 1));
  const messages = formatEvent(event({ text }));
  assert.ok(messages.length > 1);
  assert.ok(
    messages.every((part) => part.length <= 4096 && part.isWellFormed()),
  );
  assert.ok(messages.every((part) => part.includes("Session: demo-session")));
  assert.equal(
    messages.map((part) => part.split(/Part \d+\/\d+\n\n/)[1]).join(""),
    `${text}\n\nTokens: input=1, output=1, total=2`,
  );
});

test("renders tool inputs/results and image metadata without base64", () => {
  const [message] = formatEvent(
    event({
      tool_calls: [
        {
          call_id: "c1",
          name: "exec",
          input: "echo demo",
          input_sha256: "sha",
        },
      ],
      tool_results: [{ call_id: "c1", output: "demo", output_sha256: "sha" }],
      attachments: [
        {
          position: 0,
          media_type: "image/png",
          byte_size: 100,
          sha256: "sha",
          content_base64: "SECRET_IMAGE",
        },
      ],
    }),
  );
  assert.match(message, /Tool call: exec/);
  assert.match(message, /Tool result: c1/);
  assert.match(message, /image\/png, 100 bytes/);
  assert.doesNotMatch(message, /SECRET_IMAGE|final answer/i);
});

async function directory(t) {
  const dir = await mkdtemp("/tmp/abyss-outbox-");
  t.after(() => rm(dir, { force: true, recursive: true }));
  return dir;
}

test("outbox checkpoints chunks across restarts, deduplicates, and preserves FIFO retries", async (t) => {
  const dir = await directory(t);
  let box = new Outbox(dir, "bot/chat");
  assert.equal(box.enqueue("one", ["first", "second"]), true);
  box.enqueue("two", ["third"]);
  assert.equal(box.enqueue("one", ["duplicate"]), false);
  box.acknowledge(box.peek());
  box.retry(box.peek(), 123456);
  box.close();
  box = new Outbox(dir, "bot/chat");
  t.after(() => box.close());
  assert.deepEqual(box.peek(), {
    eventId: "one",
    chunk: 1,
    text: "second",
    attempts: 1,
    retryAt: 123456,
  });
  box.acknowledge(box.peek());
  assert.equal(box.peek().text, "third");
  box.acknowledge(box.peek());
  assert.equal(box.peek(), undefined);
  assert.equal(box.enqueue("one", ["duplicate after delivery"]), false);
  assert.equal((await stat(join(dir, "outbox.sqlite"))).mode & 0o777, 0o600);
  assert.equal((await stat(dir)).mode & 0o777, 0o700);
});

test("queue refuses cross-destination replay and bounded capacity overflow", async (t) => {
  const dir = await directory(t);
  const box = new Outbox(dir, "a", { bytes: 30, events: 2 });
  box.enqueue("one", ["small"]);
  assert.throws(
    () => box.enqueue("two", ["x".repeat(100)]),
    /capacity exceeded/,
  );
  box.enqueue("two", ["small"]);
  assert.throws(() => box.enqueue("three", ["small"]), /capacity exceeded/);
  box.close();
  assert.throws(() => new Outbox(dir, "b"), /destination mismatch/);
  const reopened = new Outbox(dir, "a");
  assert.equal(reopened.peek().text, "small");
  reopened.close();
});
