import assert from "node:assert/strict";
import { PassThrough } from "node:stream";
import test from "node:test";

import { readJsonFrames, writeJsonFrame } from "../dist/plugin/framing.js";

test("v1 carries JSON frames above the former 16 MiB limit", async () => {
  const stream = new PassThrough();
  const frames = readJsonFrames(stream);
  const received = frames.next();
  const text = "x".repeat(16 * 1024 * 1024 + 1);
  await writeJsonFrame(stream, { text });
  stream.end();
  assert.equal((await received).value.text, text);
  assert.equal((await frames.next()).done, true);
});

test("v1 rejects a frame above 64 MiB before reading its body", async () => {
  const stream = new PassThrough();
  const header = Buffer.alloc(4);
  header.writeUInt32BE(64 * 1024 * 1024 + 1);
  stream.end(header);
  await assert.rejects(
    readJsonFrames(stream).next(),
    /exceeds maximum 67108864/,
  );
});
