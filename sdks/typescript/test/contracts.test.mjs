import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { decodeAgentEvent } from "../dist/event.js";
import { BrokerClient } from "../dist/index.js";

const fixtureUrl = new URL(
  "../../../specs/broker-plugin-protocol/v1/fixtures/agent-event.json",
  import.meta.url,
);

test("shared AgentEvent fixture decodes through the TypeScript SDK", async () => {
  const fixture = JSON.parse(await readFile(fixtureUrl, "utf8"));
  const event = decodeAgentEvent(fixture);

  assert.equal(event.event_id, "evt-123");
  assert.equal(event.llm.provider, "openai");
  assert.equal(event.tool_calls[0].name, "exec");
});

test("AgentEvent decoder rejects invalid counters and unknown sides", () => {
  const base = {
    event_id: "evt-test",
    occurred_at: "2026-08-19T10:00:00Z",
    device: { host_name: "host", platform: "linux" },
    agent: { name: "codex" },
    session_id: "session",
    turn_index: 1,
    llm: { provider: "openai", model: "gpt-test" },
    side: "request",
    token_usage: {
      input_tokens: 1,
      output_tokens: 0,
      cache_read_tokens: 0,
      cache_write_tokens: 0,
      reasoning_tokens: 0,
      total_tokens: 1,
    },
  };

  assert.throws(
    () => decodeAgentEvent({ ...base, side: "unknown" }),
    /side must be request or response/,
  );
  assert.throws(
    () =>
      decodeAgentEvent({
        ...base,
        token_usage: { ...base.token_usage, input_tokens: -1 },
      }),
    /non-negative safe integer/,
  );
  assert.throws(
    () => decodeAgentEvent({ ...base, metadata: { private: true } }),
    /unknown fields: metadata/,
  );
});

test("BrokerClient rejects URLs outside the loopback HTTP boundary", () => {
  assert.throws(
    () => new BrokerClient({ baseUrl: "http://example.com:18190" }),
    /HTTP and a loopback host/,
  );
  assert.throws(
    () => new BrokerClient({ baseUrl: "https://127.0.0.1:18190" }),
    /HTTP and a loopback host/,
  );
});
