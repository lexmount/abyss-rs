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
  assert.equal(event.response_id, "resp-123");
  assert.equal(event.previous_response_id, "resp-122");
  assert.equal(event.subagent_id, "agent-2");
  assert.equal(event.parent_subagent_id, "agent-1");
  assert.equal(event.turn_id, "turn-1");
  assert.equal(event.purpose, "session_title");
  assert.deepEqual(event.conversation, fixture.conversation);
  assert.equal(event.path, "/v1/responses");
  assert.deepEqual(event.headers, fixture.headers);
  assert.equal("turn_index" in event, false);
});

test("undeclared context and entry identities may be omitted", async () => {
  const fixture = JSON.parse(await readFile(fixtureUrl, "utf8"));
  for (const field of [
    "response_id",
    "previous_response_id",
    "subagent_id",
    "parent_subagent_id",
    "turn_id",
    "purpose",
    "conversation",
    "headers",
  ]) {
    delete fixture[field];
  }
  assert.equal(decodeAgentEvent(fixture).response_id, undefined);
  assert.equal(decodeAgentEvent(fixture).subagent_id, undefined);
  assert.equal(decodeAgentEvent(fixture).headers, undefined);
  fixture.purpose = "compaction";
  fixture.omitted = ["conversation_text"];
  fixture.conversation = {
    entries: [{ role: "unknown", text: "" }],
    completeness: "partial",
  };
  const event = decodeAgentEvent(fixture);
  assert.deepEqual(event.conversation, fixture.conversation);
  assert.deepEqual(event.omitted, ["conversation_text"]);
});

test("explicit prewarm retains its observed usage in v1", async () => {
  const fixture = JSON.parse(await readFile(fixtureUrl, "utf8"));
  fixture.purpose = "prewarm";
  const event = decodeAgentEvent(fixture);
  assert.equal(event.purpose, "prewarm");
  assert.deepEqual(event.token_usage, fixture.token_usage);
});

test("structured events reject obsolete fields and malformed content", async () => {
  const original = JSON.parse(await readFile(fixtureUrl, "utf8"));
  for (const mutate of [
    (e) => {
      e.turn_index = 1;
    },
    (e) => {
      e.text = "hello";
    },
    (e) => {
      e.tool_calls = [];
    },
    (e) => {
      e.tool_results = [];
    },
    (e) => {
      e.naming_thread = true;
    },
    (e) => {
      e.stream_id = "thread-1";
    },
    (e) => {
      e.session_title = "title";
    },
    (e) => {
      e.purpose = "other";
    },
    (e) => {
      e.omitted = ["text"];
    },
    (e) => {
      e.conversation.entries[0].role = "tool";
    },
    (e) => {
      e.conversation.entries[0].blocks = [];
    },
    (e) => {
      e.conversation.entries[0].text = 1;
    },
    (e) => {
      e.conversation.entries[0].item_id = 1;
    },
    (e) => {
      e.conversation.entries = {};
    },
    (e) => {
      e.conversation.completeness = "failed";
    },
    (e) => {
      e.conversation.messages = [];
    },
    (e) => {
      e.conversation.instructions_present = true;
    },
    (e) => {
      e.conversation.policy_omitted = false;
    },
    (e) => {
      e.headers[0].value = 1;
    },
    (e) => {
      e.headers[0].value_base64 = "dg==";
    },
    (e) => {
      delete e.headers[0].value;
    },
    (e) => {
      e.headers[0].raw = true;
    },
  ]) {
    const fixture = structuredClone(original);
    mutate(fixture);
    assert.throws(() => decodeAgentEvent(fixture), TypeError);
  }
});

test("AgentEvent decoder rejects invalid counters and unknown sides", () => {
  const base = {
    event_id: "evt-test",
    occurred_at: "2026-08-19T10:00:00Z",
    device: { host_name: "host", platform: "linux" },
    agent: { name: "codex" },
    session_id: "session",
    llm: { provider: "openai", model: "gpt-test" },
    side: "request",
    path: "/v1/responses",
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
