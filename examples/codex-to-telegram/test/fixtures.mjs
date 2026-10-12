export function event(overrides = {}) {
  return {
    event_id: "event-1",
    occurred_at: "2026-10-12T10:00:00Z",
    device: { host_name: "demo", platform: "linux" },
    agent: { name: "codex" },
    session_id: "demo-session",
    turn_index: 1,
    llm: { provider: "openai", model: "demo-model" },
    side: "response",
    text: "Hello Telegram",
    token_usage: {
      input_tokens: 1,
      output_tokens: 1,
      total_tokens: 2,
      reasoning_tokens: 0,
      cache_read_tokens: 0,
      cache_write_tokens: 0,
    },
    ...overrides,
  };
}

export function frame(value) {
  const body = Buffer.from(JSON.stringify(value));
  const header = Buffer.alloc(4);
  header.writeUInt32BE(body.length);
  return Buffer.concat([header, body]);
}
