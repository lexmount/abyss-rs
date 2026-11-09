/** Real-Codex SDK participant. Emit only sanitized test evidence. */
import { appendFileSync } from "node:fs";
import { BrokerPlugin } from "../dist/plugin/index.js";

const allowMarker = process.env.ABYSS_SDK_CODEX_ALLOW_MARKER;
const blockMarker = process.env.ABYSS_SDK_CODEX_BLOCK_MARKER;
const record = (value) =>
  appendFileSync(
    process.env.ABYSS_SDK_CODEX_EVIDENCE,
    JSON.stringify(value) + "\n",
  );
const contains = (conversation, marker) =>
  conversation?.entries.some((entry) => entry.text.includes(marker)) ?? false;

const close = await new BrokerPlugin({
  consumerId: "blackbox.codex.typescript",
  endpoint: process.env.ABYSS_SDK_CODEX_ENDPOINT,
  agentEvents: true,
  onAgentRequest(context) {
    if (context.path === "/__abyss_sdk_ready") record({ kind: "ready" });
    const blocked = contains(context.agent?.conversation, blockMarker);
    for (const [scenario, marker] of [
      ["allow", allowMarker],
      ["block", blockMarker],
    ]) {
      if (!context.body.content.includes(marker)) continue;
      record({
        kind: "inspection",
        case: scenario,
        request_id: context.request_id,
        harness: context.harness?.id,
        host: context.destination_host,
        server_name: context.server_name,
        source_process_absent: context.source_process === null,
        parsing_status: context.parsing_status,
        model: context.agent?.model,
        protocol: context.agent?.protocol,
        agent_has_marker: contains(context.agent?.conversation, marker),
        json_has_marker: JSON.stringify(context.json).includes(marker),
        credential_headers_absent: !context.headers.some(([name]) =>
          [
            "authorization",
            "proxy-authorization",
            "cookie",
            "x-api-key",
          ].includes(name.toLowerCase()),
        ),
        allow: !blocked,
      });
    }
    return blocked
      ? { allow: false, reason: "SDK black-box policy" }
      : { allow: true };
  },
}).run((event) =>
  record({
    kind: "event",
    side: event.side,
    agent: event.agent.name,
    response_id: event.response_id,
    session_id: event.session_id,
    model: event.llm.model,
    provider: event.llm.provider,
    allow_marker: contains(event.conversation, allowMarker),
    block_marker: contains(event.conversation, blockMarker),
    token_usage: event.token_usage,
  }),
);
if (close.code !== 100)
  throw new Error("broker did not close the SDK session cleanly");
