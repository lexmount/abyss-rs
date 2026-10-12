/** Plain-text event rendering; no Telegram markup or inline attachment payloads. */
import type { AgentEvent } from "@lexmount/abyss-sdk/plugin";

export function accepts(event: AgentEvent, sessionId?: string): boolean {
  return (
    event.agent.name.toLowerCase() === "codex" &&
    (sessionId === undefined || event.session_id === sessionId)
  );
}

export function formatEvent(event: AgentEvent): string[] {
  const sections: string[] = [];
  if (event.text) sections.push(event.text);
  for (const call of event.tool_calls ?? []) {
    sections.push(
      `Tool call: ${call.name}\nID: ${call.call_id}\n${call.input}`,
    );
  }
  for (const result of event.tool_results ?? []) {
    sections.push(`Tool result: ${result.call_id}\n${result.output}`);
  }
  for (const attachment of event.attachments ?? []) {
    sections.push(
      `Image ${attachment.position}: ${attachment.media_type}, ${attachment.byte_size} bytes\nSHA256: ${attachment.sha256}`,
    );
  }
  if (sections.length === 0)
    sections.push(
      "(No text/tool content in this event; check broker content policy.)",
    );
  const usage = event.token_usage;
  if (usage.total_tokens > 0)
    sections.push(
      `Tokens: input=${usage.input_tokens}, output=${usage.output_tokens}, total=${usage.total_tokens}`,
    );
  const header = `Codex · ${event.side} · turn ${event.turn_index}\nSession: ${label(event.session_id)}\nModel: ${label(event.llm.model)}\nEvent: ${label(event.event_id)}\n${label(event.occurred_at)}`;
  const chunks = splitText(sections.join("\n\n"), 3500 - header.length);
  return chunks.map(
    (chunk, index) =>
      `${header}\nPart ${index + 1}/${chunks.length}\n\n${chunk}`,
  );
}

function label(value: string): string {
  return Array.from(value.replace(/[\r\n\t]/g, " "))
    .slice(0, 160)
    .join("");
}

/** Splits at UTF-16 boundaries conservatively, without cutting surrogate pairs. */
export function splitText(text: string, maxUnits: number): string[] {
  if (!Number.isInteger(maxUnits) || maxUnits < 2)
    throw new Error("Chunk size must be at least two.");
  const chunks: string[] = [];
  let start = 0;
  while (start < text.length) {
    let end = Math.min(start + maxUnits, text.length);
    const last = text.charCodeAt(end - 1);
    if (end < text.length && last >= 0xd800 && last <= 0xdbff) end--;
    chunks.push(text.slice(start, end));
    start = end;
  }
  return chunks.length ? chunks : [""];
}
