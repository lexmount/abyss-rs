/** Public Agent event contract carried by plugin protocol version 1. */

export interface AgentEvent {
  event_id: string;
  occurred_at: string;
  device: DeviceContext;
  agent: AgentContext;
  session_id: string;
  response_id?: string;
  previous_response_id?: string;
  /** Subagent the client declared in its request headers, verbatim. */
  subagent_id?: string;
  /** Subagent that spawned it; absent when the main agent spawned it. */
  parent_subagent_id?: string;
  /** Turn opened by input from outside the agent loop that this works for. */
  turn_id?: string;
  purpose?: EventPurpose;
  llm: LlmContext;
  side: AgentEventSide;
  /** Content categories the content policy omitted; absent when none were. */
  omitted?: ContentCategory[];
  /** The side's content, one entry per protocol block or item. */
  conversation?: Conversation;
  /** Captured headers of the event's side, credential values redacted. */
  headers?: HttpHeader[];
  token_usage: TokenUsage;
  attachments?: ImageAttachment[];
}

export type EventPurpose = "session_title" | "compaction" | "prewarm";

export type EntryRole =
  | "system"
  | "developer"
  | "user"
  | "assistant"
  | "reasoning"
  | "tool_call"
  | "tool_result"
  | "unknown";

export type ContentCompleteness = "complete" | "partial" | "unsupported";

export type ContentCategory =
  "token_usage" | "conversation_text" | "tool_content" | "images";

/** One protocol block or item, in provider order. */
export interface ConversationEntry {
  role: EntryRole;
  /** Visible text; a tool call's arguments or input, a tool result's output. */
  text: string;
  /** Pairs a tool call with its result; tool entries only. */
  call_id?: string;
  /** Tool name; tool calls only. */
  name?: string;
  /** Identity of the item the entry belongs to, as the traffic carries it. */
  item_id?: string;
}

export interface Conversation {
  entries: ConversationEntry[];
  completeness: ContentCompleteness;
}

/** One captured header; `value_base64` carries a value that is not UTF-8. */
export type HttpHeader =
  { name: string; value: string } | { name: string; value_base64: string };

export interface DeviceContext {
  host_name: string;
  platform: string;
  os_version?: string;
}

export interface AgentContext {
  name: string;
  version?: string;
}

export interface LlmContext {
  provider: string;
  model: string;
}

export type AgentEventSide = "request" | "response";

/**
 * Normalized non-negative token counters. Input, cache read, cache write, and
 * output counters are disjoint; `reasoning_tokens` is a breakdown of
 * `output_tokens` and `total_tokens` is the sum of the four disjoint counters.
 */
export interface TokenUsage {
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
  reasoning_tokens: number;
  total_tokens: number;
}

export type ImageMediaType =
  "image/png" | "image/jpeg" | "image/webp" | "image/gif";

export interface ImageAttachment {
  position: number;
  media_type: ImageMediaType;
  byte_size: number;
  sha256: string;
  content_base64?: string;
}

export function decodeAgentEvent(value: unknown): AgentEvent {
  const event = record(value, "AgentEvent");
  rejectUnknown(
    event,
    [
      "event_id",
      "occurred_at",
      "device",
      "agent",
      "session_id",
      "response_id",
      "previous_response_id",
      "subagent_id",
      "parent_subagent_id",
      "turn_id",
      "purpose",
      "llm",
      "side",
      "omitted",
      "conversation",
      "headers",
      "token_usage",
      "attachments",
    ],
    "AgentEvent",
  );
  stringField(event, "event_id");
  const occurredAt = stringField(event, "occurred_at");
  if (Number.isNaN(Date.parse(occurredAt))) {
    throw new TypeError("AgentEvent.occurred_at must be an RFC 3339 timestamp");
  }
  decodeDevice(event.device);
  decodeAgent(event.agent);
  stringField(event, "session_id");
  for (const field of [
    "response_id",
    "previous_response_id",
    "subagent_id",
    "parent_subagent_id",
    "turn_id",
  ]) {
    optionalStringField(event, field);
  }
  if (event.purpose !== undefined) {
    choiceField(event, "purpose", ["session_title", "compaction", "prewarm"]);
  }
  decodeLlm(event.llm);
  if (event.side !== "request" && event.side !== "response") {
    throw new TypeError("AgentEvent.side must be request or response");
  }
  optionalArray(event, "omitted").forEach((category, index) => {
    if (
      typeof category !== "string" ||
      !["token_usage", "conversation_text", "tool_content", "images"].includes(
        category,
      )
    ) {
      throw new TypeError(`omitted[${index}] is not a content category`);
    }
  });
  if (event.conversation !== undefined) {
    decodeConversation(event.conversation);
  }
  optionalArray(event, "headers").forEach(decodeHeader);
  decodeTokenUsage(event.token_usage);
  optionalArray(event, "attachments").forEach(decodeAttachment);
  return event as unknown as AgentEvent;
}

function decodeConversation(value: unknown): void {
  const conversation = record(value, "AgentEvent.conversation");
  rejectUnknown(conversation, ["entries", "completeness"], "conversation");
  if (!Array.isArray(conversation.entries)) {
    throw new TypeError("conversation.entries must be an array");
  }
  for (const value of conversation.entries) {
    const entry = record(value, "conversation.entries[]");
    rejectUnknown(
      entry,
      ["role", "text", "call_id", "name", "item_id"],
      "conversation entry",
    );
    choiceField(entry, "role", [
      "system",
      "developer",
      "user",
      "assistant",
      "reasoning",
      "tool_call",
      "tool_result",
      "unknown",
    ]);
    stringField(entry, "text");
    for (const field of ["call_id", "name", "item_id"]) {
      optionalStringField(entry, field);
    }
  }
  choiceField(conversation, "completeness", [
    "complete",
    "partial",
    "unsupported",
  ]);
}

function decodeHeader(value: unknown): void {
  const header = record(value, "AgentEvent.headers[]");
  rejectUnknown(header, ["name", "value", "value_base64"], "header");
  stringField(header, "name");
  optionalStringField(header, "value");
  optionalStringField(header, "value_base64");
  if ((header.value === undefined) === (header.value_base64 === undefined)) {
    throw new TypeError(
      "a header carries exactly one of value and value_base64",
    );
  }
}

function decodeDevice(value: unknown): void {
  const device = record(value, "AgentEvent.device");
  rejectUnknown(
    device,
    ["host_name", "platform", "os_version"],
    "AgentEvent.device",
  );
  stringField(device, "host_name");
  stringField(device, "platform");
  optionalStringField(device, "os_version");
}

function decodeAgent(value: unknown): void {
  const agent = record(value, "AgentEvent.agent");
  rejectUnknown(agent, ["name", "version"], "AgentEvent.agent");
  stringField(agent, "name");
  optionalStringField(agent, "version");
}

function decodeLlm(value: unknown): void {
  const llm = record(value, "AgentEvent.llm");
  rejectUnknown(llm, ["provider", "model"], "AgentEvent.llm");
  stringField(llm, "provider");
  stringField(llm, "model");
}

function decodeTokenUsage(value: unknown): void {
  const usage = record(value, "AgentEvent.token_usage");
  const fields = [
    "input_tokens",
    "output_tokens",
    "cache_read_tokens",
    "cache_write_tokens",
    "reasoning_tokens",
    "total_tokens",
  ];
  rejectUnknown(usage, fields, "AgentEvent.token_usage");
  for (const field of fields) {
    nonNegativeIntegerField(usage, field);
  }
}

function decodeAttachment(value: unknown): void {
  const attachment = record(value, "AgentEvent.attachments[]");
  rejectUnknown(
    attachment,
    ["position", "media_type", "byte_size", "sha256", "content_base64"],
    "attachment",
  );
  nonNegativeIntegerField(attachment, "position");
  const mediaType = stringField(attachment, "media_type");
  if (
    !["image/png", "image/jpeg", "image/webp", "image/gif"].includes(mediaType)
  ) {
    throw new TypeError(
      `unsupported AgentEvent attachment media type ${mediaType}`,
    );
  }
  nonNegativeIntegerField(attachment, "byte_size");
  stringField(attachment, "sha256");
  optionalStringField(attachment, "content_base64");
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function stringField(value: Record<string, unknown>, field: string): string {
  const fieldValue = value[field];
  if (typeof fieldValue !== "string") {
    throw new TypeError(`${field} must be a string`);
  }
  return fieldValue;
}

function optionalStringField(
  value: Record<string, unknown>,
  field: string,
): void {
  if (value[field] !== undefined) {
    stringField(value, field);
  }
}

function nonNegativeIntegerField(
  value: Record<string, unknown>,
  field: string,
): number {
  const fieldValue = value[field];
  if (
    typeof fieldValue !== "number" ||
    !Number.isSafeInteger(fieldValue) ||
    fieldValue < 0
  ) {
    throw new TypeError(`${field} must be a non-negative safe integer`);
  }
  return fieldValue;
}

function choiceField(
  value: Record<string, unknown>,
  field: string,
  choices: readonly string[],
): void {
  const fieldValue = stringField(value, field);
  if (!choices.includes(fieldValue)) {
    throw new TypeError(`${field} must be one of: ${choices.join(", ")}`);
  }
}

function optionalArray(
  value: Record<string, unknown>,
  field: string,
): unknown[] {
  const fieldValue = value[field];
  if (fieldValue === undefined) {
    return [];
  }
  if (!Array.isArray(fieldValue)) {
    throw new TypeError(`${field} must be an array`);
  }
  return fieldValue;
}

function rejectUnknown(
  value: Record<string, unknown>,
  allowed: readonly string[],
  label: string,
): void {
  const allowedFields = new Set(allowed);
  const unknown = Object.keys(value).filter(
    (field) => !allowedFields.has(field),
  );
  if (unknown.length !== 0) {
    throw new TypeError(
      `${label} contains unknown fields: ${unknown.sort().join(", ")}`,
    );
  }
}
