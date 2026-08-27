/** Public Agent event contract carried by plugin protocol version 1. */

export interface AgentEvent {
  event_id: string;
  occurred_at: string;
  device: DeviceContext;
  agent: AgentContext;
  session_id: string;
  turn_index: number;
  llm: LlmContext;
  side: AgentEventSide;
  text?: string;
  token_usage: TokenUsage;
  tool_calls?: ToolCall[];
  tool_results?: ToolResult[];
  attachments?: ImageAttachment[];
}

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

export interface TokenUsage {
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
  reasoning_tokens: number;
  total_tokens: number;
}

export interface ToolCall {
  call_id: string;
  name: string;
  input: string;
  input_sha256: string;
}

export interface ToolResult {
  call_id: string;
  output: string;
  output_sha256: string;
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
      "turn_index",
      "llm",
      "side",
      "text",
      "token_usage",
      "tool_calls",
      "tool_results",
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
  positiveIntegerField(event, "turn_index");
  decodeLlm(event.llm);
  if (event.side !== "request" && event.side !== "response") {
    throw new TypeError("AgentEvent.side must be request or response");
  }
  optionalStringField(event, "text");
  decodeTokenUsage(event.token_usage);
  optionalArray(event, "tool_calls").forEach(decodeToolCall);
  optionalArray(event, "tool_results").forEach(decodeToolResult);
  optionalArray(event, "attachments").forEach(decodeAttachment);
  return event as unknown as AgentEvent;
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

function decodeToolCall(value: unknown): void {
  const call = record(value, "AgentEvent.tool_calls[]");
  rejectUnknown(
    call,
    ["call_id", "name", "input", "input_sha256"],
    "tool call",
  );
  stringField(call, "call_id");
  stringField(call, "name");
  stringField(call, "input");
  stringField(call, "input_sha256");
}

function decodeToolResult(value: unknown): void {
  const result = record(value, "AgentEvent.tool_results[]");
  rejectUnknown(result, ["call_id", "output", "output_sha256"], "tool result");
  stringField(result, "call_id");
  stringField(result, "output");
  stringField(result, "output_sha256");
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

function positiveIntegerField(
  value: Record<string, unknown>,
  field: string,
): number {
  const fieldValue = nonNegativeIntegerField(value, field);
  if (fieldValue === 0) {
    throw new TypeError(`${field} must be greater than zero`);
  }
  return fieldValue;
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
