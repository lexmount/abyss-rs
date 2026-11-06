/** Complete request context supplied before provider forwarding. */
import type { Conversation, EventPurpose, ImageAttachment } from "../event.js";

export type RequestDecision =
  { allow: true } | { allow: false; reason: string };
export type RequestHandler = (
  context: AgentRequestContext,
) => RequestDecision | Promise<RequestDecision>;

export interface RequestSourceProcess {
  pid: number | null;
  pid_version: number | null;
  name: string | null;
  executable_path: string | null;
  application_id: string | null;
  entry_point: string | null;
  working_directory: string | null;
}

export interface RequestHarness {
  id: string;
  version: string | null;
  turn_id: string | null;
  subagent_id: string | null;
  parent_subagent_id: string | null;
  purpose: EventPurpose | null;
}

export interface AgentRequestProjection {
  protocol: string;
  provider: string;
  model: string | null;
  conversation: Conversation;
  attachments: ImageAttachment[];
  tools: unknown;
  previous_response_id: string | null;
}

export interface AgentRequestContext {
  flow_id: string;
  request_id: string;
  ingress: string;
  source_process: RequestSourceProcess | null;
  destination: string;
  destination_host: string | null;
  server_name: string | null;
  authority: string | null;
  proxy_endpoint: string | null;
  method: string;
  path: string;
  websocket: boolean;
  sequence: number;
  message_type: "text" | "binary" | null;
  /** Authorization, proxy credentials, cookies and provider API-key headers are omitted. */
  headers: [string, string][];
  body: { encoding: "utf8" | "base64"; content: string };
  json: unknown;
  parsing_status: "parsed" | "unknown_protocol" | "invalid_payload";
  harness: RequestHarness | null;
  agent: AgentRequestProjection | null;
}
