/** Complete request context supplied before provider forwarding. */
import type { Conversation, EventPurpose, ImageAttachment } from "../event.js";

export type ModifyAction =
  | { readonly op: "set_auth_token"; readonly value: string }
  | { readonly op: "remove_auth_token" }
  | { readonly op: "set_model"; readonly value: string }
  | { readonly op: "remove_model" }
  | { readonly op: "set_base_url"; readonly value: string };

export type RequestDecision =
  | { readonly action: "allow" }
  | { readonly action: "block"; readonly reason: string }
  | { readonly action: "modify"; readonly actions: readonly ModifyAction[] };
export type RequestHandler = (
  context: AgentRequestContext,
) => RequestDecision | Promise<RequestDecision>;

export interface RequestSourceProcess {
  readonly pid: number | null;
  readonly pid_version: number | null;
  readonly name: string | null;
  readonly executable_path: string | null;
  readonly application_id: string | null;
  readonly entry_point: string | null;
  readonly working_directory: string | null;
}

export interface RequestHarness {
  readonly id: string;
  readonly version: string | null;
  readonly turn_id: string | null;
  readonly subagent_id: string | null;
  readonly parent_subagent_id: string | null;
  readonly purpose: EventPurpose | null;
}

export interface AgentRequestProjection {
  readonly protocol: string;
  readonly provider: string;
  readonly model: string | null;
  readonly conversation: Conversation;
  readonly attachments: readonly ImageAttachment[];
  readonly tools: unknown;
  readonly previous_response_id: string | null;
}

export interface AgentRequestContext {
  readonly flow_id: string;
  readonly request_id: string;
  readonly ingress: string;
  readonly source_process: RequestSourceProcess | null;
  readonly destination: string;
  readonly destination_host: string | null;
  readonly server_name: string | null;
  readonly authority: string | null;
  readonly proxy_endpoint: string | null;
  readonly method: string;
  readonly path: string;
  readonly websocket: boolean;
  readonly sequence: number;
  readonly message_type: "text" | "binary" | null;
  /** Authorization, proxy credentials, cookies and provider API-key headers are omitted. */
  readonly headers: readonly (readonly [string, string])[];
  readonly body: {
    readonly encoding: "utf8" | "base64";
    readonly content: string;
  };
  readonly json: unknown;
  readonly parsing_status: "parsed" | "unknown_protocol" | "invalid_payload";
  readonly harness: RequestHarness | null;
  readonly auth_token: string | null;
  readonly auth_token_writable: boolean;
  readonly model_writable: boolean;
  readonly base_url: string | null;
  readonly base_url_writable: boolean;
  readonly agent: AgentRequestProjection | null;
}
