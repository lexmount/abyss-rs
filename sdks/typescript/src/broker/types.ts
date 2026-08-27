/** Stable request and response types from the broker REST contract. */

export interface HealthResponse {
  service: "abyss-broker";
  status: "ok";
}

export type ProxyLifecycle = "running" | "stopped";
export type ProxyMode = "explicit" | "transparent";
export type IngressSource =
  "explicit_http" | "macos_network_extension" | "windows_wfp";

export interface IngressStatus {
  source: IngressSource;
  listen_addr: string | null;
  socket_path?: string;
}

export interface ProxyStatus {
  lifecycle: ProxyLifecycle;
  process_id: number;
  mode: ProxyMode | null;
  ingresses: IngressStatus[];
  listen_addr: string | null;
  socket_path?: string;
}

export type TlsDecryptionAction = "intercept" | "passthrough";

export interface TlsDecryptionRule {
  id: string;
  enabled: boolean;
  action: TlsDecryptionAction;
  process_names?: string[];
  application_ids?: string[];
  destination_hosts: string[];
}

export interface TlsDecryptionPolicy {
  default_action: TlsDecryptionAction;
  missing_sni_action: TlsDecryptionAction | null;
  rules: TlsDecryptionRule[];
}

export interface MitmConfig {
  tls_decryption: TlsDecryptionPolicy;
}

export interface HarnessUsageContentConfig {
  token_usage: boolean;
  conversation_text: boolean;
  tool_calls: boolean;
  images: boolean;
}

export interface HarnessMatcherConfig {
  process_names?: string[];
  application_ids?: string[];
}

export interface HarnessConfig {
  enabled?: boolean;
  content?: HarnessUsageContentConfig;
  matchers?: HarnessMatcherConfig[];
}

export interface HarnessUsageConfig {
  content: HarnessUsageContentConfig;
  harnesses: Record<string, HarnessConfig>;
}

export interface HooksConfig {
  harness_usage: {
    enabled: boolean;
    config: HarnessUsageConfig;
  };
}

export interface BrokerLogRequest {
  max_bytes_per_file?: number;
}

export interface BrokerLogFile {
  name: string;
  content: string;
  truncated: boolean;
  original_size: number;
}

export interface BrokerLogError {
  name: string;
  error: string;
}

export interface BrokerLogResponse {
  files: BrokerLogFile[];
  errors: BrokerLogError[];
}

export interface ActiveFlow {
  id: string;
  host: string;
  process?: string;
  pid?: number;
  upload_bytes: number;
  download_bytes: number;
}

export interface TrafficSnapshot {
  sampled_at_unix_ms: number;
  upload_bytes_per_second: number;
  download_bytes_per_second: number;
  total_upload_bytes: number;
  total_download_bytes: number;
  active_flows: ActiveFlow[];
}

export interface DiagnosticsSnapshot {
  schema_version: number;
  collected_at_unix_ms: number;
  broker: Record<string, unknown>;
  proxy: ProxyStatus;
  flow: Record<string, unknown>;
}

export interface NetworkObservationsResponse {
  schema_version: 1;
  broker_started_at_unix_ms: number;
  observations: Record<string, unknown>[];
}
