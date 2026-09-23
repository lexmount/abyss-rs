/** Node.js client for the loopback broker REST management API. */

import { readFile } from "node:fs/promises";
import { isIP } from "node:net";

import type {
  BrokerLogRequest,
  BrokerLogResponse,
  DiagnosticsSnapshot,
  HealthResponse,
  HooksConfig,
  MitmConfig,
  NetworkObservationsResponse,
  ProxyStatus,
  TrafficSnapshot,
} from "./types.js";

const DEFAULT_TIMEOUT_MS = 10_000;
const MAX_ERROR_BODY_CHARS = 16 * 1024;

export interface BrokerClientOptions {
  baseUrl: string;
  bearerToken?: string;
  timeoutMs?: number;
}

interface StartupInfo {
  api_addr: string;
  auth_token_file: string;
}

export class BrokerApiError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(`broker REST request failed with HTTP ${status}: ${message}`);
    this.name = "BrokerApiError";
    this.status = status;
  }
}

export class BrokerClient {
  readonly #baseUrl: URL;
  readonly #bearerToken: string | undefined;
  readonly #timeoutMs: number;

  constructor(options: BrokerClientOptions) {
    this.#baseUrl = normalizedBaseUrl(options.baseUrl);
    this.#bearerToken = options.bearerToken;
    this.#timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    if (!Number.isSafeInteger(this.#timeoutMs) || this.#timeoutMs <= 0) {
      throw new TypeError("timeoutMs must be a positive safe integer");
    }
  }

  static async fromStartupInfo(path: string): Promise<BrokerClient> {
    const startup = JSON.parse(await readFile(path, "utf8")) as StartupInfo;
    if (
      typeof startup.api_addr !== "string" ||
      typeof startup.auth_token_file !== "string"
    ) {
      throw new TypeError(
        "broker startup info is missing REST discovery fields",
      );
    }
    const token = (await readFile(startup.auth_token_file, "utf8")).trim();
    return new BrokerClient({
      baseUrl: `http://${startup.api_addr}`,
      bearerToken: token,
    });
  }

  getHealth(): Promise<HealthResponse> {
    return this.#request("healthz", { protected: false });
  }

  getProxyStatus(): Promise<ProxyStatus> {
    return this.#request("v1/proxy/status", { protected: false });
  }

  getMitmConfig(): Promise<MitmConfig> {
    return this.#request("v1/mitm/config");
  }

  updateMitmConfig(config: MitmConfig): Promise<MitmConfig> {
    return this.#request("v1/mitm/config", { method: "PUT", body: config });
  }

  getHooksConfig(): Promise<HooksConfig> {
    return this.#request("v1/hooks/config");
  }

  updateHooksConfig(config: HooksConfig): Promise<HooksConfig> {
    return this.#request("v1/hooks/config", { method: "PUT", body: config });
  }

  collectBrokerLogs(
    request: BrokerLogRequest = {},
  ): Promise<BrokerLogResponse> {
    return this.#request("v1/support/logs/broker", {
      method: "POST",
      body: request,
    });
  }

  getDiagnostics(): Promise<DiagnosticsSnapshot> {
    return this.#request("v1/support/diagnostics");
  }

  getNetworkObservations(limit?: number): Promise<NetworkObservationsResponse> {
    if (
      limit !== undefined &&
      (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000)
    ) {
      throw new TypeError(
        "network observation limit must be between 1 and 1000",
      );
    }
    const query = limit === undefined ? "" : `?limit=${limit}`;
    return this.#request(`v1/network/observations${query}`);
  }

  getTrafficSnapshot(): Promise<TrafficSnapshot> {
    return this.#request("v1/traffic/snapshot");
  }

  shutdown(): Promise<ProxyStatus> {
    return this.#request("v1/broker/shutdown", { method: "POST" });
  }

  async #request<T>(
    path: string,
    options: {
      protected?: boolean;
      method?: "GET" | "POST" | "PUT";
      body?: unknown;
    } = {},
  ): Promise<T> {
    const protectedRoute = options.protected ?? true;
    const headers = new Headers({ Accept: "application/json" });
    if (protectedRoute && this.#bearerToken !== undefined) {
      headers.set("Authorization", `Bearer ${this.#bearerToken}`);
    }
    let body: string | undefined;
    if (options.body !== undefined) {
      headers.set("Content-Type", "application/json");
      body = JSON.stringify(options.body);
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.#timeoutMs);
    try {
      const request: RequestInit = {
        method: options.method ?? "GET",
        headers,
        signal: controller.signal,
      };
      if (body !== undefined) {
        request.body = body;
      }
      const response = await fetch(new URL(path, this.#baseUrl), request);
      if (!response.ok) {
        const text = (await response.text()).slice(0, MAX_ERROR_BODY_CHARS);
        let message = text;
        try {
          const parsed = JSON.parse(text) as { error?: unknown };
          if (typeof parsed.error === "string") {
            message = parsed.error;
          }
        } catch {
          // Preserve a non-JSON response as diagnostic context.
        }
        throw new BrokerApiError(response.status, message);
      }
      return (await response.json()) as T;
    } finally {
      clearTimeout(timer);
    }
  }
}

function normalizedBaseUrl(baseUrl: string): URL {
  const value = baseUrl.trim();
  if (value.length === 0) {
    throw new TypeError("baseUrl must not be empty");
  }
  const url = new URL(value.endsWith("/") ? value : `${value}/`);
  if (url.protocol !== "http:" || !isLoopbackHost(url.hostname)) {
    throw new TypeError("baseUrl must use HTTP and a loopback host");
  }
  return url;
}

function isLoopbackHost(hostname: string): boolean {
  if (hostname.toLowerCase() === "localhost") {
    return true;
  }
  const normalized = hostname.startsWith("[")
    ? hostname.slice(1, -1)
    : hostname;
  const addressFamily = isIP(normalized);
  return (
    (addressFamily === 4 && normalized.startsWith("127.")) ||
    (addressFamily === 6 && normalized === "::1")
  );
}
