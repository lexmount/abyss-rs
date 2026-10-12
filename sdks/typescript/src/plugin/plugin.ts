/** High-level broker plugin handshake and typed event stream. */

import type { Socket } from "node:net";

import { decodeAgentEvent, type AgentEvent } from "../event.js";
import {
  BrokerPluginError,
  HandshakeRejectedError,
  UnexpectedBrokerEofError,
} from "./errors.js";
import { readJsonFrames, writeJsonFrame } from "./framing.js";
import { connectPluginStream, resolvePluginEndpoint } from "./transport.js";

export interface BrokerPluginOptions {
  consumerId: string;
  endpoint?: string;
}

export interface BrokerClose {
  code: number;
  reason: string;
}

export interface PluginConnectOptions {
  /** Cancels connection setup and closes the established event stream. */
  signal?: AbortSignal;
  /** Optional deadline for endpoint discovery, connection, and handshake. */
  timeoutMs?: number;
}

interface BrokerHello {
  protocol_version: number;
}

export class PluginConnection implements AsyncIterable<AgentEvent> {
  readonly #socket: Socket;
  readonly #frames: AsyncIterator<unknown>;
  #close: BrokerClose | undefined;
  #finished = false;

  constructor(socket: Socket, frames: AsyncIterator<unknown>) {
    this.#socket = socket;
    this.#frames = frames;
  }

  get close(): BrokerClose | undefined {
    return this.#close;
  }

  closeConnection(): void {
    if (!this.#finished) {
      this.#finished = true;
      this.#socket.destroy();
    }
  }

  async nextEvent(): Promise<AgentEvent | undefined> {
    if (this.#finished) {
      return undefined;
    }
    const next = await this.#frames.next();
    if (next.done) {
      this.#finished = true;
      throw new UnexpectedBrokerEofError();
    }
    if (isBrokerClose(next.value)) {
      this.#close = next.value;
      this.#finished = true;
      this.#socket.end();
      return undefined;
    }
    return decodeAgentEvent(next.value);
  }

  async *[Symbol.asyncIterator](): AsyncGenerator<AgentEvent> {
    while (true) {
      const event = await this.nextEvent();
      if (event === undefined) {
        return;
      }
      yield event;
    }
  }
}

export class BrokerPlugin {
  readonly #consumerId: string;
  readonly #endpoint: string | undefined;

  constructor(options: BrokerPluginOptions) {
    if (!/^[a-zA-Z0-9._-]{1,128}$/.test(options.consumerId)) {
      throw new TypeError(
        "consumerId must contain 1-128 ASCII letters, digits, dots, underscores, or hyphens",
      );
    }
    this.#consumerId = options.consumerId;
    this.#endpoint = options.endpoint;
  }

  async connect(options: PluginConnectOptions = {}): Promise<PluginConnection> {
    if (
      options.timeoutMs !== undefined &&
      (!Number.isSafeInteger(options.timeoutMs) || options.timeoutMs < 1)
    ) {
      throw new TypeError("timeoutMs must be a positive safe integer");
    }
    options.signal?.throwIfAborted();
    const deadline = new AbortController();
    const timer =
      options.timeoutMs === undefined
        ? undefined
        : setTimeout(
            () =>
              deadline.abort(new Error("broker plugin handshake timed out")),
            options.timeoutMs,
          );
    const signal =
      options.signal === undefined
        ? deadline.signal
        : AbortSignal.any([options.signal, deadline.signal]);
    let socket: Socket | undefined;
    try {
      const endpoint = await resolvePluginEndpoint(this.#endpoint);
      socket = await connectPluginStream(endpoint, signal);
      const frames = readJsonFrames(socket)[Symbol.asyncIterator]();
      await writeJsonFrame(socket, {
        protocol_version: 1,
        plugin_id: this.#consumerId,
      });
      const response = await frames.next();
      if (response.done) {
        throw new UnexpectedBrokerEofError();
      }
      if (isBrokerError(response.value)) {
        throw new HandshakeRejectedError(
          response.value.code,
          response.value.reason,
        );
      }
      const hello = response.value as Partial<BrokerHello>;
      if (hello.protocol_version !== 1) {
        throw new BrokerPluginError(
          "broker returned an invalid handshake response",
        );
      }
      return new PluginConnection(socket, frames);
    } catch (error) {
      socket?.destroy();
      throw error;
    } finally {
      clearTimeout(timer);
    }
  }

  async run(
    handler: (event: AgentEvent) => void | Promise<void>,
  ): Promise<BrokerClose> {
    const connection = await this.connect();
    try {
      for await (const event of connection) {
        await handler(event);
      }
      if (connection.close === undefined) {
        throw new UnexpectedBrokerEofError();
      }
      return connection.close;
    } finally {
      connection.closeConnection();
    }
  }
}

function isBrokerError(value: unknown): value is BrokerClose {
  return isBrokerClose(value);
}

function isBrokerClose(value: unknown): value is BrokerClose {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const candidate = value as Record<string, unknown>;
  return (
    typeof candidate.code === "number" && typeof candidate.reason === "string"
  );
}
