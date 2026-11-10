/** High-level broker plugin handshake and typed event stream. */

import type { AgentRequestContext, RequestHandler } from "./inspection.js";

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
  onAgentRequest?: RequestHandler;
  agentEvents?: boolean;
}

export interface BrokerClose {
  code: number;
  reason: string;
}

interface BrokerHello {
  type: "broker_hello";
  protocol_version: number;
}

export class PluginConnection implements AsyncIterable<AgentEvent> {
  readonly #socket: Socket;
  readonly #frames: AsyncIterator<unknown>;
  readonly #inspect: RequestHandler | undefined;
  #close: BrokerClose | undefined;
  #finished = false;

  constructor(
    socket: Socket,
    frames: AsyncIterator<unknown>,
    inspect?: RequestHandler,
  ) {
    this.#socket = socket;
    this.#frames = frames;
    this.#inspect = inspect;
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
    try {
      while (true) {
        const next = await this.#frames.next();
        if (next.done) throw new UnexpectedBrokerEofError();
        if (isBrokerClose(next.value)) {
          this.#close = next.value;
          this.#finished = true;
          this.#socket.end();
          return undefined;
        }
        const frame = next.value as {
          type: string;
          event?: unknown;
          context: AgentRequestContext;
        };
        if (frame.type === "agent_event") return decodeAgentEvent(frame.event);
        if (frame.type !== "inspect_request" || this.#inspect === undefined) {
          throw new BrokerPluginError("unexpected broker session message");
        }
        const decision = await this.#inspect(frame.context);
        await writeJsonFrame(this.#socket, {
          type: "inspect_response",
          request_id: frame.context.request_id,
          decision,
        });
      }
    } catch (error) {
      this.closeConnection();
      throw error;
    }
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
  readonly #inspect: RequestHandler | undefined;
  readonly #events: boolean;

  constructor(options: BrokerPluginOptions) {
    if (!/^[a-zA-Z0-9._-]{1,128}$/.test(options.consumerId)) {
      throw new TypeError(
        "consumerId must contain 1-128 ASCII letters, digits, dots, underscores, or hyphens",
      );
    }
    this.#consumerId = options.consumerId;
    this.#endpoint = options.endpoint;
    this.#inspect = options.onAgentRequest;
    this.#events = options.agentEvents ?? true;
  }

  async connect(): Promise<PluginConnection> {
    const endpoint = await resolvePluginEndpoint(this.#endpoint);
    const socket = await connectPluginStream(endpoint);
    const frames = readJsonFrames(socket)[Symbol.asyncIterator]();
    try {
      await writeJsonFrame(socket, {
        type: "plugin_hello",
        capabilities: [
          ...(this.#events ? ["agent_events"] : []),
          ...(this.#inspect === undefined ? [] : ["agent_request"]),
        ],
        protocol_version: 2,
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
      if (hello.type !== "broker_hello" || hello.protocol_version !== 2) {
        throw new BrokerPluginError(
          "broker returned an invalid handshake response",
        );
      }
      return new PluginConnection(socket, frames, this.#inspect);
    } catch (error) {
      socket.destroy();
      throw error;
    }
  }

  async run(
    handler: (event: AgentEvent) => void | Promise<void> = () => {},
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
  return isControl(value, "broker_error");
}

function isBrokerClose(value: unknown): value is BrokerClose {
  return isControl(value, "broker_close");
}

function isControl(value: unknown, type: string): value is BrokerClose {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const candidate = value as Record<string, unknown>;
  return (
    candidate.type === type &&
    typeof candidate.code === "number" &&
    typeof candidate.reason === "string"
  );
}
