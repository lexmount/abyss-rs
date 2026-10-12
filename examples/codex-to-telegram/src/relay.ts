/** Independent broker receiver and Telegram sender, joined by a durable outbox. */
import { setTimeout as delay } from "node:timers/promises";
import {
  BrokerPlugin,
  HandshakeRejectedError,
  type PluginConnection,
} from "@lexmount/abyss-sdk/plugin";
import type { Config } from "./config.js";
import { accepts, formatEvent } from "./format.js";
import { Outbox, OutboxError } from "./outbox.js";
import { TelegramClient, TelegramFailure } from "./telegram.js";

export type Log = (event: string, details?: Record<string, unknown>) => void;

export async function receive(
  config: Config,
  outbox: Outbox | undefined,
  signal: AbortSignal,
  log: Log,
): Promise<void> {
  const plugin = new BrokerPlugin({
    consumerId: "example.codex-telegram",
    ...(config.endpoint ? { endpoint: config.endpoint } : {}),
  });
  let failures = 0;
  while (!signal.aborted) {
    let connection: PluginConnection | undefined;
    try {
      connection = await plugin.connect({ signal, timeoutMs: 10000 });
      log("broker_connected");
      for await (const event of connection) {
        failures = 0;
        if (!accepts(event, config.sessionId)) continue;
        const chunks = formatEvent(event);
        if (outbox) {
          if (outbox.enqueue(event.event_id, chunks))
            log("queued", { event_id: event.event_id, chunks: chunks.length });
        } else {
          for (const text of chunks) process.stdout.write(`${text}\n\n`);
        }
      }
    } catch (error) {
      if (signal.aborted) return;
      if (
        error instanceof OutboxError ||
        error instanceof HandshakeRejectedError
      )
        throw error;
      // SDK errors may include local paths or arbitrary broker diagnostics: log only the category.
      log("broker_disconnected", {
        error: error instanceof Error ? error.name : "Error",
      });
    } finally {
      connection?.closeConnection();
    }
    const wait = Math.min(30000, 500 * 2 ** Math.min(failures++, 6));
    log("broker_reconnect", {
      delay_ms: wait,
      warning:
        "Events emitted while disconnected cannot be replayed by the broker.",
    });
    await delay(wait, undefined, { signal });
  }
}

export async function sendPending(
  outbox: Outbox,
  telegram: TelegramClient,
  chatId: string,
  signal: AbortSignal,
  log: Log,
): Promise<void> {
  while (!signal.aborted) {
    const message = outbox.peek();
    if (!message) {
      await delay(100, undefined, { signal });
      continue;
    }
    const wait = message.retryAt - Date.now();
    if (wait > 0) {
      await delay(wait, undefined, { signal });
      continue;
    }
    try {
      const messageId = await telegram.send(chatId, message.text, signal);
      outbox.acknowledge(message);
      log("sent", {
        event_id: message.eventId,
        chunk: message.chunk + 1,
        telegram_message_id: messageId,
      });
      await delay(1100, undefined, { signal });
    } catch (error) {
      if (signal.aborted) return;
      if (!(error instanceof TelegramFailure) || !error.retryable) throw error;
      const backoff = Math.min(
        60000,
        1000 * 2 ** Math.min(message.attempts, 6),
      );
      const retryMs = Math.max(
        error.retryAfterMs,
        backoff + Math.floor(Math.random() * 250),
      );
      outbox.retry(message, Date.now() + retryMs);
      log("telegram_retry", { status: error.status, delay_ms: retryMs });
    }
  }
}
