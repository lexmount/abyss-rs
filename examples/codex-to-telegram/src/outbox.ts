/** Durable ordered outbox with chunk checkpoints and destination binding. */
import { chmodSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { UserError } from "./errors.js";

export class OutboxError extends UserError {}

export interface PendingMessage {
  eventId: string;
  chunk: number;
  text: string;
  attempts: number;
  retryAt: number;
}

export class Outbox {
  readonly #db: DatabaseSync;
  readonly #maxBytes: number;
  readonly #maxEvents: number;
  constructor(
    directory: string,
    destination: string,
    limits = { bytes: 64 * 1024 * 1024, events: 10000 },
  ) {
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    chmodSync(directory, 0o700);
    const path = join(directory, "outbox.sqlite");
    this.#db = new DatabaseSync(path);
    this.#maxBytes = limits.bytes;
    this.#maxEvents = limits.events;
    try {
      chmodSync(path, 0o600);
      this.#db.exec(`
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = FULL;
        CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS events (
          seq INTEGER PRIMARY KEY AUTOINCREMENT,
          event_id TEXT NOT NULL UNIQUE,
          chunks TEXT,
          bytes INTEGER NOT NULL,
          next_chunk INTEGER NOT NULL DEFAULT 0,
          attempts INTEGER NOT NULL DEFAULT 0,
          retry_at INTEGER NOT NULL DEFAULT 0,
          delivered_at INTEGER
        );
      `);
      this.#db
        .prepare("INSERT OR IGNORE INTO metadata VALUES ('version', '1')")
        .run();
      this.#db
        .prepare("INSERT OR IGNORE INTO metadata VALUES ('destination', ?)")
        .run(destination);
      const meta = this.#db.prepare("SELECT key, value FROM metadata").all();
      if (
        meta.find((row) => row.key === "version")?.value !== "1" ||
        meta.find((row) => row.key === "destination")?.value !== destination
      ) {
        throw new OutboxError(
          "Outbox version/destination mismatch; use a separate state directory.",
        );
      }
      this.#db
        .prepare("DELETE FROM events WHERE delivered_at < ?")
        .run(Date.now() - 30 * 86400000);
    } catch (error) {
      this.#db.close();
      throw error;
    }
  }

  enqueue(eventId: string, chunks: string[]): boolean {
    try {
      if (
        this.#db.prepare("SELECT 1 FROM events WHERE event_id = ?").get(eventId)
      )
        return false;
      if (!chunks.length) throw new Error("Empty event");
      const payload = JSON.stringify(chunks);
      const bytes = Buffer.byteLength(payload);
      const size = this.#db
        .prepare(
          "SELECT COUNT(*) AS count, COALESCE(SUM(bytes), 0) AS bytes FROM events WHERE chunks IS NOT NULL",
        )
        .get()!;
      if (
        Number(size.count) >= this.#maxEvents ||
        Number(size.bytes) + bytes > this.#maxBytes
      ) {
        throw new OutboxError(
          "Outbox capacity exceeded; stopped receiving. Broker cannot replay the rejected event.",
        );
      }
      this.#db
        .prepare(
          "INSERT INTO events (event_id, chunks, bytes) VALUES (?, ?, ?)",
        )
        .run(eventId, payload, bytes);
      return true;
    } catch (error) {
      if (error instanceof OutboxError) throw error;
      throw new OutboxError("Failed to persist event; stopped receiving.");
    }
  }

  peek(): PendingMessage | undefined {
    const row = this.#db
      .prepare(
        "SELECT * FROM events WHERE chunks IS NOT NULL ORDER BY seq LIMIT 1",
      )
      .get();
    if (!row) return undefined;
    const chunks = JSON.parse(String(row.chunks)) as string[];
    const text = chunks[Number(row.next_chunk)];
    if (typeof text !== "string")
      throw new OutboxError("Invalid outbox chunk checkpoint.");
    return {
      eventId: String(row.event_id),
      chunk: Number(row.next_chunk),
      text,
      attempts: Number(row.attempts),
      retryAt: Number(row.retry_at),
    };
  }

  acknowledge(message: PendingMessage): void {
    this.#db
      .prepare(
        `UPDATE events SET
      next_chunk = next_chunk + 1, attempts = 0, retry_at = 0,
      bytes = CASE WHEN next_chunk + 1 = json_array_length(chunks) THEN 0 ELSE bytes END,
      delivered_at = CASE WHEN next_chunk + 1 = json_array_length(chunks) THEN ? ELSE NULL END,
      chunks = CASE WHEN next_chunk + 1 = json_array_length(chunks) THEN NULL ELSE chunks END
      WHERE event_id = ? AND next_chunk = ? AND chunks IS NOT NULL`,
      )
      .run(Date.now(), message.eventId, message.chunk);
  }

  retry(message: PendingMessage, retryAt: number): void {
    this.#db
      .prepare(
        "UPDATE events SET attempts = attempts + 1, retry_at = ? WHERE event_id = ? AND next_chunk = ?",
      )
      .run(retryAt, message.eventId, message.chunk);
  }

  close(): void {
    this.#db.close();
  }
}
