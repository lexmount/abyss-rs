/** Telegram HTTP boundary; errors deliberately exclude URLs, tokens, and response bodies. */
import { Agent, ProxyAgent, request, type Dispatcher } from "undici";
import { UserError } from "./errors.js";

export class TelegramFailure extends UserError {
  constructor(
    readonly status: number,
    readonly retryAfterMs: number = 0,
  ) {
    super(
      status === 0
        ? "Telegram network/response failure; delivery will retry."
        : `Telegram API error ${status}${status === 409 ? "; disable the bot webhook/other getUpdates poller before using chats" : ""}.`,
    );
  }
  get retryable(): boolean {
    return this.status === 0 || this.status === 429 || this.status >= 500;
  }
}

interface TelegramResponse {
  ok?: boolean;
  result?: unknown;
  error_code?: number;
  parameters?: { retry_after?: number };
}

export class TelegramClient {
  readonly #dispatcher: Dispatcher;
  constructor(
    readonly token: string,
    readonly baseUrl: string,
    proxyUrl?: string,
  ) {
    try {
      this.#dispatcher = proxyUrl ? new ProxyAgent(proxyUrl) : new Agent();
    } catch {
      throw new UserError("Invalid TELEGRAM_PROXY_URL.");
    }
  }

  async call(
    method: string,
    payload: Record<string, unknown>,
    signal: AbortSignal,
  ): Promise<unknown> {
    signal.throwIfAborted();
    try {
      const response = await request(
        `${this.baseUrl}/bot${this.token}/${method}`,
        {
          method: "POST",
          dispatcher: this.#dispatcher,
          maxRedirections: 0,
          headers: { "content-type": "application/json" },
          body: JSON.stringify(payload),
          signal: AbortSignal.any([signal, AbortSignal.timeout(15000)]),
          headersTimeout: 15000,
          bodyTimeout: 15000,
        },
      );
      let size = 0;
      const buffers: Buffer[] = [];
      for await (const chunk of response.body) {
        const buffer = Buffer.from(chunk);
        size += buffer.length;
        if (size > 1024 * 1024) {
          response.body.destroy();
          throw new TelegramFailure(0);
        }
        buffers.push(buffer);
      }
      let parsed: TelegramResponse = {};
      try {
        parsed = JSON.parse(
          Buffer.concat(buffers).toString("utf8"),
        ) as TelegramResponse;
      } catch {
        /* Preserve HTTP status even if an upstream gateway returns HTML. */
      }
      if (response.statusCode !== 200 || parsed?.ok !== true) {
        const code = Number.isInteger(parsed?.error_code)
          ? parsed.error_code!
          : response.statusCode;
        const seconds = parsed?.parameters?.retry_after;
        const retryAfterMs =
          typeof seconds === "number" && Number.isFinite(seconds) && seconds > 0
            ? Math.min(seconds * 1000, 2147483647)
            : 0;
        throw new TelegramFailure(code === 200 ? 0 : code, retryAfterMs);
      }
      return parsed.result;
    } catch (error) {
      signal.throwIfAborted();
      if (error instanceof TelegramFailure) throw error;
      throw new TelegramFailure(0);
    }
  }

  async send(
    chatId: string,
    text: string,
    signal: AbortSignal,
  ): Promise<number> {
    const result = (await this.call(
      "sendMessage",
      {
        chat_id: chatId,
        text,
        link_preview_options: { is_disabled: true },
      },
      signal,
    )) as { message_id?: number } | undefined;
    if (!Number.isSafeInteger(result?.message_id)) throw new TelegramFailure(0);
    return result!.message_id!;
  }

  async privateChats(signal: AbortSignal): Promise<unknown> {
    const bot = (await this.call("getMe", {}, signal)) as {
      id: number;
      username: string;
    };
    const updates = await this.call(
      "getUpdates",
      { timeout: 0, limit: 100 },
      signal,
    );
    if (!Array.isArray(updates)) throw new TelegramFailure(0);
    const chats = new Map<
      number,
      { id: number; username?: string; first_name?: string }
    >();
    for (const update of updates) {
      const chat = update?.message?.chat;
      if (chat?.type === "private" && Number.isSafeInteger(chat.id)) {
        chats.set(chat.id, {
          id: chat.id,
          ...(chat.username ? { username: chat.username } : {}),
          ...(chat.first_name ? { first_name: chat.first_name } : {}),
        });
      }
    }
    // No offset: discovering a chat never acknowledges or consumes bot updates.
    return {
      bot: { id: bot.id, username: bot.username },
      chats: [...chats.values()],
      ...(chats.size
        ? {}
        : {
            instruction: `Open https://t.me/${bot.username} and send /start, then run chats again.`,
          }),
    };
  }

  async close(): Promise<void> {
    await this.#dispatcher.destroy();
  }
}
