/** CLI configuration; Telegram credentials come exclusively from environment variables. */
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { UserError } from "./errors.js";

export interface Config {
  command: "run" | "chats" | "help";
  dryRun: boolean;
  endpoint: string | undefined;
  sessionId: string | undefined;
  stateDir: string;
  token: string;
  chatId: string;
  apiBase: string;
  proxyUrl: string | undefined;
}

export function readConfig(args = process.argv.slice(2)): Config {
  const { values, positionals } = parseArgs({
    args,
    allowPositionals: true,
    options: {
      help: { type: "boolean", short: "h" },
      "dry-run": { type: "boolean" },
      endpoint: { type: "string" },
      session: { type: "string" },
      "state-dir": { type: "string" },
    },
  });
  const command = values.help ? "help" : (positionals[0] ?? "run");
  if (!["run", "chats", "help"].includes(command) || positionals.length > 1) {
    throw new UserError("Use run, chats, or --help.");
  }
  const dryRun = values["dry-run"] ?? false;
  let token = "";
  let chatId = "";
  if (command !== "help" && !(command === "run" && dryRun)) {
    token = requiredEnvironment("TELEGRAM_BOT_TOKEN");
    if (!/^\d+:[A-Za-z0-9_-]+$/.test(token))
      throw new UserError("Invalid Telegram bot token format.");
    if (command === "run") {
      chatId = requiredEnvironment("TELEGRAM_CHAT_ID");
      if (!/^[1-9]\d*$/.test(chatId) || !Number.isSafeInteger(Number(chatId))) {
        throw new UserError(
          "TELEGRAM_CHAT_ID must be a positive private-chat ID; use chats to discover it.",
        );
      }
    }
  }
  const apiBase =
    process.env.TELEGRAM_API_BASE_URL ?? "https://api.telegram.org";
  const url = new URL(apiBase);
  const official = url.origin === "https://api.telegram.org";
  const localTest =
    url.protocol === "http:" && ["127.0.0.1", "[::1]"].includes(url.hostname);
  if (
    (!official && !localTest) ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    url.pathname !== "/"
  ) {
    throw new UserError(
      "Telegram API must use https://api.telegram.org or an HTTP loopback test server.",
    );
  }
  return {
    command: command as Config["command"],
    dryRun,
    endpoint: values.endpoint,
    sessionId:
      values.session ?? (process.env.ABYSS_TELEGRAM_SESSION_ID || undefined),
    stateDir: resolve(
      values["state-dir"] ??
        process.env.ABYSS_TELEGRAM_STATE_DIR ??
        join(homedir(), ".local", "state", "abyss", "codex-to-telegram"),
    ),
    token,
    chatId,
    apiBase: url.origin,
    proxyUrl: process.env.TELEGRAM_PROXY_URL || undefined,
  };
}

function requiredEnvironment(name: string): string {
  const value = process.env[name]?.trim();
  if (!value)
    throw new UserError(`Set the ${name} environment variable (see --help).`);
  return value;
}
