/** Executable entry point: credentials, exclusive state ownership, and shutdown. */
import { mkdir, chmod } from "node:fs/promises";
import lockfile from "proper-lockfile";
import { readConfig } from "./config.js";
import { Outbox } from "./outbox.js";
import { receive, sendPending, type Log } from "./relay.js";
import { TelegramClient } from "./telegram.js";
import { UserError } from "./errors.js";

const help = `Codex → Telegram (Node.js >=22.16)

  npm start -- chats                   Discover private chat IDs after /start
  npm start -- run                     Forward Codex events to the configured chat
  npm start -- run --dry-run           Print events, without Telegram or a queue
  npm start -- run --session SESSION   Forward one exact session ID
  npm start -- run --endpoint PATH     Override broker plugin socket discovery
  npm start -- run --state-dir PATH    Use a separate durable queue

Broker: ABYSS_BROKER_PLUGIN_ENDPOINT, ABYSS_BROKER_STARTUP_INFO, or ABYSS_HOME.
Telegram: TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID environment variables.
chats requires only TELEGRAM_BOT_TOKEN; --dry-run requires neither.
Optional Telegram-only HTTP proxy: TELEGRAM_PROXY_URL.
Default queue: ~/.local/state/abyss/codex-to-telegram (contains captured context).
Without --session, all Codex sessions on the selected broker are forwarded.
Use Ctrl-C to stop; pending messages remain queued for the next run.
`;

async function main(): Promise<void> {
  process.umask(0o077);
  const config = readConfig();
  if (config.command === "help") {
    process.stdout.write(help);
    return;
  }
  const controller = new AbortController();
  const stop = (): void => controller.abort();
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);
  const log: Log = (event, details) =>
    process.stderr.write(`${JSON.stringify({ event, ...details })}\n`);
  let telegram: TelegramClient | undefined;
  let outbox: Outbox | undefined;
  let release: (() => Promise<void>) | undefined;
  let fatal: unknown;
  try {
    if (config.dryRun && config.command === "run") {
      await receive(config, undefined, controller.signal, log);
      return;
    }
    telegram = new TelegramClient(
      config.token,
      config.apiBase,
      config.proxyUrl,
    );
    if (config.command === "chats") {
      process.stdout.write(
        `${JSON.stringify(await telegram.privateChats(controller.signal), null, 2)}\n`,
      );
      return;
    }
    await mkdir(config.stateDir, { recursive: true, mode: 0o700 });
    await chmod(config.stateDir, 0o700);
    try {
      release = await lockfile.lock(config.stateDir, {
        stale: 10000,
        update: 2000,
        retries: 0,
        onCompromised: () => {
          fatal = new UserError(
            "Outbox lock lost; stopped to avoid concurrent delivery.",
          );
          stop();
        },
      });
    } catch {
      throw new UserError(
        "Outbox is locked by another relay (or a recent crash); retry after 10 seconds or use another state directory.",
      );
    }
    outbox = new Outbox(
      config.stateDir,
      JSON.stringify({
        bot: config.token.split(":")[0],
        chat: config.chatId,
        api: config.apiBase,
      }),
    );
    log("ready", {
      scope: config.sessionId ?? "all Codex sessions on the selected broker",
    });
    const guard = async (task: Promise<void>): Promise<void> => {
      try {
        await task;
      } catch (error) {
        if (!controller.signal.aborted) {
          fatal = error;
          stop();
        }
      }
    };
    await Promise.all([
      guard(receive(config, outbox, controller.signal, log)),
      guard(
        sendPending(outbox, telegram, config.chatId, controller.signal, log),
      ),
    ]);
    if (fatal) throw fatal;
  } catch (error) {
    if (!controller.signal.aborted || fatal) throw error;
  } finally {
    stop();
    outbox?.close();
    await telegram?.close();
    await release?.();
    process.off("SIGINT", stop);
    process.off("SIGTERM", stop);
  }
}

main().catch((error: unknown) => {
  // SDK/proxy/filesystem exceptions can contain credentials or captured context.
  const detail =
    error instanceof UserError
      ? error.message
      : "Check configuration, queue ownership/capacity, and broker access.";
  process.stderr.write(
    `Relay failed: ${detail} Pending messages are retained.\n`,
  );
  process.exitCode = 1;
});
