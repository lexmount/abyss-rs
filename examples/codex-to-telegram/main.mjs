// Forward Codex text and tool context from an existing broker to Telegram.
import { setTimeout as delay } from "node:timers/promises";
import { BrokerPlugin } from "@lexmount.com/abyss-sdk/plugin";

async function main() {
  const token = process.env.TELEGRAM_BOT_TOKEN?.trim();
  const chatId = process.env.TELEGRAM_CHAT_ID?.trim();
  if (!token || !chatId) {
    console.error("Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID.");
    process.exitCode = 1;
    return;
  }

  await new BrokerPlugin({ consumerId: "example.codex-telegram" }).run(
    async (event) => {
      if (event.agent.name.toLowerCase() !== "codex") return;
      const context = [
        event.text,
        ...(event.tool_calls ?? []).map(
          (call) => `Tool: ${call.name}\n${call.input}`,
        ),
        ...(event.tool_results ?? []).map(
          (result) => `Result: ${result.call_id}\n${result.output}`,
        ),
      ]
        .filter(Boolean)
        .join("\n\n");
      if (!context) return;

      const text = `Codex ${event.side} · turn ${event.turn_index}\nSession: ${event.session_id}\n\n${context}`;
      const characters = Array.from(text);
      // 2,000 Unicode code points fit Telegram's limit even with emoji.
      for (let offset = 0; offset < characters.length; offset += 2000) {
        const response = await fetch(
          `https://api.telegram.org/bot${token}/sendMessage`,
          {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              chat_id: chatId,
              text: characters.slice(offset, offset + 2000).join(""),
              link_preview_options: { is_disabled: true },
            }),
            signal: AbortSignal.timeout(15000),
            redirect: "error",
          },
        );
        const result = await response.json();
        if (!response.ok || !result.ok) {
          console.error(
            `Telegram sendMessage failed (HTTP ${response.status}).`,
          );
          throw new Error("Telegram delivery failed");
        }
        // Avoid sending long context faster than a private chat allows.
        await delay(1100);
      }
      console.log(`Forwarded ${event.side}: ${event.session_id}`);
    },
  );
}

main().catch(() => {
  // Do not log request URLs: they contain the bot token.
  console.error(
    "Forwarding stopped. Check broker connectivity and Telegram configuration.",
  );
  process.exitCode = 1;
});
