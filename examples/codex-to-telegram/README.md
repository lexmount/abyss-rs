# Codex → Telegram Demo

A single script that subscribes to Codex events from `abyss-broker` and forwards
text, tool calls, and tool results to Telegram. Long messages are split automatically.

## Setup

- Node.js 20+.
- A running broker with Codex content capture enabled. Codex must use the broker's
  proxy and trust its CA certificate.
- A Telegram bot token and a private chat ID. Send `/start` to the bot first.

Install the published SDK package from npm, running from the repository root:

```bash
npm --prefix examples/codex-to-telegram ci
```

## Run

```bash
export TELEGRAM_BOT_TOKEN='your-bot-token'
export TELEGRAM_CHAT_ID='your-private-chat-id'
export ABYSS_BROKER_STARTUP_INFO='/absolute/path/to/startup-info.json'

npm --prefix examples/codex-to-telegram start
```

Send a message in Codex while it uses the broker's proxy. Its context will appear
in Telegram. You can also set `ABYSS_BROKER_PLUGIN_ENDPOINT` to specify the plugin
socket directly. Press Ctrl-C to stop.

The token and chat ID are read only from environment variables. To use
[.env.example](.env.example), copy it to a local `.env` file and fill in the values.
With Node.js 22+, run `node --env-file=.env main.mjs` from the example directory.
`npm start` does not load `.env` automatically.

This demo forwards context in one direction. It exits on a delivery failure or
broker disconnection, with no persistent queue or historical replay. It forwards
all Codex sessions on the connected broker. Images are not forwarded.

Run the basic tests without a real bot token:

```bash
npm --prefix examples/codex-to-telegram test
```
