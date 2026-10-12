# Codex → Telegram 最小示例

一个脚本：订阅 `abyss-broker` 的 Codex 事件，将文本、工具调用和工具结果直接发送到 Telegram。长消息自动分段。

## 准备

- Node.js 20+。
- 一个正在运行的 broker，Codex 已通过它的代理运行并信任对应 CA；broker 的 Codex 内容采集已开启。
- Telegram Bot Token 和私聊 chat ID；先向 Bot 发送 `/start`。

在仓库根目录安装依赖、构建 SDK：

```bash
npm --prefix sdks/typescript ci
npm --prefix sdks/typescript run build
npm --prefix examples/codex-to-telegram ci
```

## 运行

```bash
export TELEGRAM_BOT_TOKEN='你的 Bot Token'
export TELEGRAM_CHAT_ID='你的私聊数字 ID'
export ABYSS_BROKER_STARTUP_INFO='/absolute/path/to/startup-info.json'

npm --prefix examples/codex-to-telegram start
```

然后在通过该 broker 代理运行的 Codex 中发一条消息，Telegram 就会收到上下文。也可用 `ABYSS_BROKER_PLUGIN_ENDPOINT` 直接指定插件 socket。按 Ctrl-C 退出。

Token 和 chat ID 只从环境变量读取。若使用 [.env.example](.env.example)，复制为本地 `.env` 并填写后，可在示例目录用 Node 22+ 执行 `node --env-file=.env main.mjs`；`npm start` 不自动加载该文件。

这是单向转发 demo：发送失败或 broker 断开就退出，不保存队列，也不补发历史消息。它会转发所连接 broker 上的所有 Codex 会话；图片不转发。

运行最小测试（无需真实 Token）：

```bash
npm --prefix examples/codex-to-telegram test
```
