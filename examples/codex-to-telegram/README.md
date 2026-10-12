# Codex → Telegram

通过 `abyss-broker` 的公开插件协议，将 Codex 的请求、响应、工具调用和工具结果转发到 Telegram 私聊。无需 backend、dashboard 或 delivery-plugin，也不需要公网入站端口。

```text
Codex → 本地 HTTPS 代理 → abyss-broker / Agent Hook
                                      ↓ 本地插件 socket
                            TypeScript receiver → SQLite outbox
                                                      ↓ 独立发送任务
                                                 Telegram Bot API
```

## 准备

- macOS/Linux：运行完整的一次性 demo。转发程序也可连接 Windows named pipe。
- Node.js **22.16+**（推荐 24；使用内置 `node:sqlite`）、npm。
- 已登录且可正常执行 `codex exec` 的本地 Codex CLI。
- Rust 工具链，用于从本仓库构建 broker；已有兼容 broker 二进制时可通过 `ABYSS_BROKER_BIN` 指定。
- `openssl`，仅用于一次性 demo 的临时 CA。
- Telegram Bot Token，以及向该 Bot 发过 `/start` 的私聊账号。
- 能连接 Codex 服务和 `api.telegram.org` 的网络。

在仓库根目录安装和构建：

```bash
npm --prefix sdks/typescript ci
npm --prefix sdks/typescript run build
npm --prefix examples/codex-to-telegram ci
npm --prefix examples/codex-to-telegram run build
cargo build -p abyss-broker
```

示例通过 `file:../../sdks/typescript` 使用本仓库 SDK，包含连接取消和超时支持。需要保留仓库目录结构，并先构建 SDK。

## 配置 Bot 和私聊

通过环境变量配置 Token 和目标私聊 ID：

```bash
export TELEGRAM_BOT_TOKEN='你的 Bot Token'
export TELEGRAM_CHAT_ID='你的私聊数字 ID'
```

发送模式和一次性 demo 都必须设置这两个环境变量；缺失或为空时会在启动前报错。程序不再读取默认凭据文件，也不支持 `TELEGRAM_BOT_TOKEN_FILE`、`TELEGRAM_CHAT_ID_FILE`。

还不知道私聊 ID 时，先设置 `TELEGRAM_BOT_TOKEN`，在 Telegram 打开 Bot 并发送 `/start`，再运行：

```bash
cd examples/codex-to-telegram
npm start -- chats
```

`chats` 命令只需要 Token，会验证 Bot 并列出收到的私聊 `id`；把目标私聊的数字 ID 设置为 `TELEGRAM_CHAT_ID`。它不会推进 `getUpdates` 的 offset，也不会消费更新。若 Bot 已配置 webhook 或有其他轮询程序，需先解决该冲突；本示例不会自动删除 webhook。

也可参考 [.env.example](.env.example)，通过 Node 显式加载 `.env`，将其中的值注入环境变量：转发程序使用 `node --env-file=.env dist/main.js`，一次性 demo 使用 `node --env-file=.env dist/demo.js`。`npm start` 和 `npm run demo` 不会自动加载 `.env`。本地 `.env` 已被 Git 忽略，不要将真实凭据写入示例文件或日志。

## 一条命令跑真实 demo

```bash
npm run demo -- --dry-run
npm run demo
```

启动器会创建权限受限的 `/tmp/abyss-tg-demo-*` 目录，生成一天有效的临时 CA，启动独立 broker 和转发程序，再运行一个只读 Codex 任务：读取专门生成的 `demo.txt`，回复唯一标记。只有这个 Codex 子进程使用临时代理和 CA；不会安装系统 CA，也不会接入其他 Codex 会话。它会忽略 Codex 用户配置，但继续使用已有登录凭据。

`--dry-run` 不调用 Telegram，也不创建发送队列；渲染结果保存在该次运行目录的 `relay.log`。普通运行会等待 Telegram 确认全部消息后退出，自动停止测试进程。完整上下文包含 Codex 发给模型的指令，因此一个简单任务也可能产生多条消息。

日志和队列保留在输出的私密运行目录中，便于检查或恢复。`codex.log` 记录测试任务，`relay-events.jsonl` 记录入队与 Telegram message ID。发送失败后可保留该目录的 `state`，按下面的常驻转发方式继续发送；broker 不可用时，已入队的消息仍会发送。临时目录可能被系统清理，需要长期保留时移到自己的私密目录。

需要代理访问 Telegram 时设置 `TELEGRAM_PROXY_URL=http://127.0.0.1:7890`。它独立于 Codex 的 `HTTP_PROXY` / `HTTPS_PROXY`，不会自动继承这些变量。启动器运行期间只接受 `--dry-run` 或 `--help`；它始终使用独立状态目录。

## 接入已有 broker

确认 broker 已开启 Codex 的 `harness_usage`，并在内容策略中启用 `conversation_text`、`tool_calls`。使用 MITM 代理时，Codex 进程须信任 broker 的 CA；代理和 CA 应按进程配置。仓库默认策略可作为参考。

```bash
export ABYSS_BROKER_STARTUP_INFO=/absolute/path/to/startup-info.json

# 先确认可见内容和会话 ID
npm start -- run --dry-run

# 精确限定一个会话
npm start -- run --session YOUR_SESSION_ID

# 或转发这个 broker 上的全部 Codex 会话
npm start -- run
```

插件端点也可用 `--endpoint`、`ABYSS_BROKER_PLUGIN_ENDPOINT` 或 `ABYSS_HOME` 发现。`ABYSS_TELEGRAM_SESSION_ID` 等价于 `--session`。

默认队列目录为 `~/.local/state/abyss/codex-to-telegram`，可用 `--state-dir` 或 `ABYSS_TELEGRAM_STATE_DIR` 修改。请使用专用目录：程序会将目录权限设为 `0700`。同一目录只允许一个发送进程，并绑定 Bot ID、chat ID 和 API 地址，避免把旧消息重放到另一个收件人。`--session` 只过滤新收到的事件，不会丢弃已有队列；要完全隔离会话，请使用不同的状态目录。

## 行为和边界

- 仅接收 `agent.name=codex` 的公开 `AgentEvent`，按会话、轮次、请求/响应标注消息；没有“任务完成”事件，不将普通 response 误标为最终答案。
- 文本和工具输入/输出保留完整内容；纯文本发送，禁用链接预览，长消息按 Unicode 安全边界拆分至 Telegram 限制以下。图片只发送类型、大小和 SHA256，不发送二进制内容。
- 接收任务同步提交 SQLite WAL；发送任务独立处理，每条消息间隔约 1.1 秒。429 遵守 `retry_after`；网络故障和 5xx 指数退避。其他 4xx 停止程序并保留队列，修正配置后重启。
- 每成功发送一段便提交进度，重启后续发。重复 `event_id` 去重；已送达记录移除正文，重启时清理超过 30 天的去重记录。进程在 Telegram 接收成功、SQLite 提交前崩溃时，重试可能产生重复消息。
- 未送达队列上限为 10,000 个事件 / 64 MiB 文本负载。达到上限或写盘失败时停止接收并报错。队列包含捕获上下文，应按需要管理保存时间；SQLite 数据文件大小不等同于当前待发负载大小。
- broker 的订阅流是实时、尽力交付，**无 ACK / 历史重放**。订阅前、断线期间、broker 缓冲溢出或队列写入失败的事件无法由此示例补回。重连只恢复后续接收。
- 这是一条 Codex → Telegram 的单向通路，不会执行 Telegram 发来的命令。

## 验证

```bash
# 仓库根目录；无需真实 Token，不访问 Telegram/Codex
make test-example-codex-to-telegram
npm --prefix sdks/typescript test
```

测试包含 Unicode 分段、过滤、SQLite 重启恢复/去重/容量、目的地绑定，以及通过真实子进程、本地 socket 和 HTTP 服务验证握手、限流重试、断线重连、错误脱敏、独占锁、dry-run 和私聊发现。CI 同样执行这些检查。真实网络验收使用上面的 `npm run demo`，不会在 CI 中自动运行。
