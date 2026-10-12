/** One-shot real demo: isolated broker, process-local CA, relay, and a read-only Codex task. */
import { spawn, type ChildProcess } from "node:child_process";
import { mkdtemp, mkdir, writeFile, readFile, open } from "node:fs/promises";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { BrokerClient } from "@lexmount/abyss-sdk";
import { readConfig } from "./config.js";
import { UserError } from "./errors.js";

interface ProcessRun {
  process: ChildProcess;
  done: Promise<number | null>;
  ended: boolean;
}

async function demo(): Promise<void> {
  process.umask(0o077);
  if (
    process.argv
      .slice(2)
      .some((arg) => !["--dry-run", "--help", "-h"].includes(arg))
  ) {
    throw new UserError(
      "demo accepts only --dry-run or --help; use npm start for relay options.",
    );
  }
  const config = readConfig();
  if (config.command === "help") {
    process.stdout.write(
      "npm run demo [-- --dry-run]\nRequires openssl, a built abyss-broker, and a logged-in local codex. Runs one isolated read-only demo task.\nSet TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID environment variables; --dry-run requires neither.\n",
    );
    return;
  }
  if (config.command !== "run" || config.sessionId || config.endpoint)
    throw new UserError(
      "demo creates its own broker/session; use only --dry-run or --help.",
    );
  if (process.platform === "win32")
    throw new UserError(
      "The one-shot demo launcher currently supports macOS/Linux; the relay itself also supports Windows.",
    );
  const dir = await mkdtemp("/tmp/abyss-tg-demo-");
  const repo = fileURLToPath(new URL("../../..", import.meta.url));
  const brokerBin =
    process.env.ABYSS_BROKER_BIN ??
    join(repo, "target", "debug", "abyss-broker");
  const controller = new AbortController();
  const stop = (): void => controller.abort();
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);
  const processes: ProcessRun[] = [];
  const logs: Awaited<ReturnType<typeof open>>[] = [];
  let relayOutput = "";
  async function start(
    command: string,
    args: string[],
    name: string,
    env = process.env,
    observe?: (text: string) => void,
  ): Promise<ProcessRun> {
    const log = await open(join(dir, `${name}.log`), "w", 0o600);
    logs.push(log);
    const child = spawn(command, args, {
      env,
      stdio: ["ignore", log.fd, observe ? "pipe" : log.fd],
    });
    if (observe)
      child.stderr?.on("data", (data: Buffer) => {
        observe(data.toString());
      });
    const run: ProcessRun = {
      process: child,
      ended: false,
      done: Promise.resolve(null),
    };
    run.done = new Promise((resolve, reject) => {
      child.once("error", () => {
        run.ended = true;
        reject(
          new UserError(`Could not start ${name}; check installed binaries.`),
        );
      });
      child.once("exit", (code) => {
        run.ended = true;
        resolve(code);
      });
    });
    // A later awaited readiness check reports failures; suppress premature unhandled rejection.
    void run.done.catch(() => {});
    processes.push(run);
    return run;
  }
  async function command(
    binary: string,
    args: string[],
    name: string,
  ): Promise<void> {
    const run = await start(binary, args, name);
    if ((await run.done) !== 0)
      throw new UserError(`${name} failed; inspect the private demo logs.`);
  }
  async function waitFor(
    check: () => Promise<boolean> | boolean,
    milliseconds: number,
    message: string,
  ): Promise<void> {
    const deadline = Date.now() + milliseconds;
    while (Date.now() < deadline) {
      controller.signal.throwIfAborted();
      if (await check()) return;
      await delay(100, undefined, { signal: controller.signal });
    }
    throw new UserError(message);
  }
  process.stderr.write(`Private demo files: ${dir}\n`);
  try {
    const ca = join(dir, "ca");
    const home = join(dir, "home");
    const workspace = join(dir, "workspace");
    await Promise.all(
      [ca, home, workspace].map((path) => mkdir(path, { mode: 0o700 })),
    );
    await writeFile(
      join(dir, "openssl.cnf"),
      `[req]\ndistinguished_name=dn\nx509_extensions=v3_ca\nprompt=no\n[dn]\nCN=Abyss Telegram Demo Root\n[v3_ca]\nbasicConstraints=critical,CA:true\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n`,
    );
    const pem = join(ca, "abyss-root-ca.pem");
    await command(
      "openssl",
      [
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "1",
        "-sha256",
        "-config",
        join(dir, "openssl.cnf"),
        "-keyout",
        join(ca, "abyss-root-ca-key.pem"),
        "-out",
        pem,
      ],
      "create-ca",
    );
    await command(
      "openssl",
      [
        "x509",
        "-in",
        pem,
        "-outform",
        "DER",
        "-out",
        join(ca, "abyss-root-ca.der"),
      ],
      "export-ca",
    );
    const brokerConfig = join(dir, "broker-config.toml");
    await writeFile(
      brokerConfig,
      `schema_version = 1\n[devtools]\nlog_level = "info"\nlog_location = ${JSON.stringify(join(dir, "logs"))}\n[ca]\npath = ${JSON.stringify(ca)}\n[proxy]\nmode = "explicit"\nlisten_addr = "127.0.0.1:0"\n`,
    );
    await writeFile(
      join(home, "runtime-policy.toml"),
      await readFile(
        join(repo, "crates/abyss-cli/defaults/runtime-policy.toml"),
      ),
    );
    const startupFile = join(dir, "startup-info.json");
    const broker = await start(
      brokerBin,
      [
        "--config",
        brokerConfig,
        "--api",
        "127.0.0.1:0",
        "--auth-token-file",
        join(dir, "broker.token"),
        "--startup-info-file",
        startupFile,
      ],
      "broker",
      { ...process.env, ABYSS_HOME: home },
    );
    let startup: { plugin_endpoint: string } | undefined;
    await waitFor(
      async () => {
        if (broker.ended)
          throw new UserError(
            "Broker exited before startup; inspect broker.log.",
          );
        try {
          startup = JSON.parse(
            await readFile(startupFile, "utf8"),
          ) as typeof startup;
          return Boolean(startup?.plugin_endpoint);
        } catch {
          return false;
        }
      },
      15000,
      "Broker startup timed out.",
    );
    const brokerClient = await BrokerClient.fromStartupInfo(startupFile);
    const proxyStatus = await brokerClient.getProxyStatus();
    if (!proxyStatus.listen_addr || proxyStatus.lifecycle !== "running")
      throw new UserError("Broker explicit proxy is not running.");
    const relay = await start(
      process.execPath,
      [
        fileURLToPath(new URL("./main.js", import.meta.url)),
        "run",
        "--endpoint",
        startup!.plugin_endpoint,
        "--state-dir",
        join(dir, "state"),
        ...(config.dryRun ? ["--dry-run"] : []),
      ],
      "relay",
      process.env,
      (text) => {
        relayOutput += text;
        process.stderr.write(text);
      },
    );
    await waitFor(
      () => {
        if (relay.ended) throw new UserError("Relay exited before connection.");
        return relayOutput.includes('"broker_connected"');
      },
      15000,
      "Relay connection timed out.",
    );
    const marker = `ABYSS_TELEGRAM_DEMO_${Date.now()}`;
    await writeFile(
      join(workspace, "demo.txt"),
      `${marker}\nThis is a dedicated, non-secret Codex to Telegram test.\n`,
    );
    const codexEnv = { ...process.env };
    for (const key of Object.keys(codexEnv)) {
      if (/^telegram_/i.test(key) || /^(http|https|all|no)_proxy$/i.test(key))
        delete codexEnv[key];
    }
    const proxy = `http://${proxyStatus.listen_addr}`;
    Object.assign(codexEnv, {
      HTTP_PROXY: proxy,
      HTTPS_PROXY: proxy,
      NO_PROXY: "127.0.0.1,localhost,::1",
      CODEX_CA_CERTIFICATE: pem,
      SSL_CERT_FILE: pem,
    });
    const codex = await start(
      process.env.CODEX_BIN ?? "codex",
      [
        "exec",
        "--json",
        "--ephemeral",
        "--ignore-user-config",
        "--skip-git-repo-check",
        "-C",
        workspace,
        "-s",
        "read-only",
        "Read demo.txt using a shell tool, then reply with its marker and the words Telegram demo complete. Do not access other files or the network.",
      ],
      "codex",
      codexEnv,
    );
    await waitFor(
      () => codex.ended || relay.ended || broker.ended,
      180000,
      "Codex demo timed out.",
    );
    if (relay.ended || broker.ended)
      throw new UserError("Broker/relay exited during the Codex task.");
    if ((await codex.done) !== 0)
      throw new UserError(
        "Codex failed; inspect codex.log for authentication/connectivity details.",
      );
    await delay(2000, undefined, { signal: controller.signal });
    if (config.dryRun) {
      const rendered = await readFile(join(dir, "relay.log"), "utf8");
      if (!rendered.includes(marker) || !rendered.includes("Codex · response"))
        throw new UserError(
          "Codex completed but expected broker context was not observed.",
        );
    } else {
      await waitFor(
        () => {
          if (relay.ended)
            throw new UserError(
              "Relay stopped; pending messages remain in the demo state directory.",
            );
          const events = relayOutput.split("\n").flatMap((line) => {
            try {
              return [JSON.parse(line) as { event: string; chunks?: number }];
            } catch {
              return [];
            }
          });
          const queued = events
            .filter((item) => item.event === "queued")
            .reduce((sum, item) => sum + (item.chunks ?? 0), 0);
          return (
            queued > 0 &&
            events.filter((item) => item.event === "sent").length === queued
          );
        },
        180000,
        "Telegram queue did not drain; state retained for manual restart.",
      );
    }
    process.stdout.write(
      `${config.dryRun ? "Dry-run verified" : "Telegram delivery verified"}: ${marker}\nFiles retained at ${dir}\n`,
    );
  } finally {
    stop();
    for (const run of [...processes].reverse()) {
      if (!run.ended) {
        run.process.kill("SIGTERM");
        const force = setTimeout(() => run.process.kill("SIGKILL"), 3000);
        await run.done.catch(() => {});
        clearTimeout(force);
      }
    }
    await Promise.all(logs.map((log) => log.close()));
    await writeFile(join(dir, "relay-events.jsonl"), relayOutput, {
      mode: 0o600,
    });
    process.off("SIGINT", stop);
    process.off("SIGTERM", stop);
  }
}

demo().catch((error: unknown) => {
  process.stderr.write(
    `${error instanceof UserError ? error.message : "Demo stopped or failed; inspect its private logs."}\n`,
  );
  process.exitCode = 1;
});
