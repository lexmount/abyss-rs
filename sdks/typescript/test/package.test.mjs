import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const sdkDir = fileURLToPath(new URL("../", import.meta.url));

test("packed SDK installs and exposes both public entry points", async () => {
  const directory = await mkdtemp(join(tmpdir(), "abyss-sdk-package-"));
  const npm = (args, cwd) =>
    execFileSync(process.execPath, [process.env.npm_execpath, ...args], {
      cwd,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "inherit"],
    });

  try {
    // npm test has already built the SDK; do not rerun lifecycle scripts.
    const [packed] = JSON.parse(
      npm(
        ["pack", "--ignore-scripts", "--json", "--pack-destination", directory],
        sdkDir,
      ),
    );
    npm(
      [
        "install",
        "--ignore-scripts",
        "--no-audit",
        "--no-fund",
        "--package-lock=false",
        join(directory, packed.filename),
      ],
      directory,
    );

    execFileSync(
      process.execPath,
      [
        "--input-type=module",
        "-e",
        `import assert from 'node:assert/strict';
         import { BrokerClient } from '@lexmount.com/abyss-sdk';
         import { BrokerPlugin } from '@lexmount.com/abyss-sdk/plugin';
         assert.ok(new BrokerClient({ baseUrl: 'http://127.0.0.1:18190' }));
         assert.ok(new BrokerPlugin({ consumerId: 'package-smoke' }));`,
      ],
      { cwd: directory, stdio: "inherit" },
    );

    const installed = join(directory, "node_modules/@lexmount.com/abyss-sdk");
    assert.equal(
      await readFile(join(installed, "LICENSE"), "utf8"),
      await readFile(new URL("../../../LICENSE", import.meta.url), "utf8"),
    );
    for (const entry of ["dist/index.d.ts", "dist/plugin/index.d.ts"]) {
      assert.ok((await readFile(join(installed, entry), "utf8")).length > 0);
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
