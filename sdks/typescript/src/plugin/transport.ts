/** Platform-local plugin endpoint discovery and stream connection. */

import { readFile } from "node:fs/promises";
import { connect as connectSocket, type Socket } from "node:net";
import { join } from "node:path";

import { AbyssPluginError } from "./errors.js";

interface StartupInfo {
  plugin_endpoint: string;
}

export async function resolvePluginEndpoint(
  explicit?: string,
): Promise<string> {
  if (explicit !== undefined && explicit.trim().length !== 0) {
    return explicit;
  }
  const environmentEndpoint = process.env.ABYSS_BROKER_PLUGIN_ENDPOINT?.trim();
  if (environmentEndpoint !== undefined && environmentEndpoint.length !== 0) {
    return environmentEndpoint;
  }
  const startupInfo =
    process.env.ABYSS_BROKER_STARTUP_INFO?.trim() ||
    (process.env.ABYSS_HOME
      ? join(process.env.ABYSS_HOME, "runtime", "startup-info.json")
      : undefined);
  if (startupInfo === undefined) {
    throw new AbyssPluginError(
      "broker plugin endpoint is unavailable; configure ABYSS_BROKER_PLUGIN_ENDPOINT, ABYSS_BROKER_STARTUP_INFO, or ABYSS_HOME",
    );
  }
  let parsed: StartupInfo;
  try {
    parsed = JSON.parse(await readFile(startupInfo, "utf8")) as StartupInfo;
  } catch (error) {
    throw new AbyssPluginError(`read broker startup info ${startupInfo}`, {
      cause: error,
    });
  }
  if (
    typeof parsed.plugin_endpoint !== "string" ||
    parsed.plugin_endpoint.length === 0
  ) {
    throw new AbyssPluginError("broker startup info has no plugin_endpoint");
  }
  return parsed.plugin_endpoint;
}

export async function connectPluginStream(endpoint: string): Promise<Socket> {
  return new Promise<Socket>((resolve, reject) => {
    const socket = connectSocket(endpoint);
    const onError = (error: Error): void => {
      socket.destroy();
      reject(
        new AbyssPluginError(`connect to broker plugin endpoint ${endpoint}`, {
          cause: error,
        }),
      );
    };
    socket.once("error", onError);
    socket.once("connect", () => {
      socket.off("error", onError);
      resolve(socket);
    });
  });
}
