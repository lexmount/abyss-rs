/** Length-prefixed JSON codec for plugin protocol version 1. */

import type { Socket } from "node:net";

import { AbyssPluginError } from "./errors.js";

const FRAME_HEADER_BYTES = 4;
const MAX_JSON_FRAME_BYTES = 16 * 1024 * 1024;

export async function writeJsonFrame(
  socket: Socket,
  value: unknown,
): Promise<void> {
  const payload = Buffer.from(JSON.stringify(value), "utf8");
  if (payload.length > MAX_JSON_FRAME_BYTES) {
    throw new AbyssPluginError(
      `plugin frame payload length ${payload.length} exceeds maximum ${MAX_JSON_FRAME_BYTES}`,
    );
  }
  const header = Buffer.allocUnsafe(FRAME_HEADER_BYTES);
  header.writeUInt32BE(payload.length);
  await new Promise<void>((resolve, reject) => {
    socket.write(Buffer.concat([header, payload]), (error) => {
      if (error === null || error === undefined) {
        resolve();
      } else {
        reject(error);
      }
    });
  });
}

export async function* readJsonFrames(socket: Socket): AsyncGenerator<unknown> {
  let buffered: Buffer<ArrayBufferLike> = Buffer.alloc(0);
  for await (const rawChunk of socket) {
    const chunk = Buffer.isBuffer(rawChunk)
      ? rawChunk
      : Buffer.from(rawChunk as Uint8Array);
    buffered = buffered.length === 0 ? chunk : Buffer.concat([buffered, chunk]);
    while (buffered.length >= FRAME_HEADER_BYTES) {
      const payloadLength = buffered.readUInt32BE(0);
      if (payloadLength > MAX_JSON_FRAME_BYTES) {
        throw new AbyssPluginError(
          `plugin frame payload length ${payloadLength} exceeds maximum ${MAX_JSON_FRAME_BYTES}`,
        );
      }
      const frameLength = FRAME_HEADER_BYTES + payloadLength;
      if (buffered.length < frameLength) {
        break;
      }
      const payload = buffered.subarray(FRAME_HEADER_BYTES, frameLength);
      buffered = buffered.subarray(frameLength);
      try {
        yield JSON.parse(payload.toString("utf8")) as unknown;
      } catch (error) {
        throw new AbyssPluginError("decode broker plugin JSON frame", {
          cause: error,
        });
      }
    }
  }
  if (buffered.length !== 0) {
    throw new AbyssPluginError("broker plugin stream ended within a frame");
  }
}
