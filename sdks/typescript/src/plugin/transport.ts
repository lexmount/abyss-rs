/** Platform-local stream connection to the client's configured plugin endpoint. */

import { connect as connectSocket, type Socket } from "node:net";

import { BrokerPluginError } from "./errors.js";

export async function connectPluginStream(endpoint: string): Promise<Socket> {
  return new Promise<Socket>((resolve, reject) => {
    const socket = connectSocket(endpoint);
    const onError = (error: Error): void => {
      socket.destroy();
      reject(
        new BrokerPluginError(`connect to broker plugin endpoint ${endpoint}`, {
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
