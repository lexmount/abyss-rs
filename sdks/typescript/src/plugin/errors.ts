/** Typed plugin connection and protocol failures. */

export class AbyssPluginError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "AbyssPluginError";
  }
}

export class HandshakeRejectedError extends AbyssPluginError {
  readonly code: number;
  readonly reason: string;

  constructor(code: number, reason: string) {
    super(`broker rejected plugin handshake with code ${code}: ${reason}`);
    this.name = "HandshakeRejectedError";
    this.code = code;
    this.reason = reason;
  }
}

export class UnexpectedBrokerEofError extends AbyssPluginError {
  constructor() {
    super("broker plugin stream ended without BrokerClose");
    this.name = "UnexpectedBrokerEofError";
  }
}
