import { createConnection, type Socket } from "node:net";

/**
 * Client for the oaid-signer daemon.
 *
 * The signer daemon holds private keys and performs signing operations
 * so that agent processes never need direct access to key material.
 *
 * Wire protocol: 4-byte big-endian length prefix + JSON payload.
 */
export class Signer {
  private socket: Socket;
  private responseBuffer: Buffer = Buffer.alloc(0);
  private pendingResolve: ((value: unknown) => void) | null = null;
  private pendingReject: ((reason: Error) => void) | null = null;

  private constructor(socket: Socket) {
    this.socket = socket;

    this.socket.on("data", (chunk: Buffer) => {
      this.responseBuffer = Buffer.concat([this.responseBuffer, chunk]);
      this.tryParse();
    });

    this.socket.on("error", (err: Error) => {
      if (this.pendingReject) {
        this.pendingReject(err);
        this.pendingResolve = null;
        this.pendingReject = null;
      }
    });
  }

  /**
   * Connect to the oaid-signer daemon via Unix socket.
   * @param socketPath Defaults to /tmp/oaid-signer.sock
   */
  static async connect(
    socketPath?: string,
  ): Promise<Signer> {
    const path = socketPath ?? "/tmp/oaid-signer.sock";

    return new Promise<Signer>((resolve, reject) => {
      const socket = createConnection({ path }, () => {
        resolve(new Signer(socket));
      });
      socket.on("error", (err: Error) => {
        reject(
          new Error(`Failed to connect to oaid-signer at ${path}: ${err.message}`),
        );
      });
    });
  }

  /**
   * Request the signer daemon to sign data.
   * @param keyId Key identifier known to the signer daemon
   * @param operation Operation type (e.g. "ed25519-sign")
   * @param data Raw data to sign
   * @returns The signature bytes
   */
  async sign(
    keyId: string,
    operation: string,
    data: Uint8Array,
  ): Promise<Uint8Array> {
    const request = {
      method: "sign",
      params: {
        key_id: keyId,
        operation,
        data: Buffer.from(data).toString("base64"),
      },
    };

    const response = (await this.sendRequest(request)) as {
      signature?: string;
      error?: string;
    };

    if (response.error) {
      throw new Error(`Signer error: ${response.error}`);
    }

    return Uint8Array.from(Buffer.from(response.signature!, "base64"));
  }

  /**
   * Request the public key for a given key ID.
   */
  async getPublicKey(keyId: string): Promise<Uint8Array> {
    const request = {
      method: "get_public_key",
      params: { key_id: keyId },
    };

    const response = (await this.sendRequest(request)) as {
      public_key?: string;
      error?: string;
    };

    if (response.error) {
      throw new Error(`Signer error: ${response.error}`);
    }

    return Uint8Array.from(Buffer.from(response.public_key!, "base64"));
  }

  /**
   * Close the connection to the signer daemon.
   */
  close(): void {
    this.socket.destroy();
  }

  // ---- internal ----

  private sendRequest(request: unknown): Promise<unknown> {
    return new Promise((resolve, reject) => {
      this.pendingResolve = resolve;
      this.pendingReject = reject;

      const json = JSON.stringify(request);
      const payload = Buffer.from(json, "utf-8");
      const header = Buffer.alloc(4);
      header.writeUInt32BE(payload.length, 0);

      this.socket.write(Buffer.concat([header, payload]));
    });
  }

  private tryParse(): void {
    if (this.responseBuffer.length < 4) return;

    const length = this.responseBuffer.readUInt32BE(0);
    if (this.responseBuffer.length < 4 + length) return;

    const json = this.responseBuffer.subarray(4, 4 + length).toString("utf-8");
    this.responseBuffer = this.responseBuffer.subarray(4 + length);

    try {
      const parsed = JSON.parse(json);
      if (this.pendingResolve) {
        this.pendingResolve(parsed);
        this.pendingResolve = null;
        this.pendingReject = null;
      }
    } catch (err) {
      if (this.pendingReject) {
        this.pendingReject(new Error(`Invalid JSON from signer: ${json}`));
        this.pendingResolve = null;
        this.pendingReject = null;
      }
    }
  }
}
