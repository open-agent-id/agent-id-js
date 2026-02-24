import type { Signer } from "./signer.js";
import { signHttpRequest } from "./signing.js";

/**
 * High-level Agent class that uses an oaid-signer for all signing operations.
 */
export class Agent {
  private readonly keyId: string;
  private readonly signer: Signer;
  private readonly registryUrl: string;
  private agentDid: string | undefined;

  readonly http: {
    get: (url: string, opts?: RequestInit) => Promise<Response>;
    post: (url: string, body?: unknown, opts?: RequestInit) => Promise<Response>;
  };

  constructor(opts: {
    keyId: string;
    signer: Signer;
    did?: string;
    registryUrl?: string;
  }) {
    this.keyId = opts.keyId;
    this.signer = opts.signer;
    this.agentDid = opts.did;
    this.registryUrl = opts.registryUrl ?? "https://api.openagentid.org";

    // Bind HTTP helpers
    this.http = {
      get: (url: string, opts?: RequestInit) => this.request("GET", url, undefined, opts),
      post: (url: string, body?: unknown, opts?: RequestInit) => this.request("POST", url, body, opts),
    };
  }

  get did(): string {
    if (!this.agentDid) {
      throw new Error("Agent DID not set. Provide did in constructor options or call registerAgent first.");
    }
    return this.agentDid;
  }

  /**
   * Sign raw data using the signer daemon.
   */
  async sign(data: Uint8Array): Promise<Uint8Array> {
    return this.signer.sign(this.keyId, "ed25519-sign", data);
  }

  /**
   * Send a message to another agent via the registry relay.
   */
  async send(
    to: string,
    message: Record<string, unknown>,
  ): Promise<unknown> {
    const url = `${this.registryUrl}/v1/messages`;
    const body = JSON.stringify({ to, from: this.did, message });
    const bodyBytes = new TextEncoder().encode(body);

    const headers = await signHttpRequest(this.signer, "POST", url, bodyBytes);
    headers["X-Agent-DID"] = this.did;
    headers["Content-Type"] = "application/json";

    const res = await fetch(url, {
      method: "POST",
      headers,
      body,
    });

    if (!res.ok) {
      throw new Error(`Send failed (${res.status}): ${await res.text()}`);
    }

    return res.json();
  }

  // ---- internal ----

  private async request(
    method: string,
    url: string,
    body?: unknown,
    opts?: RequestInit,
  ): Promise<Response> {
    let bodyBytes: Uint8Array | null = null;
    let bodyStr: string | undefined;

    if (body !== undefined) {
      bodyStr = JSON.stringify(body);
      bodyBytes = new TextEncoder().encode(bodyStr);
    }

    const signedHeaders = await signHttpRequest(
      this.signer,
      method,
      url,
      bodyBytes,
    );

    const headers: Record<string, string> = {
      ...signedHeaders,
      "X-Agent-DID": this.did,
    };

    if (bodyStr !== undefined) {
      headers["Content-Type"] = "application/json";
    }

    // Merge any user-provided headers
    if (opts?.headers) {
      const userHeaders =
        opts.headers instanceof Headers
          ? Object.fromEntries(opts.headers.entries())
          : (opts.headers as Record<string, string>);
      Object.assign(headers, userHeaders);
    }

    return fetch(url, {
      ...opts,
      method,
      headers,
      body: bodyStr,
    });
  }
}
