import * as ed from "@noble/ed25519";
import {
  sign as cryptoSign,
  verify as cryptoVerify,
  sha256Hex,
  base64urlEncode,
  base64urlDecode,
  generateNonce,
} from "./crypto.js";
import { validateDid } from "./did.js";
import {
  registerAgent,
  getAgent,
  type AgentInfo,
  type RegisterOptions,
} from "./client.js";
import { PublicKeyCache } from "./cache.js";

const cache = new PublicKeyCache();

export class AgentIdentity {
  readonly did: string;
  readonly publicKeyBase64url: string;

  private readonly privateKey: Uint8Array | null;
  private readonly publicKey: Uint8Array;

  private constructor(
    did: string,
    privateKey: Uint8Array | null,
    publicKey: Uint8Array,
  ) {
    this.did = did;
    this.privateKey = privateKey;
    this.publicKey = publicKey;
    this.publicKeyBase64url = base64urlEncode(publicKey);
  }

  /**
   * Register a new agent identity with the registry.
   * Returns an AgentIdentity with signing capabilities.
   */
  static async register(options: RegisterOptions): Promise<AgentIdentity> {
    const result = await registerAgent(options);

    const publicKey = base64urlDecode(result.public_key);
    const privateKey = base64urlDecode(result.private_key);

    return new AgentIdentity(result.did, privateKey, publicKey);
  }

  /**
   * Load an existing agent identity from a DID and private key.
   * The private key should be base64url-encoded.
   */
  static load(options: { did: string; privateKey: string }): AgentIdentity {
    if (!validateDid(options.did)) {
      throw new Error(`Invalid DID: ${options.did}`);
    }

    const privateKeyBytes = base64urlDecode(options.privateKey);

    // Extract the public key from the private key.
    // For Ed25519, the 64-byte "private key" is seed (32) + public key (32).
    let publicKey: Uint8Array;
    if (privateKeyBytes.length === 64) {
      publicKey = privateKeyBytes.slice(32);
    } else if (privateKeyBytes.length === 32) {
      // If only the seed is provided, derive the public key
      publicKey = ed.getPublicKey(privateKeyBytes);
    } else {
      throw new Error(
        `Invalid private key length: expected 32 or 64 bytes, got ${privateKeyBytes.length}`,
      );
    }

    return new AgentIdentity(options.did, privateKeyBytes, publicKey);
  }

  /**
   * Sign a payload string and return the base64url-encoded signature.
   */
  sign(payload: string): string {
    if (!this.privateKey) {
      throw new Error("Cannot sign: no private key available");
    }
    const payloadBytes = new TextEncoder().encode(payload);
    const signature = cryptoSign(payloadBytes, this.privateKey);
    return base64urlEncode(signature);
  }

  /**
   * Sign an HTTP request and return the required headers.
   *
   * Canonical payload format:
   *   {method}\n{url}\n{body_hash}\n{timestamp}\n{nonce}
   */
  signRequest(
    method: string,
    url: string,
    body?: string,
  ): Record<string, string> {
    if (!this.privateKey) {
      throw new Error("Cannot sign: no private key available");
    }

    const timestamp = Math.floor(Date.now() / 1000).toString();
    const nonce = generateNonce(16);
    const bodyHash = sha256Hex(body ?? "");

    const canonicalPayload = `${method.toUpperCase()}\n${url}\n${bodyHash}\n${timestamp}\n${nonce}`;

    const signature = this.sign(canonicalPayload);

    return {
      "X-Agent-DID": this.did,
      "X-Agent-Timestamp": timestamp,
      "X-Agent-Nonce": nonce,
      "X-Agent-Signature": signature,
    };
  }

  /**
   * Verify a signature against a DID's public key.
   * Fetches the public key from cache or registry API.
   */
  static async verify(options: {
    did: string;
    payload: string;
    signature: string;
    apiUrl?: string;
  }): Promise<boolean> {
    const { did, payload, signature, apiUrl } = options;

    // Try cache first
    let publicKey = cache.get(did);

    if (!publicKey) {
      // Fetch from registry
      try {
        const agentInfo = await getAgent(did, apiUrl);
        publicKey = base64urlDecode(agentInfo.public_key);
        cache.set(did, publicKey);
      } catch {
        return false;
      }
    }

    const payloadBytes = new TextEncoder().encode(payload);
    const signatureBytes = base64urlDecode(signature);

    return cryptoVerify(payloadBytes, signatureBytes, publicKey);
  }

  /**
   * Look up agent information by DID.
   */
  static async lookup(did: string, apiUrl?: string): Promise<AgentInfo> {
    return getAgent(did, apiUrl);
  }
}

export type { AgentInfo };
