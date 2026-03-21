import {
  ed25519Sign,
  ed25519Verify,
  sha256,
  base64urlEncode,
  generateNonce,
} from "./crypto.js";
import type { Signer } from "./signer.js";

const encoder = new TextEncoder();

/**
 * Produce the canonical URL for signing: scheme + host (lowercase) + path.
 *
 * Query parameters are sorted alphabetically by key. The fragment is stripped.
 * This ensures a deterministic URL representation regardless of parameter order.
 *
 * @param url - The full URL to canonicalize
 * @returns The canonical URL string with sorted query params and no fragment
 *
 * @example
 * ```ts
 * canonicalUrl("https://API.example.com/v1/tasks?b=2&a=1#frag");
 * // => "https://api.example.com/v1/tasks?a=1&b=2"
 * ```
 */
export function canonicalUrl(url: string): string {
  const parsed = new URL(url);
  // Sort query params by key
  const params = [...parsed.searchParams.entries()].sort((a, b) =>
    a[0].localeCompare(b[0]),
  );
  let result = `${parsed.protocol}//${parsed.host.toLowerCase()}${parsed.pathname}`;
  if (params.length > 0) {
    const qs = params
      .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
      .join("&");
    result += `?${qs}`;
  }
  return result;
}

/**
 * Produce deterministic canonical JSON: sorted keys, no whitespace, no undefined values.
 *
 * Keys are sorted recursively at every level of nesting. This guarantees
 * identical JSON output for semantically equivalent objects.
 *
 * @param obj - The object to serialize
 * @returns A deterministic JSON string with sorted keys
 *
 * @example
 * ```ts
 * canonicalJson({ z: 1, a: 2 });
 * // => '{"a":2,"z":1}'
 * ```
 */
export function canonicalJson(obj: Record<string, unknown>): string {
  return JSON.stringify(sortKeys(obj));
}

function sortKeys(val: unknown): unknown {
  if (val === null || val === undefined) return val;
  if (Array.isArray(val)) return val.map(sortKeys);
  if (typeof val === "object") {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(val as Record<string, unknown>).sort()) {
      sorted[key] = sortKeys((val as Record<string, unknown>)[key]);
    }
    return sorted;
  }
  return val;
}

/**
 * Sign agent authentication headers for the registry API.
 *
 * Produces the standard `X-Agent-*` headers used to authenticate agent-level
 * API requests. Uses the simple payload format: `{did}\n{timestamp}\n{nonce}`.
 *
 * @param did - The agent's DID (e.g., `"did:oaid:base:0x..."`)
 * @param privateKey - The agent's 32-byte Ed25519 private key (seed)
 * @param timestamp - Optional Unix timestamp in seconds (defaults to `Date.now() / 1000`)
 * @param nonce - Optional hex nonce string (defaults to a random 16-byte nonce)
 * @returns A headers object with `X-Agent-DID`, `X-Agent-Timestamp`, `X-Agent-Nonce`, and `X-Agent-Signature`
 *
 * @example
 * ```ts
 * const headers = signAgentAuth("did:oaid:base:0xABC", privateKey);
 * const res = await fetch("https://api.openagentid.org/v1/messages", {
 *   method: "GET",
 *   headers,
 * });
 * ```
 */
export function signAgentAuth(
  did: string,
  privateKey: Uint8Array,
  timestamp?: number,
  nonce?: string,
): Record<string, string> {
  const ts = timestamp ?? Math.floor(Date.now() / 1000);
  const n = nonce ?? generateNonce(16);
  const payload = encoder.encode(`${did}\n${ts}\n${n}`);
  const signature = ed25519Sign(privateKey, payload);
  return {
    "X-Agent-DID": did,
    "X-Agent-Timestamp": String(ts),
    "X-Agent-Nonce": n,
    "X-Agent-Signature": base64urlEncode(signature),
  };
}

/**
 * Verify agent authentication headers from the registry API.
 *
 * Reconstructs the simple payload `{did}\n{timestamp}\n{nonce}` and verifies
 * the Ed25519 signature. Does **not** check timestamp freshness -- callers
 * should enforce their own staleness window.
 *
 * @param publicKey - The agent's 32-byte Ed25519 public key
 * @param did - The agent's DID from the `X-Agent-DID` header
 * @param timestamp - Unix timestamp from the `X-Agent-Timestamp` header
 * @param nonce - Nonce string from the `X-Agent-Nonce` header
 * @param signature - Raw signature bytes (decoded from `X-Agent-Signature`)
 * @returns `true` if the signature is valid, `false` otherwise
 *
 * @example
 * ```ts
 * const valid = verifyAgentAuth(publicKey, did, timestamp, nonce, signatureBytes);
 * if (!valid) throw new Error("Invalid agent signature");
 * ```
 */
export function verifyAgentAuth(
  publicKey: Uint8Array,
  did: string,
  timestamp: number,
  nonce: string,
  signature: Uint8Array,
): boolean {
  const payload = encoder.encode(`${did}\n${timestamp}\n${nonce}`);
  return ed25519Verify(publicKey, payload, signature);
}

/**
 * Sign an HTTP request and return the authentication headers.
 *
 * Builds the canonical payload:
 * ```
 * oaid-http/v1\n{METHOD}\n{CANONICAL_URL}\n{BODY_HASH}\n{TIMESTAMP}\n{NONCE}
 * ```
 * and signs it with either a raw Ed25519 private key or a {@link Signer} instance.
 *
 * @param privateKeyOrSigner - 32-byte Ed25519 private key or a Signer instance
 * @param method - HTTP method (e.g., `"GET"`, `"POST"`)
 * @param url - Full request URL (will be canonicalized)
 * @param body - Optional request body bytes (used for body hash)
 * @param timestamp - Optional Unix timestamp in seconds (defaults to now)
 * @param nonce - Optional hex nonce string (defaults to a random 16-byte nonce)
 * @returns A headers object with `X-Agent-Timestamp`, `X-Agent-Nonce`, and `X-Agent-Signature`
 *
 * @example
 * ```ts
 * const headers = await signHttpRequest(
 *   privateKey,
 *   "POST",
 *   "https://api.example.com/v1/tasks",
 *   new TextEncoder().encode('{"task":"search"}'),
 * );
 * ```
 */
export async function signHttpRequest(
  privateKeyOrSigner: Uint8Array | Signer,
  method: string,
  url: string,
  body?: Uint8Array | null,
  timestamp?: number,
  nonce?: string,
): Promise<Record<string, string>> {
  const ts = timestamp ?? Math.floor(Date.now() / 1000);
  const n = nonce ?? generateNonce(16);
  const bodyHash = sha256(body ?? new Uint8Array(0));
  const canonical = canonicalUrl(url);

  const payload = `oaid-http/v1\n${method.toUpperCase()}\n${canonical}\n${bodyHash}\n${ts}\n${n}`;
  const payloadBytes = encoder.encode(payload);

  let signature: Uint8Array;
  if (privateKeyOrSigner instanceof Uint8Array) {
    signature = ed25519Sign(privateKeyOrSigner, payloadBytes);
  } else {
    signature = await privateKeyOrSigner.sign("default", "ed25519-sign", payloadBytes);
  }

  return {
    "X-Agent-Timestamp": String(ts),
    "X-Agent-Nonce": n,
    "X-Agent-Signature": base64urlEncode(signature),
  };
}

/**
 * Verify an HTTP request signature.
 *
 * Reconstructs the canonical payload from the request components and verifies
 * the Ed25519 signature. Does **not** check timestamp freshness.
 *
 * @param publicKey - The signer's 32-byte Ed25519 public key
 * @param method - HTTP method (e.g., `"POST"`)
 * @param url - Full request URL (will be canonicalized)
 * @param body - Request body bytes, or `null` for body-less requests
 * @param timestamp - Unix timestamp from the `X-Agent-Timestamp` header
 * @param nonce - Nonce from the `X-Agent-Nonce` header
 * @param signature - Raw signature bytes (decoded from `X-Agent-Signature`)
 * @returns `true` if the signature is valid, `false` otherwise
 */
export function verifyHttpSignature(
  publicKey: Uint8Array,
  method: string,
  url: string,
  body: Uint8Array | null,
  timestamp: number,
  nonce: string,
  signature: Uint8Array,
): boolean {
  const bodyHash = sha256(body ?? new Uint8Array(0));
  const canonical = canonicalUrl(url);

  const payload = `oaid-http/v1\n${method.toUpperCase()}\n${canonical}\n${bodyHash}\n${timestamp}\n${nonce}`;
  const payloadBytes = encoder.encode(payload);

  return ed25519Verify(publicKey, payloadBytes, signature);
}

/**
 * Sign an agent-to-agent message.
 *
 * Builds the canonical payload:
 * ```
 * oaid-msg/v1\n{TYPE}\n{ID}\n{FROM}\n{SORTED_TO}\n{REF}\n{TIMESTAMP}\n{EXPIRES_AT}\n{BODY_HASH}
 * ```
 * Recipients (`toDids`) are sorted alphabetically before inclusion. The body
 * is hashed using {@link canonicalJson} for deterministic serialization.
 *
 * @param privateKeyOrSigner - 32-byte Ed25519 private key or a Signer instance
 * @param msgType - Message type string (e.g., `"request"`, `"response"`)
 * @param msgId - Unique message identifier
 * @param fromDid - Sender's DID
 * @param toDids - Array of recipient DIDs (will be sorted for canonical form)
 * @param ref - Optional reference to a previous message ID, or `null`
 * @param timestamp - Unix timestamp in seconds, or `null` to use current time
 * @param expiresAt - Optional expiration timestamp in seconds, or `null` for no expiry
 * @param body - Message body object (will be canonicalized before hashing)
 * @returns The raw Ed25519 signature bytes
 *
 * @example
 * ```ts
 * const sig = await signMessage(
 *   privateKey,
 *   "request",
 *   "msg-123",
 *   "did:oaid:base:0xSender",
 *   ["did:oaid:base:0xRecipient"],
 *   null,
 *   null,
 *   null,
 *   { task: "summarize", url: "https://example.com" },
 * );
 * ```
 */
export async function signMessage(
  privateKeyOrSigner: Uint8Array | Signer,
  msgType: string,
  msgId: string,
  fromDid: string,
  toDids: string[],
  ref: string | null,
  timestamp: number | null,
  expiresAt: number | null,
  body: Record<string, unknown>,
): Promise<Uint8Array> {
  const ts = timestamp ?? Math.floor(Date.now() / 1000);
  const sortedTo = [...toDids].sort().join(",");
  const bodyHash = sha256(encoder.encode(canonicalJson(body)));

  const payload = [
    "oaid-msg/v1",
    msgType,
    msgId,
    fromDid,
    sortedTo,
    ref ?? "",
    String(ts),
    expiresAt != null ? String(expiresAt) : "",
    bodyHash,
  ].join("\n");

  const payloadBytes = encoder.encode(payload);

  if (privateKeyOrSigner instanceof Uint8Array) {
    return ed25519Sign(privateKeyOrSigner, payloadBytes);
  } else {
    return privateKeyOrSigner.sign("default", "ed25519-sign", payloadBytes);
  }
}

/**
 * Verify an agent-to-agent message signature.
 *
 * Reconstructs the canonical message payload and verifies the Ed25519 signature.
 * The `toDids` are sorted and the `body` is canonicalized the same way as in
 * {@link signMessage}.
 *
 * @param publicKey - The sender's 32-byte Ed25519 public key
 * @param msgType - Message type string (e.g., `"request"`, `"response"`)
 * @param msgId - Unique message identifier
 * @param fromDid - Sender's DID
 * @param toDids - Array of recipient DIDs
 * @param ref - Reference to a previous message ID, or `null`
 * @param timestamp - Unix timestamp from the message
 * @param expiresAt - Expiration timestamp, or `null`
 * @param body - Message body object
 * @param signature - Raw signature bytes to verify
 * @returns `true` if the signature is valid, `false` otherwise
 */
export function verifyMessageSignature(
  publicKey: Uint8Array,
  msgType: string,
  msgId: string,
  fromDid: string,
  toDids: string[],
  ref: string | null,
  timestamp: number,
  expiresAt: number | null,
  body: Record<string, unknown>,
  signature: Uint8Array,
): boolean {
  const sortedTo = [...toDids].sort().join(",");
  const bodyHash = sha256(encoder.encode(canonicalJson(body)));

  const payload = [
    "oaid-msg/v1",
    msgType,
    msgId,
    fromDid,
    sortedTo,
    ref ?? "",
    String(timestamp),
    expiresAt != null ? String(expiresAt) : "",
    bodyHash,
  ].join("\n");

  const payloadBytes = encoder.encode(payload);

  return ed25519Verify(publicKey, payloadBytes, signature);
}
