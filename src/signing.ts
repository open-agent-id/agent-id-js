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
 * Query parameters are sorted by key. Fragment is stripped.
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
 * Uses the simple payload format: {did}\n{timestamp}\n{nonce}
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
 * Reconstructs the simple payload {did}\n{timestamp}\n{nonce} and verifies
 * the Ed25519 signature. Does *not* check timestamp freshness.
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
 * Canonical payload:
 *   oaid-http/v1\n{METHOD}\n{CANONICAL_URL}\n{BODY_HASH}\n{TIMESTAMP}\n{NONCE}
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
 * Canonical payload:
 *   oaid-msg/v1\n{TYPE}\n{ID}\n{FROM}\n{SORTED_TO}\n{REF}\n{TIMESTAMP}\n{EXPIRES_AT}\n{BODY_HASH}
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
