import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex } from "@noble/hashes/utils";

// ed25519 v2 requires setting the sha512 hash function
ed.etc.sha512Sync = (...m: Uint8Array[]) => {
  const h = sha512.create();
  for (const msg of m) h.update(msg);
  return h.digest();
};

/**
 * Generate a new Ed25519 keypair.
 */
export function generateKeypair(): {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
} {
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = ed.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

/**
 * Sign a payload with an Ed25519 private key.
 * The privateKey should be the 32-byte seed (or 64-byte expanded key).
 */
export function sign(payload: Uint8Array, privateKey: Uint8Array): Uint8Array {
  // Use the first 32 bytes as the seed if a 64-byte key is provided
  const seed = privateKey.length === 64 ? privateKey.slice(0, 32) : privateKey;
  return ed.sign(payload, seed);
}

/**
 * Verify an Ed25519 signature.
 */
export function verify(
  payload: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  try {
    return ed.verify(signature, payload, publicKey);
  } catch {
    return false;
  }
}

/**
 * Compute SHA-256 hex digest of a string.
 */
export function sha256Hex(input: string): string {
  const data = new TextEncoder().encode(input);
  const hash = sha256(data);
  return bytesToHex(hash);
}

/**
 * Encode bytes to base64url (no padding).
 */
export function base64urlEncode(bytes: Uint8Array): string {
  // Convert to regular base64 first
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const base64 = btoa(binary);
  // Convert to base64url: replace + with -, / with _, remove =
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Decode base64url string to bytes.
 */
export function base64urlDecode(str: string): Uint8Array {
  // Convert from base64url to regular base64
  let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  // Add padding
  while (base64.length % 4 !== 0) {
    base64 += "=";
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Convert a hex string to bytes.
 */
export function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Convert bytes to a hex string.
 */
export function bytesToHexString(bytes: Uint8Array): string {
  return bytesToHex(bytes);
}

/**
 * Generate a random hex nonce of the given byte length.
 */
export function generateNonce(byteLength: number = 16): string {
  const bytes = crypto.getRandomValues(new Uint8Array(byteLength));
  return bytesToHex(bytes);
}
