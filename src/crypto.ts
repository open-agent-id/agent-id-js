import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { sha256 as sha256Hash } from "@noble/hashes/sha256";
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
export function generateEd25519Keypair(): {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
} {
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = ed.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

/**
 * Sign data with an Ed25519 private key (32-byte seed).
 */
export function ed25519Sign(
  privateKey: Uint8Array,
  data: Uint8Array,
): Uint8Array {
  const seed =
    privateKey.length === 64 ? privateKey.slice(0, 32) : privateKey;
  return ed.sign(data, seed);
}

/**
 * Verify an Ed25519 signature.
 */
export function ed25519Verify(
  publicKey: Uint8Array,
  data: Uint8Array,
  signature: Uint8Array,
): boolean {
  try {
    return ed.verify(signature, data, publicKey);
  } catch {
    return false;
  }
}

/**
 * Encode bytes to base64url (no padding).
 */
export function base64urlEncode(data: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < data.length; i++) {
    binary += String.fromCharCode(data[i]);
  }
  const base64 = btoa(binary);
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Decode base64url string to bytes.
 */
export function base64urlDecode(s: string): Uint8Array {
  let base64 = s.replace(/-/g, "+").replace(/_/g, "/");
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
 * Compute SHA-256 of data, returned as lowercase hex string.
 */
export function sha256(data: Uint8Array): string {
  const hash = sha256Hash(data);
  return bytesToHex(hash);
}

/**
 * Generate a random hex nonce of the given byte length.
 */
export function generateNonce(byteLength: number = 16): string {
  const bytes = crypto.getRandomValues(new Uint8Array(byteLength));
  return bytesToHex(bytes);
}
