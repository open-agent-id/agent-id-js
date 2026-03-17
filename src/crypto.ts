import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { sha256 as sha256Hash } from "@noble/hashes/sha256";
import { bytesToHex } from "@noble/hashes/utils";
import nacl from "tweetnacl";
import ed2curve from "ed2curve";

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

// ---------------------------------------------------------------------------
// End-to-end encryption (NaCl box: X25519-XSalsa20-Poly1305)
// ---------------------------------------------------------------------------

/**
 * Convert an Ed25519 public key to an X25519 public key for encryption.
 */
export function ed25519ToX25519Public(ed25519Pub: Uint8Array): Uint8Array {
  const result = ed2curve.convertPublicKey(ed25519Pub);
  if (!result) {
    throw new Error("failed to convert Ed25519 public key to X25519");
  }
  return result;
}

/**
 * Convert an Ed25519 private key (32-byte seed) to an X25519 private key.
 *
 * Accepts either a 32-byte seed or a 64-byte expanded secret key.
 * If a 32-byte seed is provided it is first expanded via
 * `nacl.sign.keyPair.fromSeed`.
 */
export function ed25519ToX25519Private(ed25519Priv: Uint8Array): Uint8Array {
  const sk64 =
    ed25519Priv.length === 64
      ? ed25519Priv
      : nacl.sign.keyPair.fromSeed(ed25519Priv).secretKey;
  const result = ed2curve.convertSecretKey(sk64);
  if (!result) {
    throw new Error("failed to convert Ed25519 private key to X25519");
  }
  return result;
}

/**
 * Encrypt plaintext for a recipient using NaCl box (X25519-XSalsa20-Poly1305).
 *
 * Returns `[24-byte nonce][ciphertext + 16-byte MAC]`.
 */
export function encryptFor(
  plaintext: Uint8Array,
  recipientEd25519Pub: Uint8Array,
  senderEd25519Priv: Uint8Array,
): Uint8Array {
  const senderX25519 = ed25519ToX25519Private(senderEd25519Priv);
  const recipientX25519 = ed25519ToX25519Public(recipientEd25519Pub);
  const nonce = nacl.randomBytes(nacl.box.nonceLength);
  const encrypted = nacl.box(plaintext, nonce, recipientX25519, senderX25519);
  if (!encrypted) {
    throw new Error("encryption failed");
  }
  const result = new Uint8Array(nonce.length + encrypted.length);
  result.set(nonce);
  result.set(encrypted, nonce.length);
  return result;
}

/**
 * Decrypt ciphertext from a sender using NaCl box.
 *
 * The ciphertext must include the 24-byte nonce prefix (standard NaCl box
 * format). Returns `null` if decryption fails (wrong key / tampered data).
 */
export function decryptFrom(
  ciphertext: Uint8Array,
  senderEd25519Pub: Uint8Array,
  recipientEd25519Priv: Uint8Array,
): Uint8Array | null {
  const recipientX25519 = ed25519ToX25519Private(recipientEd25519Priv);
  const senderX25519 = ed25519ToX25519Public(senderEd25519Pub);
  const nonce = ciphertext.slice(0, nacl.box.nonceLength);
  const message = ciphertext.slice(nacl.box.nonceLength);
  return nacl.box.open(message, nonce, senderX25519, recipientX25519);
}
