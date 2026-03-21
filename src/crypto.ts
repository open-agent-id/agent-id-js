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
 *
 * Uses a cryptographically secure random private key (32-byte seed) and
 * derives the corresponding public key.
 *
 * @returns An object containing the `privateKey` (32-byte seed) and `publicKey` (32 bytes)
 *
 * @example
 * ```ts
 * const { publicKey, privateKey } = generateEd25519Keypair();
 * // publicKey: Uint8Array(32) -- encode with base64urlEncode() for API calls
 * // privateKey: Uint8Array(32) -- store securely, never share
 * ```
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
 * Sign data with an Ed25519 private key.
 *
 * Accepts either a 32-byte seed or a 64-byte expanded secret key.
 * If 64 bytes are provided, only the first 32 (the seed) are used.
 *
 * @param privateKey - Ed25519 private key (32-byte seed or 64-byte expanded key)
 * @param data - The data bytes to sign
 * @returns The 64-byte Ed25519 signature
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
 *
 * Returns `false` (rather than throwing) if the signature is malformed
 * or does not match.
 *
 * @param publicKey - The signer's 32-byte Ed25519 public key
 * @param data - The original data bytes that were signed
 * @param signature - The 64-byte Ed25519 signature to verify
 * @returns `true` if the signature is valid, `false` otherwise
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
 *
 * Produces the URL-safe base64 variant: `+` becomes `-`, `/` becomes `_`,
 * and trailing `=` padding is removed.
 *
 * @param data - The bytes to encode
 * @returns The base64url-encoded string
 *
 * @example
 * ```ts
 * const encoded = base64urlEncode(publicKey);
 * // Use in API calls: { public_key: encoded }
 * ```
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
 * Decode a base64url string to bytes.
 *
 * Handles the URL-safe base64 variant and re-adds padding as needed.
 *
 * @param s - The base64url-encoded string to decode
 * @returns The decoded bytes
 *
 * @example
 * ```ts
 * const publicKey = base64urlDecode(agent.public_key);
 * ```
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
 * Compute SHA-256 of data, returned as a lowercase hex string.
 *
 * @param data - The bytes to hash
 * @returns The SHA-256 digest as a lowercase hex string (64 characters)
 */
export function sha256(data: Uint8Array): string {
  const hash = sha256Hash(data);
  return bytesToHex(hash);
}

/**
 * Generate a random hex nonce of the given byte length.
 *
 * Uses `crypto.getRandomValues()` for cryptographically secure randomness.
 *
 * @param byteLength - Number of random bytes (default: 16, producing a 32-character hex string)
 * @returns A hex-encoded random nonce string
 *
 * @example
 * ```ts
 * const nonce = generateNonce();    // 32 hex chars (16 bytes)
 * const long = generateNonce(32);   // 64 hex chars (32 bytes)
 * ```
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
 *
 * Required for NaCl box encryption, which uses X25519 key agreement
 * rather than Ed25519 signing keys.
 *
 * @param ed25519Pub - A 32-byte Ed25519 public key
 * @returns The corresponding 32-byte X25519 public key
 * @throws Error if the conversion fails (e.g., invalid key)
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
 *
 * @param ed25519Priv - Ed25519 private key (32-byte seed or 64-byte expanded key)
 * @returns The corresponding 32-byte X25519 private key
 * @throws Error if the conversion fails
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
 * Automatically converts Ed25519 keys to X25519 for the key agreement.
 * Returns the nonce prepended to the ciphertext: `[24-byte nonce][ciphertext + 16-byte MAC]`.
 *
 * @param plaintext - The data to encrypt
 * @param recipientEd25519Pub - Recipient's 32-byte Ed25519 public key
 * @param senderEd25519Priv - Sender's Ed25519 private key (32-byte seed or 64-byte expanded)
 * @returns The encrypted payload with prepended nonce
 * @throws Error if encryption fails
 *
 * @example
 * ```ts
 * const encrypted = encryptFor(
 *   new TextEncoder().encode("hello agent"),
 *   recipientPublicKey,
 *   senderPrivateKey,
 * );
 * // Send base64urlEncode(encrypted) to the recipient
 * ```
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
 * format produced by {@link encryptFor}). Returns `null` if decryption fails
 * (wrong key or tampered data).
 *
 * @param ciphertext - The encrypted payload with prepended 24-byte nonce
 * @param senderEd25519Pub - Sender's 32-byte Ed25519 public key
 * @param recipientEd25519Priv - Recipient's Ed25519 private key (32-byte seed or 64-byte expanded)
 * @returns The decrypted plaintext bytes, or `null` if decryption fails
 *
 * @example
 * ```ts
 * const plaintext = decryptFrom(encrypted, senderPublicKey, recipientPrivateKey);
 * if (plaintext) {
 *   console.log(new TextDecoder().decode(plaintext)); // "hello agent"
 * }
 * ```
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
