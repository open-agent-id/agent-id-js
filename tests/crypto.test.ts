import { describe, it, expect } from "vitest";
import {
  generateKeypair,
  sign,
  verify,
  sha256Hex,
  base64urlEncode,
  base64urlDecode,
  hexToBytes,
  bytesToHexString,
  generateNonce,
} from "../src/crypto.js";

// Test vectors from the protocol spec
const TEST_PRIVATE_KEY_HEX =
  "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const TEST_PUBLIC_KEY_HEX =
  "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const TEST_PUBLIC_KEY_BASE64URL =
  "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";

describe("crypto", () => {
  describe("generateKeypair", () => {
    it("should generate a valid keypair", () => {
      const kp = generateKeypair();
      expect(kp.privateKey).toBeInstanceOf(Uint8Array);
      expect(kp.publicKey).toBeInstanceOf(Uint8Array);
      expect(kp.privateKey.length).toBe(32);
      expect(kp.publicKey.length).toBe(32);
    });

    it("should generate different keypairs each time", () => {
      const kp1 = generateKeypair();
      const kp2 = generateKeypair();
      expect(bytesToHexString(kp1.privateKey)).not.toBe(
        bytesToHexString(kp2.privateKey),
      );
    });
  });

  describe("sign and verify", () => {
    it("should sign and verify with generated keypair", () => {
      const kp = generateKeypair();
      const payload = new TextEncoder().encode("hello world");
      const signature = sign(payload, kp.privateKey);
      expect(signature).toBeInstanceOf(Uint8Array);
      expect(signature.length).toBe(64);
      expect(verify(payload, signature, kp.publicKey)).toBe(true);
    });

    it("should fail verification with wrong public key", () => {
      const kp1 = generateKeypair();
      const kp2 = generateKeypair();
      const payload = new TextEncoder().encode("hello world");
      const signature = sign(payload, kp1.privateKey);
      expect(verify(payload, signature, kp2.publicKey)).toBe(false);
    });

    it("should fail verification with wrong payload", () => {
      const kp = generateKeypair();
      const payload = new TextEncoder().encode("hello world");
      const wrong = new TextEncoder().encode("wrong payload");
      const signature = sign(payload, kp.privateKey);
      expect(verify(wrong, signature, kp.publicKey)).toBe(false);
    });

    it("should produce correct signature for empty payload (test vector)", () => {
      const privateKey = hexToBytes(TEST_PRIVATE_KEY_HEX);
      const publicKey = hexToBytes(TEST_PUBLIC_KEY_HEX);
      const payload = new Uint8Array(0);
      const signature = sign(payload, privateKey);
      const expectedHex =
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
      expect(bytesToHexString(signature)).toBe(expectedHex);
      expect(verify(payload, signature, publicKey)).toBe(true);
    });
  });

  describe("sha256Hex", () => {
    it("should compute SHA-256 of empty string", () => {
      expect(sha256Hex("")).toBe(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      );
    });

    it("should compute SHA-256 of JSON body", () => {
      expect(sha256Hex('{"task":"search"}')).toBe(
        "0dfd9a0e52fe94a5e6311a6ef4643304c65636ae7fc316a0334e91c9665370af",
      );
    });
  });

  describe("base64url", () => {
    it("should round-trip encode/decode", () => {
      const original = hexToBytes(TEST_PUBLIC_KEY_HEX);
      const encoded = base64urlEncode(original);
      const decoded = base64urlDecode(encoded);
      expect(bytesToHexString(decoded)).toBe(TEST_PUBLIC_KEY_HEX);
    });

    it("should encode test vector public key correctly", () => {
      const publicKey = hexToBytes(TEST_PUBLIC_KEY_HEX);
      expect(base64urlEncode(publicKey)).toBe(TEST_PUBLIC_KEY_BASE64URL);
    });

    it("should decode test vector public key correctly", () => {
      const decoded = base64urlDecode(TEST_PUBLIC_KEY_BASE64URL);
      expect(bytesToHexString(decoded)).toBe(TEST_PUBLIC_KEY_HEX);
    });
  });

  describe("hexToBytes / bytesToHexString", () => {
    it("should round-trip", () => {
      const hex = "deadbeef01020304";
      expect(bytesToHexString(hexToBytes(hex))).toBe(hex);
    });
  });

  describe("generateNonce", () => {
    it("should generate a hex string of correct length", () => {
      const nonce = generateNonce(16);
      expect(nonce.length).toBe(32); // 16 bytes = 32 hex chars
      expect(/^[0-9a-f]+$/.test(nonce)).toBe(true);
    });

    it("should generate unique nonces", () => {
      const n1 = generateNonce();
      const n2 = generateNonce();
      expect(n1).not.toBe(n2);
    });
  });
});
