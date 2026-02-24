import { describe, it, expect } from "vitest";
import {
  generateEd25519Keypair,
  ed25519Sign,
  ed25519Verify,
  base64urlEncode,
  base64urlDecode,
  sha256,
  generateNonce,
} from "../src/crypto.js";

describe("crypto", () => {
  describe("generateEd25519Keypair", () => {
    it("should generate a keypair with correct lengths", () => {
      const { privateKey, publicKey } = generateEd25519Keypair();
      expect(privateKey.length).toBe(32);
      expect(publicKey.length).toBe(32);
    });

    it("should generate unique keypairs", () => {
      const kp1 = generateEd25519Keypair();
      const kp2 = generateEd25519Keypair();
      expect(kp1.privateKey).not.toEqual(kp2.privateKey);
      expect(kp1.publicKey).not.toEqual(kp2.publicKey);
    });
  });

  describe("ed25519Sign / ed25519Verify", () => {
    it("should sign and verify", () => {
      const { privateKey, publicKey } = generateEd25519Keypair();
      const data = new TextEncoder().encode("hello world");
      const sig = ed25519Sign(privateKey, data);
      expect(sig.length).toBe(64);
      expect(ed25519Verify(publicKey, data, sig)).toBe(true);
    });

    it("should fail verification with wrong data", () => {
      const { privateKey, publicKey } = generateEd25519Keypair();
      const data = new TextEncoder().encode("hello");
      const sig = ed25519Sign(privateKey, data);
      const wrong = new TextEncoder().encode("world");
      expect(ed25519Verify(publicKey, wrong, sig)).toBe(false);
    });

    it("should fail verification with wrong key", () => {
      const kp1 = generateEd25519Keypair();
      const kp2 = generateEd25519Keypair();
      const data = new TextEncoder().encode("test");
      const sig = ed25519Sign(kp1.privateKey, data);
      expect(ed25519Verify(kp2.publicKey, data, sig)).toBe(false);
    });
  });

  describe("base64url", () => {
    it("should roundtrip encode/decode", () => {
      const original = new Uint8Array([0, 1, 2, 255, 254, 253]);
      const encoded = base64urlEncode(original);
      const decoded = base64urlDecode(encoded);
      expect(decoded).toEqual(original);
    });

    it("should produce no padding", () => {
      const data = new Uint8Array([1, 2, 3]);
      const encoded = base64urlEncode(data);
      expect(encoded).not.toContain("=");
    });

    it("should use URL-safe characters", () => {
      const data = new Uint8Array([251, 255, 254]);
      const encoded = base64urlEncode(data);
      expect(encoded).not.toContain("+");
      expect(encoded).not.toContain("/");
    });

    it("should handle empty input", () => {
      const encoded = base64urlEncode(new Uint8Array(0));
      expect(encoded).toBe("");
      const decoded = base64urlDecode("");
      expect(decoded).toEqual(new Uint8Array(0));
    });
  });

  describe("sha256", () => {
    it("should produce lowercase hex", () => {
      const data = new TextEncoder().encode("hello");
      const hash = sha256(data);
      expect(hash).toMatch(/^[0-9a-f]{64}$/);
    });

    it("should produce correct hash for empty input", () => {
      const hash = sha256(new Uint8Array(0));
      expect(hash).toBe(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      );
    });

    it("should produce correct hash for 'hello'", () => {
      const data = new TextEncoder().encode("hello");
      const hash = sha256(data);
      expect(hash).toBe(
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
      );
    });
  });

  describe("generateNonce", () => {
    it("should generate a hex string of correct length", () => {
      const nonce = generateNonce(16);
      expect(nonce.length).toBe(32);
      expect(/^[0-9a-f]+$/.test(nonce)).toBe(true);
    });

    it("should generate unique nonces", () => {
      const n1 = generateNonce();
      const n2 = generateNonce();
      expect(n1).not.toBe(n2);
    });
  });
});
