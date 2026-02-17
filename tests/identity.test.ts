import { describe, it, expect } from "vitest";
import { AgentIdentity } from "../src/identity.js";
import {
  hexToBytes,
  base64urlEncode,
  base64urlDecode,
  verify as cryptoVerify,
  sha256Hex,
} from "../src/crypto.js";

// Test vectors (hex values are authoritative, base64url computed from hex)
const TEST_PRIVATE_KEY_HEX =
  "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const TEST_PUBLIC_KEY_HEX =
  "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

// Compute base64url from hex (ground truth)
const TEST_PRIVATE_KEY_BASE64URL = base64urlEncode(
  hexToBytes(TEST_PRIVATE_KEY_HEX),
);
const TEST_PUBLIC_KEY_BASE64URL = base64urlEncode(
  hexToBytes(TEST_PUBLIC_KEY_HEX),
);

const TEST_DID = "did:agent:tokli:agt_a1B2c3D4e5";

describe("AgentIdentity", () => {
  describe("load", () => {
    it("should load from DID and private key", () => {
      const identity = AgentIdentity.load({
        did: TEST_DID,
        privateKey: TEST_PRIVATE_KEY_BASE64URL,
      });

      expect(identity.did).toBe(TEST_DID);
      expect(identity.publicKeyBase64url).toBe(TEST_PUBLIC_KEY_BASE64URL);
    });

    it("should throw on invalid DID", () => {
      expect(() =>
        AgentIdentity.load({
          did: "invalid",
          privateKey: TEST_PRIVATE_KEY_BASE64URL,
        }),
      ).toThrow("Invalid DID");
    });
  });

  describe("sign", () => {
    it("should sign a payload and return base64url string", () => {
      const identity = AgentIdentity.load({
        did: TEST_DID,
        privateKey: TEST_PRIVATE_KEY_BASE64URL,
      });

      const signature = identity.sign("hello world");
      expect(typeof signature).toBe("string");
      // base64url: only [A-Za-z0-9_-]
      expect(signature).toMatch(/^[A-Za-z0-9_-]+$/);

      // Verify the signature
      const sigBytes = base64urlDecode(signature);
      expect(sigBytes.length).toBe(64);

      const publicKey = hexToBytes(TEST_PUBLIC_KEY_HEX);
      const payload = new TextEncoder().encode("hello world");
      expect(cryptoVerify(payload, sigBytes, publicKey)).toBe(true);
    });

    it("should produce deterministic signatures", () => {
      const identity = AgentIdentity.load({
        did: TEST_DID,
        privateKey: TEST_PRIVATE_KEY_BASE64URL,
      });

      const sig1 = identity.sign("test payload");
      const sig2 = identity.sign("test payload");
      expect(sig1).toBe(sig2);
    });
  });

  describe("signRequest", () => {
    it("should return all required headers", () => {
      const identity = AgentIdentity.load({
        did: TEST_DID,
        privateKey: TEST_PRIVATE_KEY_BASE64URL,
      });

      const headers = identity.signRequest(
        "POST",
        "https://api.example.com/v1/tasks",
        '{"task":"search"}',
      );

      expect(headers["X-Agent-DID"]).toBe(TEST_DID);
      expect(headers["X-Agent-Timestamp"]).toBeDefined();
      expect(headers["X-Agent-Nonce"]).toBeDefined();
      expect(headers["X-Agent-Signature"]).toBeDefined();

      // Timestamp should be a recent unix timestamp
      const ts = parseInt(headers["X-Agent-Timestamp"]);
      const now = Math.floor(Date.now() / 1000);
      expect(Math.abs(ts - now)).toBeLessThan(5);

      // Nonce should be 32 hex chars (16 bytes)
      expect(headers["X-Agent-Nonce"]).toMatch(/^[0-9a-f]{32}$/);

      // Signature should be base64url
      expect(headers["X-Agent-Signature"]).toMatch(/^[A-Za-z0-9_-]+$/);
    });

    it("should produce verifiable signatures", () => {
      const identity = AgentIdentity.load({
        did: TEST_DID,
        privateKey: TEST_PRIVATE_KEY_BASE64URL,
      });

      const method = "GET";
      const url = "https://api.example.com/v1/agents";
      const headers = identity.signRequest(method, url);

      // Reconstruct the canonical payload
      const bodyHash = sha256Hex("");
      const canonical = `${method}\n${url}\n${bodyHash}\n${headers["X-Agent-Timestamp"]}\n${headers["X-Agent-Nonce"]}`;

      // Verify
      const sigBytes = base64urlDecode(headers["X-Agent-Signature"]);
      const publicKey = hexToBytes(TEST_PUBLIC_KEY_HEX);
      const payloadBytes = new TextEncoder().encode(canonical);
      expect(cryptoVerify(payloadBytes, sigBytes, publicKey)).toBe(true);
    });
  });
});
