import { describe, it, expect } from "vitest";
import { sha256Hex, hexToBytes, sign, verify, base64urlEncode, base64urlDecode } from "../src/crypto.js";

// Test vectors from vectors.json
const TEST_PRIVATE_KEY_HEX =
  "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const TEST_PUBLIC_KEY_HEX =
  "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

describe("signing", () => {
  describe("canonical payload construction", () => {
    it("GET request with no body", () => {
      const method = "GET";
      const url =
        "https://api.example.com/v1/agents/did:agent:tokli:agt_a1B2c3D4e5";
      const body = "";
      const timestamp = 1708123456;
      const nonce = "a3f1b2c4d5e6f708";

      const bodyHash = sha256Hex(body);
      const canonical = `${method}\n${url}\n${bodyHash}\n${timestamp}\n${nonce}`;

      expect(canonical).toBe(
        "GET\nhttps://api.example.com/v1/agents/did:agent:tokli:agt_a1B2c3D4e5\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n1708123456\na3f1b2c4d5e6f708",
      );
    });

    it("POST request with JSON body", () => {
      const method = "POST";
      const url = "https://api.example.com/v1/tasks";
      const body = '{"task":"search"}';
      const timestamp = 1708123456;
      const nonce = "b4f2c3d5e6a7f809";

      const bodyHash = sha256Hex(body);
      expect(bodyHash).toBe(
        "0dfd9a0e52fe94a5e6311a6ef4643304c65636ae7fc316a0334e91c9665370af",
      );

      const canonical = `${method}\n${url}\n${bodyHash}\n${timestamp}\n${nonce}`;

      expect(canonical).toBe(
        "POST\nhttps://api.example.com/v1/tasks\n0dfd9a0e52fe94a5e6311a6ef4643304c65636ae7fc316a0334e91c9665370af\n1708123456\nb4f2c3d5e6a7f809",
      );
    });
  });

  describe("sign and verify canonical payload", () => {
    it("should sign and verify a canonical GET payload", () => {
      const privateKey = hexToBytes(TEST_PRIVATE_KEY_HEX);
      const publicKey = hexToBytes(TEST_PUBLIC_KEY_HEX);

      const canonical =
        "GET\nhttps://api.example.com/v1/agents/did:agent:tokli:agt_a1B2c3D4e5\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n1708123456\na3f1b2c4d5e6f708";

      const payloadBytes = new TextEncoder().encode(canonical);
      const signature = sign(payloadBytes, privateKey);

      expect(verify(payloadBytes, signature, publicKey)).toBe(true);
    });

    it("should sign and verify a canonical POST payload", () => {
      const privateKey = hexToBytes(TEST_PRIVATE_KEY_HEX);
      const publicKey = hexToBytes(TEST_PUBLIC_KEY_HEX);

      const canonical =
        "POST\nhttps://api.example.com/v1/tasks\nd1bc8d3ba4afc7e109612cb73acbdddac052c93025aa1f82942edabb7deb82a1\n1708123456\nb4f2c3d5e6a7f809";

      const payloadBytes = new TextEncoder().encode(canonical);
      const signature = sign(payloadBytes, privateKey);

      expect(verify(payloadBytes, signature, publicKey)).toBe(true);
    });

    it("should round-trip signature through base64url encoding", () => {
      const privateKey = hexToBytes(TEST_PRIVATE_KEY_HEX);
      const publicKey = hexToBytes(TEST_PUBLIC_KEY_HEX);

      const canonical =
        "POST\nhttps://api.example.com/v1/tasks\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n1708123456\na3f1b2c4d5e6f708";

      const payloadBytes = new TextEncoder().encode(canonical);
      const signature = sign(payloadBytes, privateKey);

      // Encode and decode through base64url
      const encoded = base64urlEncode(signature);
      const decoded = base64urlDecode(encoded);

      expect(verify(payloadBytes, decoded, publicKey)).toBe(true);
    });
  });
});
