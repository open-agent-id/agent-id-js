import { describe, it, expect } from "vitest";
import { validateDid, parseDid, generateUniqueId } from "../src/did.js";

// Test vectors from vectors.json
const VALID_DIDS = [
  "did:agent:tokli:agt_a1B2c3D4e5",
  "did:agent:openai:agt_X9yZ8wV7u6",
  "did:agent:langchain:agt_Q3rS4tU5v6",
  "did:agent:abc:agt_0000000000",
];

const INVALID_DIDS = [
  "did:agent:AB:agt_a1B2c3D4e5", // platform too short (2 chars) and uppercase
  "did:agent:toolongplatformnamehere:agt_a1B2c3D4e5", // platform too long
  "did:agent:tokli:a1B2c3D4e5", // missing agt_ prefix
  "did:agent:tokli:agt_short", // unique ID too short
  "did:agent:tokli:agt_a1B2c3D4e5!", // invalid character
  "did:other:tokli:agt_a1B2c3D4e5", // wrong method
  "did:agent:UPPER:agt_a1B2c3D4e5", // uppercase platform
  "", // empty string
];

describe("did", () => {
  describe("validateDid", () => {
    it.each(VALID_DIDS)("should accept valid DID: %s", (did) => {
      expect(validateDid(did)).toBe(true);
    });

    it.each(INVALID_DIDS)("should reject invalid DID: '%s'", (did) => {
      expect(validateDid(did)).toBe(false);
    });
  });

  describe("parseDid", () => {
    it("should parse a valid DID", () => {
      const result = parseDid("did:agent:tokli:agt_a1B2c3D4e5");
      expect(result).toEqual({
        method: "agent",
        platform: "tokli",
        uniqueId: "agt_a1B2c3D4e5",
      });
    });

    it("should parse DID with longer platform name", () => {
      const result = parseDid("did:agent:langchain:agt_Q3rS4tU5v6");
      expect(result).toEqual({
        method: "agent",
        platform: "langchain",
        uniqueId: "agt_Q3rS4tU5v6",
      });
    });

    it("should throw on invalid DID", () => {
      expect(() => parseDid("invalid")).toThrow("Invalid DID");
      expect(() => parseDid("")).toThrow("Invalid DID");
    });
  });

  describe("generateUniqueId", () => {
    it("should generate ID with correct format", () => {
      const id = generateUniqueId();
      expect(id).toMatch(/^agt_[0-9A-Za-z]{10}$/);
    });

    it("should generate unique IDs", () => {
      const ids = new Set(Array.from({ length: 100 }, () => generateUniqueId()));
      expect(ids.size).toBe(100);
    });
  });
});
