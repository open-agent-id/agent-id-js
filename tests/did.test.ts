import { describe, it, expect } from "vitest";
import { validateDid, parseDid, formatDid } from "../src/did.js";

const VALID_DIDS = [
  "did:oaid:base:0x1234567890abcdef1234567890abcdef12345678",
  "did:oaid:ethereum:0x0000000000000000000000000000000000000000",
  "did:oaid:base:0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "did:oaid:polygon:0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
];

const INVALID_DIDS = [
  "", // empty
  "did:agent:tokli:agt_a1B2c3D4e5", // V1 format
  "did:oaid:base:0xABCD", // too short
  "did:oaid:base:1234567890abcdef1234567890abcdef12345678", // missing 0x
  "did:oaid:base:0x1234567890ABCDEF1234567890abcdef12345678", // uppercase hex
  "did:oaid:Base:0x1234567890abcdef1234567890abcdef12345678", // uppercase chain
  "did:oaid::0x1234567890abcdef1234567890abcdef12345678", // empty chain
  "did:other:base:0x1234567890abcdef1234567890abcdef12345678", // wrong method
  "did:oaid:base:0x1234567890abcdef1234567890abcdef1234567g", // invalid hex char
  "did:oaid:base:0x1234567890abcdef1234567890abcdef123456789", // 41 hex chars
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
      const result = parseDid(
        "did:oaid:base:0x1234567890abcdef1234567890abcdef12345678",
      );
      expect(result).toEqual({
        method: "oaid",
        chain: "base",
        agentAddress: "0x1234567890abcdef1234567890abcdef12345678",
      });
    });

    it("should parse DID with different chain", () => {
      const result = parseDid(
        "did:oaid:ethereum:0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
      );
      expect(result).toEqual({
        method: "oaid",
        chain: "ethereum",
        agentAddress: "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
      });
    });

    it("should throw on invalid DID", () => {
      expect(() => parseDid("invalid")).toThrow("Invalid DID");
      expect(() => parseDid("")).toThrow("Invalid DID");
      expect(() => parseDid("did:agent:tokli:agt_a1B2c3D4e5")).toThrow(
        "Invalid DID",
      );
    });
  });

  describe("formatDid", () => {
    it("should format a valid DID", () => {
      const did = formatDid(
        "base",
        "0x1234567890abcdef1234567890abcdef12345678",
      );
      expect(did).toBe(
        "did:oaid:base:0x1234567890abcdef1234567890abcdef12345678",
      );
    });

    it("should normalize address to lowercase", () => {
      const did = formatDid(
        "base",
        "0x1234567890ABCDEF1234567890ABCDEF12345678",
      );
      expect(did).toBe(
        "did:oaid:base:0x1234567890abcdef1234567890abcdef12345678",
      );
    });

    it("should normalize chain to lowercase", () => {
      const did = formatDid(
        "Base",
        "0x1234567890abcdef1234567890abcdef12345678",
      );
      expect(did).toBe(
        "did:oaid:base:0x1234567890abcdef1234567890abcdef12345678",
      );
    });

    it("should throw on invalid components", () => {
      expect(() => formatDid("", "0x1234")).toThrow("Cannot format valid DID");
      expect(() => formatDid("base", "notanaddress")).toThrow(
        "Cannot format valid DID",
      );
    });
  });
});
