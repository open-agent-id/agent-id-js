import { describe, it, expect } from "vitest";
import {
  canonicalUrl,
  canonicalJson,
  signHttpRequest,
  verifyHttpSignature,
  signMessage,
  verifyMessageSignature,
} from "../src/signing.js";
import {
  generateEd25519Keypair,
  base64urlDecode,
} from "../src/crypto.js";

describe("canonicalUrl", () => {
  it("should lowercase host", () => {
    expect(canonicalUrl("https://API.Example.COM/v1/agents")).toBe(
      "https://api.example.com/v1/agents",
    );
  });

  it("should sort query parameters by key", () => {
    expect(
      canonicalUrl("https://api.example.com/search?z=1&a=2&m=3"),
    ).toBe("https://api.example.com/search?a=2&m=3&z=1");
  });

  it("should strip fragment", () => {
    expect(canonicalUrl("https://api.example.com/page#section")).toBe(
      "https://api.example.com/page",
    );
  });

  it("should preserve path", () => {
    expect(canonicalUrl("https://api.example.com/v1/agents/some-id")).toBe(
      "https://api.example.com/v1/agents/some-id",
    );
  });

  it("should handle URL without query or fragment", () => {
    expect(canonicalUrl("https://api.example.com/v1")).toBe(
      "https://api.example.com/v1",
    );
  });
});

describe("canonicalJson", () => {
  it("should sort keys alphabetically", () => {
    expect(canonicalJson({ z: 1, a: 2, m: 3 })).toBe(
      '{"a":2,"m":3,"z":1}',
    );
  });

  it("should sort nested keys", () => {
    expect(canonicalJson({ b: { d: 1, c: 2 }, a: 3 })).toBe(
      '{"a":3,"b":{"c":2,"d":1}}',
    );
  });

  it("should handle arrays (preserve order)", () => {
    expect(canonicalJson({ items: [3, 1, 2] })).toBe(
      '{"items":[3,1,2]}',
    );
  });

  it("should handle null values", () => {
    expect(canonicalJson({ a: null, b: 1 })).toBe('{"a":null,"b":1}');
  });

  it("should handle empty object", () => {
    expect(canonicalJson({})).toBe("{}");
  });
});

describe("signHttpRequest / verifyHttpSignature", () => {
  it("should sign and verify an HTTP request", async () => {
    const { privateKey, publicKey } = generateEd25519Keypair();
    const method = "POST";
    const url = "https://api.example.com/v1/agents";
    const body = new TextEncoder().encode('{"name":"test"}');
    const timestamp = 1700000000;
    const nonce = "deadbeef";

    const headers = await signHttpRequest(
      privateKey,
      method,
      url,
      body,
      timestamp,
      nonce,
    );

    expect(headers["X-Agent-Timestamp"]).toBe("1700000000");
    expect(headers["X-Agent-Nonce"]).toBe("deadbeef");
    expect(headers["X-Agent-Signature"]).toBeTruthy();

    const sigBytes = base64urlDecode(headers["X-Agent-Signature"]);
    const valid = verifyHttpSignature(
      publicKey,
      method,
      url,
      body,
      timestamp,
      nonce,
      sigBytes,
    );
    expect(valid).toBe(true);
  });

  it("should fail verification with wrong key", async () => {
    const { privateKey } = generateEd25519Keypair();
    const { publicKey: wrongKey } = generateEd25519Keypair();

    const headers = await signHttpRequest(
      privateKey,
      "GET",
      "https://api.example.com/v1",
      null,
      1700000000,
      "abc",
    );

    const sigBytes = base64urlDecode(headers["X-Agent-Signature"]);
    const valid = verifyHttpSignature(
      wrongKey,
      "GET",
      "https://api.example.com/v1",
      null,
      1700000000,
      "abc",
      sigBytes,
    );
    expect(valid).toBe(false);
  });

  it("should fail verification with tampered body", async () => {
    const { privateKey, publicKey } = generateEd25519Keypair();
    const body = new TextEncoder().encode("original");

    const headers = await signHttpRequest(
      privateKey,
      "POST",
      "https://api.example.com/v1",
      body,
      1700000000,
      "nonce1",
    );

    const sigBytes = base64urlDecode(headers["X-Agent-Signature"]);
    const tampered = new TextEncoder().encode("tampered");
    const valid = verifyHttpSignature(
      publicKey,
      "POST",
      "https://api.example.com/v1",
      tampered,
      1700000000,
      "nonce1",
      sigBytes,
    );
    expect(valid).toBe(false);
  });

  it("should handle null body", async () => {
    const { privateKey, publicKey } = generateEd25519Keypair();

    const headers = await signHttpRequest(
      privateKey,
      "GET",
      "https://api.example.com/",
      null,
      1700000000,
      "nonce2",
    );

    const sigBytes = base64urlDecode(headers["X-Agent-Signature"]);
    const valid = verifyHttpSignature(
      publicKey,
      "GET",
      "https://api.example.com/",
      null,
      1700000000,
      "nonce2",
      sigBytes,
    );
    expect(valid).toBe(true);
  });
});

describe("signMessage / verifyMessageSignature", () => {
  it("should sign and verify a message", async () => {
    const { privateKey, publicKey } = generateEd25519Keypair();
    const msgType = "request";
    const msgId = "msg-001";
    const fromDid = "did:oaid:base:0x1234567890abcdef1234567890abcdef12345678";
    const toDids = [
      "did:oaid:base:0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
    ];
    const ref = null;
    const timestamp = 1700000000;
    const expiresAt = 1700000300;
    const body = { action: "hello", data: { value: 42 } };

    const signature = await signMessage(
      privateKey,
      msgType,
      msgId,
      fromDid,
      toDids,
      ref,
      timestamp,
      expiresAt,
      body,
    );

    const valid = verifyMessageSignature(
      publicKey,
      msgType,
      msgId,
      fromDid,
      toDids,
      ref,
      timestamp,
      expiresAt,
      body,
      signature,
    );
    expect(valid).toBe(true);
  });

  it("should sort toDids in signature", async () => {
    const { privateKey, publicKey } = generateEd25519Keypair();
    const toDids1 = [
      "did:oaid:base:0xbbbb000000000000000000000000000000000000",
      "did:oaid:base:0xaaaa000000000000000000000000000000000000",
    ];
    const toDids2 = [
      "did:oaid:base:0xaaaa000000000000000000000000000000000000",
      "did:oaid:base:0xbbbb000000000000000000000000000000000000",
    ];

    const sig1 = await signMessage(
      privateKey,
      "test",
      "id1",
      "did:oaid:base:0x1111000000000000000000000000000000000000",
      toDids1,
      null,
      1700000000,
      null,
      {},
    );

    const valid = verifyMessageSignature(
      publicKey,
      "test",
      "id1",
      "did:oaid:base:0x1111000000000000000000000000000000000000",
      toDids2,
      null,
      1700000000,
      null,
      {},
      sig1,
    );
    expect(valid).toBe(true);
  });

  it("should fail with tampered body", async () => {
    const { privateKey, publicKey } = generateEd25519Keypair();

    const signature = await signMessage(
      privateKey,
      "test",
      "id2",
      "did:oaid:base:0x1111000000000000000000000000000000000000",
      [],
      null,
      1700000000,
      null,
      { key: "value" },
    );

    const valid = verifyMessageSignature(
      publicKey,
      "test",
      "id2",
      "did:oaid:base:0x1111000000000000000000000000000000000000",
      [],
      null,
      1700000000,
      null,
      { key: "tampered" },
      signature,
    );
    expect(valid).toBe(false);
  });
});
