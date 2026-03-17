# @openagentid/sdk

JavaScript/TypeScript SDK for [Open Agent ID](https://openagentid.org) -- register, sign, and verify AI agent identities on-chain.

## Installation

```bash
npm install @openagentid/sdk
```

Requires Node.js >= 18.

## DID Format (V2)

```
did:oaid:{chain}:{address}
```

Examples:
- `did:oaid:base:0x1234567890abcdef1234567890abcdef12345678`
- `did:oaid:base-sepolia:0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef`
- `did:oaid:ethereum:0x0000000000000000000000000000000000000000`

## Quick Start

### Sign an HTTP request

```typescript
import { signHttpRequest, canonicalUrl } from "@openagentid/sdk";

// Sign with a raw Ed25519 private key
const headers = await signHttpRequest(
  privateKey,          // Uint8Array (32 bytes)
  "POST",
  "https://api.example.com/v1/tasks",
  new TextEncoder().encode('{"task":"search"}'),
);
// headers = {
//   "X-Agent-Timestamp": "1708123456",
//   "X-Agent-Nonce": "a3f1b2c4d5e6f7089012abcd",
//   "X-Agent-Signature": "<base64url signature>"
// }
```

### Verify an HTTP signature

```typescript
import { verifyHttpSignature } from "@openagentid/sdk";

const valid = verifyHttpSignature(
  publicKey,           // Uint8Array (32 bytes)
  "POST",
  "https://api.example.com/v1/tasks",
  bodyBytes,           // Uint8Array | null
  timestamp,           // number (unix seconds)
  nonce,               // string
  signature,           // Uint8Array
);
```

### Sign a P2P message

```typescript
import { signMessage } from "@openagentid/sdk";

const signature = await signMessage(
  privateKey,
  "task.request",                          // message type
  "msg-001",                               // message ID
  "did:oaid:base:0xaaaa...aaaa",           // from DID
  ["did:oaid:base:0xbbbb...bbbb"],         // to DIDs
  null,                                    // ref
  null,                                    // timestamp (auto)
  null,                                    // expiresAt
  { task: "summarize", url: "https://..." }, // body
);
```

### Use the Signer daemon

```typescript
import { Signer, Agent } from "@openagentid/sdk";

const signer = await Signer.connect("/tmp/oaid-signer.sock");
const agent = new Agent({
  keyId: "default",
  signer,
  did: "did:oaid:base:0x1234567890abcdef1234567890abcdef12345678",
});

// Signed HTTP requests via the Agent helper
const res = await agent.http.post("https://api.example.com/v1/tasks", {
  task: "search",
});
```

### Registry client

```typescript
import { RegistryClient } from "@openagentid/sdk";

const registry = new RegistryClient();

// Look up an agent
const info = await registry.getAgent("did:oaid:base:0x1234...");

// Wallet auth flow
const { challengeId, challengeText } = await registry.requestChallenge(walletAddress);
// ... sign challengeText with wallet ...
const token = await registry.verifyWallet(walletAddress, challengeId, walletSignature);

// Register an agent
const agent = await registry.registerAgent(token, {
  name: "my-agent",
  capabilities: ["search"],
  publicKey: base64urlPublicKey,
});
```

### DID utilities

```typescript
import { validateDid, parseDid, formatDid } from "@openagentid/sdk";

validateDid("did:oaid:base:0x1234...abcd");  // true
parseDid("did:oaid:base:0x1234...abcd");
// { method: "oaid", chain: "base", agentAddress: "0x1234...abcd" }
formatDid("base", "0x1234...abcd");
// "did:oaid:base:0x1234...abcd"
```

### Canonical helpers

```typescript
import { canonicalUrl, canonicalJson } from "@openagentid/sdk";

canonicalUrl("https://API.example.com/path?b=2&a=1");
// "https://api.example.com/path?a=1&b=2"

canonicalJson({ z: 1, a: 2 });
// '{"a":2,"z":1}'
```

## Exports

```typescript
// DID
export { parseDid, validateDid, formatDid, ParsedDid };

// Signing
export { signHttpRequest, verifyHttpSignature, signMessage, verifyMessageSignature, canonicalUrl, canonicalJson };

// Signer daemon client
export { Signer };

// Registry API client
export { RegistryClient, AgentInfo, AuthOptions };

// High-level Agent
export { Agent };

// Crypto utilities
export { generateEd25519Keypair, ed25519Sign, ed25519Verify, base64urlEncode, base64urlDecode, sha256, generateNonce };

// Constants
export { DEFAULT_EXPIRE_SECONDS, HTTP_TIMESTAMP_TOLERANCE, DEDUP_CACHE_TTL };
```

## Development

```bash
npm install
npm run build   # compile TypeScript
npm test        # run tests with vitest
```

## License

Apache-2.0
