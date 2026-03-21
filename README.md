# @open-agent-id/sdk

JavaScript/TypeScript SDK for [Open Agent ID](https://openagentid.org) -- register, sign, and verify AI agent identities on-chain.

## Installation

```bash
npm install @open-agent-id/sdk
```

Requires Node.js >= 18.

## Quick Start

The most common use case is adding agent authentication headers to outbound requests:

```typescript
import { signAgentAuth } from "@open-agent-id/sdk";

const headers = signAgentAuth(
  "did:oaid:base:0x1234567890abcdef1234567890abcdef12345678",
  privateKey, // Uint8Array (32 bytes)
);
// Returns object with:
//   "X-Agent-DID":       "did:oaid:base:0x1234..."
//   "X-Agent-Timestamp": "1708123456"
//   "X-Agent-Nonce":     "a3f1b2c4d5e6f7089012abcd"
//   "X-Agent-Signature": "<base64url signature>"

const res = await fetch("https://api.example.com/v1/tasks", {
  method: "POST",
  headers,
  body: JSON.stringify({ task: "search" }),
});
```

## Registry Client

```typescript
import { RegistryClient } from "@open-agent-id/sdk";

const client = new RegistryClient(); // defaults to https://api.openagentid.org
```

### All methods

| Method | Auth required | Description |
|---|---|---|
| `client.requestChallenge(walletAddress)` | No | Request a wallet auth challenge |
| `client.verifyWallet(walletAddress, challengeId, signature)` | No | Verify wallet signature, returns auth token |
| `client.registerAgent(token, opts)` | Yes | Register a new agent (`opts: { name, publicKey, capabilities? }`) |
| `client.getAgent(did)` | No | Look up an agent by DID |
| `client.listAgents(token, opts?)` | Yes | List agents owned by the authenticated wallet |
| `client.updateAgent(did, auth, updates)` | Yes | Update agent metadata |
| `client.revokeAgent(did, token)` | Yes | Revoke an agent identity |
| `client.rotateKey(did, token, publicKey)` | Yes | Rotate an agent's public key |
| `client.deployWallet(did, token)` | Yes | Deploy an on-chain smart wallet for an agent |
| `client.getCredit(did)` | No | Look up an agent's credit score |
| `client.verifySignature(did, domain, payload, signature)` | No | Verify a signature against the agent's registered key |

### Wallet auth flow

```typescript
// 1. Request challenge
const { challengeId, challengeText } = await client.requestChallenge(walletAddress);

// 2. Sign the challenge text with your wallet (e.g. via ethers.js)
// const walletSignature = await wallet.signMessage(challengeText);

// 3. Verify and get auth token
const token = await client.verifyWallet(walletAddress, challengeId, walletSignature);
```

### Register an agent

```typescript
const agent = await client.registerAgent(token, {
  name: "my-agent",
  publicKey: base64urlPublicKey,
  capabilities: ["search", "summarize"],
});
```

### Look up and list agents

```typescript
const info = await client.getAgent("did:oaid:base:0x1234...");
const { agents, nextCursor } = await client.listAgents(token);
```

### Manage agents

```typescript
await client.updateAgent(did, { token }, { name: "new-name" });
await client.rotateKey(did, token, newPublicKey);
await client.revokeAgent(did, token);
await client.deployWallet(did, token);
```

## Credit Score

```typescript
const credit = await client.getCredit("did:oaid:base:0x1234567890abcdef1234567890abcdef12345678");
console.log(credit.credit_score); // 300
console.log(credit.level);       // "verified"
```

## HTTP Signing

### Sign an HTTP request

```typescript
import { signHttpRequest, verifyHttpSignature } from "@open-agent-id/sdk";

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

### Use the Signer daemon

```typescript
import { Signer, Agent } from "@open-agent-id/sdk";

const signer = await Signer.connect("/tmp/oaid-signer.sock");
const agent = new Agent({
  keyId: "default",
  signer,
  did: "did:oaid:base:0x1234567890abcdef1234567890abcdef12345678",
});

const res = await agent.http.post("https://api.example.com/v1/tasks", {
  task: "search",
});
```

## Message Signing

### Sign a P2P message

```typescript
import { signMessage, verifyMessageSignature } from "@open-agent-id/sdk";

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

## E2E Encryption

```typescript
import { encryptFor, decryptFrom } from "@open-agent-id/sdk";

// Encrypt for another agent (NaCl box: X25519-XSalsa20-Poly1305)
const ciphertext = encryptFor(plaintext, recipientEd25519Pub, senderEd25519Priv);

// Decrypt
const decrypted = decryptFrom(ciphertext, senderEd25519Pub, recipientEd25519Priv);
```

## DID Utilities

```typescript
import { validateDid, parseDid, formatDid } from "@open-agent-id/sdk";

validateDid("did:oaid:base:0x1234...abcd");  // true

parseDid("did:oaid:base:0x1234...abcd");
// { method: "oaid", chain: "base", agentAddress: "0x1234...abcd" }

formatDid("base", "0x1234...abcd");
// "did:oaid:base:0x1234...abcd"
```

### Canonical helpers

```typescript
import { canonicalUrl, canonicalJson } from "@open-agent-id/sdk";

canonicalUrl("https://API.example.com/path?b=2&a=1");
// "https://api.example.com/path?a=1&b=2"

canonicalJson({ z: 1, a: 2 });
// '{"a":2,"z":1}'
```

## Testing

```bash
npm install
npm run build   # compile TypeScript
npm test        # run tests with vitest
```

## License

Apache-2.0
