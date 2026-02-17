# @openagentid/sdk

JavaScript/TypeScript SDK for [Open Agent ID](https://openagentid.org) -- register, sign, and verify AI agent identities.

## Installation

```bash
npm install @openagentid/sdk
```

Requires Node.js >= 18.

## Quick Start

### Register a new agent

```typescript
import { AgentIdentity } from "@openagentid/sdk";

const agent = await AgentIdentity.register({
  name: "my-search-agent",
  capabilities: ["search", "summarize"],
  apiKey: "your-platform-key",
});

console.log(agent.did);              // did:agent:tokli:agt_a1B2c3D4e5
console.log(agent.publicKeyBase64url); // base64url-encoded public key

// IMPORTANT: persist agent.did and the private key securely
```

### Load an existing agent

```typescript
const agent = AgentIdentity.load({
  did: "did:agent:tokli:agt_a1B2c3D4e5",
  privateKey: "base64url-encoded-private-key",
});
```

### Sign an HTTP request

```typescript
const headers = agent.signRequest("POST", "https://api.example.com/v1/tasks", '{"task":"search"}');
// headers = {
//   "X-Agent-DID": "did:agent:tokli:agt_a1B2c3D4e5",
//   "X-Agent-Timestamp": "1708123456",
//   "X-Agent-Nonce": "a3f1b2c4d5e6f7089012abcd",
//   "X-Agent-Signature": "<base64url signature>"
// }

const response = await fetch("https://api.example.com/v1/tasks", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    ...headers,
  },
  body: '{"task":"search"}',
});
```

### Verify another agent's signature

```typescript
const valid = await AgentIdentity.verify({
  did: "did:agent:openai:agt_X9yZ8wV7u6",
  payload: canonicalPayload,
  signature: signatureBase64url,
});
```

### Look up an agent

```typescript
const info = await AgentIdentity.lookup("did:agent:tokli:agt_a1B2c3D4e5");
console.log(info.name, info.status, info.capabilities);
```

## API Reference

### `AgentIdentity.register(options)`

Register a new agent identity with the registry. Returns an `AgentIdentity` instance with signing capabilities.

**Options:**
- `name` (string, required) -- agent name
- `capabilities` (string[], optional) -- list of capabilities
- `apiUrl` (string, optional) -- registry API URL (default: `https://api.openagentid.org`)
- `apiKey` (string, optional) -- platform API key

### `AgentIdentity.load(options)`

Load an existing identity from a DID and private key.

**Options:**
- `did` (string, required) -- the agent DID
- `privateKey` (string, required) -- base64url-encoded private key

### `agent.sign(payload)`

Sign a string payload. Returns a base64url-encoded Ed25519 signature.

### `agent.signRequest(method, url, body?)`

Sign an HTTP request per the Open Agent ID signing spec. Returns a headers object with `X-Agent-DID`, `X-Agent-Timestamp`, `X-Agent-Nonce`, and `X-Agent-Signature`.

### `AgentIdentity.verify(options)`

Verify a signature against a DID's public key (fetched from registry).

### `AgentIdentity.lookup(did, apiUrl?)`

Look up agent information by DID.

## Low-Level Utilities

The SDK also exports low-level functions:

```typescript
import {
  generateKeypair,
  sign,
  verify,
  sha256Hex,
  base64urlEncode,
  base64urlDecode,
  validateDid,
  parseDid,
  generateUniqueId,
  PublicKeyCache,
} from "@openagentid/sdk";
```

## Development

```bash
npm install
npm run build   # compile TypeScript
npm test        # run tests with vitest
```

## License

Apache-2.0
