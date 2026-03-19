// DID
export { parseDid, validateDid, formatDid } from "./did.js";
export type { ParsedDid } from "./did.js";

// Signing
export {
  signHttpRequest,
  verifyHttpSignature,
  signMessage,
  verifyMessageSignature,
  canonicalUrl,
  canonicalJson,
} from "./signing.js";

// Signer
export { Signer } from "./signer.js";

// Registry client
export { RegistryClient } from "./client.js";
export type { AgentInfo, AuthOptions, CreditInfo } from "./client.js";

// Agent
export { Agent } from "./agent.js";

// Crypto utilities
export {
  generateEd25519Keypair,
  ed25519Sign,
  ed25519Verify,
  base64urlEncode,
  base64urlDecode,
  sha256,
  generateNonce,
  ed25519ToX25519Public,
  ed25519ToX25519Private,
  encryptFor,
  decryptFrom,
} from "./crypto.js";

// Constants
export {
  DEFAULT_EXPIRE_SECONDS,
  HTTP_TIMESTAMP_TOLERANCE,
  DEDUP_CACHE_TTL,
} from "./constants.js";
