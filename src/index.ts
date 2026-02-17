export { AgentIdentity } from "./identity.js";
export type { AgentInfo } from "./client.js";
export {
  generateKeypair,
  sign,
  verify,
  sha256Hex,
  base64urlEncode,
  base64urlDecode,
  hexToBytes,
  bytesToHexString,
  generateNonce,
} from "./crypto.js";
export { validateDid, parseDid, generateUniqueId } from "./did.js";
export type { ParsedDid } from "./did.js";
export { registerAgent, getAgent } from "./client.js";
export type { RegisterOptions, RegisterResponse } from "./client.js";
export { PublicKeyCache } from "./cache.js";
