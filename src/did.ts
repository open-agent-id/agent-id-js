const BASE62_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

const DID_REGEX =
  /^did:agent:([a-z0-9]{3,20}):(agt_[0-9A-Za-z]{10})$/;

export interface ParsedDid {
  method: string;
  platform: string;
  uniqueId: string;
}

/**
 * Validate a DID string against the Open Agent ID format rules.
 *
 * Rules:
 * 1. Method MUST be "agent"
 * 2. Platform MUST be 3-20 characters, lowercase [a-z0-9]
 * 3. Unique ID MUST start with "agt_" followed by exactly 10 base62 characters
 * 4. Total DID length MUST NOT exceed 60 characters
 */
export function validateDid(did: string): boolean {
  if (!did || did.length > 60) return false;
  return DID_REGEX.test(did);
}

/**
 * Parse a DID string into its components.
 * Throws if the DID is invalid.
 */
export function parseDid(did: string): ParsedDid {
  if (!validateDid(did)) {
    throw new Error(`Invalid DID: ${did}`);
  }
  const match = did.match(DID_REGEX)!;
  return {
    method: "agent",
    platform: match[1],
    uniqueId: match[2],
  };
}

/**
 * Generate a unique ID in the format agt_ + 10 base62 characters.
 */
export function generateUniqueId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(10));
  let id = "agt_";
  for (let i = 0; i < 10; i++) {
    id += BASE62_CHARS[bytes[i] % 62];
  }
  return id;
}
