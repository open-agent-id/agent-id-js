/**
 * V2 DID format: did:oaid:{chain}:{agent_address}
 * - chain: lowercase string (e.g. "base")
 * - agent_address: 0x + 40 lowercase hex chars
 */

const DID_REGEX = /^did:oaid:([a-z][a-z0-9]*):((0x[0-9a-f]{40}))$/;

export interface ParsedDid {
  method: string;
  chain: string;
  agentAddress: string;
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
    method: "oaid",
    chain: match[1],
    agentAddress: match[2],
  };
}

/**
 * Validate a DID string against the V2 Open Agent ID format.
 */
export function validateDid(did: string): boolean {
  if (!did || did.length > 100) return false;
  return DID_REGEX.test(did);
}

/**
 * Format a DID from chain and agent address components.
 * Normalizes address to lowercase.
 */
export function formatDid(chain: string, agentAddress: string): string {
  const did = `did:oaid:${chain.toLowerCase()}:${agentAddress.toLowerCase()}`;
  if (!validateDid(did)) {
    throw new Error(
      `Cannot format valid DID from chain="${chain}", agentAddress="${agentAddress}"`,
    );
  }
  return did;
}
