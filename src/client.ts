const DEFAULT_API_URL = "https://api.openagentid.org";

export interface AgentInfo {
  did: string;
  name?: string;
  public_key: string;
  wallet_address: string;
  agent_address: string;
  chain: string;
  capabilities?: string[];
  platform?: string;
  endpoint?: string;
  endpoint_type?: string;
  chain_status: "pending" | "submitted" | "anchored";
  chain_tx_hash?: string | null;
  chain_anchor_block?: number | null;
  chain_confirmations?: number;
  nonce?: number;
  wallet_deployed?: boolean;
  credit_score: number;
  referred_by?: string;
  created_at: string;
  updated_at: string;
}

export interface CreditInfo {
  did: string;
  credit_score: number;
  level: string;
  verified: boolean;
  flagged: boolean;
  active_reports: number;
  lifetime_reports: number;
  active_referrals: number;
  lifetime_referrals: number;
  reports_filed: number;
  reports_filed_verified: number;
  registered_at: string;
}

export interface AuthOptions {
  /** Bearer token from wallet auth. */
  token?: string;
  /** Agent DID + signature headers (set automatically by Agent class). */
  agentHeaders?: Record<string, string>;
}

/**
 * Client for the Open Agent ID registry API.
 *
 * Provides methods for wallet authentication, agent registration and management,
 * credit score lookups, and signature verification.
 *
 * @example
 * ```ts
 * const client = new RegistryClient();
 * const agent = await client.getAgent("did:oaid:base:0x...");
 * console.log(agent.name, agent.chain_status);
 * ```
 */
export class RegistryClient {
  private readonly baseUrl: string;

  /**
   * Create a new RegistryClient.
   *
   * @param baseUrl - Base URL of the registry API. Defaults to `https://api.openagentid.org`.
   */
  constructor(baseUrl?: string) {
    this.baseUrl = baseUrl ?? DEFAULT_API_URL;
  }

  // ---- Wallet Auth ----

  /**
   * Request a wallet authentication challenge.
   *
   * This is the first step in the wallet auth flow. The returned challenge text
   * must be signed by the wallet's private key and submitted via {@link verifyWallet}.
   *
   * @param walletAddress - Ethereum wallet address (e.g., `"0x1234..."`)
   * @returns An object containing the `challengeId` and `challengeText` to sign
   * @throws Error if the request fails
   *
   * @example
   * ```ts
   * const client = new RegistryClient();
   * const { challengeId, challengeText } = await client.requestChallenge("0xYourWallet");
   * // Sign challengeText with your wallet, then call verifyWallet()
   * ```
   */
  async requestChallenge(
    walletAddress: string,
  ): Promise<{ challengeId: string; challengeText: string }> {
    const res = await fetch(`${this.baseUrl}/v1/auth/challenge`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ wallet_address: walletAddress }),
    });

    if (!res.ok) {
      throw new Error(
        `Challenge request failed (${res.status}): ${await res.text()}`,
      );
    }

    const data = (await res.json()) as {
      challenge_id: string;
      challenge: string;
    };
    return {
      challengeId: data.challenge_id,
      challengeText: data.challenge,
    };
  }

  /**
   * Verify a wallet signature and receive a bearer token.
   *
   * This is the second step in the wallet auth flow. Submit the signed challenge
   * to receive a bearer token for authenticated API calls.
   *
   * @param walletAddress - Ethereum wallet address that signed the challenge
   * @param challengeId - The `challengeId` returned by {@link requestChallenge}
   * @param signature - The wallet's signature over the challenge text
   * @returns A bearer token string for use in `Authorization` headers
   * @throws Error if the signature is invalid or the request fails
   *
   * @example
   * ```ts
   * const token = await client.verifyWallet("0xWallet", challengeId, signature);
   * // Use token for registerAgent(), rotateKey(), etc.
   * ```
   */
  async verifyWallet(
    walletAddress: string,
    challengeId: string,
    signature: string,
  ): Promise<string> {
    const res = await fetch(`${this.baseUrl}/v1/auth/wallet`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        wallet_address: walletAddress,
        challenge_id: challengeId,
        signature,
      }),
    });

    if (!res.ok) {
      throw new Error(
        `Wallet verification failed (${res.status}): ${await res.text()}`,
      );
    }

    const data = (await res.json()) as { token: string };
    return data.token;
  }

  // ---- Agent Management ----

  /**
   * Register a new agent under the authenticated wallet.
   *
   * The agent receives a DID immediately via CREATE2 address derivation.
   * The `chain_status` starts as `"pending"` and progresses to `"anchored"`
   * once the registration is batched on-chain.
   *
   * @param token - Bearer token from {@link verifyWallet}
   * @param opts - Agent registration options
   * @param opts.name - Human-readable name for the agent
   * @param opts.publicKey - Base64url-encoded Ed25519 public key
   * @param opts.capabilities - Optional list of capability strings
   * @returns The newly created agent's full info including its DID
   * @throws Error if registration fails (e.g., invalid token, duplicate name)
   *
   * @example
   * ```ts
   * import { generateEd25519Keypair, base64urlEncode } from "@openagentid/sdk";
   *
   * const { publicKey, privateKey } = generateEd25519Keypair();
   * const agent = await client.registerAgent(token, {
   *   name: "my-agent",
   *   publicKey: base64urlEncode(publicKey),
   *   capabilities: ["search", "summarize"],
   * });
   * console.log(agent.did); // "did:oaid:base:0x..."
   * ```
   */
  async registerAgent(
    token: string,
    opts: { name: string; publicKey: string; capabilities?: string[] },
  ): Promise<AgentInfo> {
    const body: Record<string, unknown> = {
      name: opts.name,
      public_key: opts.publicKey,
    };
    if (opts.capabilities) body.capabilities = opts.capabilities;

    const res = await fetch(`${this.baseUrl}/v1/agents`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      throw new Error(
        `Agent registration failed (${res.status}): ${await res.text()}`,
      );
    }

    return (await res.json()) as AgentInfo;
  }

  /**
   * Look up an agent by DID.
   *
   * Public endpoint -- no authentication required.
   *
   * @param did - The agent's DID (e.g., `"did:oaid:base:0x..."`)
   * @returns The agent's full info including chain status and capabilities
   * @throws Error if the agent is not found (404) or the request fails
   *
   * @example
   * ```ts
   * const agent = await client.getAgent("did:oaid:base:0xABC...");
   * console.log(agent.name, agent.chain_status);
   * ```
   */
  async getAgent(did: string): Promise<AgentInfo> {
    const res = await fetch(
      `${this.baseUrl}/v1/agents/${encodeURIComponent(did)}`,
      {
        method: "GET",
        headers: { Accept: "application/json" },
      },
    );

    if (!res.ok) {
      if (res.status === 404) {
        throw new Error(`Agent not found: ${did}`);
      }
      throw new Error(
        `Agent lookup failed (${res.status}): ${await res.text()}`,
      );
    }

    return (await res.json()) as AgentInfo;
  }

  /**
   * List agents owned by the authenticated wallet.
   *
   * Supports cursor-based pagination. Use the returned `nextCursor` value
   * in subsequent calls to page through results.
   *
   * @param token - Bearer token from {@link verifyWallet}
   * @param opts - Optional pagination parameters
   * @param opts.limit - Maximum number of agents to return per page
   * @param opts.cursor - Cursor from a previous call's `nextCursor` for pagination
   * @returns An object with the `agents` array and an optional `nextCursor`
   * @throws Error if the request fails (e.g., invalid token)
   *
   * @example
   * ```ts
   * const { agents, nextCursor } = await client.listAgents(token, { limit: 10 });
   * for (const a of agents) {
   *   console.log(a.did, a.name);
   * }
   * ```
   */
  async listAgents(
    token: string,
    opts?: { limit?: number; cursor?: string },
  ): Promise<{ agents: AgentInfo[]; nextCursor?: string }> {
    const params = new URLSearchParams();
    if (opts?.limit) params.set("limit", String(opts.limit));
    if (opts?.cursor) params.set("cursor", opts.cursor);

    const query = params.toString();
    const url = query
      ? `${this.baseUrl}/v1/agents?${query}`
      : `${this.baseUrl}/v1/agents`;

    const res = await fetch(url, {
      method: "GET",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${token}`,
      },
    });

    if (!res.ok) {
      throw new Error(
        `List agents failed (${res.status}): ${await res.text()}`,
      );
    }

    const data = (await res.json()) as {
      agents: AgentInfo[];
      next_cursor?: string;
    };
    return { agents: data.agents, nextCursor: data.next_cursor };
  }

  /**
   * Update an agent's metadata.
   *
   * Can be authenticated with either a Bearer token (wallet owner) or
   * agent signature headers (the agent itself).
   *
   * @param did - The agent's DID to update
   * @param auth - Authentication options (Bearer token and/or agent signature headers)
   * @param updates - Partial agent fields to update (e.g., `name`, `capabilities`, `endpoint`)
   * @returns The updated agent info
   * @throws Error if the agent is not found, auth is invalid, or the request fails
   *
   * @example
   * ```ts
   * const updated = await client.updateAgent(
   *   "did:oaid:base:0x...",
   *   { token },
   *   { name: "new-name", capabilities: ["search"] },
   * );
   * ```
   */
  async updateAgent(
    did: string,
    auth: AuthOptions,
    updates: Partial<AgentInfo>,
  ): Promise<AgentInfo> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };

    if (auth.token) {
      headers["Authorization"] = `Bearer ${auth.token}`;
    }
    if (auth.agentHeaders) {
      Object.assign(headers, auth.agentHeaders);
    }

    const res = await fetch(
      `${this.baseUrl}/v1/agents/${encodeURIComponent(did)}`,
      {
        method: "PATCH",
        headers,
        body: JSON.stringify(updates),
      },
    );

    if (!res.ok) {
      throw new Error(
        `Agent update failed (${res.status}): ${await res.text()}`,
      );
    }

    return (await res.json()) as AgentInfo;
  }

  /**
   * Rotate an agent's Ed25519 public key.
   *
   * Replaces the agent's current public key with a new one. The old key
   * becomes invalid for signing immediately. Requires wallet-level Bearer auth.
   *
   * @param did - The agent's DID whose key to rotate
   * @param token - Bearer token from {@link verifyWallet}
   * @param publicKey - The new base64url-encoded Ed25519 public key
   * @returns The updated agent info with the new public key
   * @throws Error if the agent is not found, auth is invalid, or the request fails
   *
   * @example
   * ```ts
   * const { publicKey: newPub } = generateEd25519Keypair();
   * const updated = await client.rotateKey(agent.did, token, base64urlEncode(newPub));
   * ```
   */
  async rotateKey(
    did: string,
    token: string,
    publicKey: string,
  ): Promise<AgentInfo> {
    const res = await fetch(
      `${this.baseUrl}/v1/agents/${encodeURIComponent(did)}/key`,
      {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ public_key: publicKey }),
      },
    );

    if (!res.ok) {
      throw new Error(
        `Key rotation failed (${res.status}): ${await res.text()}`,
      );
    }

    return (await res.json()) as AgentInfo;
  }

  /**
   * Deploy the agent's smart contract wallet on Base L2.
   *
   * This deploys a counterfactual wallet at the agent's pre-computed address,
   * enabling on-chain transactions. Only needs to be called once per agent.
   *
   * @param did - The agent's DID whose wallet to deploy
   * @param token - Bearer token from {@link verifyWallet}
   * @returns Deployment result including the agent address and transaction hash
   * @throws Error if the wallet is already deployed, auth is invalid, or the request fails
   *
   * @example
   * ```ts
   * const result = await client.deployWallet(agent.did, token);
   * console.log(result.agent_address); // "0x..."
   * console.log(result.tx_hash);       // deployment tx hash
   * ```
   */
  async deployWallet(
    did: string,
    token: string,
  ): Promise<{
    wallet_deployed: boolean;
    agent_address: string;
    tx_hash?: string;
  }> {
    const res = await fetch(
      `${this.baseUrl}/v1/agents/${encodeURIComponent(did)}/deploy-wallet`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
        },
      },
    );

    if (!res.ok) {
      throw new Error(
        `Wallet deployment failed (${res.status}): ${await res.text()}`,
      );
    }

    return (await res.json()) as {
      wallet_deployed: boolean;
      agent_address: string;
      tx_hash?: string;
    };
  }

  /**
   * Revoke (delete) an agent.
   *
   * This permanently removes the agent from the registry. The agent's DID
   * will no longer resolve and its signatures will fail verification.
   *
   * @param did - The agent's DID to revoke
   * @param token - Bearer token from {@link verifyWallet}
   * @returns Resolves when the agent has been successfully revoked
   * @throws Error if the agent is not found, auth is invalid, or the request fails
   *
   * @example
   * ```ts
   * await client.revokeAgent("did:oaid:base:0x...", token);
   * ```
   */
  async revokeAgent(did: string, token: string): Promise<void> {
    const res = await fetch(
      `${this.baseUrl}/v1/agents/${encodeURIComponent(did)}`,
      {
        method: "DELETE",
        headers: {
          Authorization: `Bearer ${token}`,
        },
      },
    );

    if (!res.ok) {
      throw new Error(
        `Agent revocation failed (${res.status}): ${await res.text()}`,
      );
    }
  }

  /**
   * Get an agent's credit score and trust level.
   *
   * Public endpoint -- no authentication required.
   *
   * @param did - The agent's DID (e.g., `"did:oaid:base:0x..."`)
   * @returns Credit info including score, level, verification status, and report counts
   * @throws Error if the request fails or agent is not found (404)
   *
   * @example
   * ```ts
   * const credit = await client.getCredit("did:oaid:base:0x...");
   * console.log(credit.credit_score); // 300
   * console.log(credit.level);        // "verified"
   * console.log(credit.flagged);      // false
   * ```
   */
  async getCredit(did: string): Promise<CreditInfo> {
    const res = await fetch(
      `${this.baseUrl}/v1/credit/${encodeURIComponent(did)}`,
      {
        method: "GET",
        headers: { Accept: "application/json" },
      },
    );

    if (!res.ok) {
      throw new Error(
        `Credit lookup failed (${res.status}): ${await res.text()}`,
      );
    }

    return (await res.json()) as CreditInfo;
  }

  /**
   * Verify a signature via the registry API.
   *
   * Public endpoint -- no authentication required. Useful for verifying
   * agent signatures without needing the agent's public key locally.
   *
   * @param did - The agent's DID that produced the signature
   * @param domain - The signature domain (e.g., `"oaid-http/v1"`, `"oaid-msg/v1"`)
   * @param payload - The canonical payload string that was signed
   * @param signature - The base64url-encoded signature to verify
   * @returns `true` if the signature is valid, `false` otherwise
   * @throws Error if the request fails (e.g., agent not found)
   *
   * @example
   * ```ts
   * const valid = await client.verifySignature(
   *   "did:oaid:base:0x...",
   *   "oaid-http/v1",
   *   canonicalPayload,
   *   signatureBase64url,
   * );
   * console.log(valid); // true
   * ```
   */
  async verifySignature(
    did: string,
    domain: string,
    payload: string,
    signature: string,
  ): Promise<boolean> {
    const res = await fetch(`${this.baseUrl}/v1/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ did, domain, payload, signature }),
    });

    if (!res.ok) {
      throw new Error(
        `Signature verification failed (${res.status}): ${await res.text()}`,
      );
    }

    const data = (await res.json()) as { valid: boolean };
    return data.valid;
  }
}
