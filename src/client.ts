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
  status: "active" | "revoked";
  chain_status: "pending" | "submitted" | "anchored";
  chain_tx_hash?: string | null;
  nonce?: number;
  wallet_deployed?: boolean;
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
 */
export class RegistryClient {
  private readonly baseUrl: string;

  constructor(baseUrl?: string) {
    this.baseUrl = baseUrl ?? DEFAULT_API_URL;
  }

  // ---- Wallet Auth ----

  /**
   * Request a wallet auth challenge.
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
   * Register a new agent.
   */
  async registerAgent(
    token: string,
    opts: { name: string; capabilities?: string[]; publicKey?: string },
  ): Promise<AgentInfo> {
    const body: Record<string, unknown> = {
      name: opts.name,
    };
    if (opts.capabilities) body.capabilities = opts.capabilities;
    if (opts.publicKey) body.public_key = opts.publicKey;

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
   * Revoke an agent.
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
   * Get an agent's credit score. Public endpoint, no auth required.
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
