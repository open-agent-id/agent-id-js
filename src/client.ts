const DEFAULT_API_URL = "https://api.openagentid.org";

export interface RegisterOptions {
  name: string;
  capabilities?: string[];
  apiUrl?: string;
  apiKey?: string;
}

export interface RegisterResponse {
  did: string;
  public_key: string;
  private_key: string;
  chain_status: "pending" | "anchored" | "failed";
  created_at: string;
}

export interface AgentInfo {
  did: string;
  name: string;
  public_key: string;
  capabilities: string[];
  status: "active" | "revoked";
  chain_status: "pending" | "anchored" | "failed";
  chain_tx_hash: string | null;
  created_at: string;
  updated_at: string;
}

/**
 * Register a new agent with the Open Agent ID registry.
 */
export async function registerAgent(
  options: RegisterOptions,
): Promise<RegisterResponse> {
  const apiUrl = options.apiUrl ?? DEFAULT_API_URL;
  const url = `${apiUrl}/v1/agents`;

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (options.apiKey) {
    headers["X-Platform-Key"] = options.apiKey;
  }

  const response = await fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify({
      name: options.name,
      capabilities: options.capabilities,
    }),
  });

  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(
      `Registration failed (${response.status}): ${errorBody}`,
    );
  }

  return (await response.json()) as RegisterResponse;
}

/**
 * Look up an agent by DID.
 */
export async function getAgent(
  did: string,
  apiUrl?: string,
): Promise<AgentInfo> {
  const base = apiUrl ?? DEFAULT_API_URL;
  const url = `${base}/v1/agents/${encodeURIComponent(did)}`;

  const response = await fetch(url, {
    method: "GET",
    headers: { Accept: "application/json" },
  });

  if (!response.ok) {
    if (response.status === 404) {
      throw new Error(`Agent not found: ${did}`);
    }
    const errorBody = await response.text();
    throw new Error(
      `Lookup failed (${response.status}): ${errorBody}`,
    );
  }

  return (await response.json()) as AgentInfo;
}
