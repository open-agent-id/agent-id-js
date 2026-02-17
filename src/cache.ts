interface CacheEntry {
  publicKey: Uint8Array;
  expiresAt: number;
}

/**
 * In-memory TTL cache for public keys, keyed by DID.
 */
export class PublicKeyCache {
  private readonly store = new Map<string, CacheEntry>();
  private readonly ttlMs: number;

  /**
   * @param ttlSeconds Time-to-live in seconds (default: 3600 = 1 hour)
   */
  constructor(ttlSeconds: number = 3600) {
    this.ttlMs = ttlSeconds * 1000;
  }

  /**
   * Get a cached public key for the given DID, or null if not found / expired.
   */
  get(did: string): Uint8Array | null {
    const entry = this.store.get(did);
    if (!entry) return null;
    if (Date.now() > entry.expiresAt) {
      this.store.delete(did);
      return null;
    }
    return entry.publicKey;
  }

  /**
   * Store a public key for the given DID.
   */
  set(did: string, publicKey: Uint8Array): void {
    this.store.set(did, {
      publicKey,
      expiresAt: Date.now() + this.ttlMs,
    });
  }

  /**
   * Remove a cached entry.
   */
  delete(did: string): void {
    this.store.delete(did);
  }

  /**
   * Clear all cached entries.
   */
  clear(): void {
    this.store.clear();
  }

  /**
   * Number of entries currently in the cache (including potentially expired ones).
   */
  get size(): number {
    return this.store.size;
  }
}
