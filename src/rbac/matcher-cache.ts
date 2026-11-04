export interface MatcherCacheOptions {
  /** Maximum number of compiled permission matchers to retain. */
  maxEntries?: number;
  /** Time-to-live in milliseconds for each entry. 0 disables expiry. */
  ttl?: number;
}

export interface MatcherCacheStats {
  size: number;
  maxEntries: number;
  ttl: number;
  hits: number;
  misses: number;
  evictions: number;
  expired: number;
}

export class MatcherCache {
  private readonly maxEntries: number;
  private readonly ttl: number;
  private readonly map = new Map<string, { value: RegExp; expiresAt: number }>();
  private hits = 0;
  private misses = 0;
  private evictions = 0;
  private expired = 0;

  constructor(options: MatcherCacheOptions = {}) {
    this.maxEntries = Math.max(1, options.maxEntries ?? 1024);
    this.ttl = Math.max(0, options.ttl ?? 0);
  }

  get(key: string): RegExp | undefined {
    const entry = this.map.get(key);
    if (entry === undefined) {
      this.misses += 1;
      return undefined;
    }
    if (this.ttl > 0 && Date.now() >= entry.expiresAt) {
      this.map.delete(key);
      this.expired += 1;
      this.misses += 1;
      return undefined;
    }
    // LRU: promote to most recently used.
    this.map.delete(key);
    this.map.set(key, entry);
    this.hits += 1;
    return entry.value;
  }

  set(key: string, value: RegExp): void {
    const expiresAt = this.ttl > 0 ? Date.now() + this.ttl : 0;
    if (this.map.has(key)) {
      this.map.delete(key);
    } else if (this.map.size >= this.maxEntries) {
      const oldest = this.map.keys().next().value;
      if (oldest !== undefined) {
        this.map.delete(oldest);
        this.evictions += 1;
      }
    }
    this.map.set(key, { value, expiresAt });
  }

  has(key: string): boolean {
    const entry = this.map.get(key);
    if (entry === undefined) {
      return false;
    }
    if (this.ttl > 0 && Date.now() >= entry.expiresAt) {
      this.map.delete(key);
      this.expired += 1;
      return false;
    }
    return true;
  }

  delete(key: string): boolean {
    return this.map.delete(key);
  }

  clear(): void {
    this.map.clear();
  }

  get size(): number {
    return this.map.size;
  }

  stats(): MatcherCacheStats {
    return {
      size: this.map.size,
      maxEntries: this.maxEntries,
      ttl: this.ttl,
      hits: this.hits,
      misses: this.misses,
      evictions: this.evictions,
      expired: this.expired,
    };
  }

  clearExpired(): number {
    let removed = 0;
    if (this.ttl > 0) {
      const now = Date.now();
      for (const [key, entry] of this.map) {
        if (now >= entry.expiresAt) {
          this.map.delete(key);
          this.expired += 1;
          removed += 1;
        }
      }
    }
    return removed;
  }
}
