import { JwksCache, type JwksCacheConfig } from "../crypto/jwks.js";
import { SharedJwksCache, type SharedJwksCacheOptions } from "./shared-cache.js";

export interface CacheProviderOptions {
  /** Default maxEntries applied to newly created named JWKS caches. */
  defaultMaxEntries?: number;
}

type NamedCache = JwksCache | SharedJwksCache;

/**
 * Factory for named JWKS cache instances with aggregate visibility.
 *
 * Use this when an application runs multiple Auth instances or tenants and
 * wants a single place to create, inspect, and clear their JWKS caches.
 */
export class CacheProvider {
  private readonly caches = new Map<string, NamedCache>();
  private readonly defaultMaxEntries: number;

  constructor(options?: CacheProviderOptions) {
    this.defaultMaxEntries = Math.max(1, options?.defaultMaxEntries ?? 500);
  }

  createJwksCache(name: string, config?: JwksCacheConfig): JwksCache {
    const existing = this.caches.get(name);
    if (existing instanceof JwksCache) {
      return existing;
    }
    const cache = new JwksCache(config);
    this.caches.set(name, cache);
    return cache;
  }

  createSharedJwksCache(name: string, options?: SharedJwksCacheOptions): SharedJwksCache {
    const existing = this.caches.get(name);
    if (existing instanceof SharedJwksCache) {
      return existing;
    }
    const shared = new SharedJwksCache(options);
    this.caches.set(name, shared);
    return shared;
  }

  get(name: string): NamedCache | undefined {
    return this.caches.get(name);
  }

  has(name: string): boolean {
    return this.caches.has(name);
  }

  remove(name: string): boolean {
    const cache = this.caches.get(name);
    if (cache) {
      cache.clear();
    }
    return this.caches.delete(name);
  }

  clearAll(): void {
    for (const cache of this.caches.values()) {
      cache.clear();
    }
    this.caches.clear();
  }

  size(): number {
    let total = 0;
    for (const cache of this.caches.values()) {
      total += cache.size();
    }
    return total;
  }

  stats(): Array<{
    name: string;
    kind: "jwks" | "shared";
    stats: unknown;
  }> {
    const result: Array<{ name: string; kind: "jwks" | "shared"; stats: unknown }> = [];
    for (const [name, cache] of this.caches) {
      if (cache instanceof SharedJwksCache) {
        result.push({ name, kind: "shared", stats: cache.stats() });
      } else {
        result.push({ name, kind: "jwks", stats: (cache as JwksCache).stats() });
      }
    }
    return result;
  }
}

export const defaultCacheProvider = new CacheProvider();
