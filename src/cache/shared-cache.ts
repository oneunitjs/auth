import {
  JwksCache,
  type JwksCacheConfig,
  type ResolvedJwksConfig,
  type ValidJwk,
} from "../crypto/jwks.js";

export interface SharedJwksCacheOptions {
  /** Aggregate maximum entries across all tenants. Default 500. */
  maxEntries?: number;
  /** Maximum entries per tenant. Defaults to a share of maxEntries. */
  perTenantMaxEntries?: number;
  /** Base config applied to every tenant cache. */
  jwks?: JwksCacheConfig;
}

export interface ResolvedSharedJwksCacheOptions {
  maxEntries: number;
  perTenantMaxEntries: number;
  jwks: JwksCacheConfig;
}

const DEFAULT_MAX_ENTRIES = 500;

function resolveSharedConfig(options?: SharedJwksCacheOptions): ResolvedSharedJwksCacheOptions {
  const maxEntries = Math.max(1, options?.maxEntries ?? DEFAULT_MAX_ENTRIES);
  const perTenantMaxEntries = Math.max(
    1,
    options?.perTenantMaxEntries ?? Math.ceil(maxEntries / 10),
  );
  return {
    maxEntries,
    perTenantMaxEntries,
    jwks: options?.jwks ?? {},
  };
}

/**
 * Aggregate JWKS cache with tenant-safe key isolation.
 *
 * Each tenant receives its own JwksCache instance, so keys for one tenant can
 * never be returned for another. Aggregate capacity is enforced by evicting the
 * least-recently-used tenant (and all of its entries) when the total exceeds
 * `maxEntries`.
 */
export class SharedJwksCache {
  private readonly options: ResolvedSharedJwksCacheOptions;
  private readonly caches = new Map<string, JwksCache>();
  private readonly tenantOrder: string[] = [];
  private hits = 0;
  private misses = 0;

  constructor(options?: SharedJwksCacheOptions) {
    this.options = resolveSharedConfig(options);
  }

  private getOrCreateTenant(tenantId: string): JwksCache {
    let cache = this.caches.get(tenantId);
    if (!cache) {
      cache = new JwksCache({
        ...this.options.jwks,
        maxEntries: this.options.perTenantMaxEntries,
      });
      this.caches.set(tenantId, cache);
      this.tenantOrder.push(tenantId);
    } else {
      const index = this.tenantOrder.indexOf(tenantId);
      if (index !== -1) {
        this.tenantOrder.splice(index, 1);
      }
      this.tenantOrder.push(tenantId);
    }
    return cache;
  }

  private evictToFit(): void {
    let total = this.size();
    while (total > this.options.maxEntries && this.tenantOrder.length > 0) {
      const lruTenant = this.tenantOrder.shift();
      if (!lruTenant) {
        break;
      }
      const tenantCache = this.caches.get(lruTenant);
      if (tenantCache) {
        total -= tenantCache.size();
        tenantCache.clear();
        this.caches.delete(lruTenant);
      }
    }
  }

  async getKeys(
    tenantId: string,
    identity: string,
    url: string,
    ttlMs?: number,
  ): Promise<Map<string, ValidJwk>> {
    const cache = this.getOrCreateTenant(tenantId);
    const wasCached = cache.has(identity);
    const keys = await cache.getKeys(identity, url, ttlMs);
    if (wasCached) {
      this.hits += 1;
    } else {
      this.misses += 1;
    }
    this.evictToFit();
    return keys;
  }

  async refreshForUnknownKid(
    tenantId: string,
    identity: string,
    url: string,
    ttlMs?: number,
  ): Promise<boolean> {
    const cache = this.getOrCreateTenant(tenantId);
    const refreshed = await cache.refreshForUnknownKid(identity, url, ttlMs);
    this.evictToFit();
    return refreshed;
  }

  invalidate(tenantId: string, identity: string): void {
    const cache = this.caches.get(tenantId);
    if (cache) {
      cache.invalidate(identity);
    }
  }

  invalidateTenant(tenantId: string): void {
    const cache = this.caches.get(tenantId);
    if (cache) {
      cache.clear();
      this.caches.delete(tenantId);
      const index = this.tenantOrder.indexOf(tenantId);
      if (index !== -1) {
        this.tenantOrder.splice(index, 1);
      }
    }
  }

  has(tenantId: string, identity: string): boolean {
    const cache = this.caches.get(tenantId);
    return cache ? cache.has(identity) : false;
  }

  size(): number {
    let total = 0;
    for (const cache of this.caches.values()) {
      total += cache.size();
    }
    return total;
  }

  clear(): void {
    for (const cache of this.caches.values()) {
      cache.clear();
    }
    this.caches.clear();
    this.tenantOrder.length = 0;
    this.hits = 0;
    this.misses = 0;
  }

  stats(): {
    size: number;
    maxEntries: number;
    perTenantMaxEntries: number;
    tenantCount: number;
    perTenant: Record<string, { size: number; maxEntries: number }>;
    hits: number;
    misses: number;
  } {
    const perTenant: Record<string, { size: number; maxEntries: number }> = {};
    let total = 0;
    for (const [tenantId, cache] of this.caches) {
      const tenantSize = cache.size();
      total += tenantSize;
      perTenant[tenantId] = {
        size: tenantSize,
        maxEntries: (cache.getConfig() as ResolvedJwksConfig).maxEntries,
      };
    }
    return {
      size: total,
      maxEntries: this.options.maxEntries,
      perTenantMaxEntries: this.options.perTenantMaxEntries,
      tenantCount: this.caches.size,
      perTenant,
      hits: this.hits,
      misses: this.misses,
    };
  }
}
