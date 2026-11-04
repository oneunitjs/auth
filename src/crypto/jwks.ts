import { InvalidTokenError } from "../errors/index.js";
import { dispatchHttp } from "../http/transport.js";

/* ------------------------------------------------------------------ */
/* Configuration                                                        */
/* ------------------------------------------------------------------ */

export interface JwksCacheConfig {
  /** Maximum number of cached JWKS entries (issuer/JWKS URI pairs). Default 10, hard cap 100. */
  maxEntries?: number;
  /** Maximum number of keys to retain per JWKS document. Default 10, hard cap 100. */
  maxKeysPerEntry?: number;
  /** Maximum number of concurrent JWKS fetch requests. Default 50, hard cap 200. */
  maxInflight?: number;
  /** Default TTL in ms when upstream provides no freshness metadata. Default 1 hour. */
  defaultTtlMs?: number;
  /** Maximum permitted TTL in ms. Default 24 hours. */
  maxTtlMs?: number;
  /** Fetch timeout in ms. Default 10 seconds. */
  fetchTimeoutMs?: number;
  /** Maximum response body size in bytes. Default 1 MB. */
  maxResponseSizeBytes?: number;
  /** Cooldown in ms before refreshing again for an unknown kid. Default 30 seconds. */
  unknownKidCooldownMs?: number;
}

export interface ResolvedJwksConfig {
  maxEntries: number;
  maxKeysPerEntry: number;
  maxInflight: number;
  defaultTtlMs: number;
  maxTtlMs: number;
  fetchTimeoutMs: number;
  maxResponseSizeBytes: number;
  unknownKidCooldownMs: number;
}

const DEFAULTS: ResolvedJwksConfig = {
  maxEntries: 10,
  maxKeysPerEntry: 10,
  maxInflight: 50,
  defaultTtlMs: 60 * 60 * 1000,
  maxTtlMs: 24 * 60 * 60 * 1000,
  fetchTimeoutMs: 10 * 1000,
  maxResponseSizeBytes: 1024 * 1024,
  unknownKidCooldownMs: 30 * 1000,
};

const HARD_LIMITS: ResolvedJwksConfig = {
  maxEntries: 100,
  maxKeysPerEntry: 100,
  maxInflight: 200,
  defaultTtlMs: 60 * 60 * 1000,
  maxTtlMs: 24 * 60 * 60 * 1000,
  fetchTimeoutMs: 60 * 1000,
  maxResponseSizeBytes: 5 * 1024 * 1024,
  unknownKidCooldownMs: 300 * 1000,
};

function clamp(value: number, min: number, max: number): number {
  return Math.min(Math.max(value, min), max);
}

function resolveConfig(config?: JwksCacheConfig): ResolvedJwksConfig {
  return {
    maxEntries: clamp(config?.maxEntries ?? DEFAULTS.maxEntries, 1, HARD_LIMITS.maxEntries),
    maxKeysPerEntry: clamp(config?.maxKeysPerEntry ?? DEFAULTS.maxKeysPerEntry, 1, HARD_LIMITS.maxKeysPerEntry),
    maxInflight: clamp(config?.maxInflight ?? DEFAULTS.maxInflight, 1, HARD_LIMITS.maxInflight),
    defaultTtlMs: clamp(config?.defaultTtlMs ?? DEFAULTS.defaultTtlMs, 1_000, HARD_LIMITS.maxTtlMs),
    maxTtlMs: clamp(config?.maxTtlMs ?? DEFAULTS.maxTtlMs, DEFAULTS.defaultTtlMs, HARD_LIMITS.maxTtlMs),
    fetchTimeoutMs: clamp(config?.fetchTimeoutMs ?? DEFAULTS.fetchTimeoutMs, 1_000, HARD_LIMITS.fetchTimeoutMs),
    maxResponseSizeBytes: clamp(
      config?.maxResponseSizeBytes ?? DEFAULTS.maxResponseSizeBytes,
      1_024,
      HARD_LIMITS.maxResponseSizeBytes,
    ),
    unknownKidCooldownMs: clamp(
      config?.unknownKidCooldownMs ?? DEFAULTS.unknownKidCooldownMs,
      1_000,
      HARD_LIMITS.unknownKidCooldownMs,
    ),
  };
}

/* ------------------------------------------------------------------ */
/* JWK validation                                                       */
/* ------------------------------------------------------------------ */

const SUPPORTED_KEY_TYPES = new Set(["RSA", "EC", "OKP"]);
const SUPPORTED_ALGORITHMS = new Set(["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA"]);
const REQUIRED_FIELDS = new Set(["kty", "kid", "alg"]);

export interface ValidJwk {
  kty: string;
  kid: string;
  alg: string;
  use?: string;
  key_ops?: string[];
  x?: string;
  y?: string;
  n?: string;
  e?: string;
  d?: string;
  p?: string;
  q?: string;
  dp?: string;
  dq?: string;
  qi?: string;
  [key: string]: unknown;
}

function isPrivateKeyMaterial(jwk: Record<string, unknown>): boolean {
  const privateFields = ["d", "p", "q", "dp", "dq", "qi"];
  return privateFields.some((field) => typeof jwk[field] === "string" && jwk[field].length > 0);
}

function validateJwk(jwk: unknown, index: number): ValidJwk {
  if (!jwk || typeof jwk !== "object" || Array.isArray(jwk)) {
    throw new InvalidTokenError(`JWK at index ${index} is not an object`);
  }

  const record = jwk as Record<string, unknown>;

  for (const field of REQUIRED_FIELDS) {
    if (typeof record[field] !== "string" || record[field].length === 0) {
      throw new InvalidTokenError(`JWK at index ${index} is missing required field "${field}"`);
    }
  }

  const kty = record.kty as string;
  if (!SUPPORTED_KEY_TYPES.has(kty)) {
    throw new InvalidTokenError(`JWK at index ${index} has unsupported key type "${kty}"`);
  }

  const kid = record.kid as string;
  const alg = record.alg as string;
  if (!SUPPORTED_ALGORITHMS.has(alg)) {
    throw new InvalidTokenError(`JWK "${kid}" has unsupported algorithm "${alg}"`);
  }

  const use = record.use;
  if (use !== undefined && use !== "sig") {
    throw new InvalidTokenError(`JWK "${kid}" has unsupported "use" "${String(use)}"`);
  }

  if (isPrivateKeyMaterial(record)) {
    throw new InvalidTokenError(`JWK "${kid}" contains private key material`);
  }

  return record as ValidJwk;
}

function validateJwksDocument(doc: unknown, maxKeys: number): ValidJwk[] {
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) {
    throw new InvalidTokenError("JWKS response is not a JSON object");
  }

  const record = doc as Record<string, unknown>;
  const keys = record.keys;
  if (!Array.isArray(keys)) {
    throw new InvalidTokenError("JWKS response is missing a 'keys' array");
  }

  if (keys.length === 0) {
    throw new InvalidTokenError("JWKS response contains no keys");
  }

  if (keys.length > maxKeys) {
    throw new InvalidTokenError(
      `JWKS response contains ${keys.length} keys, exceeding the maximum of ${maxKeys}`,
    );
  }

  const validKeys: ValidJwk[] = [];
  const seenKids = new Set<string>();

  for (let i = 0; i < keys.length; i++) {
    const jwk = validateJwk(keys[i], i);
    if (seenKids.has(jwk.kid)) {
      throw new InvalidTokenError(`JWKS response contains duplicate kid "${jwk.kid}"`);
    }
    seenKids.add(jwk.kid);
    validKeys.push(jwk);
  }

  return validKeys;
}

/* ------------------------------------------------------------------ */
/* Cache entry                                                          */
/* ------------------------------------------------------------------ */

interface CacheEntry {
  keys: Map<string, ValidJwk>;
  expiresAt: number;
  fetchedAt: number;
}

interface InFlightEntry {
  promise: Promise<CacheEntry>;
  abort: () => void;
}

/* ------------------------------------------------------------------ */
/* Hardened JWKS cache                                                  */
/* ------------------------------------------------------------------ */

export class JwksCache {
  private readonly config: ResolvedJwksConfig;
  private readonly entries = new Map<string, CacheEntry>();
  private readonly order: string[] = [];
  private readonly inflight = new Map<string, InFlightEntry>();
  private readonly unknownKidCooldown = new Map<string, number>();
  private readonly unknownKidOrder: string[] = [];
  private inflightCount = 0;
  private inflightQueue: Array<{ resolve: () => void; reject: (err: unknown) => void }> = [];
  private hits = 0;
  private misses = 0;
  private evictions = 0;
  private expired = 0;

  constructor(config?: JwksCacheConfig) {
    this.config = resolveConfig(config);
  }

  private evictIfNeeded(): void {
    while (this.entries.size > this.config.maxEntries) {
      const lru = this.order.shift();
      if (!lru) {
        break;
      }
      if (lru && this.entries.has(lru)) {
        this.entries.delete(lru);
        this.evictions += 1;
      }
    }
  }

  private evictUnknownKidIfNeeded(): void {
    while (this.unknownKidCooldown.size >= this.config.maxEntries) {
      const oldest = this.unknownKidOrder.shift();
      if (!oldest) {
        break;
      }
      if (this.unknownKidCooldown.has(oldest)) {
        this.unknownKidCooldown.delete(oldest);
      }
    }
  }

  private recordUnknownKid(identity: string): void {
    const index = this.unknownKidOrder.indexOf(identity);
    if (index !== -1) {
      this.unknownKidOrder.splice(index, 1);
    }
    this.unknownKidOrder.push(identity);
  }

  private async withInflightSlot<T>(fn: () => Promise<T>): Promise<T> {
    if (this.inflightCount >= this.config.maxInflight) {
      await new Promise<void>((resolve, reject) => {
        this.inflightQueue.push({ resolve, reject });
      });
    }
    this.inflightCount += 1;
    try {
      return await fn();
    } finally {
      this.inflightCount -= 1;
      const next = this.inflightQueue.shift();
      if (next) {
        next.resolve();
      }
    }
  }

  private recordAccess(identity: string): void {
    const index = this.order.indexOf(identity);
    if (index !== -1) {
      this.order.splice(index, 1);
    }
    this.order.push(identity);
  }

  private async fetchJwksDocument(url: string, signal?: AbortSignal): Promise<Record<string, unknown>> {
    let result;
    try {
      result = await dispatchHttp(url, {
        timeoutMs: this.config.fetchTimeoutMs,
        maxResponseBytes: this.config.maxResponseSizeBytes,
        redirect: "error",
        signal,
      });
    } catch (error) {
      throw new InvalidTokenError(
        `Failed to fetch JWKS from ${url}: ${error instanceof Error ? error.message : String(error)}`,
        { cause: error },
      );
    }

    if (!result.ok) {
      throw new InvalidTokenError(`JWKS endpoint ${url} returned HTTP ${result.status}`);
    }

    let json: unknown;
    try {
      json = JSON.parse(result.text);
    } catch {
      throw new InvalidTokenError(`JWKS response from ${url} is not valid JSON`);
    }

    return json as Record<string, unknown>;
  }

  private async refreshEntry(identity: string, url: string, ttlMs?: number, signal?: AbortSignal): Promise<CacheEntry> {
    const raw = await this.fetchJwksDocument(url, signal);
    const keys = validateJwksDocument(raw, this.config.maxKeysPerEntry);

    const keyMap = new Map<string, ValidJwk>();
    for (const key of keys) {
      keyMap.set(key.kid, key);
    }

    const ttl = clamp(ttlMs ?? this.config.defaultTtlMs, 1, this.config.maxTtlMs);
    const expiresAt = Date.now() + ttl;

    const entry: CacheEntry = { keys: keyMap, expiresAt, fetchedAt: Date.now() };
    this.entries.set(identity, entry);
    this.recordAccess(identity);
    this.evictIfNeeded();

    return entry;
  }

  getEntry(identity: string): CacheEntry | undefined {
    const entry = this.entries.get(identity);
    if (!entry) {
      this.misses += 1;
      return undefined;
    }
    if (entry.expiresAt <= Date.now()) {
      this.entries.delete(identity);
      this.order.splice(this.order.indexOf(identity), 1);
      this.expired += 1;
      this.misses += 1;
      return undefined;
    }
    this.recordAccess(identity);
    this.hits += 1;
    return entry;
  }

  async getKeys(identity: string, url: string, ttlMs?: number): Promise<Map<string, ValidJwk>> {
    const cached = this.getEntry(identity);
    if (cached) {
      return cached.keys;
    }

    const inFlight = this.inflight.get(identity);
    if (inFlight) {
      return (await inFlight.promise).keys;
    }

    return this.withInflightSlot(async () => {
      // Re-check after acquiring a slot: another request may have populated it.
      const cachedAgain = this.getEntry(identity);
      if (cachedAgain) {
        return cachedAgain.keys;
      }
      const inFlightAgain = this.inflight.get(identity);
      if (inFlightAgain) {
        return (await inFlightAgain.promise).keys;
      }

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), this.config.fetchTimeoutMs);

      const promise = (async () => {
        try {
          return await this.refreshEntry(identity, url, ttlMs, controller.signal);
        } finally {
          this.inflight.delete(identity);
          clearTimeout(timeoutId);
        }
      })();

      this.inflight.set(identity, { promise, abort: () => controller.abort() });
      return promise.then((entry) => entry.keys);
    });
  }

  /**
   * Called when a token contains a kid that is not in the current snapshot.
   * Allows at most one coordinated refresh per identity, subject to a cooldown.
   * Returns true if a refresh was performed, false if suppressed by cooldown.
   */
  async refreshForUnknownKid(identity: string, url: string, ttlMs?: number): Promise<boolean> {
    const now = Date.now();
    const last = this.unknownKidCooldown.get(identity);
    if (last !== undefined && now - last < this.config.unknownKidCooldownMs) {
      return false;
    }

    this.evictUnknownKidIfNeeded();
    this.unknownKidCooldown.set(identity, now);
    this.recordUnknownKid(identity);

    try {
      const entry = await this.refreshEntry(identity, url, ttlMs);
      return entry.keys.size > 0;
    } catch {
      return false;
    }
  }

  invalidate(identity: string): void {
    this.entries.delete(identity);
    this.order.splice(this.order.indexOf(identity), 1);
    this.inflight.delete(identity);
    this.unknownKidCooldown.delete(identity);
    this.unknownKidOrder.splice(this.unknownKidOrder.indexOf(identity), 1);
  }

  clear(): void {
    this.entries.clear();
    this.order.length = 0;
    this.inflight.clear();
    this.inflightQueue.length = 0;
    this.inflightCount = 0;
    this.unknownKidCooldown.clear();
    this.unknownKidOrder.length = 0;
  }

  size(): number {
    return this.entries.size;
  }

  has(identity: string): boolean {
    return this.entries.has(identity);
  }

  stats(): {
    size: number;
    maxEntries: number;
    maxInflight: number;
    inflight: number;
    queued: number;
    unknownKidCount: number;
    hits: number;
    misses: number;
    evictions: number;
    expired: number;
  } {
    return {
      size: this.entries.size,
      maxEntries: this.config.maxEntries,
      maxInflight: this.config.maxInflight,
      inflight: this.inflightCount,
      queued: this.inflightQueue.length,
      unknownKidCount: this.unknownKidCooldown.size,
      hits: this.hits,
      misses: this.misses,
      evictions: this.evictions,
      expired: this.expired,
    };
  }

  getConfig(): ResolvedJwksConfig {
    return { ...this.config };
  }
}

/* ------------------------------------------------------------------ */
/* Resolver (replaces resolveJwks from shared.ts)                       */
/* ------------------------------------------------------------------ */

export interface JwksSourceConfig {
  jwks?: Record<string, unknown> | (() => Record<string, unknown> | Promise<Record<string, unknown>>);
  jwksUrl?: string;
  jwksCacheTtlMs?: number;
  verifyIdTokenSignature?: boolean;
  maxKeysPerEntry?: number;
}

export async function resolveJwksDocument(
  config: JwksSourceConfig,
  cache: JwksCache,
  defaultJwksUrl: string,
): Promise<Map<string, ValidJwk>> {
  if (config.verifyIdTokenSignature === false) {
    throw new InvalidTokenError("JWKS signature verification is disabled for this provider");
  }

  const maxKeys = config.maxKeysPerEntry ?? cache.getConfig().maxKeysPerEntry;

  if (typeof config.jwks === "function") {
    const raw = await config.jwks();
    const keys = validateJwksDocument(raw, maxKeys);
    const map = new Map<string, ValidJwk>();
    for (const key of keys) map.set(key.kid, key);
    return map;
  }

  if (config.jwks && typeof config.jwks === "object") {
    const keys = validateJwksDocument(config.jwks, maxKeys);
    const map = new Map<string, ValidJwk>();
    for (const key of keys) map.set(key.kid, key);
    return map;
  }

  const url = (typeof config.jwksUrl === "string" ? config.jwksUrl : defaultJwksUrl) || defaultJwksUrl;
  const identity = url;

  const cached = cache.getEntry(identity);
  if (cached) {
    return cached.keys;
  }

  return cache.getKeys(identity, url, config.jwksCacheTtlMs);
}

/* ------------------------------------------------------------------ */
/* Single global cache instance (process-scoped)                        */
/* ------------------------------------------------------------------ */

export const defaultJwksCache = new JwksCache();
