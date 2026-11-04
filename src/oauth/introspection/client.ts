import { dispatchHttp } from "../../http/transport.js";
import { sha256 } from "../../utils.js";
import { emitDiagnostic } from "../../diagnostics/index.js";
import {
  type IntrospectionCacheEntry,
  type IntrospectionConfig,
  type IntrospectionResult,
  type ResolvedIntrospectionConfig,
  IntrospectionError,
} from "./types.js";
import { validateIntrospectionResponse } from "./validator.js";

const DEFAULT_MAX_CACHE_ENTRIES = 500;
const HARD_MAX_CACHE_ENTRIES = 2000;
const DEFAULT_CACHE_TTL_MS = 5 * 60 * 1000;
const DEFAULT_MAX_CACHE_TTL_MS = 60 * 60 * 1000;
const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_RESPONSE_BYTES = 1_048_576;

function clamp(value: number, min: number, max: number): number {
  return Math.min(Math.max(value, min), max);
}

function resolveConfig(config: IntrospectionConfig): ResolvedIntrospectionConfig {
  if (!config.endpoint || typeof config.endpoint !== "string") {
    throw new IntrospectionError("Introspection endpoint is required", {
      code: "CONFIGURATION_ERROR",
      status: 400,
    });
  }
  if (!config.clientId || typeof config.clientId !== "string") {
    throw new IntrospectionError("Introspection clientId is required", {
      code: "CONFIGURATION_ERROR",
      status: 400,
    });
  }
  return {
    endpoint: config.endpoint,
    clientId: config.clientId,
    clientSecret: config.clientSecret,
    tokenTypeHint: config.tokenTypeHint,
    maxCacheEntries: clamp(
      config.maxCacheEntries ?? DEFAULT_MAX_CACHE_ENTRIES,
      1,
      HARD_MAX_CACHE_ENTRIES,
    ),
    cacheTtlMs: clamp(config.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS, 1_000, DEFAULT_MAX_CACHE_TTL_MS),
    maxCacheTtlMs: clamp(
      config.maxCacheTtlMs ?? DEFAULT_MAX_CACHE_TTL_MS,
      DEFAULT_CACHE_TTL_MS,
      DEFAULT_MAX_CACHE_TTL_MS,
    ),
    http: {
      timeoutMs: clamp(config.http?.timeoutMs ?? DEFAULT_TIMEOUT_MS, 1_000, 120_000),
      maxResponseBytes: clamp(
        config.http?.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES,
        1_024,
        5 * 1_048_576,
      ),
    },
  };
}

/**
 * Bounded LRU cache for introspection results.
 *
 * Never exceeds `maxEntries`; expired entries are dropped on read. Entries
 * are never cached past the introspected token's own `exp`, so a cached
 * result can never authorize an expired token.
 */
class IntrospectionCache {
  private readonly maxEntries: number;
  private readonly map = new Map<string, IntrospectionCacheEntry>();
  private readonly order: string[] = [];

  constructor(maxEntries: number) {
    this.maxEntries = maxEntries;
  }

  get(key: string): IntrospectionCacheEntry | undefined {
    const entry = this.map.get(key);
    if (!entry) {
      return undefined;
    }
    if (entry.expiresAt <= Date.now()) {
      this.map.delete(key);
      const index = this.order.indexOf(key);
      if (index !== -1) {
        this.order.splice(index, 1);
      }
      return undefined;
    }
    // LRU promotion.
    const index = this.order.indexOf(key);
    if (index !== -1) {
      this.order.splice(index, 1);
    }
    this.order.push(key);
    return entry;
  }

  set(key: string, entry: IntrospectionCacheEntry): void {
    if (this.map.has(key)) {
      const index = this.order.indexOf(key);
      if (index !== -1) {
        this.order.splice(index, 1);
      }
      this.map.delete(key);
    } else if (this.map.size >= this.maxEntries) {
      const oldest = this.order.shift();
      if (oldest !== undefined) {
        this.map.delete(oldest);
      }
    }
    this.map.set(key, entry);
    this.order.push(key);
  }

  size(): number {
    return this.map.size;
  }

  clear(): void {
    this.map.clear();
    this.order.length = 0;
  }
}

function buildBasicAuth(clientId: string, clientSecret: string): string {
  return "Basic " + Buffer.from(`${clientId}:${clientSecret}`).toString("base64");
}

export class TokenIntrospector {
  private readonly config: ResolvedIntrospectionConfig;
  private readonly cache: IntrospectionCache;

  constructor(config: IntrospectionConfig) {
    this.config = resolveConfig(config);
    this.cache = new IntrospectionCache(this.config.maxCacheEntries);
  }

  private cacheKey(token: string): string {
    return sha256(`${token}:${this.config.tokenTypeHint ?? ""}`);
  }

  private async performIntrospection(
    token: string,
  ): Promise<IntrospectionResult> {
    const bodyParams: Record<string, string> = { token };
    if (this.config.tokenTypeHint) {
      bodyParams.token_type_hint = this.config.tokenTypeHint;
    }

    const headers: Record<string, string> = {
      "content-type": "application/x-www-form-urlencoded",
      accept: "application/json",
    };
    if (this.config.clientSecret) {
      headers.Authorization = buildBasicAuth(this.config.clientId, this.config.clientSecret!);
    } else {
      bodyParams.client_id = this.config.clientId;
    }

    const form = new URLSearchParams(bodyParams);

    let response;
    try {
      response = await dispatchHttp(this.config.endpoint, {
        method: "POST",
        body: form.toString(),
        headers,
        redirect: "error",
        timeoutMs: this.config.http.timeoutMs,
        maxResponseBytes: this.config.http.maxResponseBytes,
      });
    } catch (error) {
      // Network / timeout / size failures: do not validate the token.
      throw new IntrospectionError(
        `Introspection request failed: ${error instanceof Error ? error.message : String(error)}`,
        { code: "unavailable", status: 502, cause: error },
      );
    }

    if (!response.ok) {
      throw new IntrospectionError(
        `Introspection endpoint ${this.config.endpoint} returned HTTP ${response.status}`,
        { code: "unavailable", status: response.status },
      );
    }

    let json: unknown;
    try {
      json = JSON.parse(response.text);
    } catch (error) {
      throw new IntrospectionError("Introspection response is not valid JSON", {
        code: "validation",
        status: 502,
        cause: error,
      });
    }

    let result: IntrospectionResult;
    try {
      result = validateIntrospectionResponse(json);
    } catch (error) {
      throw new IntrospectionError(
        `Introspection response validation failed: ${error instanceof Error ? error.message : String(error)}`,
        { code: "validation", status: 502, cause: error },
      );
    }

    // Defense in depth: honor the token's own expiration even when the
    // server reports active.
    if (result.active && typeof result.exp === "number" && result.exp <= Math.floor(Date.now() / 1000)) {
      result = { ...result, active: false };
    }

    return result;
  }

  /**
   * Introspect a token per RFC 7662.
   *
   * Returns `{ active: false }` for inactive or expired tokens. Throws
   * `IntrospectionError` when the endpoint is unavailable or the response
   * is malformed — a failure never causes a token to be treated as valid.
   *
   * Results are cached bounded by `maxCacheEntries` and never past the
   * token's `exp`.
   */
  async introspect(token: string): Promise<IntrospectionResult> {
    if (typeof token !== "string" || token.length === 0) {
      throw new IntrospectionError("token is required", { code: "validation", status: 400 });
    }

    const key = this.cacheKey(token);
    const cached = this.cache.get(key);
    if (cached) {
      emitDiagnostic({
        type: "oauth.introspection.completed",
        timestamp: Date.now(),
      });
      return cached.result;
    }

    let result: IntrospectionResult;
    try {
      result = await this.performIntrospection(token);
    } catch (error) {
      emitDiagnostic({
        type: "oauth.introspection.failed",
        timestamp: Date.now(),
        reason: "unavailable",
      });
      throw error;
    }

    // Never cache past the token's own expiration.
    let ttlMs = this.config.cacheTtlMs;
    if (typeof result.exp === "number") {
      const expMs = result.exp * 1000 - Date.now();
      if (expMs > 0 && expMs < ttlMs) {
        ttlMs = expMs;
      }
    }
    const entry: IntrospectionCacheEntry = {
      result,
      expiresAt: Date.now() + ttlMs,
    };
    this.cache.set(key, entry);

    emitDiagnostic({
      type: "oauth.introspection.completed",
      timestamp: Date.now(),
    });
    return result;
  }

  /** Number of entries currently in the introspection cache. */
  cacheSize(): number {
    return this.cache.size();
  }

  /** Clear the introspection cache. */
  clearCache(): void {
    this.cache.clear();
  }

  /** Resolved configuration (copy). */
  getConfig(): ResolvedIntrospectionConfig {
    return { ...this.config };
  }
}

export function createTokenIntrospector(config: IntrospectionConfig): TokenIntrospector {
  return new TokenIntrospector(config);
}
