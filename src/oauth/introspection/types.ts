export type TokenTypeHint = "access_token" | "refresh_token";

export interface IntrospectionConfig {
  /** Introspection endpoint URL (RFC 7662). Required. */
  endpoint: string;
  /** OAuth client id used for client authentication. Required. */
  clientId: string;
  /** OAuth client secret. When present, sent as HTTP Basic auth per RFC 7662. */
  clientSecret?: string;
  /** Hint about the token type being introspected. */
  tokenTypeHint?: TokenTypeHint;
  /** Maximum cache entries for introspection results. Default 500, hard cap 2000. */
  maxCacheEntries?: number;
  /** Default TTL in ms for cached introspection results. Default 5 minutes. */
  cacheTtlMs?: number;
  /** Maximum permitted cache TTL in ms. Default 1 hour. */
  maxCacheTtlMs?: number;
  /** HTTP client overrides (timeoutMs, maxResponseBytes). */
  http?: { timeoutMs?: number; maxResponseBytes?: number };
}

export interface IntrospectionResult {
  active: boolean;
  scope?: string | string[];
  clientId?: string;
  username?: string;
  tokenType?: string;
  exp?: number;
  iat?: number;
  nbf?: number;
  sub?: string;
  aud?: string | string[];
  iss?: string;
  jti?: string;
  [key: string]: unknown;
}

export interface ResolvedIntrospectionConfig {
  endpoint: string;
  clientId: string;
  clientSecret?: string;
  tokenTypeHint?: TokenTypeHint;
  maxCacheEntries: number;
  cacheTtlMs: number;
  maxCacheTtlMs: number;
  http: { timeoutMs: number; maxResponseBytes: number };
}

export interface IntrospectionCacheEntry {
  result: IntrospectionResult;
  expiresAt: number;
}

export class IntrospectionError extends Error {
  override readonly name: string;
  readonly code: string;
  readonly status: number;
  override readonly cause?: unknown;

  constructor(message: string, { code = "INTROSPECTION_ERROR", status = 502, cause }: { code?: string; status?: number; cause?: unknown } = {}) {
    super(message);
    this.name = this.constructor.name;
    this.code = code;
    this.status = status;
    this.cause = cause;
  }
}
