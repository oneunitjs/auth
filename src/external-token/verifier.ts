import { jwtVerify, decodeProtectedHeader, importJWK } from "jose";
import { ConfigurationError, InvalidTokenError, TokenExpiredError, ValidationError } from "../errors/index.js";
import { JwksCache, resolveJwksDocument } from "../crypto/jwks.js";
import type { JwtAlgorithm } from "../crypto/jwt-backend.js";
import type {
  ExternalTokenClaims,
  ExternalTokenResult,
  ExternalTokenVerifyOptions,
  TrustedIssuerConfig,
} from "./types.js";

const MAX_TOKEN_LENGTH = 16_384;
const DEFAULT_CLOCK_TOLERANCE = 0;

function asAudienceList(value: string | string[]): string[] {
  return Array.isArray(value) ? value : [value];
}

function decodeUnverifiedPayload(token: string): Record<string, unknown> {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new InvalidTokenError("External token is not a well-formed JWT");
  }
  try {
    return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8")) as Record<string, unknown>;
  } catch {
    throw new InvalidTokenError("External token payload is not valid JSON");
  }
}

function audiencesMatch(actual: unknown, expected: string[]): boolean {
  const presented = Array.isArray(actual) ? actual.map(String) : actual === undefined ? [] : [String(actual)];
  return expected.some((item) => presented.includes(item));
}

export class ExternalTokenVerifier {
  private readonly issuers = new Map<string, TrustedIssuerConfig>();
  private readonly cache: JwksCache;

  constructor(issuers: TrustedIssuerConfig[], cache?: JwksCache) {
    this.cache = cache ?? new JwksCache();
    for (const issuer of issuers) {
      this.addIssuer(issuer);
    }
  }

  addIssuer(config: TrustedIssuerConfig): this {
    if (!config.issuer || typeof config.issuer !== "string") {
      throw new ConfigurationError("Trusted issuer must include an exact issuer identifier");
    }
    if (this.issuers.has(config.issuer)) {
      throw new ConfigurationError(`Duplicate trusted issuer: ${config.issuer}`);
    }
    if (!config.algorithms?.length) {
      throw new ConfigurationError(`Trusted issuer ${config.issuer} must declare an algorithm allowlist`);
    }
    if (config.algorithms.includes("none" as JwtAlgorithm)) {
      throw new ConfigurationError("Algorithm none is never permitted");
    }
    if (config.keySource.type === "jwks") {
      const uri = config.keySource.uri;
      const scheme = uri.split("://")[0]?.toLowerCase();
      const isHttps = scheme === "https";
      const isInsecureHttp = scheme === "http" && config.allowInsecureHttp;
      if (!isHttps && !isInsecureHttp) {
        throw new ConfigurationError(
          `JWKS URI for ${config.issuer} must use HTTPS${config.allowInsecureHttp ? "" : " or enable allowInsecureHttp for HTTP"}`,
        );
      }
    }
    this.issuers.set(config.issuer, { ...config, enabled: config.enabled !== false });
    return this;
  }

  async verify(token: string, options: ExternalTokenVerifyOptions = {}): Promise<ExternalTokenResult> {
    if (typeof token !== "string" || token.trim().length === 0) {
      throw new InvalidTokenError("External token is required");
    }
    if (token.length > MAX_TOKEN_LENGTH) {
      throw new InvalidTokenError("External token exceeds the maximum supported length");
    }

    let header: { alg?: unknown; kid?: unknown; typ?: unknown };
    try {
      header = decodeProtectedHeader(token);
    } catch {
      throw new InvalidTokenError("External token header is invalid");
    }

    const unverified = decodeUnverifiedPayload(token);
    const issuerHint = unverified.iss;
    if (typeof issuerHint !== "string" || !this.issuers.has(issuerHint)) {
      throw new InvalidTokenError("External token issuer is not trusted");
    }
    const profile = this.issuers.get(issuerHint)!;
    if (!profile.enabled) {
      throw new InvalidTokenError("External token issuer is disabled");
    }
    if (typeof header.alg !== "string" || !profile.algorithms.includes(header.alg as JwtAlgorithm)) {
      throw new InvalidTokenError("External token algorithm is not permitted");
    }

    const key = await this.resolveKey(profile, typeof header.kid === "string" ? header.kid : undefined, header.alg as JwtAlgorithm);

    let payload: ExternalTokenClaims;
    try {
      const verified = await jwtVerify(token, key, {
        algorithms: profile.algorithms,
        clockTolerance: options.clockTolerance ?? profile.clockTolerance ?? DEFAULT_CLOCK_TOLERANCE,
      });
      payload = verified.payload as ExternalTokenClaims;
    } catch (error) {
      if (error instanceof Error && error.name === "JWTExpired") {
        throw new TokenExpiredError("External token has expired", { cause: error });
      }
      throw new InvalidTokenError("External token signature is invalid", { cause: error });
    }

    this.validateClaims(payload, profile, options);
    return {
      issuer: profile.issuer,
      audience: payload.aud ?? profile.audience,
      subject: typeof payload.sub === "string" ? payload.sub : undefined,
      claims: payload,
    };
  }

  private async resolveKey(profile: TrustedIssuerConfig, kid: string | undefined, algorithm: JwtAlgorithm) {
    if (profile.keySource.type === "static") {
      const raw = profile.keySource.key;
      return typeof raw === "string" ? new TextEncoder().encode(raw) : raw;
    }
    const document = profile.keySource.type === "jwks-document"
      ? await resolveJwksDocument({ jwks: profile.keySource.jwks }, this.cache, "")
      : await resolveJwksDocument(
        { jwksUrl: profile.keySource.uri, jwksCacheTtlMs: profile.keySource.cacheTtlMs },
        this.cache,
        profile.keySource.uri,
      );
    const selected = kid ? document.get(kid) : document.values().next().value;
    if (!selected) {
      throw new InvalidTokenError("External token was signed by an unknown key");
    }
    return importJWK(selected, algorithm);
  }

  private validateClaims(
    payload: ExternalTokenClaims,
    profile: TrustedIssuerConfig,
    options: ExternalTokenVerifyOptions,
  ): void {
    if (payload.iss !== profile.issuer) {
      throw new InvalidTokenError("External token issuer does not match");
    }
    const expectedAudience = asAudienceList(options.audience ?? profile.audience);
    if (!audiencesMatch(payload.aud, expectedAudience)) {
      throw new InvalidTokenError("External token audience does not match");
    }
    if (profile.expectedTyp && payload.typ !== profile.expectedTyp) {
      throw new InvalidTokenError("External token type does not match");
    }
    const required = profile.requiredClaims ?? ["sub", "exp", "iat"];
    for (const claim of required) {
      if (payload[claim] === undefined || payload[claim] === null) {
        throw new ValidationError(`External token is missing required claim ${claim}`);
      }
    }
    if (typeof payload.exp !== "number") {
      throw new InvalidTokenError("External token is missing exp");
    }
    const now = Math.floor(Date.now() / 1000);
    const skew = options.clockTolerance ?? profile.clockTolerance ?? DEFAULT_CLOCK_TOLERANCE;
    if (typeof payload.nbf === "number" && payload.nbf > now + skew) {
      throw new InvalidTokenError("External token is not yet valid");
    }
    const effectiveMaxTokenAge = options.maxTokenAge ?? profile.maxTokenAge;
    if (effectiveMaxTokenAge !== undefined) {
      if (typeof payload.iat !== "number") {
        throw new InvalidTokenError("External token is missing iat required for maxTokenAge validation");
      }
      if (now - payload.iat > effectiveMaxTokenAge + skew) {
        throw new InvalidTokenError("External token exceeds maxTokenAge");
      }
    }
  }
}

export function createExternalTokenVerifier(issuers: TrustedIssuerConfig[], cache?: JwksCache): ExternalTokenVerifier {
  return new ExternalTokenVerifier(issuers, cache);
}
