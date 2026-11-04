import {
  SignJWT,
  jwtVerify,
  compactVerify,
  decodeJwt,
  type JWTPayload,
  type JWTHeaderParameters,
  importJWK,
} from "jose";
import {
  createSecretKey,
  type KeyObject,
} from "node:crypto";
import {
  AuthError,
  InvalidTokenError,
  TokenExpiredError,
  ValidationError,
  ConfigurationError,
  UnauthorizedError,
} from "../errors/index.js";
import type {
  JwtPayload,
  JwtSignOptions,
  JwtVerifyOptions,
} from "../types/index.js";
import { isValidExpiresIn, parseExpiresIn } from "../utils.js";
import { JwksCache, resolveJwksDocument } from "./jwks.js";

export type JwtSigningKey = string | Uint8Array | KeyObject;
export type JwtVerificationKey = string | Uint8Array | KeyObject;

export type JwtAlgorithm = "HS256" | "RS256" | "ES256";

export interface JwtAlgorithmPolicy {
  signing: JwtAlgorithm[];
  verification: JwtAlgorithm[];
}

export const DEFAULT_ALGORITHM_POLICY: JwtAlgorithmPolicy = {
  signing: ["HS256"],
  verification: ["HS256"],
};

export interface JwtSigningKeyOptions {
  algorithm?: JwtAlgorithm;
  kid?: string;
}

export interface JwtVerificationKeyOptions {
  algorithm?: JwtAlgorithm;
  kid?: string;
  issuer?: string;
  jwksUrl?: string;
  jwksCacheTtlMs?: number;
}

export interface JwtBackendConfig {
  signingKey?: JwtSigningKey;
  refreshSigningKey?: JwtSigningKey;
  verificationKey?: JwtVerificationKey;
  refreshVerificationKey?: JwtVerificationKey;
  keyResolver?: JwtKeyResolver;
  algorithmPolicy?: JwtAlgorithmPolicy;
}

export interface JwtBackend {
  sign(payload: JwtPayload, options: JwtSignOptions): Promise<string>;
  verify(token: string, options: JwtVerifyOptions): Promise<JwtPayload>;
}

export interface JwtKeyResolver {
  resolveSigningKey(options: JwtSigningKeyOptions): Promise<JwtSigningKey>;
  resolveVerificationKey(options: JwtVerificationKeyOptions): Promise<JwtVerificationKey>;
}

function normalizeSigningKey(key: JwtSigningKey): KeyObject {
  if (typeof key === "string") {
    return createSecretKey(Buffer.from(key));
  }
  if (key instanceof Uint8Array) {
    return createSecretKey(key);
  }
  return key;
}

function normalizeVerificationKey(key: JwtVerificationKey): KeyObject {
  if (typeof key === "string") {
    return createSecretKey(Buffer.from(key));
  }
  if (key instanceof Uint8Array) {
    return createSecretKey(key);
  }
  return key;
}

export class JwtBackendImpl implements JwtBackend {
  private readonly signingKey: JwtSigningKey | undefined;
  private readonly refreshSigningKey: JwtSigningKey | undefined;
  private readonly verificationKey: JwtVerificationKey | undefined;
  private readonly refreshVerificationKey: JwtVerificationKey | undefined;
  private readonly keyResolver: JwtKeyResolver | undefined;
  private readonly policy: JwtAlgorithmPolicy;

  constructor(config: JwtBackendConfig) {
    this.signingKey = config.signingKey;
    this.refreshSigningKey = config.refreshSigningKey;
    this.verificationKey = config.verificationKey;
    this.refreshVerificationKey = config.refreshVerificationKey;
    this.keyResolver = config.keyResolver;
    this.policy = config.algorithmPolicy ?? DEFAULT_ALGORITHM_POLICY;
  }

  async sign(payload: JwtPayload, options: JwtSignOptions): Promise<string> {
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
      throw new ValidationError("Token payload must be an object");
    }

    const algorithm =
      (options.algorithm as JwtAlgorithm) ?? this.policy.signing[0];

    if (!this.policy.signing.includes(algorithm)) {
      throw new ValidationError(
        `Algorithm "${algorithm}" is not allowed for signing`,
      );
    }

    const signingKey = await this.resolveSigningKey(options, payload.typ);

    try {
      const signPayload: Record<string, unknown> = { ...payload };

      let expiresInSecondsResolved: number | undefined;
      if (options.expiresIn !== undefined && options.expiresIn !== null) {
        if (!isValidExpiresIn(options.expiresIn)) {
          throw new ValidationError(
            `Invalid expiresIn: ${JSON.stringify(options.expiresIn)}`,
          );
        }
        expiresInSecondsResolved =
          typeof options.expiresIn === "number"
            ? options.expiresIn
            : parseExpiresIn(options.expiresIn);
      }

      const now = Math.floor(Date.now() / 1000);
      if (expiresInSecondsResolved !== undefined) {
        signPayload.exp = now + expiresInSecondsResolved;
      }
      if (options.notBefore !== undefined) {
        signPayload.nbf =
          typeof options.notBefore === "number"
            ? options.notBefore
            : parseExpiresIn(options.notBefore);
      }
      if (options.audience !== undefined) {
        signPayload.aud = options.audience;
      }
      if (options.issuer !== undefined) {
        signPayload.iss = options.issuer;
      }
      if (options.subject !== undefined) {
        signPayload.sub = String(options.subject);
      }
      if (options.jwtid !== undefined) {
        signPayload.jti = options.jwtid;
      }

      const key = normalizeSigningKey(signingKey);

      const header: JWTHeaderParameters = { alg: algorithm, typ: "JWT" };
      if (options.keyid) {
        header.kid = options.keyid;
      }
      if (options.header) {
        Object.assign(header, options.header);
      }

      return new SignJWT(signPayload as JWTPayload)
        .setProtectedHeader(header)
        .sign(key);
    } catch (error) {
      if (error instanceof AuthError) {
        throw error;
      }
      throw new InvalidTokenError(
        error instanceof Error ? error.message : "Failed to sign token",
        { cause: error },
      );
    }
  }

  async verify(token: string, options: JwtVerifyOptions): Promise<JwtPayload> {
    if (!token || typeof token !== "string") {
      throw new InvalidTokenError("Token is required");
    }

    const {
      algorithms = this.policy.verification,
      ignoreExpiration = false,
    } = options;

    const verificationKey = normalizeVerificationKey(
      await this.resolveVerificationKey(token, options),
    );

    try {
      const { payload } = (await jwtVerify(token, verificationKey, {
        algorithms: algorithms as string[],
        clockTolerance: options.clockTolerance,
      })) as { payload: JWTPayload };

      this.validateClaims(payload, options);

      return payload as JwtPayload;
    } catch (error) {
      if (error instanceof AuthError) {
        throw error;
      }
      if (error instanceof Error) {
        if (error.name === "JWTExpired" && ignoreExpiration) {
          let payload: JWTPayload;
          try {
            // jwtVerify verifies the JWS signature before validating claims, so
            // a JWTExpired error means the signature is already
            // cryptographically valid. Re-verify the signature explicitly with
            // compactVerify (signature verification only, no claim/expiration
            // checks) so expiration can be ignored without ever accepting an
            // unverified or forged token.
            await compactVerify(token, verificationKey, {
              algorithms: algorithms as string[],
            });
            payload = (decodeJwt(token) as JWTPayload) as JwtPayload;
          } catch {
            throw new InvalidTokenError("Invalid or expired token", {
              cause: error,
            });
          }
          this.validateClaims(payload, options);
          return payload;
        }
        if (error.name === "JWTExpired") {
          throw new TokenExpiredError("Token has expired", { cause: error });
        }
        if (error.name === "JWTInvalid" || error.name === "JWSInvalid") {
          throw new InvalidTokenError("Invalid or expired token", {
            cause: error,
          });
        }
      }
      throw new InvalidTokenError("Invalid or expired token", {
        cause: error,
      });
    }
  }

  private validateClaims(
    payload: JwtPayload,
    options: JwtVerifyOptions,
  ): void {
    const { audience, issuer, subject, acceptTokenType } = options;

    if (audience !== undefined) {
      const tokenAud = payload.aud;
      const matches = Array.isArray(tokenAud)
        ? tokenAud.includes(audience as string)
        : tokenAud === audience;
      if (!matches) {
        throw new InvalidTokenError("Token audience does not match");
      }
    }

    if (issuer !== undefined && payload.iss !== issuer) {
      throw new InvalidTokenError("Token issuer does not match");
    }

    if (subject !== undefined && payload.sub !== subject) {
      throw new InvalidTokenError("Token subject does not match");
    }

    if (acceptTokenType !== undefined && payload.typ !== acceptTokenType) {
      throw new UnauthorizedError(
        `Token type "${payload.typ}" does not match expected type "${acceptTokenType}"`,
      );
    }
  }

  private async resolveSigningKey(
    options: JwtSignOptions,
    typ?: string,
  ): Promise<KeyObject> {
    // For refresh tokens, use the refresh-specific signing key if available.
    // The `typ` is read from the JWT payload, not from signing options
    // (JwtSignOptions has no `typ` field).
    const key =
      typ === "refresh" && this.refreshSigningKey
        ? this.refreshSigningKey
        : this.signingKey;

    if (!key) {
      if (this.keyResolver) {
        return normalizeSigningKey(
          await this.keyResolver.resolveSigningKey({
            algorithm: options.algorithm as JwtAlgorithm,
            kid: options.jwtid,
          }),
        );
      }
      throw new ConfigurationError(
        "No signing key configured",
        { code: "CONFIGURATION_ERROR" },
      );
    }
    return normalizeSigningKey(key);
  }

  private async resolveVerificationKey(
    token: string,
    options: JwtVerificationKeyOptions,
  ): Promise<JwtVerificationKey> {
    // Read the token's typ claim (without signature verification) to select
    // the correct verification key: refresh tokens are signed with the
    // refresh secret and must be verified with the refresh verification key.
    let typ: string | undefined;
    try {
      typ = (decodeJwt(token) as { typ?: string }).typ;
    } catch {
      // Ignore decode errors; fall back to the default verification key.
    }

    // Extract the kid from the token header without verification
    let kid: string | undefined;
    try {
      const header = JSON.parse(
        Buffer.from(token.split(".")[0], "base64url").toString("utf8"),
      ) as { kid?: string; alg?: string };
      kid = header.kid;
    } catch {
      // If we can't parse the header, fall back to static key
    }

    if (kid) {
      if (this.keyResolver) {
        return normalizeVerificationKey(
          await this.keyResolver.resolveVerificationKey({
            algorithm: (options.algorithm as JwtAlgorithm) ?? undefined,
            kid,
            issuer: options.issuer,
          }),
        );
      }
      // If we have a static verification key, use it regardless of kid
      if (this.verificationKey) {
        return normalizeVerificationKey(this.verificationKey);
      }
    } else if (this.verificationKey) {
      if (typ === "refresh" && this.refreshVerificationKey) {
        return normalizeVerificationKey(this.refreshVerificationKey);
      }
      return normalizeVerificationKey(this.verificationKey);
    }

    throw new ConfigurationError(
      "No verification key configured",
      { code: "CONFIGURATION_ERROR" },
    );
  }
}

export class JwksKeyResolver implements JwtKeyResolver {
  constructor(private cache: JwksCache, private defaultJwksUrl: string) {}

  async resolveSigningKey(_options: JwtSigningKeyOptions): Promise<JwtSigningKey> {
    throw new InvalidTokenError(
      "Signing key resolution from JWKS is not supported",
    );
  }

  async resolveVerificationKey(
    options: JwtVerificationKeyOptions,
  ): Promise<JwtVerificationKey> {
    const jwksUrl = options.jwksUrl ?? this.defaultJwksUrl;
    const keys = await resolveJwksDocument(
      { jwksUrl },
      this.cache,
      this.defaultJwksUrl,
    );

    const kid = options.kid ?? "";
    let key = kid ? keys.get(kid) : undefined;
    if (!key) {
      const refreshed = await this.cache.refreshForUnknownKid(
        jwksUrl,
        jwksUrl,
        options.jwksCacheTtlMs,
      );
      if (refreshed) {
        const updated = await resolveJwksDocument(
          { jwksUrl },
          this.cache,
          this.defaultJwksUrl,
        );
        key = kid ? updated.get(kid) : undefined;
      }
    }

    if (!key) {
      throw new InvalidTokenError(`Unknown key id: ${options.kid}`);
    }

    return normalizeVerificationKey(
      (await importJWK(key, options.algorithm ?? "RS256")) as unknown as KeyObject,
    );
  }
}
