import { JwtBackendImpl } from "./jwt-backend.js";
import { decodeJwt } from "jose";
import { InvalidTokenError, ValidationError } from "../errors/index.js";
import type { JwtPayload, JwtSignOptions, JwtVerifyOptions, Secret } from "../types/index.js";

const DEFAULT_ALGORITHM = "HS256";
const DEFAULT_EXPIRES_IN = 60 * 60 * 24;

function secretByteLength(secret: Secret): number {
  if (typeof secret === "string") {
    return Buffer.byteLength(secret, "utf8");
  }
  if (secret instanceof Uint8Array) {
    return secret.length;
  }
  return 0;
}

function normalizeSecret(secret: Secret): Uint8Array {
  if (secretByteLength(secret) < 32) {
    throw new ValidationError(
      "Secret must be at least 32 bytes (256 bits) of high-entropy material",
    );
  }
  if (typeof secret === "string" && secret.length > 0) {
    return new TextEncoder().encode(secret);
  }
  if (secret instanceof Uint8Array && secret.length > 0) {
    return secret;
  }
  if (Buffer.isBuffer(secret) && secret.length > 0) {
    return new Uint8Array(secret);
  }
  throw new ValidationError("A non-empty secret is required to sign or verify tokens");
}

function backendFor(secret: Secret): JwtBackendImpl {
  return new JwtBackendImpl({
    signingKey: secret,
    verificationKey: secret,
    algorithmPolicy: {
      signing: ["HS256"],
      verification: ["HS256"],
    },
  });
}

export async function encode(
  payload: object = {},
  secret: Secret,
  options: JwtSignOptions = {},
): Promise<string> {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new ValidationError("Token payload must be an object");
  }
  normalizeSecret(secret);

  const backend = options.backend ?? backendFor(secret);
  return backend.sign(payload as JwtPayload, {
    expiresIn:
      options.expiresIn ?? options.expiresInSeconds ?? DEFAULT_EXPIRES_IN,
    notBefore: options.notBefore,
    audience: options.audience,
    issuer: options.issuer,
    subject: options.subject,
    jwtid: options.jwtid,
    keyid: options.keyid,
    header: options.header,
    algorithm: options.algorithm,
  });
}

export async function decode(
  token: string,
  secret: Secret,
  options: JwtVerifyOptions = {},
): Promise<JwtPayload> {
  if (!token || typeof token !== "string") {
    throw new InvalidTokenError("Token is required");
  }
  normalizeSecret(secret);

  const backend = options.backend ?? backendFor(secret);
  return backend.verify(token, {
    ...options,
    algorithms: [DEFAULT_ALGORITHM],
  });
}

export function decodeUnsafe(token: string): unknown {
  if (!token || typeof token !== "string") {
    return null;
  }
  return decodeJwt(token) ?? null;
}

function withTyp(
  payload: object,
  typ: string,
  options: JwtSignOptions & { secret: Secret } = { secret: "" },
): Promise<string> {
  const next: Record<string, unknown> = { ...(payload as Record<string, unknown>), typ };
  const subject = options.subject ?? next.sub ?? next.userId;
  if (subject !== undefined && next.sub === undefined) {
    next.sub = String(subject);
  }
  return encode(next, options.secret, {
    expiresIn: options.expiresIn,
    notBefore: options.notBefore,
    audience: options.audience,
    issuer: options.issuer,
    jwtid: options.jwtid,
    keyid: options.keyid,
    header: options.header,
    algorithm: options.algorithm,
  });
}

export function encodeAccessToken(
  payload: object,
  secret: Secret,
  options: JwtSignOptions = {},
): Promise<string> {
  return withTyp(payload, "access", {
    ...options,
    secret,
    expiresIn: options.expiresIn ?? "15m",
  });
}

export function encodeRefreshToken(
  payload: object,
  secret: Secret,
  options: JwtSignOptions = {},
): Promise<string> {
  return withTyp(payload, "refresh", {
    ...options,
    secret,
    expiresIn: options.expiresIn ?? "7d",
  });
}
