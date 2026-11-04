import type { JwtAlgorithm } from "../crypto/jwt-backend.js";

export type ExternalKeySource =
  | { type: "jwks"; uri: string; cacheTtlMs?: number }
  | { type: "jwks-document"; jwks: Record<string, unknown> }
  | { type: "static"; key: string | Uint8Array };

export interface TrustedIssuerConfig {
  issuer: string;
  audience: string | string[];
  algorithms: JwtAlgorithm[];
  keySource: ExternalKeySource;
  requiredClaims?: string[];
  clockTolerance?: number;
  maxTokenAge?: number;
  expectedTyp?: string;
  enabled?: boolean;
  allowInsecureHttp?: boolean;
}

export interface ExternalTokenVerifyOptions {
  audience?: string | string[];
  clockTolerance?: number;
  maxTokenAge?: number;
}

export interface ExternalTokenClaims {
  iss: string;
  aud?: string | string[];
  sub?: string;
  exp?: number;
  nbf?: number;
  iat?: number;
  typ?: string;
  [key: string]: unknown;
}

export interface ExternalTokenResult {
  issuer: string;
  audience: string | string[];
  subject?: string;
  claims: ExternalTokenClaims;
}
