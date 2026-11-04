 
import { describe, it, expect } from "vitest";
import { SignJWT, generateKeyPair, exportJWK } from "jose";
import {
  createExternalTokenVerifier,
  InvalidTokenError,
  ConfigurationError,
  TokenExpiredError,
  ValidationError,
} from "../../src/index.js";

const SECRET = new TextEncoder().encode("external-token-secret-key-123456");

async function mint(
  claims: Record<string, unknown>,
  alg = "HS256",
  header: Record<string, unknown> = {},
): Promise<string> {
  return new SignJWT(claims)
    .setProtectedHeader({ alg, typ: "JWT", ...header })
    .sign(SECRET);
}

function issuer(overrides: Record<string, unknown> = {}): any {
  return {
    issuer: "https://identity.example.com",
    audience: "orders-api",
    algorithms: ["HS256"],
    keySource: { type: "static", key: SECRET },
    requiredClaims: ["sub", "exp", "iat"],
    ...overrides,
  };
}

describe("external token verifier (real)", () => {
  it("accepts a token from a configured issuer", async () => {
    const verifier = createExternalTokenVerifier([issuer()]);
    const now = Math.floor(Date.now() / 1000);
    const token = await mint({
      iss: "https://identity.example.com",
      aud: "orders-api",
      sub: "user-1",
      iat: now,
      exp: now + 60,
    });
    const result = await verifier.verify(token);
    expect(result.issuer).toBe("https://identity.example.com");
    expect(result.subject).toBe("user-1");
    expect(result.claims.sub).toBe("user-1");
    expect(result).not.toHaveProperty("accessToken");
    expect(result).not.toHaveProperty("session");
  });

  it("accepts any audience in a configured allowlist", async () => {
    const verifier = createExternalTokenVerifier([
      issuer({ audience: ["orders-api", "billing-api"] }),
    ]);
    const now = Math.floor(Date.now() / 1000);
    const token = await mint({
      iss: "https://identity.example.com",
      aud: "billing-api",
      sub: "user-1",
      iat: now,
      exp: now + 60,
    });
    const result = await verifier.verify(token);
    expect(result.subject).toBe("user-1");
  });

  it("verifies tokens against an inline JWKS document", async () => {
    const { publicKey, privateKey } = await generateKeyPair("RS256");
    const jwk = await exportJWK(publicKey);
    jwk.kid = "rsa-1";
    jwk.alg = "RS256";
    jwk.use = "sig";
    const verifier = createExternalTokenVerifier([
      issuer({
        algorithms: ["RS256"],
        keySource: { type: "jwks-document", jwks: { keys: [jwk] } },
      }),
    ]);
    const now = Math.floor(Date.now() / 1000);
    const token = await new SignJWT({
      iss: "https://identity.example.com",
      aud: "orders-api",
      sub: "user-1",
      iat: now,
      exp: now + 60,
    })
      .setProtectedHeader({ alg: "RS256", kid: "rsa-1", typ: "JWT" })
      .sign(privateKey);
    const result = await verifier.verify(token);
    expect(result.subject).toBe("user-1");
  });
});

describe("external token verifier (edge)", () => {
  it("rejects empty, oversized, and malformed tokens", async () => {
    const verifier = createExternalTokenVerifier([issuer()]);
    await expect(verifier.verify("")).rejects.toThrow(InvalidTokenError);
    await expect(verifier.verify("a.b")).rejects.toThrow(InvalidTokenError);
    await expect(verifier.verify("x".repeat(16_385))).rejects.toThrow(InvalidTokenError);
    const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
    const payload = Buffer.from("{not-json").toString("base64url");
    await expect(verifier.verify(`${header}.${payload}.sig`)).rejects.toThrow(InvalidTokenError);
  });

  it("rejects an unknown issuer before signature checks", async () => {
    const verifier = createExternalTokenVerifier([issuer()]);
    const now = Math.floor(Date.now() / 1000);
    const token = await mint({
      iss: "https://evil.example.com",
      aud: "orders-api",
      sub: "user-1",
      iat: now,
      exp: now + 60,
    });
    await expect(verifier.verify(token)).rejects.toThrow(InvalidTokenError);
  });

  it("rejects a mismatched audience", async () => {
    const verifier = createExternalTokenVerifier([issuer()]);
    const now = Math.floor(Date.now() / 1000);
    const token = await mint({
      iss: "https://identity.example.com",
      aud: "other-api",
      sub: "user-1",
      iat: now,
      exp: now + 60,
    });
    await expect(verifier.verify(token)).rejects.toThrow(InvalidTokenError);
  });

  it("rejects a disabled issuer", async () => {
    const verifier = createExternalTokenVerifier([issuer({ enabled: false })]);
    const now = Math.floor(Date.now() / 1000);
    const token = await mint({
      iss: "https://identity.example.com",
      aud: "orders-api",
      sub: "user-1",
      iat: now,
      exp: now + 60,
    });
    await expect(verifier.verify(token)).rejects.toThrow(/disabled/);
  });

  it("rejects algorithms outside the issuer allowlist", async () => {
    const verifier = createExternalTokenVerifier([issuer({ algorithms: ["HS256"] })]);
    const now = Math.floor(Date.now() / 1000);
    const token = await mint({
      iss: "https://identity.example.com",
      aud: "orders-api",
      sub: "user-1",
      iat: now,
      exp: now + 60,
    }, "HS384");
    await expect(verifier.verify(token)).rejects.toThrow(/algorithm/);
  });

  it("rejects expired tokens and not-yet-valid tokens", async () => {
    const verifier = createExternalTokenVerifier([issuer()]);
    const now = Math.floor(Date.now() / 1000);
    const expired = await mint({
      iss: "https://identity.example.com",
      aud: "orders-api",
      sub: "user-1",
      iat: now - 120,
      exp: now - 30,
    });
    await expect(verifier.verify(expired)).rejects.toThrow(TokenExpiredError);
    const early = await mint({
      iss: "https://identity.example.com",
      aud: "orders-api",
      sub: "user-1",
      iat: now,
      nbf: now + 60,
      exp: now + 120,
    });
    await expect(verifier.verify(early)).rejects.toThrow(InvalidTokenError);
  });

  it("rejects tokens older than maxTokenAge", async () => {
    const verifier = createExternalTokenVerifier([issuer({ maxTokenAge: 10 })]);
    const now = Math.floor(Date.now() / 1000);
    const token = await mint({
      iss: "https://identity.example.com",
      aud: "orders-api",
      sub: "user-1",
      iat: now - 60,
      exp: now + 60,
    });
    await expect(verifier.verify(token)).rejects.toThrow(/maxTokenAge/);
  });

  it("rejects missing required claims", async () => {
    const verifier = createExternalTokenVerifier([issuer({ requiredClaims: ["sub", "email"] })]);
    const now = Math.floor(Date.now() / 1000);
    const token = await mint({
      iss: "https://identity.example.com",
      aud: "orders-api",
      sub: "user-1",
      iat: now,
      exp: now + 60,
    });
    await expect(verifier.verify(token)).rejects.toThrow(ValidationError);
  });
});

describe("external token verifier (behavior)", () => {
  it("rejects duplicate issuer configuration and algorithm none", () => {
    expect(() => createExternalTokenVerifier([issuer(), issuer()])).toThrow(ConfigurationError);
    expect(() => createExternalTokenVerifier([
      issuer({ algorithms: ["none"] }),
    ])).toThrow(ConfigurationError);
    expect(() => createExternalTokenVerifier([
      issuer({ algorithms: [] }),
    ])).toThrow(ConfigurationError);
    expect(() => createExternalTokenVerifier([
      issuer({ issuer: "" }),
    ])).toThrow(ConfigurationError);
  });

  it("requires HTTPS for remote JWKS unless explicitly allowed", () => {
    expect(() => createExternalTokenVerifier([
      issuer({
        algorithms: ["RS256"],
        keySource: { type: "jwks", uri: "http://identity.example.com/jwks" },
      }),
    ])).toThrow(ConfigurationError);
    expect(() => createExternalTokenVerifier([
      issuer({
        algorithms: ["RS256"],
        keySource: { type: "jwks", uri: "http://identity.example.com/jwks" },
        allowInsecureHttp: true,
      }),
    ])).not.toThrow();
  });

  it("honors per-call audience overrides and expected token types", async () => {
    const verifier = createExternalTokenVerifier([
      issuer({ expectedTyp: "at+jwt", audience: "orders-api" }),
    ]);
    const now = Math.floor(Date.now() / 1000);
    const token = await mint({
      iss: "https://identity.example.com",
      aud: "billing-api",
      sub: "user-1",
      iat: now,
      exp: now + 60,
      typ: "at+jwt",
    });
    await expect(verifier.verify(token)).rejects.toThrow(/audience/);
    const result = await verifier.verify(token, { audience: "billing-api" });
    expect(result.subject).toBe("user-1");
  });

  it("rejects an unknown kid from a JWKS document", async () => {
    const { publicKey, privateKey } = await generateKeyPair("RS256");
    const jwk = await exportJWK(publicKey);
    jwk.kid = "rsa-1";
    jwk.alg = "RS256";
    jwk.use = "sig";
    const verifier = createExternalTokenVerifier([
      issuer({
        algorithms: ["RS256"],
        keySource: { type: "jwks-document", jwks: { keys: [jwk] } },
      }),
    ]);
    const now = Math.floor(Date.now() / 1000);
    const token = await new SignJWT({
      iss: "https://identity.example.com",
      aud: "orders-api",
      sub: "user-1",
      iat: now,
      exp: now + 60,
    })
      .setProtectedHeader({ alg: "RS256", kid: "missing", typ: "JWT" })
      .sign(privateKey);
    await expect(verifier.verify(token)).rejects.toThrow(/unknown key/);
  });
});
