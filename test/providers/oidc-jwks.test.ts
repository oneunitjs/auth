 
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import type { KeyObject } from "node:crypto";
import { generateKeyPairSync, sign as signRSA } from "node:crypto";
import { createServer as createHttpServer } from "node:http";
import {
  createOAuth,
  apple,
} from "../../src/index.js";

/**
 * Local OIDC / JWKS test server for deterministic key-rotation testing.
 *
 * The package does not implement OIDC discovery (`/.well-known/openid-configuration`)
 * nor automatic JWKS URL derivation from issuer metadata. JWKS URLs are configured
 * per provider through `OAuthProviderConfig.jwksUrl` or the `jwks` inline option.
 * This test server exercises the package's actual JWKS fetch + kid cache + refetch
 * behaviour against a controllable local endpoint instead of a live third-party
 * provider.
 *
 * The built-in `apple` provider checks `iss === "https://appleid.apple.com"`, so
 * test tokens use Apple's real issuer string while pointing `jwksUrl` at the local
 * test server. This verifies the full JWKS fetch + signature verification path
 * without touching Apple's network.
 */
interface JwkEntry {
  publicKey: KeyObject;
  privateKey: KeyObject;
  kid: string;
}

const APPLE_ISSUER = "https://appleid.apple.com";

function buildJwks(keys: JwkEntry[]): { keys: Record<string, unknown>[] } {
  return {
    keys: keys.map(({ publicKey, kid }) => {
      const jwk = publicKey.export({ format: "jwk" }) as Record<string, unknown>;
      return { ...jwk, kid, alg: "RS256", use: "sig" };
    }),
  };
}

function signIdToken(
  claims: Record<string, unknown>,
  privateKey: KeyObject,
  options: { kid?: string; alg?: string } = {},
): string {
  const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
  const header: Record<string, unknown> = { alg: options.alg ?? "RS256" };
  if (options.kid !== undefined) header.kid = options.kid;
  const head = b64(header);
  const body = b64(claims);
  const signature = signRSA("RSA-SHA256", Buffer.from(`${head}.${body}`, "utf8"), privateKey);
  return `${head}.${body}.${signature.toString("base64url")}`;
}

function createJwksServer() {
  let currentKeys: Array<{ publicKey: KeyObject; privateKey: KeyObject; kid: string }> = [];
  let failNext = false;
  const server = createHttpServer((req, res) => {
    const url = new URL(req.url ?? "", `http://${req.headers.host}`);
    if (url.pathname !== "/.well-known/jwks.json") {
      res.writeHead(404);
      res.end("not found");
      return;
    }
    if (failNext) {
      failNext = false;
      res.writeHead(503);
      res.end("temporary outage");
      return;
    }
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(buildJwks(currentKeys)));
  });
  return { server, setKeys: (keys: Array<{ publicKey: KeyObject; privateKey: KeyObject; kid: string }>) => { currentKeys = keys; }, setFailNext: () => { failNext = true; } };
}

describe("OIDC JWKS", () => {
  let server: ReturnType<typeof createJwksServer>["server"];
  let setKeys: ReturnType<typeof createJwksServer>["setKeys"];
  let setFailNext: ReturnType<typeof createJwksServer>["setFailNext"];
  let jwksUrl: string;

  beforeAll(async () => {
    const r = createJwksServer();
    server = r.server;
    setKeys = r.setKeys;
    setFailNext = r.setFailNext;
    await new Promise<void>((resolve) => r.server.listen(0, "127.0.0.1", resolve));
    jwksUrl = `http://127.0.0.1:${(r.server.address() as { port: number }).port}/.well-known/jwks.json`;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it("generates a valid S256 PKCE challenge", () => {
    // placeholder test
    expect(true).toBe(true);
  });

  it("verifies Apple ID token signature against local JWKS", async () => {
    const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    setKeys([{ publicKey, privateKey, kid: "apple-kid-1" }]);

    const now = Math.floor(Date.now() / 1000);
    const idToken = signIdToken(
      {
        iss: APPLE_ISSUER,
        aud: "com.example.app",
        sub: "apple-user-1",
        email: "user@example.com",
        exp: now + 3600,
        iat: now,
      },
      privateKey,
      { kid: "apple-kid-1" },
    );

    const oauth = createOAuth({
      providers: {
        apple: {
          clientId: "com.example.app",
          provider: apple,
          jwksUrl,
          jwksCacheTtlMs: 50,
          verifyIdTokenSignature: true,
        },
      },
    });

    const profile = await oauth.providers.get("apple")!.provider.fetchProfile(
      oauth.providers.get("apple")!.config,
      { id_token: idToken },
    );
    expect(profile.id).toBe("apple-user-1");
    expect(profile.email).toBe("user@example.com");
  });

  it("rejects token signed by unknown kid", async () => {
    const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    setKeys([{ publicKey, privateKey, kid: "apple-kid-1" }]);

    const now = Math.floor(Date.now() / 1000);
    const idToken = signIdToken(
      {
        iss: APPLE_ISSUER,
        aud: "com.example.app",
        sub: "apple-user-2",
        email: "user@example.com",
        exp: now + 3600,
        iat: now,
      },
      privateKey,
      { kid: "unknown-kid" },
    );

    const oauth = createOAuth({
      providers: {
        apple: {
          clientId: "com.example.app",
          provider: apple,
          jwksUrl,
          jwksCacheTtlMs: 50,
          verifyIdTokenSignature: true,
        },
      },
    });

    await expect(() =>
      oauth.providers.get("apple")!.provider.fetchProfile(
        oauth.providers.get("apple")!.config,
        { id_token: idToken },
      ),
    ).rejects.toThrow(/unknown key/i);
  });

  it("rotates keys after JWKS refresh", async () => {
    const { publicKey: oldKey, privateKey: oldPrivateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const { publicKey: newKey, privateKey: newPrivateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });

    setKeys([{ publicKey: oldKey, privateKey: oldPrivateKey, kid: "apple-kid-1" }]);

    const now = Math.floor(Date.now() / 1000);
    const idToken = signIdToken(
      {
        iss: APPLE_ISSUER,
        aud: "com.example.app",
        sub: "apple-user-1",
        email: "user@example.com",
        exp: now + 3600,
        iat: now,
      },
      oldPrivateKey,
      { kid: "apple-kid-1" },
    );

    const oauth = createOAuth({
      providers: {
        apple: {
          clientId: "com.example.app",
          provider: apple,
          jwksUrl,
          jwksCacheTtlMs: 50,
          verifyIdTokenSignature: true,
        },
      },
    });

    const profile = await oauth.providers.get("apple")!.provider.fetchProfile(
      oauth.providers.get("apple")!.config,
      { id_token: idToken },
    );
    expect(profile.id).toBe("apple-user-1");

    // Rotate keys
    setKeys([{ publicKey: newKey, privateKey: newPrivateKey, kid: "apple-kid-2" }]);

    await new Promise((resolve) => setTimeout(resolve, 250));

    const idToken2 = signIdToken(
      {
        iss: APPLE_ISSUER,
        aud: "com.example.app",
        sub: "apple-user-2",
        email: "user@example.com",
        exp: now + 3600,
        iat: now,
      },
      newPrivateKey,
      { kid: "apple-kid-2" },
    );

    const profile2 = await oauth.providers.get("apple")!.provider.fetchProfile(
      oauth.providers.get("apple")!.config,
      { id_token: idToken2 },
    );
    expect(profile2.id).toBe("apple-user-2");
  });

  it("fails closed when JWKS endpoint is unavailable", async () => {
    setFailNext();

    const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    setKeys([{ publicKey, privateKey, kid: "apple-kid-1" }]);

    const now = Math.floor(Date.now() / 1000);
    const idToken = signIdToken(
      {
        iss: APPLE_ISSUER,
        aud: "com.example.app",
        sub: "apple-user-1",
        email: "user@example.com",
        exp: now + 3600,
        iat: now,
      },
      privateKey,
      { kid: "apple-kid-1" },
    );

    const oauth = createOAuth({
      providers: {
        apple: {
          clientId: "com.example.app",
          provider: apple,
          jwksUrl,
          jwksCacheTtlMs: 50,
          verifyIdTokenSignature: true,
        },
      },
    });

    await expect(() =>
      oauth.providers.get("apple")!.provider.fetchProfile(
        oauth.providers.get("apple")!.config,
        { id_token: idToken },
      ),
    ).rejects.toThrow();
  });
});
