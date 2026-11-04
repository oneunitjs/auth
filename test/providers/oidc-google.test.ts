 
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createServer as createHttpServer } from "node:http";
import { generateKeyPairSync, sign as signRSA } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { createOAuth, google } from "../../src/index.js";

const GOOGLE_ISSUER = "https://accounts.google.com";
const CLIENT_ID = "test-google-client-id";

function buildJwks(keys: Array<{ publicKey: KeyObject; kid: string }>) {
  return {
    keys: keys.map(({ publicKey, kid }) => ({
      ...(publicKey.export({ format: "jwk" }) as Record<string, unknown>),
      kid,
      alg: "RS256",
      use: "sig",
    })),
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

describe("Google OAuth PKCE", () => {
  let server: ReturnType<typeof createJwksServer>["server"];
  let setKeys: ReturnType<typeof createJwksServer>["setKeys"];
  let jwksUrl: string;

  beforeAll(async () => {
    const r = createJwksServer();
    server = r.server;
    setKeys = r.setKeys;
    await new Promise<void>((resolve) => r.server.listen(0, "127.0.0.1", resolve));
    jwksUrl = `http://127.0.0.1:${(r.server.address() as { port: number }).port}/.well-known/jwks.json`;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it("google includes S256 challenge", async () => {
    const oauth = createOAuth({
      providers: { google: { clientId: "cid", provider: google, redirectUri: "http://localhost/cb", redirectUriPolicy: { allowedRedirectUris: ["http://localhost/cb"], allowLocalhostHttp: true } } },
    });
    const { url } = await oauth.authorize("google", { state: "g" });
    expect(url).toMatch(/code_challenge_method=S256/);
  });

  it("verifies Google ID token signature against local JWKS", async () => {
    const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    setKeys([{ publicKey, privateKey, kid: "google-kid-1" }]);

    const now = Math.floor(Date.now() / 1000);
    const idToken = signIdToken(
      {
        iss: GOOGLE_ISSUER,
        aud: CLIENT_ID,
        sub: "google-user-1",
        email: "user@example.com",
        exp: now + 3600,
        iat: now,
      },
      privateKey,
      { kid: "google-kid-1" },
    );

    const oauth = createOAuth({
      providers: {
        google: {
          clientId: CLIENT_ID,
          provider: google,
          jwksUrl,
          verifyIdTokenSignature: true,
        },
      },
    });

    const profile = await oauth.providers.get("google")!.provider.fetchProfile(
      oauth.providers.get("google")!.config,
      { id_token: idToken },
    );
    expect(profile.id).toBe("google-user-1");
    expect(profile.email).toBe("user@example.com");
  });

  it("rejects token signed by unknown kid", async () => {
    const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    setKeys([{ publicKey, privateKey, kid: "google-kid-1" }]);

    const now = Math.floor(Date.now() / 1000);
    const idToken = signIdToken(
      {
        iss: GOOGLE_ISSUER,
        aud: CLIENT_ID,
        sub: "google-user-2",
        email: "user@example.com",
        exp: now + 3600,
        iat: now,
      },
      privateKey,
      { kid: "unknown-kid" },
    );

    const oauth = createOAuth({
      providers: {
        google: {
          clientId: CLIENT_ID,
          provider: google,
          jwksUrl,
          verifyIdTokenSignature: true,
        },
      },
    });

    await expect(() =>
      oauth.providers.get("google")!.provider.fetchProfile(
        oauth.providers.get("google")!.config,
        { id_token: idToken },
      ),
    ).rejects.toThrow(/unknown key/i);
  });
});
