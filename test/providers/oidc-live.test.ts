 
import { describe, it, expect } from "vitest";
import { createOAuth, apple } from "../../src/index.js";

const LIVE = process.env.OIDC_LIVE === "1";

const skipReason = LIVE
  ? false
  : true;

describe("live OIDC provider integration (opt-in)", { skip: skipReason }, () => {
  it("fetches the provider discovery document", async () => {
    const issuer = process.env.OIDC_ISSUER ?? "https://appleid.apple.com";
    const res = await fetch(`${issuer}/.well-known/openid-configuration`);
    expect(res.ok).toBe(true);
    const metadata = (await res.json()) as Record<string, unknown>;
    expect(metadata.issuer).toBe(issuer);
    expect(typeof metadata.jwks_uri).toBe("string");
  });

  it("retrieves the provider JWKS document", async () => {
    const issuer = process.env.OIDC_ISSUER ?? "https://appleid.apple.com";
    const metaRes = await fetch(`${issuer}/.well-known/openid-configuration`);
    expect(metaRes.ok).toBe(true);
    const metadata = (await metaRes.json()) as { jwks_uri: string };
    const keysRes = await fetch(metadata.jwks_uri);
    expect(keysRes.ok).toBe(true);
    const jwks = (await keysRes.json()) as { keys?: unknown[] };
    expect(Array.isArray(jwks.keys) && jwks.keys.length > 0).toBe(true);
  });

  it("validates a configured id_token against the live provider when supplied", async () => {
    const idToken = process.env.OIDC_ID_TOKEN;
    const clientId = process.env.OIDC_CLIENT_ID;
    if (!idToken || !clientId) {
      it.skip("OIDC_ID_TOKEN and OIDC_CLIENT_ID are required for token validation");
      return;
    }
    const issuer = process.env.OIDC_ISSUER ?? "https://appleid.apple.com";
    const oauth = createOAuth({
      providers: {
        apple: {
          clientId,
          provider: apple,
          verifyIdTokenSignature: true,
        },
      },
    });
    const entry = oauth.get("apple");
    if (issuer !== "https://appleid.apple.com") {
      it.skip("live token validation is only wired for the built-in Apple provider");
      return;
    }
    const profile = await entry.provider.fetchProfile(entry.config, { id_token: idToken });
    expect(profile && typeof profile.id === "string").toBe(true);
  });

  it("rejects an id_token with a tampered signature using the live JWKS", async () => {
    const idToken = process.env.OIDC_ID_TOKEN;
    const clientId = process.env.OIDC_CLIENT_ID;
    if (!idToken || !clientId) {
      it.skip("OIDC_ID_TOKEN and OIDC_CLIENT_ID are required for token validation");
      return;
    }
    const issuer = process.env.OIDC_ISSUER ?? "https://appleid.apple.com";
    const oauth = createOAuth({
      providers: {
        apple: {
          clientId,
          provider: apple,
          verifyIdTokenSignature: true,
        },
      },
    });
    const entry = oauth.get("apple");
    if (issuer !== "https://appleid.apple.com") {
      it.skip("live token validation is only wired for the built-in Apple provider");
      return;
    }
    const tamperedToken = idToken.slice(0, -10) + "aaaaaaaaaa";
    await expect(() =>
      entry.provider.fetchProfile(entry.config, { id_token: tamperedToken }),
    ).rejects.toThrow();
  });
});
