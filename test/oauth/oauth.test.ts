 
import { describe, it, expect } from "vitest";
import {
  createOAuth,
  createProvider,
  getProvider,
  builtinProviders,
  google,
  github,
  instagram,
  ValidationError,
  OAuthError,
} from "../../src/index.js";
import type { ProviderDefinition } from "../../src/index.js";

const TEST_REDIRECT_POLICY = {
  redirectUriPolicy: {
    allowedRedirectUris: [
      "http://localhost/cb",
      "http://localhost/callback/github",
      "http://localhost/callback/instagram",
      "http://localhost:3000/auth/google/callback",
      "http://localhost/discord",
    ],
    allowLocalhostHttp: true,
  },
};

describe("oauth providers", () => {
  it("exposes built-in social providers", () => {
    for (const id of [
      "google",
      "github",
      "instagram",
      "facebook",
      "twitter",
      "discord",
      "apple",
      "linkedin",
      "microsoft",
      "reddit",
      "twitch",
      "slack",
      "spotify",
      "tiktok",
    ] as const) {
      expect(builtinProviders[id]).toBeDefined();
      expect(getProvider(id).id === "twitter" || getProvider(id).id === id).toBe(true);
    }
    expect(google.id).toBe("google");
    expect(github.id).toBe("github");
    expect(instagram.id).toBe("instagram");
  });

  it("builds a google authorization url", async () => {
    const oauth = createOAuth({
      redirectUri: "http://localhost:3000/auth/google/callback",
      providers: {
        google: { clientId: "google-client", clientSecret: "google-secret", ...TEST_REDIRECT_POLICY },
      },
    });

    const result = await oauth.authorize("google", { state: "abc123" });
    const url = new URL(result.url);
    expect(url.hostname).toBe("accounts.google.com");
    expect(url.searchParams.get("client_id")).toBe("google-client");
    expect(url.searchParams.get("state")).toBe("abc123");
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("scope")).toMatch(/openid/);
  });

  it("builds github and instagram authorization urls", async () => {
    const oauth = createOAuth({
      providers: {
        github: {
          clientId: "gh",
          clientSecret: "secret",
          redirectUri: "http://localhost/callback/github",
          ...TEST_REDIRECT_POLICY,
        },
        instagram: {
          clientId: "ig",
          clientSecret: "secret",
          redirectUri: "http://localhost/callback/instagram",
          ...TEST_REDIRECT_POLICY,
        },
      },
    });

    const gh = await oauth.authorize("github");
    expect(gh.url).toMatch(/github\.com\/login\/oauth\/authorize/);
    const ig = await oauth.authorize("instagram");
    expect(ig.url).toMatch(/api\.instagram\.com\/oauth\/authorize/);
  });

  it("rejects unknown providers and missing codes", () => {
    const oauth = createOAuth();
    expect(() => oauth.get("missing")).toThrow(ValidationError);
    return expect(() => oauth.callback("google", {})).rejects.toThrow(ValidationError);
  });

  it("surfaces provider errors from the callback query", async () => {
    const oauth = createOAuth({
      providers: {
        google: { clientId: "id", clientSecret: "secret", redirectUri: "http://localhost/cb" },
      },
    });
    await expect(
      () => oauth.callback("google", { error: "access_denied", error_description: "user denied" }),
    ).rejects.toThrow(OAuthError);
  });

  it("creates a custom provider", () => {
    const custom = createProvider({
      id: "acme",
      authorizationUrl: "https://acme.example/oauth/authorize",
      tokenUrl: "https://acme.example/oauth/token",
      userInfoUrl: "https://acme.example/me",
      scopes: ["profile"],
      profileMap: { id: "id", email: "email" },
    });
    const { url } = custom.createAuthorizationUrl(
      { clientId: "acme-id", redirectUri: "http://localhost/cb", ...TEST_REDIRECT_POLICY },
      { state: "s" },
    );
    expect(url).toMatch(/acme\.example/);
  });

  it("rejects invalid custom provider definitions", () => {
    expect(() => createProvider({ id: "x" } as ProviderDefinition)).toThrow(ValidationError);
  });

  it("stores and validates oauth state", async () => {
    const oauth = createOAuth({
      providers: {
        discord: {
          clientId: "d",
          clientSecret: "s",
          redirectUri: "http://localhost/discord",
          ...TEST_REDIRECT_POLICY,
        },
      },
    });
    const started = await oauth.authorize("discord", { state: "discord-state" });
    expect(await oauth.verifyState(started.state, "discord")).toBe(true);
    expect(await oauth.verifyState("missing")).toBe(false);
  });
});
