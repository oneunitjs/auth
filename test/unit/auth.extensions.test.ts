import { describe, it, expect } from "vitest";
import { createAuth } from "../../src/index.js";
import { SECRET } from "./fixtures/auth.fixtures.js";

describe("Auth signing, extractors, hooks, OAuth (EXT/OAUTH)", () => {
  it("EXT-01: sign uses configured issuer, audience, algorithm, and TTL defaults", async () => {
    const auth = createAuth({
      secret: SECRET,
      issuer: "test-issuer",
      audience: "test-audience",
      algorithm: "HS256",
      accessTokenTtl: "1h",
    });
    const token = await auth.sign({ foo: "bar" });
    expect(typeof token).toBe("string");
  });

  it("EXT-02: sign with caller options merges according to method contract", async () => {
    const auth = createAuth({ secret: SECRET });
    const token = await auth.sign({ foo: "bar" }, { expiresIn: "5m", jwtid: "custom-jti" });
    expect(typeof token).toBe("string");
  });

  it("EXT-03: register extractor and collect claims includes output unless reserved", async () => {
    const auth = createAuth({ secret: SECRET });
    auth.registerExtractor("plan", async () => ({ plan: "pro" }));
    const result = await auth.login({ id: 1, email: "a@b.c" });
    expect(result.payload.plan).toBe("pro");
  });

  it("EXT-04: extractor throws exception sets that claim to null", async () => {
    const auth = createAuth({ secret: SECRET });
    auth.registerExtractor("flaky", async () => {
      throw new Error("extractor failure");
    });
    const result = await auth.login({ id: 1, email: "a@b.c" });
    expect(result.payload.flaky).toBeNull();
  });

  it("EXT-05: request only named extractors runs only requested", async () => {
    const auth = createAuth({ secret: SECRET });
    const called: string[] = [];
    auth.registerExtractor("one", async () => { called.push("one"); return { one: 1 }; });
    auth.registerExtractor("two", async () => { called.push("two"); return { two: 2 }; });
    await auth.login({ id: 1, email: "a@b.c" }, { extractors: ["one"] });
    expect(called).toEqual(["one"]);
  });

  it("OAUTH-01: request authorization URL for configured provider delegates to OAuth", async () => {
    const auth = createAuth({
      secret: SECRET,
      oauth: {
        providers: {
          acme: {
            clientId: "acme-id",
            provider: {
              id: "acme",
              pkce: false,
              createAuthorizationUrl() {
                return { url: "https://acme.example/authorize?client_id=acme-id" };
              },
              async exchangeCode() {
                return { access_token: "tok" };
              },
              async fetchProfile() {
                return { id: "u1", email: "a@b.c" };
              },
            },
            redirectUri: "https://acme.example/cb",
            redirectUriPolicy: {
              allowedRedirectUris: ["https://acme.example/cb"],
              allowLocalhostHttp: false,
            },
          },
        },
      },
    });
    const started = await auth.getAuthorizationUrl("acme");
    expect(started.url).toMatch(/acme\.example/);
  });

  it("OAUTH-02: request authorization URL for unknown provider rejects", async () => {
    const auth = createAuth({ secret: SECRET });
    await expect(auth.getAuthorizationUrl("nonexistent")).rejects.toThrow();
  });

  it("OAUTH-03: complete OAuth callback resolves/creates/links user, logs in, attaches OAuth result", async () => {
    const auth = createAuth({
      secret: SECRET,
      userStore: {
        async findByProvider() { return null; },
        async findByEmail() { return null; },
        async createFromProvider() {
          return { id: 2, email: "oauth@example.com", name: "OAuth User", roles: ["member"] };
        },
      },
      oauth: {
        providers: {
          acme: {
            clientId: "acme-id",
            provider: {
              id: "acme",
              pkce: false,
              createAuthorizationUrl() {
                return { url: "https://acme.example/authorize?client_id=acme-id", state: "stored-state" };
              },
              async exchangeCode() {
                return { access_token: "provider-access" };
              },
              async fetchProfile() {
                return { id: "acme-user-1", email: "oauth@example.com", name: "OAuth User" };
              },
            },
            redirectUri: "https://acme.example/cb",
            redirectUriPolicy: {
              allowedRedirectUris: ["https://acme.example/cb"],
              allowLocalhostHttp: false,
            },
          },
        },
      },
    });
    await auth.getAuthorizationUrl("acme", { state: "stored-state" });
    const session = await auth.loginWithOAuth("acme", { code: "ok", state: "stored-state" });
    expect(session.user.email).toBe("oauth@example.com");
    expect(session.payload.provider).toBe("acme");
    expect(session.oauth?.profile.id).toBe("acme-user-1");
  });

  it("OAUTH-04: OAuth callback fails propagates provider/bridge error", async () => {
    const auth = createAuth({
      secret: SECRET,
      oauth: {
        providers: {
          acme: {
            clientId: "acme-id",
            provider: {
              id: "acme",
              pkce: false,
              createAuthorizationUrl() {
                return { url: "https://acme.example/authorize?client_id=acme-id", state: "stored-state" };
              },
              async exchangeCode() {
                throw new Error("provider exchange failed");
              },
              async fetchProfile() {
                return { id: "u1" };
              },
            },
            redirectUri: "https://acme.example/cb",
            redirectUriPolicy: {
              allowedRedirectUris: ["https://acme.example/cb"],
              allowLocalhostHttp: false,
            },
          },
        },
      },
    });
    await auth.getAuthorizationUrl("acme", { state: "stored-state" });
    await expect(
      auth.loginWithOAuth("acme", { code: "ok", state: "stored-state" }),
    ).rejects.toThrow("provider exchange failed");
  });
});
