import { describe, it, expect } from "vitest";
import {
  createOAuth,
  createProvider,
  OAuthError,
  ProviderError,
  ValidationError,
  InvalidRedirectUriError,
  createMemoryStateStore,
} from "../../src/index.js";
import type { OAuthProvider, OAuthTokens } from "../../src/index.js";

const LOCAL_CALLBACK = "http://localhost/cb";

function makeProvider(overrides: Partial<OAuthProvider> = {}): OAuthProvider {
  const calls: string[] = [];
  return {
    id: "test-neg",
    name: "Test Negative",
    authorizationUrl: "https://example.test/auth",
    tokenUrl: "https://example.test/token",
    scopes: [],
    tokenAuthMethod: "body",
    pkce: true,
    createAuthorizationUrl: (config, { state, codeVerifier }) => {
      const url = new URL(config.authorizationUrl ?? "https://example.test/auth");
      url.searchParams.set("client_id", config.clientId ?? "");
      url.searchParams.set("redirect_uri", config.redirectUri ?? "");
      url.searchParams.set("response_type", "code");
      url.searchParams.set("state", state ?? "");
      if (codeVerifier) {
        url.searchParams.set("code_challenge", "challenge");
        url.searchParams.set("code_challenge_method", "S256");
      }
      return { url: url.toString(), state, codeVerifier };
    },
    async exchangeCode() {
      calls.push("exchangeCode");
      return { access_token: "access-token", token_type: "Bearer" } as OAuthTokens;
    },
    async fetchProfile() {
      calls.push("fetchProfile");
      return { provider: "test-neg", id: "user-1", email: "u@example.com" };
    },
    ...overrides,
  } as OAuthProvider;
}

function oauthWith(provider: OAuthProvider) {
  return createOAuth({
    stateStore: createMemoryStateStore(),
    providers: {
      [provider.id]: {
        clientId: "client-id",
        clientSecret: "client-secret",
        redirectUri: LOCAL_CALLBACK,
        provider,
        redirectUriPolicy: {
          allowedRedirectUris: [LOCAL_CALLBACK],
          allowLocalhostHttp: true,
        },
      },
    },
  });
}

describe("OAuth/OIDC negative-test matrix (OAUTH-NEG)", () => {
  it("missing authorization code is rejected", async () => {
    const oauth = oauthWith(makeProvider());
    const { state } = await oauth.authorize("test-neg");
    await expect(oauth.callback("test-neg", { state })).rejects.toThrow(
      ValidationError,
    );
  });

  it("provider error in the callback query is surfaced", async () => {
    const oauth = oauthWith(makeProvider());
    await expect(
      oauth.callback("test-neg", {
        error: "access_denied",
        error_description: "user denied",
      }),
    ).rejects.toThrow(OAuthError);
  });

  it("missing state when PKCE is enabled is rejected", async () => {
    const oauth = oauthWith(makeProvider());
    await expect(
      oauth.callback("test-neg", { code: "some-code" }),
    ).rejects.toThrow(OAuthError);
  });

  it("missing state when PKCE is disabled is still rejected", async () => {
    const provider = makeProvider({ pkce: false });
    const oauth = oauthWith(provider);
    await expect(
      oauth.callback("test-neg", { code: "some-code" }),
    ).rejects.toThrow(OAuthError);
  });

  it("callback without any state parameter is rejected even without PKCE", async () => {
    const provider = makeProvider({ pkce: false });
    const oauth = oauthWith(provider);
    await expect(
      oauth.callback("test-neg", { code: "some-code" }),
    ).rejects.toThrow(OAuthError);
  });

  it("unknown state is rejected", async () => {
    const oauth = oauthWith(makeProvider());
    await expect(
      oauth.callback("test-neg", { code: "c", state: "never-issued" }),
    ).rejects.toThrow(OAuthError);
  });

  it("replayed state is consumed exactly once and rejected on reuse", async () => {
    const oauth = oauthWith(makeProvider());
    const { state, codeVerifier } = await oauth.authorize("test-neg", {
      codeVerifier: "verifier-123",
    });
    // Manually seed the state store with a consumable record so the first
    // callback consumes it.
    await oauth.callback("test-neg", { code: "c-1", state });
    await expect(
      oauth.callback("test-neg", { code: "c-2", state }),
    ).rejects.toThrow(OAuthError);
    expect(codeVerifier).toBe("verifier-123");
  });

  it("provider mismatch between authorization and callback is rejected", async () => {
    const other = makeProvider({ id: "test-other" });
    const oauth = createOAuth({
      stateStore: createMemoryStateStore(),
      providers: {
        "test-neg": {
          clientId: "id",
          clientSecret: "s",
          redirectUri: LOCAL_CALLBACK,
          provider: makeProvider(),
          redirectUriPolicy: {
            allowedRedirectUris: [LOCAL_CALLBACK],
            allowLocalhostHttp: true,
          },
        },
        "test-other": {
          clientId: "id",
          clientSecret: "s",
          redirectUri: LOCAL_CALLBACK,
          provider: other,
          redirectUriPolicy: {
            allowedRedirectUris: [LOCAL_CALLBACK],
            allowLocalhostHttp: true,
          },
        },
      },
    });
    const { state } = await oauth.authorize("test-neg");
    await expect(
      oauth.callback("test-other", { code: "c", state }),
    ).rejects.toThrow(OAuthError);
  });

  it("redirect URI mismatch is rejected at authorization time", async () => {
    const provider = makeProvider();
    const oauth = createOAuth({
      stateStore: createMemoryStateStore(),
      providers: {
        [provider.id]: {
          clientId: "id",
          clientSecret: "s",
          redirectUri: "http://localhost/other",
          provider,
          redirectUriPolicy: {
            allowedRedirectUris: [LOCAL_CALLBACK],
            allowLocalhostHttp: true,
          },
        },
      },
    });
    await expect(
      oauth.authorize(provider.id, { redirectUri: "http://evil.example/cb" }),
    ).rejects.toThrow(InvalidRedirectUriError);
  });

  it("open-redirect to a non-allowlisted host is rejected", async () => {
    const provider = makeProvider();
    const oauth = createOAuth({
      stateStore: createMemoryStateStore(),
      providers: {
        [provider.id]: {
          clientId: "id",
          clientSecret: "s",
          redirectUri: LOCAL_CALLBACK,
          provider,
          redirectUriPolicy: {
            allowedRedirectUris: ["https://app.example.com/cb"],
            allowLocalhostHttp: false,
          },
        },
      },
    });
    await expect(
      oauth.authorize(provider.id, { redirectUri: "http://evil.example.com/cb" }),
    ).rejects.toThrow(InvalidRedirectUriError);
  });

  it("insecure HTTP outside explicitly permitted loopback is rejected", async () => {
    const provider = makeProvider();
    expect(() =>
      createOAuth({
        stateStore: createMemoryStateStore(),
        providers: {
          [provider.id]: {
            clientId: "id",
            clientSecret: "s",
            redirectUri: LOCAL_CALLBACK,
            provider,
            redirectUriPolicy: {
              allowedRedirectUris: [LOCAL_CALLBACK],
              allowLocalhostHttp: false,
            },
          },
        },
      }),
    ).toThrow(InvalidRedirectUriError);
  });

  it("token endpoint exchange failure propagates as an error", async () => {
    const boom = new Error("token endpoint down");
    const provider = makeProvider({
      async exchangeCode() {
        throw boom;
      },
    });
    const oauth = oauthWith(provider);
    const { state } = await oauth.authorize("test-neg");
    await expect(oauth.callback("test-neg", { code: "c", state })).rejects.toThrow(
      "token endpoint down",
    );
  });

  it("provider-specific malformed token response is rejected", async () => {
    const provider = makeProvider({
      async exchangeCode() {
        return {} as unknown as OAuthTokens;
      },
      async fetchProfile(_config, tokens) {
        if (!tokens?.access_token) {
          throw new ProviderError("OAuth token response is missing access_token");
        }
        return { provider: "test-neg", id: "user-1" };
      },
    });
    const oauth = oauthWith(provider);
    const { state } = await oauth.authorize("test-neg");
    await expect(
      oauth.callback("test-neg", { code: "c", state }),
    ).rejects.toThrow();
  });

  it("authorization code replay is rejected by the provider", async () => {
    let used = false;
    const provider = makeProvider({
      async exchangeCode() {
        if (used) {
          throw new OAuthError("authorization code already used");
        }
        used = true;
        return { access_token: "access-token", token_type: "Bearer" };
      },
    });
    const oauth = oauthWith(provider);
    const { state } = await oauth.authorize("test-neg");
    await oauth.callback("test-neg", { code: "replay-code", state });
    await expect(
      oauth.callback("test-neg", { code: "replay-code", state }),
    ).rejects.toThrow(OAuthError);
  });

  it("OIDC issuer mismatch is rejected by the provider", async () => {
    const provider = makeProvider({
      async fetchProfile() {
        throw new ProviderError("Google id_token has an unexpected issuer");
      },
    });
    const oauth = oauthWith(provider);
    const { state } = await oauth.authorize("test-neg");
    await expect(
      oauth.callback("test-neg", { code: "c", state }),
    ).rejects.toThrow(ProviderError);
  });

  it("OIDC audience mismatch is rejected by the provider", async () => {
    const provider = makeProvider({
      async fetchProfile() {
        throw new ProviderError(
          "Google id_token audience does not match the configured clientId",
        );
      },
    });
    const oauth = oauthWith(provider);
    const { state } = await oauth.authorize("test-neg");
    await expect(
      oauth.callback("test-neg", { code: "c", state }),
    ).rejects.toThrow(ProviderError);
  });

  it("OIDC nonce mismatch is rejected by the provider", async () => {
    const provider = makeProvider({
      async fetchProfile() {
        throw new ProviderError(
          "Google id_token nonce does not match the requested nonce",
        );
      },
    });
    const oauth = oauthWith(provider);
    const { state } = await oauth.authorize("test-neg");
    await expect(
      oauth.callback("test-neg", { code: "c", state }),
    ).rejects.toThrow(ProviderError);
  });

  it("OIDC missing or expired exp claim is rejected by the provider", async () => {
    const provider = makeProvider({
      async fetchProfile() {
        throw new ProviderError("Google id_token has expired");
      },
    });
    const oauth = oauthWith(provider);
    const { state } = await oauth.authorize("test-neg");
    await expect(
      oauth.callback("test-neg", { code: "c", state }),
    ).rejects.toThrow(ProviderError);
  });

  it("callback to the wrong provider after authorization is rejected", async () => {
    const oauth = oauthWith(makeProvider());
    const { state } = await oauth.authorize("test-neg");
    await expect(
      oauth.callback("nonexistent", { code: "c", state }),
    ).rejects.toThrow(ValidationError);
  });

  it("concurrent callbacks with the same state: only one succeeds", async () => {
    const oauth = oauthWith(makeProvider());
    const { state } = await oauth.authorize("test-neg", {
      codeVerifier: "verifier-123",
    });
    const results = await Promise.allSettled([
      oauth.callback("test-neg", { code: "c-1", state }),
      oauth.callback("test-neg", { code: "c-2", state }),
    ]);
    const succeeded = results.filter(
      (r) => r.status === "fulfilled",
    ).length;
    const failed = results.filter(
      (r) => r.status === "rejected",
    ).length;
    expect(succeeded).toBe(1);
    expect(failed).toBe(1);
  });
});
