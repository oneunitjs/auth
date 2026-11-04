 
import { describe, it, expect } from "vitest";
import {
  createOAuth,
  InvalidRedirectUriError,
  pkceChallenge,
  pkceVerifier,
  validateRedirectUri,
} from "../../src/index.js";
import type { OAuthProvider, OAuthProviderConfig } from "../../src/index.js";

function makeProvider(overrides: Partial<OAuthProvider> = {}): OAuthProvider {
  return {
    id: "test-redirect",
    name: "Test Redirect",
    authorizationUrl: "https://example.test/auth",
    tokenUrl: "https://example.test/token",
    scopes: [],
    tokenAuthMethod: "body",
    pkce: true,
    createAuthorizationUrl: (
      config: OAuthProviderConfig,
      { state, codeVerifier }: { state?: string; codeVerifier?: string },
    ) => {
      const pkceEnabled = (config as { pkce?: boolean }).pkce ?? true;
      const params: [string, string][] = [
        ["client_id", config.clientId ?? ""],
        ["redirect_uri", config.redirectUri ?? ""],
        ["response_type", "code"],
        ["scope", ""],
        ["state", state ?? ""],
      ];
      if (pkceEnabled) {
        const verifier = codeVerifier ?? pkceVerifier();
        params.push(["code_challenge", pkceChallenge(verifier)]);
        params.push(["code_challenge_method", "S256"]);
      }
      const url = new URL("https://example.test/auth");
      for (const [key, value] of params) {
        url.searchParams.set(key, value);
      }
      return {
        url: url.toString(),
        state,
        codeVerifier: pkceEnabled ? (codeVerifier ?? pkceVerifier()) : undefined,
      };
    },
    async exchangeCode() {
      return { access_token: "t", token_type: "Bearer" };
    },
    async fetchProfile() {
      return { provider: "test-redirect", id: "u1" };
    },
    ...overrides,
  };
}

function policy(
  allowed: string[],
  allowLocalhostHttp = false,
): { redirectUri: string; redirectUriPolicy: { allowedRedirectUris: string[]; allowLocalhostHttp?: boolean } } {
  return { redirectUri: allowed[0], redirectUriPolicy: { allowedRedirectUris: allowed, allowLocalhostHttp } };
}

// ---------------------------------------------------------------------------
// Unit tests — URI validation
// ---------------------------------------------------------------------------

describe("redirect URI validation", () => {
  const ALLOWED = ["https://app.example.com/cb", "https://app.example.com/cb2"];

  it("exact allowlisted URI succeeds", () => {
    expect(
      validateRedirectUri("https://app.example.com/cb", { allowedRedirectUris: ALLOWED }),
    ).toBe("https://app.example.com/cb");
  });

  it("different host is rejected", () => {
    expect(() =>
      validateRedirectUri("https://evil.example.com/cb", { allowedRedirectUris: ALLOWED }),
    ).toThrow(InvalidRedirectUriError);
  });

  it("different port is rejected", () => {
    expect(() =>
      validateRedirectUri("https://app.example.com:8443/cb", { allowedRedirectUris: ALLOWED }),
    ).toThrow(InvalidRedirectUriError);
  });

  it("different path is rejected", () => {
    expect(() =>
      validateRedirectUri("https://app.example.com/other", { allowedRedirectUris: ALLOWED }),
    ).toThrow(InvalidRedirectUriError);
  });

  it("different scheme is rejected", () => {
    expect(() =>
      validateRedirectUri("http://app.example.com/cb", { allowedRedirectUris: ALLOWED }),
    ).toThrow(InvalidRedirectUriError);
  });

  it("different query string is rejected under exact-match policy", () => {
    expect(() =>
      validateRedirectUri("https://app.example.com/cb?extra=1", { allowedRedirectUris: ALLOWED }),
    ).toThrow(InvalidRedirectUriError);
  });

  it("different fragment is rejected under exact-match policy", () => {
    expect(() =>
      validateRedirectUri("https://app.example.com/cb#section", { allowedRedirectUris: ALLOWED }),
    ).toThrow(InvalidRedirectUriError);
  });

  it("prefix lookalike is rejected", () => {
    expect(() =>
      validateRedirectUri("https://app.example.com/cb/extra", { allowedRedirectUris: ALLOWED }),
    ).toThrow(InvalidRedirectUriError);
  });

  it("suffix lookalike is rejected", () => {
    expect(() =>
      validateRedirectUri("https://app.example.com/cb.evil", { allowedRedirectUris: ALLOWED }),
    ).toThrow(InvalidRedirectUriError);
  });

  it("similar-looking hostname is rejected", () => {
    expect(() =>
      validateRedirectUri("https://app-example.com/cb", { allowedRedirectUris: ALLOWED }),
    ).toThrow(InvalidRedirectUriError);
  });

  it("subdomain lookalike is rejected", () => {
    expect(() =>
      validateRedirectUri("https://app.example.com.evil/cb", { allowedRedirectUris: ALLOWED }),
    ).toThrow(InvalidRedirectUriError);
  });

  it("embedded credentials are rejected", () => {
    expect(() =>
      validateRedirectUri("https://user:pass@app.example.com/cb", { allowedRedirectUris: ALLOWED }),
    ).toThrow(InvalidRedirectUriError);
  });

  it("malformed URLs are rejected", () => {
    expect(() =>
      validateRedirectUri("not-a-url", { allowedRedirectUris: ALLOWED }),
    ).toThrow(InvalidRedirectUriError);
  });

  it("unsupported schemes are rejected", () => {
    for (const scheme of ["javascript:", "data:", "ftp:", "mailto:"]) {
      expect(() =>
        validateRedirectUri(`${scheme}//example.com/cb`, { allowedRedirectUris: ALLOWED }),
      ).toThrow(InvalidRedirectUriError);
    }
  });

  it("trailing slash differences are not normalized", () => {
    expect(() =>
      validateRedirectUri("https://app.example.com/cb/", { allowedRedirectUris: ALLOWED }),
    ).toThrow(InvalidRedirectUriError);
  });

  it("percent-encoding differences are not normalized", () => {
    expect(() =>
      validateRedirectUri("https://app.example.com/cb%2Fextra", { allowedRedirectUris: ALLOWED }),
    ).toThrow(InvalidRedirectUriError);
  });

  it("empty allowlist fails closed", () => {
    expect(() =>
      validateRedirectUri("https://app.example.com/cb", { allowedRedirectUris: [] }),
    ).toThrow(InvalidRedirectUriError);
  });

  it("missing allowlist fails closed", () => {
    expect(() =>
      validateRedirectUri("https://app.example.com/cb", {
        allowedRedirectUris: undefined as unknown as string[],
      }),
    ).toThrow(InvalidRedirectUriError);
  });

  it("missing candidate is rejected", () => {
    expect(() =>
      validateRedirectUri(undefined, { allowedRedirectUris: ALLOWED }),
    ).toThrow(InvalidRedirectUriError);
  });

  it("error carries a stable code and does not leak secrets", () => {
    let thrown: unknown = null;
    try {
      validateRedirectUri("https://evil.example.com/cb", { allowedRedirectUris: ALLOWED });
    } catch (e) {
      thrown = e;
    }
    expect(thrown instanceof InvalidRedirectUriError).toBe(true);
    expect((thrown as { code?: string }).code).toBe("NOT_ALLOWED");
  });
});

// ---------------------------------------------------------------------------
// Environment tests
// ---------------------------------------------------------------------------

describe("redirect URI environment", () => {
  it("HTTPS works in production configuration", () => {
    expect(
      validateRedirectUri("https://app.example.com/cb", {
        allowedRedirectUris: ["https://app.example.com/cb"],
        allowLocalhostHttp: false,
      }),
    ).toBe("https://app.example.com/cb");
  });

  it("HTTP localhost works only with explicit development opt-in", () => {
    expect(
      validateRedirectUri("http://localhost/cb", {
        allowedRedirectUris: ["http://localhost/cb"],
        allowLocalhostHttp: true,
      }),
    ).toBe("http://localhost/cb");
  });

  it("HTTP localhost is rejected without explicit opt-in", () => {
    expect(() =>
      validateRedirectUri("http://localhost/cb", {
        allowedRedirectUris: ["http://localhost/cb"],
        allowLocalhostHttp: false,
      }),
    ).toThrow(InvalidRedirectUriError);
  });

  it("HTTP non-localhost is rejected even with localhost opt-in", () => {
    expect(() =>
      validateRedirectUri("http://evil.example.com/cb", {
        allowedRedirectUris: ["http://evil.example.com/cb"],
        allowLocalhostHttp: true,
      }),
    ).toThrow(InvalidRedirectUriError);
  });

  it("localhost.evil.example lookalike is rejected", () => {
    expect(() =>
      validateRedirectUri("http://localhost.evil.example/cb", {
        allowedRedirectUris: ["http://localhost.evil.example/cb"],
        allowLocalhostHttp: true,
      }),
    ).toThrow(InvalidRedirectUriError);
  });

  it("loopback IPv4 127.0.0.1 is permitted with opt-in", () => {
    expect(
      validateRedirectUri("http://127.0.0.1/cb", {
        allowedRedirectUris: ["http://127.0.0.1/cb"],
        allowLocalhostHttp: true,
      }),
    ).toBe("http://127.0.0.1/cb");
  });

  it("loopback IPv6 ::1 is permitted with opt-in", () => {
    expect(
      validateRedirectUri("http://[::1]/cb", {
        allowedRedirectUris: ["http://[::1]/cb"],
        allowLocalhostHttp: true,
      }),
    ).toBe("http://[::1]/cb");
  });
});

// ---------------------------------------------------------------------------
// Authorization-flow tests
// ---------------------------------------------------------------------------

describe("redirect URI in authorization flow", () => {
  it("authorization URL construction uses only the validated configured URI", async () => {
    const oauth = createOAuth({
      providers: {
        test: {
          clientId: "cid",
          provider: makeProvider(),
          ...policy(["https://app.example.com/cb"]),
        },
      },
    });

    const { url } = await oauth.authorize("test", { state: "fixed-state" });
    const params = new URL(url).searchParams;
    expect(params.get("redirect_uri")).toBe("https://app.example.com/cb");
  });

  it("a per-request redirectUri candidate is validated before use", async () => {
    const oauth = createOAuth({
      providers: {
        test: {
          clientId: "cid",
          provider: makeProvider(),
          ...policy(["https://app.example.com/cb"]),
        },
      },
    });

    const { url } = await oauth.authorize("test", {
      state: "fixed-state",
      redirectUri: "https://app.example.com/cb",
    });
    const params = new URL(url).searchParams;
    expect(params.get("redirect_uri")).toBe("https://app.example.com/cb");
  });

  it("a per-request redirectUri not in the allowlist is rejected", async () => {
    const oauth = createOAuth({
      providers: {
        test: {
          clientId: "cid",
          provider: makeProvider(),
          ...policy(["https://app.example.com/cb"]),
        },
      },
    });

    await expect(
      () =>
        oauth.authorize("test", {
          state: "fixed-state",
          redirectUri: "https://evil.example.com/cb",
        }),
    ).rejects.toThrow(InvalidRedirectUriError);
  });

  it("the validated URI is stored with the OAuth state transaction", async () => {
    const oauth = createOAuth({
      providers: {
        test: {
          clientId: "cid",
          provider: makeProvider(),
          ...policy(["https://app.example.com/cb"]),
        },
      },
    });

    const { state } = await oauth.authorize("test", { state: "fixed-state" });
    const stored = await oauth.verifyState(state);
    expect(stored).toBe(true);
  });

  it("callback processing uses the stored URI rather than callback-supplied input", async () => {
    let seenRedirect: string | undefined;
    const provider = makeProvider({
      async exchangeCode(_config: unknown, opts: { redirectUri?: string }) {
        seenRedirect = opts?.redirectUri as string | undefined;
        return { access_token: "t", token_type: "Bearer" };
      },
    });
    const oauth = createOAuth({
      providers: {
        test: {
          clientId: "cid",
          provider,
          ...policy(["https://app.example.com/cb"]),
        },
      },
    });

    const { state } = await oauth.authorize("test", { state: "fixed-state" });
    await oauth.callback("test", { code: "auth-code", state });
    expect(seenRedirect).toBe("https://app.example.com/cb");
  });

  it("missing allowlist configuration fails closed at authorize time", async () => {
    const oauth = createOAuth({
      providers: {
        test: { clientId: "cid", provider: makeProvider() },
      },
    });

    await expect(
      () => oauth.authorize("test", { state: "fixed-state" }),
    ).rejects.toThrow(InvalidRedirectUriError);
  });

  it("invalid allowlist URIs fail fast at provider setup", () => {
    expect(() =>
      createOAuth({
        providers: {
          test: {
            clientId: "cid",
            provider: makeProvider(),
            ...policy(["https://good.example.com/cb", "not-a-valid-uri"]),
          },
        },
      }),
    ).toThrow(InvalidRedirectUriError);
  });

  it("every built-in provider rejects unvalidated redirect URIs", async () => {
    const builtinIds = [
      "google", "github", "instagram", "facebook", "twitter", "discord",
      "apple", "linkedin", "microsoft", "reddit", "twitch", "slack",
      "spotify", "tiktok",
    ] as const;

    for (const id of builtinIds) {
      const oauth = createOAuth({
        providers: { [id]: { clientId: "cid" } },
      });
      await expect(
        () => oauth.authorize(id, { state: "fixed-state" }),
      ).rejects.toThrow(InvalidRedirectUriError);
    }
  });
});

// ---------------------------------------------------------------------------
// Callback and replay tests
// ---------------------------------------------------------------------------

describe("redirect URI callback enforcement", () => {
  it("replayed state cannot reuse a consumed redirect URI transaction", async () => {
    const oauth = createOAuth({
      providers: {
        test: {
          clientId: "cid",
          provider: makeProvider(),
          ...policy(["https://app.example.com/cb"]),
        },
      },
    });

    const { state } = await oauth.authorize("test", { state: "fixed-state" });
    await oauth.callback("test", { code: "code-1", state });
    await expect(
      () => oauth.callback("test", { code: "code-2", state }),
    ).rejects.toThrow(/Invalid or expired OAuth state/);
  });

  it("callback without state is rejected when no stored transaction exists", async () => {
    const oauth = createOAuth({
      providers: {
        test: {
          clientId: "cid",
          provider: makeProvider(),
          ...policy(["https://app.example.com/cb"]),
        },
      },
    });

    await expect(
      () => oauth.callback("test", { code: "auth-code" }),
    ).rejects.toThrow(/OAuth state is required/);
  });
});
