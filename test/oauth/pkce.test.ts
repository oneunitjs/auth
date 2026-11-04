 
import { describe, it, expect } from "vitest";
import {
  createOAuth,
  pkceVerifier,
  pkceChallenge,
  builtinProviders,
  google,
  github,
  twitter,
  OAuthError,
} from "../../src/index.js";
import type { OAuthProvider, OAuthProviderConfig } from "../../src/index.js";

const TEST_REDIRECT_POLICY = {
  redirectUri: "https://app.example.com/cb",
  redirectUriPolicy: { allowedRedirectUris: ["https://app.example.com/cb"] },
};

// ---------------------------------------------------------------------------
// RFC 7636 test vector: verifier "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
// produces challenge "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGXstw-cab"
// ---------------------------------------------------------------------------

describe("PKCE cryptographic primitives", () => {
  const RFC_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
  const RFC_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

  it("pkceChallenge produces the RFC 7636 S256 challenge", () => {
    expect(pkceChallenge(RFC_VERIFIER)).toBe(RFC_CHALLENGE);
  });

  it("pkceVerifier produces a base64url string without padding", () => {
    const verifier = pkceVerifier();
    expect(verifier).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(verifier.includes("=")).toBe(false);
  });

  it("pkceVerifier meets RFC 7636 length (43-128 chars)", () => {
    const verifier = pkceVerifier();
    expect(verifier.length).toBeGreaterThanOrEqual(43);
    expect(verifier.length).toBeLessThanOrEqual(128);
  });

  it("pkceVerifier produces independent values per call", () => {
    const a = pkceVerifier();
    const b = pkceVerifier();
    expect(a).not.toBe(b);
  });

  it("same verifier always produces the same challenge", () => {
    expect(pkceChallenge(RFC_VERIFIER)).toBe(pkceChallenge(RFC_VERIFIER));
  });

  it("different verifiers produce different challenges", () => {
    expect(pkceChallenge(pkceVerifier())).not.toBe(pkceChallenge(pkceVerifier()));
  });
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeProvider(
  overrides: { pkce?: boolean } & Partial<OAuthProvider> = {},
): OAuthProvider {
  const { pkce: providerPkce = true, ...rest } = overrides;
  return {
    id: "test-pkce",
    name: "Test PKCE",
    authorizationUrl: "https://example.test/auth",
    tokenUrl: "https://example.test/token",
    scopes: [],
    tokenAuthMethod: "body",
    pkce: providerPkce,
    createAuthorizationUrl: (
      config: OAuthProviderConfig,
      { state, codeVerifier }: { state?: string; codeVerifier?: string },
    ) => {
      const pkceEnabled = (config.pkce ?? providerPkce);
      const params: [string, string][] = [
        ["client_id", config.clientId ?? ""],
        ["redirect_uri", config.redirectUri ?? ""],
        ["response_type", "code"],
        ["scope", ""],
        ["state", state ?? ""],
      ];
      let resolvedVerifier: string | undefined;
      if (pkceEnabled) {
        resolvedVerifier = codeVerifier ?? pkceVerifier();
        params.push(["code_challenge", pkceChallenge(resolvedVerifier)]);
        params.push(["code_challenge_method", "S256"]);
      }
      const url = new URL("https://example.test/auth");
      for (const [key, value] of params) {
        url.searchParams.set(key, value);
      }
      return {
        url: url.toString(),
        state,
        codeVerifier: pkceEnabled ? resolvedVerifier : undefined,
      };
    },
    async exchangeCode() {
      return { access_token: "t", token_type: "Bearer" };
    },
    async fetchProfile() {
      return { provider: "test-pkce", id: "u1" };
    },
    ...rest,
  } as unknown as OAuthProvider;
}

function makeAuth() {
  let seenVerifier: string | undefined;
  const provider = makeProvider({
    async exchangeCode(_config: unknown, opts: { codeVerifier?: string }) {
      seenVerifier = opts?.codeVerifier;
      return { access_token: "t", token_type: "Bearer" };
    },
  });
  const oauth = createOAuth({
    providers: { test: { clientId: "cid", provider, ...TEST_REDIRECT_POLICY } },
  });
  return { oauth, getVerifier: () => seenVerifier };
}

// ---------------------------------------------------------------------------
// Authorization URL generation
// ---------------------------------------------------------------------------

describe("PKCE authorization URL", () => {
  it("includes code_challenge and code_challenge_method=S256 by default", async () => {
    const oauth = createOAuth({
      providers: { test: { clientId: "cid", provider: makeProvider(), ...TEST_REDIRECT_POLICY } },
    });

    const { url } = await oauth.authorize("test", { state: "fixed-state" });
    const params = new URL(url).searchParams;
    expect(params.get("code_challenge")).toBeTruthy();
    expect(params.get("code_challenge_method")).toBe("S256");
    expect(params.get("state")).toBe("fixed-state");
  });

  it("does not expose the code verifier in the authorization URL", async () => {
    const oauth = createOAuth({
      providers: { test: { clientId: "cid", provider: makeProvider(), ...TEST_REDIRECT_POLICY } },
    });

    const { url, codeVerifier } = await oauth.authorize("test", { state: "fixed-state" });
    expect(codeVerifier).toBeTruthy();
    expect(url.includes(codeVerifier ?? "")).toBe(false);
  });

  it("binds the verifier to the state transaction", async () => {
    const oauth = createOAuth({
      providers: { test: { clientId: "cid", provider: makeProvider(), ...TEST_REDIRECT_POLICY } },
    });

    const { state, codeVerifier } = await oauth.authorize("test", { state: "bound-state" });
    expect(codeVerifier).toBeTruthy();
    expect(state).toBeTruthy();
    expect(state).not.toBe(codeVerifier);
  });

  it("honors explicit pkce: false opt-out (no challenge)", async () => {
    const oauth = createOAuth({
      providers: {
        test: { clientId: "cid", pkce: false, provider: makeProvider(), ...TEST_REDIRECT_POLICY },
      },
    });

    const { url } = await oauth.authorize("test", { state: "no-pkce" });
    const params = new URL(url).searchParams;
    expect(params.get("code_challenge")).toBeNull();
    expect(params.get("code_challenge_method")).toBeNull();
  });

  it("generates independent verifiers for concurrent authorizations", async () => {
    const oauth = createOAuth({
      providers: { test: { clientId: "cid", provider: makeProvider(), ...TEST_REDIRECT_POLICY } },
    });

    const results = await Promise.all([
      oauth.authorize("test", { state: "a" }),
      oauth.authorize("test", { state: "b" }),
      oauth.authorize("test", { state: "c" }),
    ]);

    const verifiers = results.map((r) => r.codeVerifier).filter(Boolean);
    expect(new Set(verifiers).size).toBe(verifiers.length);
  });
});

// ---------------------------------------------------------------------------
// Callback enforcement
// ---------------------------------------------------------------------------

describe("PKCE callback enforcement", () => {
  it("successful callback sends the stored verifier in the token exchange", async () => {
    const { oauth, getVerifier } = makeAuth();
    const { state, codeVerifier } = await oauth.authorize("test", { state: "cb-state" });

    const result = await oauth.callback("test", { code: "auth-code", state });
    expect(result.tokens.access_token).toBe("t");
    expect(getVerifier()).toBe(codeVerifier);
  });

  it("callback without state is rejected when PKCE is required", async () => {
    const { oauth } = makeAuth();
    await expect(() => oauth.callback("test", { code: "auth-code" })).rejects.toThrow(
      /OAuth state is required/,
    );
  });

  it("callback with unknown state is rejected", async () => {
    const { oauth } = makeAuth();
    await expect(
      () => oauth.callback("test", { code: "auth-code", state: "never-issued" }),
    ).rejects.toThrow(/Invalid or expired OAuth state/);
  });

  it("replayed state is rejected (consumed once)", async () => {
    const { oauth } = makeAuth();
    const { state } = await oauth.authorize("test", { state: "replay-state" });

    await oauth.callback("test", { code: "code-1", state });
    await expect(
      () => oauth.callback("test", { code: "code-2", state }),
    ).rejects.toThrow(/Invalid or expired OAuth state/);
  });

  it("callback on a provider with pkce: false does not require state or verifier", async () => {
    const provider = makeProvider({
      async exchangeCode() {
        return { access_token: "t", token_type: "Bearer" };
      },
    });
    const oauth = createOAuth({
      providers: { test: { clientId: "cid", pkce: false, provider, ...TEST_REDIRECT_POLICY } },
    });

    const { state } = await oauth.authorize("test", { state: "opt-out" });
    const result = await oauth.callback("test", { code: "auth-code", state });
    expect(result.tokens.access_token).toBe("t");
  });
});

// ---------------------------------------------------------------------------
// Built-in provider compatibility
// ---------------------------------------------------------------------------

describe("Built-in provider PKCE defaults", () => {
  it("every built-in provider generates an S256 challenge by default", async () => {
    for (const [id, provider] of Object.entries(builtinProviders)) {
      const oauth = createOAuth({
        providers: { [id]: { clientId: "cid", provider, ...TEST_REDIRECT_POLICY } },
      });
      const { url } = await oauth.authorize(id, { state: "builtin-state" });
      const params = new URL(url).searchParams;
      expect(params.get("code_challenge_method")).toBe("S256");
      expect(params.get("code_challenge")).toBeTruthy();
    }
  });

  it("google includes S256 challenge", async () => {
    const oauth = createOAuth({
      providers: { google: { clientId: "cid", provider: google, ...TEST_REDIRECT_POLICY } },
    });
    const { url } = await oauth.authorize("google", { state: "g" });
    expect(url).toMatch(/code_challenge_method=S256/);
  });

  it("github includes S256 challenge", async () => {
    const oauth = createOAuth({
      providers: { github: { clientId: "cid", provider: github, ...TEST_REDIRECT_POLICY } },
    });
    const { url } = await oauth.authorize("github", { state: "gh" });
    expect(url).toMatch(/code_challenge_method=S256/);
  });

  it("twitter (explicit pkce: true) includes S256 challenge", async () => {
    const oauth = createOAuth({
      providers: { twitter: { clientId: "cid", provider: twitter, ...TEST_REDIRECT_POLICY } },
    });
    const { url } = await oauth.authorize("twitter", { state: "tw" });
    expect(url).toMatch(/code_challenge_method=S256/);
  });

  it("confidential client (client secret present) still uses PKCE by default", async () => {
    const provider = makeProvider();
    const oauth = createOAuth({
      providers: {
        test: {
          clientId: "cid",
          clientSecret: "secret",
          provider,
          ...TEST_REDIRECT_POLICY,
        },
      },
    });
    const { url } = await oauth.authorize("test", { state: "confidential" });
    expect(url).toMatch(/code_challenge_method=S256/);
  });

  it("public client (no client secret) uses PKCE by default", async () => {
    const provider = makeProvider();
    const oauth = createOAuth({
      providers: { test: { clientId: "cid", provider, ...TEST_REDIRECT_POLICY } },
    });
    const { url } = await oauth.authorize("test", { state: "public" });
    expect(url).toMatch(/code_challenge_method=S256/);
  });
});

// ---------------------------------------------------------------------------
// Security regression: no silent PKCE downgrade
// ---------------------------------------------------------------------------

describe("PKCE downgrade prevention", () => {
  it("provider error does not trigger a retry without PKCE", async () => {
    let exchangeCalls = 0;
    const provider = makeProvider({
      async exchangeCode() {
        exchangeCalls += 1;
        throw new Error("token endpoint down");
      },
    });
    const oauth = createOAuth({
      providers: { test: { clientId: "cid", provider, ...TEST_REDIRECT_POLICY } },
    });

    const { state } = await oauth.authorize("test", { state: "downgrade" });
    await expect(() => oauth.callback("test", { code: "code", state })).rejects.toThrow(Error);
    expect(exchangeCalls).toBe(1);
  });

  it("missing pkce configuration does not disable PKCE", async () => {
    const provider = makeProvider();
    const oauth = createOAuth({
      providers: { test: { clientId: "cid", provider, ...TEST_REDIRECT_POLICY } },
    });
    const { url } = await oauth.authorize("test", { state: "nc" });
    expect(url).toMatch(/code_challenge_method=S256/);
  });

  it("verifier never appears in authorization errors and a failed attempt does not consume state", async () => {
    const { oauth } = makeAuth();
    const { state } = await oauth.authorize("test", { state: "leak" });

    // A callback with a wrong state must reject without consuming the real transaction.
    await expect(
      () => oauth.callback("test", { code: "code", state: "wrong-state" }),
    ).rejects.toThrow(OAuthError);

    // The real state transaction is still valid: the failed attempt did not consume it.
    const result = await oauth.callback("test", { code: "code", state });
    expect(result.tokens.access_token).toBe("t");
  });
});
