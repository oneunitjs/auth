/* eslint-disable @typescript-eslint/no-unused-vars */
 
import { describe, it, expect } from "vitest";
import { generateKeyPairSync, sign as signRSA } from "node:crypto";
import {
  createAuth,
  createOAuth,
  createProvider,
  createMemoryStateStore,
  getProvider,
  encodeRefreshToken,
  hashPassword,
  verifyPassword,
  needsRehash,
  apple,
  expressAdapter,
  createMemoryRefreshStore,
  koaAdapter,
  fastifyAdapter,
  matchPermission,
  createRBAC,
  pkceVerifier,
  pkceChallenge,
  builtinProviders,
  encode,
  parseExpiresIn,
  ConfigurationError,
  InvalidTokenError,
  ProviderError,
  UnauthorizedError,
  ValidationError,
  ForbiddenError,
  OAuthError,
} from "../../src/index.js";
import type { JwtPayload, OAuthProvider, RefreshRecord, RefreshStore, UserRecord } from "../../src/index.js";

const SECRET = "secret-key-for-testing-purposes-123456";

function memoryUsers(seed: any[] = []) {
  const users = new Map(seed.map((user) => [String(user.id), { ...user }]));
  let nextId = seed.length + 1;
  return {
    async findById(id: string | number) { return users.get(String(id)) ?? null; },
    async create(input: any) { const user = { id: nextId++, ...input }; users.set(String(user.id), user); return user; },
    async updatePassword(id: string | number, passwordHash: string) {
      const user = users.get(String(id));
      if (user) user.passwordHash = passwordHash;
    },
  };
}


describe("token type separation", () => {
  it("rejects a refresh token used as an access token", async () => {
    const auth = createAuth({ secret: SECRET });
    const session = await auth.login({ id: 1, roles: ["admin"] });
    expect(session.refreshToken).toBeTruthy();

    await expect(() => auth.verify(session.refreshToken!)).rejects.toThrow(UnauthorizedError);
    await expect(
      () => auth.verifyRequest({ headers: { authorization: `Bearer ${session.refreshToken}` } }),
    ).rejects.toThrow(UnauthorizedError);
  });

  it("accepts a refresh token when the caller explicitly opts in", async () => {
    const auth = createAuth({ secret: SECRET });
    const session = await auth.login({ id: 1 });
    const claims = await auth.verify(session.refreshToken!, { acceptTokenType: "refresh" });
    expect(claims.typ).toBe("refresh");
  });

  it("still accepts access tokens", async () => {
    const auth = createAuth({ secret: SECRET });
    const claims = await auth.verify((await auth.login({ id: 1 })).token);
    expect(claims.typ).toBe("access");
  });
});

describe("registration", () => {
  it("ignores caller-supplied roles", async () => {
    let created: Record<string, unknown> = {};
    const auth = createAuth({
      secret: SECRET,
      rbac: { defaultRole: "user", roles: { user: { permissions: ["read"] }, admin: { permissions: ["*"] } } },
      userStore: { create: (input) => { created = input; return { id: 9, ...input } as UserRecord; } },
    });

    const session = await auth.register({ email: "a@b.c", password: "pw", roles: ["admin"] });

    expect(created.roles).toEqual(["user"]);
    expect(session.user.roles).toEqual(["user"]);
    expect(auth.can(session.payload, "anything")).toBe(false);
  });

  it("uses server-side roles from the options argument", async () => {
    let created: Record<string, unknown> = {};
    const auth = createAuth({
      secret: SECRET,
      rbac: { roles: { user: { permissions: ["read"] }, admin: { permissions: ["user.manage"] } } },
      userStore: { create: (input) => { created = input; return { id: 10, ...input } as UserRecord; } },
    });

    await auth.register({ email: "a@b.c", password: "pw", roles: ["hacker"] }, { roles: ["admin"] });

    expect(created.roles).toEqual(["admin"]);
  });
});

describe("token claims", () => {
  it("does not copy user.permissions into the token by default", async () => {
    const auth = createAuth({ secret: SECRET, rbac: { roles: { user: { permissions: ["read"] } } } });
    const session = await auth.login({ id: 1, roles: ["user"], permissions: ["admin:all"] });

    const claims = await auth.verify(session.accessToken);
    expect(claims.permissions).not.toContain("admin:all");
    expect(claims.roles).toEqual(["user"]);
  });

  it("maps RBAC permissions into the token claims", async () => {
    const auth = createAuth({
      secret: SECRET,
      rbac: { defaultRole: "member", roles: { member: { permissions: ["post.read"] } } },
    });
    const session = await auth.login({ id: 1, roles: ["member"] });

    const claims = await auth.verify(session.accessToken);
    expect(claims.permissions).toContain("post.read");
  });

  it("includes no scopes when none are configured", async () => {
    const auth = createAuth({ secret: SECRET });
    const session = await auth.login({ id: 1, roles: ["user"] });

    const claims = await auth.verify(session.accessToken);
    expect(claims.scopes).toBeUndefined();
  });
});

describe("password flow", () => {
  it("hashes and verifies passwords", async () => {
    const store = memoryUsers();
    const auth = createAuth({ secret: SECRET, userStore: store });
    const created = await auth.register({ email: "a@b.c", password: "s3cret-pass", username: "a" });
    expect(await verifyPassword("s3cret-pass", (await store.findById(created.user.id))?.passwordHash ?? "")).toBe(true);
    expect(await verifyPassword("wrong-password", (await store.findById(created.user.id))?.passwordHash ?? "")).toBe(false);
  });
});

describe("state store", () => {
  it("rejects consumption of an already-consumed OAuth state", async () => {
    const oauth = createOAuth({
      providers: {
        google: {
          clientId: "cid",
          clientSecret: "secret",
          redirectUri: "http://localhost/cb",
          redirectUriPolicy: { allowedRedirectUris: ["http://localhost/cb"], allowLocalhostHttp: true },
          provider: createProvider({
            id: "google",
            authorizationUrl: "http://localhost/auth",
            tokenUrl: "http://localhost/token",
            userInfoUrl: "http://localhost/me",
            scopes: [],
            profileMap: { id: "id", email: "email" },
          }),
        },
      },
    });

    const { state } = await oauth.authorize("google", { state: "fixed-state" });
    await oauth.callback("google", { code: "code-1", state }).catch(() => {});
    await expect(() => oauth.callback("google", { code: "code-2", state })).rejects.toThrow(
      /Invalid or expired OAuth state/,
    );
  });

  it("does not accept a state from a different provider", async () => {
    const oauth = createOAuth({
      providers: {
        google: {
          clientId: "g",
          clientSecret: "secret",
          redirectUri: "http://localhost/cb",
          redirectUriPolicy: { allowedRedirectUris: ["http://localhost/cb"], allowLocalhostHttp: true },
        },
        github: {
          clientId: "gh",
          clientSecret: "secret",
          redirectUri: "http://localhost/cb",
          redirectUriPolicy: { allowedRedirectUris: ["http://localhost/cb"], allowLocalhostHttp: true },
        },
      },
    });

    const { state } = await oauth.authorize("google", { state: "cross-provider" });
    await expect(() => oauth.callback("github", { code: "code", state })).rejects.toThrow(
      /OAuth provider mismatch/,
    );
  });

  it("rejects expired OAuth state", async () => {
    const oauth = createOAuth({
      providers: {
        google: {
          clientId: "cid",
          clientSecret: "secret",
          redirectUri: "http://localhost/cb",
          redirectUriPolicy: { allowedRedirectUris: ["http://localhost/cb"], allowLocalhostHttp: true },
        },
      },
    });

    const { state } = await oauth.authorize("google", { state: "fixed-state", ttlSeconds: 0 });
    await expect(() => oauth.callback("google", { code: "code", state })).rejects.toThrow(
      /Invalid or expired OAuth state/,
    );
  });

  it("does not expose the refresh token in errors", async () => {
    const auth = createAuth({ secret: SECRET });
    const _session = await auth.login({ id: 1, roles: ["user"] });

    await expect(() => auth.refresh("invalid.token.here")).rejects.toThrow(
      /Invalid or expired token/i,
    );
  });

  it("does not expose access tokens in errors", async () => {
    const auth = createAuth({ secret: SECRET });
    const _session = await auth.login({ id: 1, roles: ["user"] });

    await expect(() => auth.verify("invalid.access.token")).rejects.toThrow(
      /Invalid or expired token/,
    );
  });
});

describe("OAuth state lifecycle", () => {
  it("rejects callback without state when state is required", async () => {
    const oauth = createOAuth({
      providers: {
        google: {
          clientId: "cid",
          clientSecret: "secret",
          redirectUri: "http://localhost/cb",
          redirectUriPolicy: { allowedRedirectUris: ["http://localhost/cb"], allowLocalhostHttp: true },
        },
      },
    });

    await expect(() => oauth.callback("google", { code: "auth-code" })).rejects.toThrow(
      /OAuth state is required/,
    );
  });

  it("does not leak verifier in authorization errors", async () => {
    const oauth = createOAuth({
      providers: {
        google: {
          clientId: "cid",
          clientSecret: "secret",
          redirectUri: "http://localhost/cb",
          redirectUriPolicy: { allowedRedirectUris: ["http://localhost/cb"], allowLocalhostHttp: true },
          pkce: true,
          provider: createProvider({
            id: "google",
            authorizationUrl: "http://localhost/auth",
            tokenUrl: "http://localhost/token",
            userInfoUrl: "http://localhost/me",
            scopes: [],
            profileMap: { id: "id", email: "email" },
          }),
        },
      },
    });

    const { state } = await oauth.authorize("google", { state: "leak-test" });
    await expect(() => oauth.callback("google", { code: "code", state: "wrong-state" })).rejects.toThrow(
      OAuthError,
    );
  });
});
