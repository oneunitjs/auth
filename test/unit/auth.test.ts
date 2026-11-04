 
import { describe, it, expect } from "vitest";
import {
  Auth,
  createAuth,
  encode,
  decode,
  ConfigurationError,
  UnauthorizedError,
  ValidationError,
  ForbiddenError,
} from "../../src/index.js";
import type { LoginResult, OAuthProfile, UserRecord } from "../../src/index.js";

const SECRET = "secret-key-for-testing-purposes-123456";

function memoryUsers(seed: UserRecord[] = []) {
  const users = new Map(seed.map((user) => [String(user.id), { ...user }]));
  let nextId = seed.length + 1;
  return {
    async findById(id: string | number) {
      return users.get(String(id)) ?? null;
    },
    async findByEmail(email: string) {
      return [...users.values()].find((user) => user.email === email) ?? null;
    },
    async findByUsername(username: string) {
      return [...users.values()].find((user) => user.username === username) ?? null;
    },
    async findByCredentials(identifier: string) {
      return (
        [...users.values()].find(
          (user) => user.email === identifier || user.username === identifier,
        ) ?? null
      );
    },
    async create(input: Record<string, unknown>) {
      const user = { id: nextId++, ...input } as UserRecord;
      users.set(String(user.id), user);
      return user;
    },
    async updatePassword(id: string | number, passwordHash: string) {
      const user = users.get(String(id));
      if (user) user.passwordHash = passwordHash;
    },
    async findByProvider(provider: string, providerId: string | number) {
      return (
        [...users.values()].find(
          (user) => user.provider === provider && String(user.providerId) === String(providerId),
        ) ?? null
      );
    },
    async createFromProvider(provider: string, profile: OAuthProfile) {
      const user: UserRecord = {
        id: nextId++,
        email: profile.email,
        username: profile.username,
        name: profile.name,
        provider,
        providerId: profile.id,
        roles: ["member"],
      };
      users.set(String(user.id), user);
      return user;
    },
    async linkProvider(id: string | number, provider: string, profile: OAuthProfile) {
      const user = users.get(String(id));
      if (user) {
        user.provider = provider;
        user.providerId = profile.id;
      }
    },
  };
}

describe("Auth", () => {
  it("requires a secret", () => {
    expect(() => new Auth()).toThrow(ConfigurationError);
    expect(createAuth({ secret: SECRET })).toBeInstanceOf(Auth);
  });

  it("issues and verifies access tokens without built-in roles", async () => {
    const auth = createAuth({
      secret: SECRET,
      issuer: "auth.test",
      rbac: {
        defaultRole: "member",
        roles: {
          member: { permissions: ["article.read"] },
          editor: { inherits: "member", permissions: ["article.write"] },
        },
      },
    });

    const result = await auth.login({
      id: 42,
      email: "ada@example.com",
      username: "ada",
      roles: ["editor"],
    });

    expect(typeof result.accessToken).toBe("string");
    expect(typeof result.refreshToken).toBe("string");
    expect(result.payload.userId).toBe(42);
    expect(result.payload.roles).toEqual(["editor"]);
    expect(result.payload.permissions?.includes("article.read")).toBe(true);
    expect(result.payload.permissions?.includes("article.write")).toBe(true);

    const verified = await auth.verify(result.token);
    expect(verified.email).toBe("ada@example.com");
    expect(verified.iss).toBe("auth.test");
  });

  it("supports password registration and login", async () => {
    const auth = createAuth({
      secret: SECRET,
      userStore: memoryUsers(),
      rbac: { defaultRole: "member", roles: { member: { permissions: ["profile.read"] } } },
    });

    const created = await auth.register({
      email: "user@example.com",
      username: "user",
      password: "s3cret-pass",
    });
    expect(created.user.email).toBe("user@example.com");

    const session = await auth.loginWithPassword("user@example.com", "s3cret-pass");
    expect(session.user.id).toBe(created.user.id);

    await expect(() => auth.loginWithPassword("user@example.com", "nope")).rejects.toThrow(
      UnauthorizedError,
    );
  });

  it("refreshes and revokes refresh tokens", async () => {
    const store = memoryUsers([{ id: 1, email: "a@b.c", roles: ["member"] }]);
    const auth = createAuth({ secret: SECRET, userStore: store });
    const first = await auth.login({ id: 1, email: "a@b.c", roles: ["member"] });
    expect(first.refreshToken).toBeTruthy();
    const next = await auth.refresh(first.refreshToken as string);
    expect(next.user.id).toBe(1);
    expect(next.accessToken).not.toBe(first.accessToken);
    await expect(() => auth.refresh(first.refreshToken as string)).rejects.toThrow(
      UnauthorizedError,
    );
    expect(await auth.logout(next.refreshToken)).toBe(true);
  });

  it("extracts bearer tokens from requests", async () => {
    const auth = createAuth({ secret: SECRET });
    const { accessToken } = await auth.login({ id: 9, roles: ["user"] });
    const claims = await auth.verifyRequest({
      headers: { authorization: `Bearer ${accessToken}` },
    });
    expect(claims.userId).toBe(9);

    const fromCookie = await auth.verifyRequest({
      headers: { cookie: `access_token=${accessToken}` },
    });
    expect(fromCookie.userId).toBe(9);
  });

  it("runs claim extractors and hooks", async () => {
    const auth = createAuth({ secret: SECRET });
    const seen: unknown[] = [];
    auth.registerExtractor("plan", async () => ({ plan: "pro" }));
    auth.hook("afterLogin", async (result) => {
      seen.push((result as LoginResult).payload.plan);
    });
    const result = await auth.login({ id: 3 });
    expect(result.payload.plan).toBe("pro");
    expect(seen).toEqual(["pro"]);
  });

  it("enforces generic permissions through Auth", async () => {
    const auth = createAuth({
      secret: SECRET,
      rbac: {
        roles: {
          reader: { permissions: ["doc.read"] },
        },
      },
    });
    const subject = { roles: ["reader"] };
    expect(auth.can(subject, "doc.read")).toBe(true);
    expect(() => auth.authorize(subject, "doc.write")).toThrow(ForbiddenError);
    expect(auth.hasRole(subject, "reader")).toBe(true);
  });

  it("rejects login without a user id", async () => {
    const auth = createAuth({ secret: SECRET });
    await expect(() => auth.login({} as UserRecord)).rejects.toThrow(ValidationError);
  });

  it("rehashes legacy scrypt passwords on successful login", async () => {
    const { hashScryptPassword } = await import("../../src/index.js");
    const legacy = await hashScryptPassword("s3cret-pass", { cost: 16384 });
    const store = memoryUsers([{ id: 1, email: "user@example.com", passwordHash: legacy }]);
    const auth = createAuth({ secret: SECRET, userStore: store });
    const session = await auth.loginWithPassword("user@example.com", "s3cret-pass");
    expect(session.user.id).toBe(1);
    const updated = await store.findById(1);
    expect(String(updated?.passwordHash)).toMatch(/^\$argon2id\$/);
    const again = await auth.loginWithPassword("user@example.com", "s3cret-pass");
    expect(again.user.id).toBe(1);
  });

  it("returns typed revocation results and keeps boolean wrappers compatible", async () => {
    const { createMemorySessionStore } = await import("../../src/index.js");
    const auth = createAuth({ secret: SECRET, sessionStore: createMemorySessionStore() });
    const session = await auth.login({ id: 1, roles: ["user"] });
    const sid = String(session.payload.sid);
    expect(await auth.revokeSessionResult(sid)).toEqual({ status: "revoked", sessionId: sid });
    expect(await auth.revokeSession(sid)).toBe(false);
    expect(await auth.revokeSessionResult(sid)).toEqual({ status: "not_found", sessionId: sid });
    expect(await auth.revokeAllSessionsResult(1)).toEqual({ status: "revoked", sessionId: "1" });
    expect(await auth.revokeAllSessions(1)).toBe(true);
  });

  it("reports unavailable when session store methods throw", async () => {
    const store = {
      async getVersion() {
        return 0;
      },
      async bumpVersion() {
        throw new Error("offline");
      },
      async revokeSession() {
        throw new Error("offline");
      },
    };
    const auth = createAuth({ secret: SECRET, sessionStore: store });
    expect(await auth.revokeAllSessionsResult(1)).toEqual({ status: "unavailable" });
    expect(await auth.revokeAllSessions(1)).toBe(false);
    expect(await auth.revokeSessionResult("sid-1")).toEqual({ status: "unavailable" });
    expect(await auth.revokeSession("sid-1")).toBe(false);
  });

  it("accepts legacy tokens without sv under migration and ignores them when disabled", async () => {
    const { createMemorySessionStore, encode } = await import("../../src/index.js");
    const migration = createAuth({
      secret: SECRET,
      sessionStore: createMemorySessionStore(),
      sessionVersionPolicy: "migration",
    });
    const legacy = await encode({ sub: "1", userId: 1, typ: "access" }, SECRET, { expiresIn: "15m" });
    expect((await migration.verify(legacy)).sub).toBe("1");

    const disabled = createAuth({
      secret: SECRET,
      sessionStore: createMemorySessionStore(),
      sessionVersionPolicy: "disabled",
    });
    const session = await disabled.login({ id: 1, roles: ["user"] });
    await disabled.revokeAllSessions(1);
    expect((await disabled.verify(session.accessToken)).sub).toBe("1");
  });

  it("signs standalone tokens", async () => {
    const auth = createAuth({ secret: SECRET, expiresIn: "1h" });
    const token = await auth.sign({ hello: true });
    const claims = await decode(token, SECRET);
    expect(claims.hello).toBe(true);
  });

  it("works with encode/decode independently of Auth", async () => {
    const token = await encode({ custom: true }, SECRET, { expiresIn: "5m" });
    expect((await decode(token, SECRET)).custom).toBe(true);
  });

  it("logs in with a custom oauth provider", async () => {
    const store = memoryUsers();
    const auth = createAuth({
      secret: SECRET,
      userStore: store,
      rbac: { defaultRole: "member", roles: { member: { permissions: ["profile.read"] } } },
      oauth: {
        providers: {
          acme: {
            clientId: "acme-id",
            provider: {
              id: "acme",
              pkce: false,
              createAuthorizationUrl() {
                return { url: "https://acme.example/authorize?client_id=acme-id", state: "st" };
              },
              async exchangeCode() {
                return { access_token: "provider-access" };
              },
              async fetchProfile() {
                return { id: "acme-user-1", email: "acme@example.com", name: "Acme User" };
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

    const started = await auth.getAuthorizationUrl("acme", { state: "st" });
    expect(started.url).toMatch(/acme\.example/);

    const session = await auth.loginWithOAuth("acme", { code: "ok", state: "st" });
    expect(session.user.email).toBe("acme@example.com");
    expect(session.payload.provider).toBe("acme");
    expect(session.oauth?.profile.id).toBe("acme-user-1");
    const verified = await auth.verify(session.accessToken);
    expect(verified.providerId).toBe("acme-user-1");
  });
});

describe("express-style adapter helpers", () => {
  it("authenticates a request-like object", async () => {
    const { expressAdapter } = await import("../../src/index.js");
    const auth = createAuth({ secret: SECRET });
    const { accessToken } = await auth.login({ id: 11, roles: ["member"] });
    const adapter = expressAdapter(auth);

    const req: {
      headers: { authorization: string };
      user?: { userId?: string | number } | null;
    } = {
      headers: { authorization: `Bearer ${accessToken}` },
    };
    const res = {
      statusCode: 200,
      body: null as unknown,
      status(code: number) {
        this.statusCode = code;
        return this;
      },
      send(body: unknown) {
        this.body = body;
        return this;
      },
    };

    await new Promise<void>((resolve, reject) => {
      adapter.authenticate()(req, res, (error) => (error ? reject(error) : resolve()));
    });
    expect(req.user?.userId).toBe(11);
  });
});
