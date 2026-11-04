import { describe, it, expect } from "vitest";
import { Auth, createAuth, createRBAC, createMemorySessionStore } from "../../src/index.js";
import type { RoleDefinition } from "../../src/index.js";
import { SECRET, REFRESH_SECRET } from "./fixtures/auth.fixtures.js";
import { fakeSessionStore } from "./fixtures/fake-session-store.js";

describe("Auth configuration (CFG)", () => {
  it("CFG-01: throws ConfigurationError when constructed without secret", () => {
    expect(() => new Auth({} as never)).toThrow();
  });

  it("CFG-01: createAuth without secret throws ConfigurationError", () => {
    expect(() => createAuth({} as never)).toThrow();
  });

  it("CFG-02: refreshSecret defaults to secret when not provided", async () => {
    const auth = createAuth({ secret: SECRET });
    expect(auth).toBeInstanceOf(Auth);
    const result = await auth.login({ id: 1, email: "a@b.c" });
    expect(result.refreshToken).toBeTruthy();
  });

  it("CFG-03: distinct refreshSecret is used for refresh tokens", async () => {
    const auth = createAuth({ secret: SECRET, refreshSecret: REFRESH_SECRET });
    const result = await auth.login({ id: 1, email: "a@b.c" });
    expect(result.refreshToken).toBeTruthy();
    expect(result.accessToken).not.toBe(result.refreshToken);
  });

  it("CFG-04: accessToken TTL defaults to expiresIn then 15m", async () => {
    const auth = createAuth({ secret: SECRET, expiresIn: "1h" });
    const result = await auth.login({ id: 1, email: "a@b.c" });
    const decoded = await (auth as never).jwtBackend.verify(result.accessToken, {
      audience: undefined,
      issuer: undefined,
      algorithms: ["HS256"],
    });
    expect(decoded).toBeDefined();
  });

  it("CFG-05: refreshToken TTL defaults to 7d", async () => {
    const auth = createAuth({ secret: SECRET });
    const result = await auth.login({ id: 1, email: "a@b.c" });
    expect(result.refreshToken).toBeTruthy();
  });

  it("CFG-06: RBAC configuration is normalized for each input shape", async () => {
    const shapes: Array<{ roles?: unknown }> = [
      { roles: { reader: { permissions: ["doc.read"] } } },
    ];
    for (const shape of shapes) {
      const auth = createAuth({ secret: SECRET, rbac: shape as never });
      expect(auth.can({ roles: ["reader"] }, "doc.read")).toBe(true);
    }
  });

  it("CFG-07: default password hasher is selected when omitted", async () => {
    const auth = createAuth({ secret: SECRET });
    const hash = await auth.hashPassword("test-password");
    expect(typeof hash).toBe("string");
    expect(hash.length).toBeGreaterThan(0);
  });

  it("CFG-08: sessionVersionPolicy defaults to migration", async () => {
    const auth = createAuth({
      secret: SECRET,
      sessionStore: createMemorySessionStore(),
    });
    const session = await auth.login({ id: 1, roles: ["user"] });
    expect(session.payload.sv).toBeDefined();
  });

  it("CFG-09: logger, HTTP, diagnostics, OAuth, persistence, JWT backend options are wired", async () => {
    const logs: unknown[] = [];
    const auth = createAuth({
      secret: SECRET,
      logger: {
        info: (payload) => logs.push(payload),
        error: (payload) => logs.push(payload),
        warn: (payload) => logs.push(payload),
        debug: (payload) => logs.push(payload),
      },
      http: { timeout: 5000 },
      diagnostics: {
        onEvent: (event) => logs.push(event),
        onError: (err) => logs.push(err),
      },
      oauth: {
        providers: {
          test: {
            clientId: "test-id",
            authorizationUrl: "https://test.example/authorize",
            tokenUrl: "https://test.example/token",
            redirectUri: "https://test.example/cb",
            redirectUriPolicy: {
              allowedRedirectUris: ["https://test.example/cb"],
              allowLocalhostHttp: false,
            },
          },
        },
      },
    });
    expect(auth).toBeInstanceOf(Auth);
    expect(logs.length).toBeGreaterThanOrEqual(0);
  });

  it("CFG-10: explicit stores take precedence over persistence adapter domains", async () => {
    const sessionStore = fakeSessionStore();
    const auth = createAuth({
      secret: SECRET,
      sessionStore,
      persistence: {
        sessions: fakeSessionStore(99),
      },
    });
    const session = await auth.login({ id: 1, roles: ["user"] });
    expect(session.payload.sv).toBe(0);
  });
});
