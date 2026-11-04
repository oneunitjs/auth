 
import { describe, it, expect } from "vitest";
import {
  createAuth,
  createMemorySessionStore,
  TokenExpiredError,
  UnauthorizedError,
  encode,
} from "../../src/index.js";

const SECRET = "secret-key-for-testing-purposes-123456";

describe("advanced session revocation", () => {
  it("rejects expired access tokens", async () => {
    const auth = createAuth({ secret: SECRET, sessionStore: createMemorySessionStore() });
    const token = await encode(
      { sub: "1", userId: 1, typ: "access", sv: 0, sid: "missing" },
      SECRET,
      { expiresIn: 0 },
    );
    await expect(() => auth.verify(token)).rejects.toThrow(TokenExpiredError);
  });

  it("rejects tokens from the revoked session but keeps another session valid", async () => {
    const auth = createAuth({ secret: SECRET, sessionStore: createMemorySessionStore() });
    const first = await auth.login({ id: 1, roles: ["user"] });
    const second = await auth.login({ id: 1, roles: ["user"] });

    expect(await auth.revokeSession(String(first.payload.sid))).toBe(true);
    await expect(() => auth.verify(first.accessToken)).rejects.toThrow(UnauthorizedError);
    expect((await auth.verify(second.accessToken)).sub).toBe("1");

    await expect(() => auth.refresh(first.refreshToken as string)).rejects.toThrow(
      UnauthorizedError,
    );
    const refreshed = await auth.refresh(second.refreshToken as string);
    expect(refreshed.accessToken).toBeTruthy();
  });

  it("invalidates all sessions on user-wide revocation", async () => {
    const auth = createAuth({ secret: SECRET, sessionStore: createMemorySessionStore() });
    const first = await auth.login({ id: 1, roles: ["user"] });
    const second = await auth.login({ id: 1, roles: ["user"] });

    expect(await auth.revokeAllSessions(1)).toBe(true);
    await expect(() => auth.verify(first.accessToken)).rejects.toThrow(UnauthorizedError);
    await expect(() => auth.verify(second.accessToken)).rejects.toThrow(UnauthorizedError);
  });

  it("does not affect a different user", async () => {
    const auth = createAuth({ secret: SECRET, sessionStore: createMemorySessionStore() });
    const session = await auth.login({ id: 1, roles: ["user"] });
    await auth.revokeAllSessions(2);
    expect((await auth.verify(session.accessToken)).sub).toBe("1");
  });

  it("fails securely when the revocation check throws", async () => {
    const store = createMemorySessionStore();
    store.isSessionRevoked = async () => {
      throw new Error("store offline");
    };
    const auth = createAuth({ secret: SECRET, sessionStore: store });
    const session = await auth.login({ id: 1, roles: ["user"] });
    await expect(() => auth.verify(session.accessToken)).rejects.toThrow();
  });

  it("revokes access tokens on logout when a session store is configured", async () => {
    const auth = createAuth({ secret: SECRET, sessionStore: createMemorySessionStore() });
    const session = await auth.login({ id: 1, roles: ["user"] });
    expect(await auth.logout(session.refreshToken)).toBe(true);
    await expect(() => auth.verify(session.accessToken)).rejects.toThrow(UnauthorizedError);
  });

  it("retains stateless behavior without a session store", async () => {
    const auth = createAuth({ secret: SECRET });
    const session = await auth.login({ id: 1, roles: ["user"] });
    expect(session.payload.sv).toBeUndefined();
    expect(session.payload.sid).toBeUndefined();
    expect(await auth.revokeAllSessions(1)).toBe(false);
    expect(await auth.revokeAllSessionsResult(1)).toEqual({ status: "not_configured" });
    expect((await auth.verify(session.accessToken)).sub).toBe("1");
  });

  it("rejects legacy tokens without sv when policy is reject", async () => {
    const auth = createAuth({
      secret: SECRET,
      sessionStore: createMemorySessionStore(),
      sessionVersionPolicy: "reject",
    });
    const token = await encode({ sub: "1", userId: 1, typ: "access" }, SECRET, { expiresIn: "15m" });
    await expect(() => auth.verify(token)).rejects.toThrow(UnauthorizedError);
  });
});

describe("shared store revocation", () => {
  it("honors revocation across independent Auth instances", async () => {
    const store = createMemorySessionStore();
    const authA = createAuth({ secret: SECRET, sessionStore: store });
    const authB = createAuth({ secret: SECRET, sessionStore: store });
    const session = await authA.login({ id: 1, roles: ["user"] });

    expect(await authB.revokeSession(String(session.payload.sid))).toBe(true);
    await expect(() => authB.verify(session.accessToken)).rejects.toThrow(UnauthorizedError);
  });
});
