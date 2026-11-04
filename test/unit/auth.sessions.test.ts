import { describe, it, expect } from "vitest";
import { createAuth, UnauthorizedError, ConfigurationError } from "../../src/index.js";
import { SECRET } from "./fixtures/auth.fixtures.js";
import { fakeSessionStore, failingSessionStore, sessionStoreWithoutBumpVersion, sessionStoreWithoutRevokeSession } from "./fixtures/fake-session-store.js";
import { fakeRefreshStore } from "./fixtures/fake-refresh-store.js";

describe("Auth session version and revocation (SES)", () => {
  it("SES-01: no session store skips session-version check", async () => {
    const auth = createAuth({ secret: SECRET });
    const result = await auth.login({ id: 1, roles: ["user"] });
    await expect(auth.verify(result.accessToken)).resolves.toBeDefined();
  });

  it("SES-02: session policy disabled skips session-version check", async () => {
    const auth = createAuth({
      secret: SECRET,
      sessionStore: fakeSessionStore(),
      sessionVersionPolicy: "disabled",
    });
    const result = await auth.login({ id: 1, roles: ["user"] });
    await auth.revokeAllSessions(1);
    await expect(auth.verify(result.accessToken)).resolves.toBeDefined();
  });

  it("SES-03: policy reject and token lacks sv throws UnauthorizedError", async () => {
    const auth = createAuth({
      secret: SECRET,
      sessionStore: fakeSessionStore(),
      sessionVersionPolicy: "reject",
    });
    const { encode } = await import("../../src/index.js");
    const legacy = await encode({ sub: "1", userId: 1, typ: "access" }, SECRET, {
      expiresIn: "15m",
    });
    await expect(auth.verify(legacy)).rejects.toThrow(
      UnauthorizedError,
    );
  });

  it("SES-04: token sv matches store version passes", async () => {
    const sessionStore = fakeSessionStore(3);
    const auth = createAuth({ secret: SECRET, sessionStore });
    const result = await auth.login({ id: 1, roles: ["user"] });
    expect(result.payload.sv).toBe(3);
    const verified = await auth.verify(result.accessToken);
    expect(verified.sub).toBe("1");
  });

  it("SES-05: token sv differs from store version throws UnauthorizedError", async () => {
    const sessionStore = fakeSessionStore(1);
    const auth = createAuth({ secret: SECRET, sessionStore });
    const result = await auth.login({ id: 1, roles: ["user"] });
    sessionStore.version = 99;
    await expect(auth.verify(result.accessToken)).rejects.toThrow(
      UnauthorizedError,
    );
  });

  it("SES-06: token with revoked sid is rejected", async () => {
    const sessionStore = fakeSessionStore();
    const auth = createAuth({ secret: SECRET, sessionStore });
    const result = await auth.login({ id: 1, roles: ["user"] });
    const sid = String(result.payload.sid);
    sessionStore.revokedSet.add(sid);
    await expect(auth.verify(result.accessToken)).rejects.toThrow(
      UnauthorizedError,
    );
  });

  it("SES-07: store exposes each documented revocation method shape is recognized", async () => {
    const store = {
      async getVersion() { return 0; },
      async isSessionRevoked(_sid: string) { return true; },
    };
    const auth = createAuth({ secret: SECRET, sessionStore: store as never });
    const result = await auth.login({ id: 1, roles: ["user"], sid: "test-sid" as never });
    await expect(auth.verify(result.accessToken)).rejects.toThrow(
      UnauthorizedError,
    );
  });

  it("SES-08: store exposes revocation through collection shapes", async () => {
    const store = {
      async getVersion() { return 0; },
      revoked: new Set<string>(),
    };
    const auth = createAuth({ secret: SECRET, sessionStore: store as never });
    const result = await auth.login({ id: 1, roles: ["user"] });
    const sid = String(result.payload.sid);
    store.revoked.add(sid);
    await expect(auth.verify(result.accessToken)).rejects.toThrow(
      UnauthorizedError,
    );
  });

  it("SES-09: no store-level revocation match but in-process map contains session treated as revoked", async () => {
    const sessionStore = fakeSessionStore();
    const auth = createAuth({ secret: SECRET, sessionStore });
    const result = await auth.login({ id: 1, roles: ["user"] });
    const sid = String(result.payload.sid);
    await auth.revokeSession(sid);
    await expect(auth.verify(result.accessToken)).rejects.toThrow(
      UnauthorizedError,
    );
  });

  it("SES-10: revokeAllSessions with bumpVersion makes existing tokens fail", async () => {
    const sessionStore = fakeSessionStore(1);
    const auth = createAuth({ secret: SECRET, sessionStore });
    const result = await auth.login({ id: 1, roles: ["user"] });
    await auth.revokeAllSessions(1);
    await expect(auth.verify(result.accessToken)).rejects.toThrow(
      UnauthorizedError,
    );
  });

  it("SES-11: revoke-all without required store capability reports not-configured/unavailable", async () => {
    const auth = createAuth({ secret: SECRET, sessionStore: sessionStoreWithoutBumpVersion() });
    const result = await auth.revokeAllSessionsResult(1);
    expect(result.status).toBe("not_configured");
    expect(await auth.revokeAllSessions(1)).toBe(false);
  });

  it("SES-12: revokeSession with store support updates store and in-process state", async () => {
    const sessionStore = fakeSessionStore();
    const auth = createAuth({ secret: SECRET, sessionStore });
    const result = await auth.login({ id: 1, roles: ["user"] });
    const sid = String(result.payload.sid);
    const res = await auth.revokeSessionResult(sid);
    expect(res.status).toBe("revoked");
    await expect(auth.revokeSession(sid)).resolves.toBe(false);
  });

  it("SES-13: revoke-session without store support reports unsupported/unavailable", async () => {
    const auth = createAuth({ secret: SECRET, sessionStore: sessionStoreWithoutRevokeSession() });
    const result = await auth.revokeSessionResult("sid-1");
    expect(result.status).toBe("not_configured");
    expect(await auth.revokeSession("sid-1")).toBe(false);
  });

  it("SES-14: revoke/logout with valid refresh token revokes it and associated session", async () => {
    const auth = createAuth({ secret: SECRET });
    const result = await auth.login({ id: 1, roles: ["user"] });
    expect(await auth.revoke(result.refreshToken as string)).toBe(true);
    await expect(auth.refresh(result.refreshToken as string)).rejects.toThrow(
      UnauthorizedError,
    );
  });

  it("SES-15: revoke/logout with invalid token or missing jti returns failure without false success", async () => {
    const auth = createAuth({ secret: SECRET });
    expect(await auth.revoke(undefined)).toBe(false);
    expect(await auth.revoke(null)).toBe(false);
    expect(await auth.revoke("")).toBe(false);
    const { encode } = await import("../../src/index.js");
    const noJti = await encode({ sub: "1", userId: 1, typ: "refresh" }, SECRET, {
      expiresIn: "7d",
    });
    expect(await auth.revoke(noJti)).toBe(false);
    expect(await auth.logout(undefined)).toBe(false);
  });

  it("SES-16: revocation through one instance is verified through another sharing the store", async () => {
    const sharedStore = fakeSessionStore();
    const authA = createAuth({ secret: SECRET, sessionStore: sharedStore });
    const authB = createAuth({ secret: SECRET, sessionStore: sharedStore });

    const result = await authA.login({ id: 1, roles: ["user"] });
    const sid = String(result.payload.sid);

    // Verify passes on instance B before revocation.
    expect((await authB.verify(result.accessToken)).sub).toBe("1");

    // Revoke through instance A.
    expect(await authA.revokeSession(sid)).toBe(true);

    // Verification through instance B now rejects the revoked session.
    await expect(authB.verify(result.accessToken)).rejects.toThrow(
      UnauthorizedError,
    );
  });

  it("SES-17: storage outage during revocation check fails closed", async () => {
    const auth = createAuth({
      secret: SECRET,
      sessionStore: failingSessionStore(),
    });
    const result = await auth.login({ id: 1, roles: ["user"] });

    // The revocation check cannot be completed: verification must fail closed,
    // not accept the token.
    await expect(auth.verify(result.accessToken)).rejects.toThrow();
  });

  it("SES-18: concurrent login and revocation leaves no accepted revoked session", async () => {
    const sessionStore = fakeSessionStore();
    const auth = createAuth({ secret: SECRET, sessionStore });

    const result = await auth.login({ id: 1, roles: ["user"] });
    const sid = String(result.payload.sid);

    // Issue a revocation and many concurrent verifications of the same token.
    const outcomes = await Promise.allSettled([
      auth.revokeSession(sid),
      ...Array.from({ length: 50 }, () => auth.verify(result.accessToken)),
    ]);

    const successes = outcomes.filter(
      (o) => o.status === "fulfilled",
    ).length;
    // At most the verifications that ran before the revocation landed succeed;
    // none succeed after the session is revoked.
    expect(successes).toBeLessThanOrEqual(50);
    await expect(auth.verify(result.accessToken)).rejects.toThrow(
      UnauthorizedError,
    );
  });

  it("SES-19: revocation propagation is bounded and measured", async () => {
    const sessionStore = fakeSessionStore();
    const auth = createAuth({ secret: SECRET, sessionStore });

    const result = await auth.login({ id: 1, roles: ["user"] });
    const sid = String(result.payload.sid);

    const start = Number(process.hrtime.bigint());
    await auth.revokeSession(sid);
    await expect(auth.verify(result.accessToken)).rejects.toThrow(
      UnauthorizedError,
    );
    const elapsedMs = Number(process.hrtime.bigint() - BigInt(start)) / 1e6;

    // Propagation should be effectively immediate (well under 1s) for an
    // in-process store. Documented as a regression guard.
    expect(elapsedMs).toBeLessThan(1_000);
  });
});
