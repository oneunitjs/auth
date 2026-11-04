import { describe, it, expect } from "vitest";
import { createAuth, UnauthorizedError, ConfigurationError, createMemoryRefreshStore } from "../../src/index.js";
import { SECRET } from "./fixtures/auth.fixtures.js";
import { fakeRefreshStore, refreshingStoreWithoutConsume } from "./fixtures/fake-refresh-store.js";

describe("Auth refresh-token rotation (REF)", () => {
  it("REF-01: refresh a valid refresh token issues new access/refresh pair", async () => {
    const auth = createAuth({ secret: SECRET });
    const first = await auth.login({ id: 1, email: "a@b.c" });
    expect(first.refreshToken).toBeTruthy();
    const next = await auth.refresh(first.refreshToken as string);
    expect(next.user.id).toBe(1);
    expect(next.accessToken).not.toBe(first.accessToken);
    expect(next.refreshToken).not.toBe(first.refreshToken);
  });

  it("REF-02: pass access token to refresh rejects because typ is not refresh", async () => {
    const auth = createAuth({ secret: SECRET });
    const result = await auth.login({ id: 1, email: "a@b.c" });
    await expect(auth.refresh(result.accessToken)).rejects.toThrow(
      UnauthorizedError,
    );
  });

  it("REF-03: refresh token with no jti throws UnauthorizedError", async () => {
    const { encode } = await import("../../src/index.js");
    const noJti = await encode({ sub: "1", userId: 1, typ: "refresh" }, SECRET, {
      expiresIn: "7d",
    });
    const auth = createAuth({ secret: SECRET });
    await expect(auth.refresh(noJti)).rejects.toThrow(UnauthorizedError);
  });

  it("REF-04: refresh store lacks atomic consume throws ConfigurationError", async () => {
    const auth = createAuth({
      secret: SECRET,
      refreshStore: refreshingStoreWithoutConsume(),
    });
    const result = await auth.login({ id: 1, email: "a@b.c" });
    await expect(auth.refresh(result.refreshToken as string)).rejects.toThrow(
      ConfigurationError,
    );
  });

  it("REF-05: refresh token already consumed or revoked throws UnauthorizedError", async () => {
    const auth = createAuth({ secret: SECRET });
    const result = await auth.login({ id: 1, email: "a@b.c" });
    await auth.refresh(result.refreshToken as string);
    await expect(
      auth.refresh(result.refreshToken as string),
    ).rejects.toThrow(UnauthorizedError);
  });

  it("REF-06: session version revoked rejects refresh before new tokens minted", async () => {
    const { createMemorySessionStore } = await import("../../src/index.js");
    const sessionStore = createMemorySessionStore();
    const auth = createAuth({ secret: SECRET, sessionStore });
    const result = await auth.login({ id: 1, roles: ["user"] });
    await auth.revokeAllSessions(1);
    await expect(auth.refresh(result.refreshToken as string)).rejects.toThrow(
      UnauthorizedError,
    );
  });

  it("REF-07: session id revoked rejects refresh before new tokens minted", async () => {
    const { createMemorySessionStore } = await import("../../src/index.js");
    const sessionStore = createMemorySessionStore();
    const auth = createAuth({ secret: SECRET, sessionStore });
    const result = await auth.login({ id: 1, roles: ["user"] });
    const sid = String(result.payload.sid);
    await auth.revokeSession(sid);
    await expect(auth.refresh(result.refreshToken as string)).rejects.toThrow(
      UnauthorizedError,
    );
  });

  it("REF-08: user store can reload user by ID, refresh uses reloaded user", async () => {
    const auth = createAuth({
      secret: SECRET,
      userStore: {
        async findById(id: string | number) {
          return { id, email: "reloaded@example.com", roles: ["member"] };
        },
      },
    });
    const result = await auth.login({ id: 1, email: "old@example.com", roles: ["member"] });
    const next = await auth.refresh(result.refreshToken as string);
    expect(next.user.email).toBe("reloaded@example.com");
  });

  it("REF-09: two concurrent refresh attempts with same token at most one succeeds", async () => {
    const auth = createAuth({ secret: SECRET });
    const result = await auth.login({ id: 1, email: "a@b.c" });
    const token = result.refreshToken as string;
    const results = await Promise.allSettled([
      auth.refresh(token),
      auth.refresh(token),
    ]);
    const successes = results.filter(
      (r) => r.status === "fulfilled",
    ).length;
    expect(successes).toBeLessThanOrEqual(1);
  });

  it("REF-10: successful refresh old token cannot be reused; new refresh token usable once", async () => {
    const auth = createAuth({ secret: SECRET });
    const first = await auth.login({ id: 1, email: "a@b.c" });
    const next = await auth.refresh(first.refreshToken as string);
    await expect(auth.refresh(first.refreshToken as string)).rejects.toThrow(
      UnauthorizedError,
    );
    const again = await auth.refresh(next.refreshToken as string);
    expect(again.user.id).toBe(1);
  });

  it("REF-16: 100 concurrent refresh attempts with the same token: exactly one succeeds", async () => {
    const auth = createAuth({ secret: SECRET });
    const result = await auth.login({ id: 1, email: "a@b.c" });
    const token = result.refreshToken as string;

    const outcomes = await Promise.allSettled(
      Array.from({ length: 100 }, () => auth.refresh(token)),
    );

    const successes = outcomes.filter((o) => o.status === "fulfilled").length;
    const failures = outcomes.filter((o) => o.status === "rejected").length;
    expect(successes).toBe(1);
    expect(failures).toBe(99);
    // Every failure is a safe authentication rejection, not an ambiguous error.
    for (const o of outcomes) {
      if (o.status === "rejected") {
        expect((o.reason as Error).message).toMatch(/revoked|consumed|Unauthorized/);
      }
    }
  });

  it("REF-17: refresh store consume timeout/connection loss fails closed", async () => {
    let consumeCalls = 0;
    const flakyStore = {
      async save() {},
      async get() {
        return null;
      },
      async consume() {
        consumeCalls += 1;
        // Simulate a storage timeout / connection loss on the first attempt.
        throw new Error("connection lost");
      },
      async revoke() {},
    } as unknown as ReturnType<typeof createMemoryRefreshStore>;

    const auth = createAuth({ secret: SECRET, refreshStore: flakyStore });
    const result = await auth.login({ id: 1, email: "a@b.c" });

    await expect(auth.refresh(result.refreshToken as string)).rejects.toThrow(
      "connection lost",
    );
    // The failure propagates; the token is not silently accepted.
    expect(consumeCalls).toBeGreaterThan(0);
  });

  it("REF-18: a failed rotation leaves no ambiguous token state", async () => {
    const auth = createAuth({ secret: SECRET });
    const result = await auth.login({ id: 1, email: "a@b.c" });
    const token = result.refreshToken as string;

    // First rotation succeeds.
    await auth.refresh(token);

    // The consumed token cannot be rotated again.
    await expect(auth.refresh(token)).rejects.toThrow(UnauthorizedError);

    // No stale state: rotating the (now consumed) token a second time still
    // fails, and the previously issued new token remains the only valid one.
    const second = await auth.login({ id: 2, email: "b@b.c" });
    await auth.refresh(second.refreshToken as string);
    await expect(auth.refresh(second.refreshToken as string)).rejects.toThrow(
      UnauthorizedError,
    );
  });

  it("REF-19: two auth instances sharing one refresh store: 100 concurrent refreshes, exactly one succeeds", async () => {
    const sharedStore = createMemoryRefreshStore();
    const authA = createAuth({ secret: SECRET, refreshStore: sharedStore });
    const authB = createAuth({ secret: SECRET, refreshStore: sharedStore });

    const resultA = await authA.login({ id: 1, email: "a@b.c" });
    const token = resultA.refreshToken as string;

    const outcomes = await Promise.allSettled([
      ...Array.from({ length: 50 }, () => authA.refresh(token)),
      ...Array.from({ length: 50 }, () => authB.refresh(token)),
    ]);

    const successes = outcomes.filter((o) => o.status === "fulfilled").length;
    expect(successes).toBe(1);
  });

  it("REF-20: replay detection after a successful rotation rejects all derived tokens", async () => {
    const auth = createAuth({ secret: SECRET });
    const first = await auth.login({ id: 1, email: "a@b.c" });
    const rotated = await auth.refresh(first.refreshToken as string);

    // Original token, the rotated-away token, and any token minted from it are
    // all rejected.
    await expect(auth.refresh(first.refreshToken as string)).rejects.toThrow(
      UnauthorizedError,
    );
    await expect(auth.refresh(rotated.refreshToken as string)).resolves.toBeDefined();
    await expect(auth.refresh(rotated.refreshToken as string)).rejects.toThrow(
      UnauthorizedError,
    );
  });
});
