import { describe, it, expect } from "vitest";
import { createAuth, encode, hashPassword } from "../../src/index.js";
import { SECRET, memoryUsers } from "./fixtures/auth.fixtures.js";
import { fakeSessionStore } from "./fixtures/fake-session-store.js";

describe("Auth security and diagnostics regression (SEC)", () => {
  it("SEC-01: override sub/userId/roles/permissions/typ/iss/aud/exp/iat/nbf/jti/sv/sid through additional claims is rejected", async () => {
    const auth = createAuth({ secret: SECRET });
    const reserved = ["sub", "userId", "roles", "permissions", "typ", "iss", "aud", "exp", "iat", "nbf", "jti", "sv", "sid"];
    for (const claim of reserved) {
      await expect(
        auth.login({ id: 1, email: "a@b.c" }, { additionalClaims: { [claim]: "attacker" } as never }),
      ).rejects.toThrow();
    }
  });

  it("SEC-02: return reserved names from claim extractor removes them", async () => {
    const auth = createAuth({ secret: SECRET });
    auth.registerExtractor("plan", async () => ({ sub: "attacker", roles: ["admin"] }));
    const result = await auth.login({ id: 1, email: "a@b.c" });
    expect(result.payload.sub).toBe("1");
    expect(result.payload.roles).not.toContain("admin");
  });

  it("SEC-03: present refresh token to access-token verification rejected by default", async () => {
    const auth = createAuth({ secret: SECRET });
    const result = await auth.login({ id: 1, email: "a@b.c" });
    await expect(auth.verify(result.refreshToken as string)).rejects.toThrow();
  });

  it("SEC-04: reuse a consumed refresh token rejected", async () => {
    const auth = createAuth({ secret: SECRET });
    const result = await auth.login({ id: 1, email: "a@b.c" });
    await auth.refresh(result.refreshToken as string);
    await expect(auth.refresh(result.refreshToken as string)).rejects.toThrow();
  });

  it("SEC-05: concurrent reuse of refresh token no more than one succeeds", async () => {
    const auth = createAuth({ secret: SECRET });
    const result = await auth.login({ id: 1, email: "a@b.c" });
    const token = result.refreshToken as string;
    const results = await Promise.allSettled([
      auth.refresh(token),
      auth.refresh(token),
    ]);
    const successes = results.filter((r) => r.status === "fulfilled").length;
    expect(successes).toBeLessThanOrEqual(1);
  });

  it("SEC-06: logger/diagnostic payloads do not expose password or token values", async () => {
    const logged: unknown[] = [];
    const hash = await hashPassword("s3cret-pass");
    const auth = createAuth({
      secret: SECRET,
      userStore: memoryUsers([{ id: 1, email: "user@example.com", passwordHash: hash }]),
      logger: {
        info: (payload) => logged.push(payload),
        debug: (payload) => logged.push(payload),
        warn: (payload) => logged.push(payload),
        error: (payload) => logged.push(payload),
      },
    });
    const result = await auth.loginWithPassword("user@example.com", "s3cret-pass");
    const loggedStr = JSON.stringify(logged);
    expect(loggedStr).not.toContain("s3cret-pass");
    expect(loggedStr).not.toContain(result.accessToken);
  });

  it("SEC-07: query-string token without opt-in not accepted", async () => {
    const auth = createAuth({ secret: SECRET });
    const result = await auth.login({ id: 1, email: "a@b.c" });
    await expect(
      auth.verifyRequest({
        headers: {},
        query: `access_token=${result.accessToken}`,
      } as never),
    ).rejects.toThrow();
  });

  it("SEC-08: register with attacker-supplied roles does not grant privileges", async () => {
    const auth = createAuth({
      secret: SECRET,
      userStore: memoryUsers(),
      rbac: { defaultRole: "member", roles: { member: { permissions: ["read"] } } },
    });
    const result = await auth.register(
      { email: "a@b.c", password: "password", roles: ["admin"] },
      { roles: ["member"] },
    );
    expect(result.payload.roles).toEqual(["member"]);
  });

  it("SEC-09: user-supplied permissions with trustUserPermissions false do not grant", async () => {
    const auth = createAuth({
      secret: SECRET,
      trustUserPermissions: false,
      userStore: memoryUsers(),
    });
    const result = await auth.login({
      id: 1,
      email: "a@b.c",
      roles: ["member"],
      permissions: ["admin.delete"],
    });
    expect(result.payload.permissions).not.toContain("admin.delete");
  });

  it("SEC-10: refresh token lacks jti rejected rather than treated as revocable", async () => {
    const noJti = await encode({ sub: "1", userId: 1, typ: "refresh" }, SECRET, {
      expiresIn: "7d",
    });
    const auth = createAuth({ secret: SECRET });
    await expect(auth.refresh(noJti)).rejects.toThrow();
  });
});
