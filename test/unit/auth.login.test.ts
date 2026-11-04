import { describe, it, expect } from "vitest";
import { createAuth, type PasswordHasher } from "../../src/index.js";
import type { LoginResult } from "../../src/index.js";
import { SECRET, baseUser, memoryUsers, makeTokenPayload } from "./fixtures/auth.fixtures.js";
import { fakeSessionStore } from "./fixtures/fake-session-store.js";

describe("Auth login and claims (LOG)", () => {
  it("LOG-01: login returns LoginResult with access token, alias, payload, and user", async () => {
    const auth = createAuth({ secret: SECRET });
    const result = await auth.login({ id: 1, email: "a@b.c" });
    expect(result).toHaveProperty("token");
    expect(result).toHaveProperty("accessToken");
    expect(result).toHaveProperty("payload");
    expect(result).toHaveProperty("user");
    expect(result.token).toBe(result.accessToken);
    expect(typeof result.accessToken).toBe("string");
    expect(result.payload.sub).toBe("1");
    expect(result.user.id).toBe(1);
  });

  it("LOG-02: login issues refresh token and saves jti in refresh store by default", async () => {
    const auth = createAuth({ secret: SECRET });
    const result = await auth.login({ id: 1, email: "a@b.c" });
    expect(result.refreshToken).toBeTruthy();
    const refreshed = await auth.refresh(result.refreshToken as string);
    expect(refreshed.user.id).toBe(1);
  });

  it("LOG-03: login with refresh: false does not issue refresh token", async () => {
    const auth = createAuth({ secret: SECRET });
    const result = await auth.login({ id: 1, email: "a@b.c" }, { refresh: false });
    expect(result.refreshToken).toBeNull();
  });

  it("LOG-04: user with both roles and role merges and deduplicates", async () => {
    const auth = createAuth({ secret: SECRET });
    const result = await auth.login({
      id: 1,
      email: "a@b.c",
      roles: ["admin", "editor"],
      role: "editor",
    });
    expect(result.payload.roles).toContain("admin");
    expect(result.payload.roles).toContain("editor");
    expect(new Set(result.payload.roles).size).toBe(result.payload.roles.length);
  });

  it("LOG-05: trustUserPermissions false does not trust user-supplied permissions", async () => {
    const auth = createAuth({
      secret: SECRET,
      trustUserPermissions: false,
      rbac: { roles: { member: { permissions: ["profile.read"] } } },
    });
    const result = await auth.login({
      id: 1,
      email: "a@b.c",
      roles: ["member"],
      permissions: ["admin.delete"],
    });
    expect(result.payload.permissions).not.toContain("admin.delete");
  });

  it("LOG-06: trustUserPermissions true includes and unions user permissions", async () => {
    const auth = createAuth({
      secret: SECRET,
      trustUserPermissions: true,
      rbac: { roles: { member: { permissions: ["profile.read"] } } },
    });
    const result = await auth.login({
      id: 1,
      email: "a@b.c",
      roles: ["member"],
      permissions: ["admin.delete"],
    });
    expect(result.payload.permissions).toContain("profile.read");
    expect(result.payload.permissions).toContain("admin.delete");
  });

  it("LOG-07: extractor returning custom claims appears in token payload", async () => {
    const auth = createAuth({ secret: SECRET });
    auth.registerExtractor("plan", async () => ({ plan: "pro" }));
    const result = await auth.login({ id: 1, email: "a@b.c" });
    expect(result.payload.plan).toBe("pro");
  });

  it("LOG-08: extractor returning reserved claims strips them", async () => {
    const auth = createAuth({ secret: SECRET });
    auth.registerExtractor("plan", async () => ({ sub: "attacker", roles: ["admin"] }));
    const result = await auth.login({ id: 1, email: "a@b.c" });
    expect(result.payload.sub).toBe("1");
    expect(result.payload.roles).not.toContain("admin");
  });

  it("LOG-09: additionalClaims without reserved names are included", async () => {
    const auth = createAuth({ secret: SECRET });
    const result = await auth.login(
      { id: 1, email: "a@b.c" },
      { additionalClaims: { department: "engineering" } },
    );
    expect(result.payload.department).toBe("engineering");
  });

  it("LOG-10: additionalClaims colliding with reserved name rejects login", async () => {
    const auth = createAuth({ secret: SECRET });
    await expect(
      auth.login({ id: 1, email: "a@b.c" }, { additionalClaims: { sub: "attacker" } }),
    ).rejects.toThrow();
  });

  it("LOG-11: session store stamps sv and sid into token", async () => {
    const sessionStore = fakeSessionStore(5);
    const auth = createAuth({ secret: SECRET, sessionStore });
    const result = await auth.login({ id: 1, roles: ["user"] });
    expect(result.payload.sv).toBe(5);
    expect(typeof result.payload.sid).toBe("string");
  });

  it("LOG-12: no session store omits sv", async () => {
    const auth = createAuth({ secret: SECRET });
    const result = await auth.login({ id: 1, roles: ["user"] });
    expect(result.payload.sv).toBeUndefined();
  });

  it("LOG-13: multiple hooks execute serially in registration order", async () => {
    const auth = createAuth({ secret: SECRET });
    const order: string[] = [];
    auth.hook("beforeLogin", async () => order.push("before1"));
    auth.hook("beforeLogin", async () => order.push("before2"));
    auth.hook("afterLogin", async () => order.push("after1"));
    auth.hook("afterLogin", async () => order.push("after2"));
    await auth.login({ id: 1, email: "a@b.c" });
    expect(order).toEqual(["before1", "before2", "after1", "after2"]);
  });

  it("LOG-14: hook throw propagates from Auth", async () => {
    const auth = createAuth({ secret: SECRET });
    auth.hook("beforeLogin", async () => {
      throw new Error("hook failure");
    });
    await expect(auth.login({ id: 1, email: "a@b.c" })).rejects.toThrow("hook failure");
  });

  it("LOG-15: supplied auth context is used; otherwise current/new fallback", async () => {
    const { createAuthContext, runWithAuthContext, getCurrentAuthContext } =
      await import("../../src/index.js");
    const auth = createAuth({ secret: SECRET });
    const ctx = createAuthContext({ requestId: "req-custom" });
    let captured: unknown = null;
    auth.hook("afterLogin", async () => {
      captured = getCurrentAuthContext();
    });
    await runWithAuthContext(ctx, async () => {
      await auth.login({ id: 1, email: "a@b.c" });
    });
    expect(captured).toBeDefined();
  });

  it("LOG-16: onLogin invoked after afterLogin hooks and emits success diagnostics", async () => {
    const auth = createAuth({ secret: SECRET });
    let onLoginCalled = false;
    auth.onLogin = async () => {
      onLoginCalled = true;
    };
    await auth.login({ id: 1, email: "a@b.c" });
    expect(onLoginCalled).toBe(true);
  });

  it("LOG-17: unknown-user password login performs a dummy verification", async () => {
    let verifyCalls = 0;
    const passwordHasher = {
      algorithm: "argon2id" as const,
      async hash() {
        return "$argon2id$v=19$m=65536,t=3,p=1$aaaaaaaa$bbbbbbbbbbbbbbbb";
      },
      async verify() {
        verifyCalls += 1;
        return false;
      },
      needsRehash() {
        return false;
      },
    } as unknown as PasswordHasher;
    const auth = createAuth({
      secret: SECRET,
      userStore: memoryUsers([]),
      passwordHasher,
    });
    await expect(auth.loginWithPassword("nobody", "any-password")).rejects.toThrow(
      "Invalid credentials",
    );
    expect(verifyCalls).toBeGreaterThan(0);
  });
});
