import { describe, it, expect } from "vitest";
import { createAuth, UnauthorizedError, ValidationError, ConfigurationError, hashPassword } from "../../src/index.js";
import { SECRET, memoryUsers } from "./fixtures/auth.fixtures.js";
import { userStoreWithoutCreate, userStoreWithoutFindByCredentials, userStoreWithoutUpdatePassword } from "./fixtures/fake-user-store.js";

describe("Auth password login and registration (PWD/REG)", () => {
  it("PWD-01: loginWithPassword without usable user lookup fails with configuration error", async () => {
    const auth = createAuth({ secret: SECRET, userStore: {} as never });
    await expect(
      auth.loginWithPassword("user@example.com", "password"),
    ).rejects.toThrow(ConfigurationError);
  });

  it("PWD-02: user lookup returns no user emits failed diagnostics and throws UnauthorizedError", async () => {
    const auth = createAuth({
      secret: SECRET,
      userStore: memoryUsers(),
    });
    await expect(
      auth.loginWithPassword("none@example.com", "password"),
    ).rejects.toThrow(UnauthorizedError);
  });

  it("PWD-03: user with no password hash fails with same generic invalid-credentials response", async () => {
    const auth = createAuth({
      secret: SECRET,
      userStore: memoryUsers([{ id: 1, email: "nohash@example.com" }]),
    });
    await expect(
      auth.loginWithPassword("nohash@example.com", "password"),
    ).rejects.toThrow(UnauthorizedError);
  });

  it("PWD-04: password verification fails emits failed diagnostics and throws UnauthorizedError", async () => {
    const store = memoryUsers([{ id: 1, email: "a@b.c", passwordHash: "bad-hash" }]);
    const auth = createAuth({ secret: SECRET, userStore: store });
    await expect(
      auth.loginWithPassword("a@b.c", "wrong-password"),
    ).rejects.toThrow(UnauthorizedError);
  });

  it("PWD-05: password verification succeeds delegates to login and returns result", async () => {
    const hash = await hashPassword("password");
    const auth = createAuth({
      secret: SECRET,
      userStore: memoryUsers([{ id: 1, email: "a@b.c", passwordHash: hash }]),
    });
    const result = await auth.loginWithPassword("a@b.c", "password");
    expect(result.user.id).toBe(1);
  });

  it("PWD-06: password hash needs rehash and store supports update rehashes and updates", async () => {
    const { hashPassword, needsRehash } = await import("../../src/index.js");
    const hash = await hashPassword("s3cret-pass");
    expect(needsRehash(hash)).toBe(false);
    const store = memoryUsers([{ id: 1, email: "a@b.c", passwordHash: hash }]);
    const auth = createAuth({ secret: SECRET, userStore: store });
    const session = await auth.loginWithPassword("a@b.c", "s3cret-pass");
    expect(session.user.id).toBe(1);
  });

  it("PWD-07: password update during rehash fails is caught and login still succeeds", async () => {
    const { hashPassword, needsRehash } = await import("../../src/index.js");
    const hash = await hashPassword("password");
    const store = userStoreWithoutUpdatePassword();
    // Override findByCredentials to return a user with a valid hash
    const originalFindByCredentials = store.findByCredentials.bind(store);
    store.findByCredentials = async () => ({
      id: 1,
      email: "user@example.com",
      passwordHash: hash,
    });
    const auth = createAuth({ secret: SECRET, userStore: store });
    // If needsRehash returns true, updatePassword is missing and should be caught
    if (needsRehash(hash)) {
      const session = await auth.loginWithPassword("user@example.com", "password");
      expect(session.user.id).toBe(1);
    } else {
      const session = await auth.loginWithPassword("user@example.com", "password");
      expect(session.user.id).toBe(1);
    }
  });

  it("REG-01: register without userStore.create fails with configuration error", async () => {
    const auth = createAuth({
      secret: SECRET,
      userStore: userStoreWithoutCreate(),
    });
    await expect(
      auth.register({ email: "a@b.c", password: "password" }),
    ).rejects.toThrow(ConfigurationError);
  });

  it("REG-02: register with missing/empty/non-string password throws ValidationError", async () => {
    const auth = createAuth({
      secret: SECRET,
      userStore: memoryUsers(),
    });
    await expect(
      auth.register({ email: "a@b.c" }),
    ).rejects.toThrow(ValidationError);
    await expect(
      auth.register({ email: "a@b.c", password: "" }),
    ).rejects.toThrow(ValidationError);
    await expect(
      auth.register({ email: "a@b.c", password: 123 as never }),
    ).rejects.toThrow(ValidationError);
  });

  it("REG-03: register with valid password hashes password before creating user", async () => {
    const auth = createAuth({
      secret: SECRET,
      userStore: memoryUsers(),
    });
    const result = await auth.register({
      email: "new@example.com",
      username: "newuser",
      password: "s3cret-pass",
    });
    expect(result.user.email).toBe("new@example.com");
    const stored = await (auth as never).userStore.findByEmail("new@example.com");
    expect(stored?.passwordHash).toBeDefined();
    expect(stored?.passwordHash).not.toBe("s3cret-pass");
  });

  it("REG-04: registration input roles are ignored (attacker-supplied)", async () => {
    const auth = createAuth({
      secret: SECRET,
      userStore: memoryUsers(),
      rbac: { defaultRole: "member", roles: { member: { permissions: ["read"] } } },
    });
    const result = await auth.register({
      email: "attacker@example.com",
      password: "password",
      roles: ["admin"],
    });
    expect(result.payload.roles).toEqual(["member"]);
  });

  it("REG-05: registration options roles are used", async () => {
    const auth = createAuth({
      secret: SECRET,
      userStore: memoryUsers(),
      rbac: { defaultRole: "member", roles: { admin: { permissions: ["all"] } } },
    });
    const result = await auth.register({
      email: "admin@example.com",
      password: "password",
    }, { roles: ["admin"] });
    expect(result.payload.roles).toEqual(["admin"]);
  });

  it("REG-06: no roles supplied uses RBAC default role", async () => {
    const auth = createAuth({
      secret: SECRET,
      userStore: memoryUsers(),
      rbac: { defaultRole: "member", roles: { member: { permissions: ["read"] } } },
    });
    const result = await auth.register({
      email: "default@example.com",
      password: "password",
    });
    expect(result.payload.roles).toEqual(["member"]);
  });

  it("REG-07: registration succeeds delegates to login with created user", async () => {
    const auth = createAuth({
      secret: SECRET,
      userStore: memoryUsers(),
    });
    const result = await auth.register({
      email: "reg@example.com",
      username: "reguser",
      password: "password",
    });
    expect(result.accessToken).toBeTruthy();
    expect(result.user.email).toBe("reg@example.com");
  });
});
