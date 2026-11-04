import { describe, it, expect } from "vitest";
import { createAuth, ForbiddenError } from "../../src/index.js";
import { SECRET } from "./fixtures/auth.fixtures.js";

describe("Auth RBAC and password delegation (RBAC/HASH)", () => {
  it("RBAC-01: can returns true for allowed permission", async () => {
    const auth = createAuth({
      secret: SECRET,
      rbac: { roles: { reader: { permissions: ["doc.read"] } } },
    });
    expect(auth.can({ roles: ["reader"] }, "doc.read")).toBe(true);
  });

  it("RBAC-02: can returns false for denied permission", async () => {
    const auth = createAuth({
      secret: SECRET,
      rbac: { roles: { reader: { permissions: ["doc.read"] } } },
    });
    expect(auth.can({ roles: ["reader"] }, "doc.write")).toBe(false);
  });

  it("RBAC-03: authorize throws ForbiddenError for denied permission", async () => {
    const auth = createAuth({
      secret: SECRET,
      rbac: { roles: { reader: { permissions: ["doc.read"] } } },
    });
    expect(() => auth.authorize({ roles: ["reader"] }, "doc.write")).toThrow(
      ForbiddenError,
    );
  });

  it("RBAC-04: hasRole returns true for matching role", async () => {
    const auth = createAuth({
      secret: SECRET,
      rbac: { roles: { admin: { permissions: ["all"] } } },
    });
    expect(auth.hasRole({ roles: ["admin"] }, "admin")).toBe(true);
  });

  it("RBAC-05: hasRole returns false for no matching role", async () => {
    const auth = createAuth({
      secret: SECRET,
      rbac: { roles: { admin: { permissions: ["all"] } } },
    });
    expect(auth.hasRole({ roles: ["member"] }, "admin")).toBe(false);
  });

  it("HASH-01: hashPassword delegates to configured password hasher", async () => {
    const auth = createAuth({ secret: SECRET });
    const hash = await auth.hashPassword("test-password");
    expect(typeof hash).toBe("string");
    expect(hash.length).toBeGreaterThan(0);
  });

  it("HASH-02: verifyPassword delegates to configured password hasher and returns result", async () => {
    const auth = createAuth({ secret: SECRET });
    const hash = await auth.hashPassword("test-password");
    expect(await auth.verifyPassword("test-password", hash)).toBe(true);
    expect(await auth.verifyPassword("wrong-password", hash)).toBe(false);
  });
});
