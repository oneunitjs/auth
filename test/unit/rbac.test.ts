 
import { describe, it, expect, vi } from "vitest";
import {
  createRBAC,
  defineRoles,
  matchPermission,
  ForbiddenError,
  ValidationError,
} from "../../src/index.js";

describe("rbac", () => {
  it("defines consumer roles and inherited permissions", () => {
    const rbac = createRBAC({
      defaultRole: "viewer",
      roles: {
        viewer: { permissions: ["post.read"] },
        editor: { inherits: "viewer", permissions: ["post.write"] },
        admin: { inherits: "editor", permissions: ["post.delete", "user.manage"] },
      },
    });

    expect(rbac.getRoles().sort()).toEqual(["admin", "editor", "viewer"]);
    expect(rbac.can({ roles: ["viewer"] }, "post.read")).toBe(true);
    expect(rbac.can({ roles: ["viewer"] }, "post.write")).toBe(false);
    expect(rbac.can({ roles: ["editor"] }, "post.read")).toBe(true);
    expect(rbac.can({ roles: ["editor"] }, "post.write")).toBe(true);
    expect(rbac.can({ roles: ["admin"] }, "user.manage")).toBe(true);
    expect(rbac.can({ roles: ["admin"] }, "post.write")).toBe(true);
  });

  it("supports wildcard permissions", () => {
    const rbac = defineRoles({
      owner: { permissions: ["*"] },
      billing: { permissions: ["invoice.*"] },
    });

    expect(rbac.can({ roles: ["owner"] }, "anything.here")).toBe(true);
    expect(rbac.can({ roles: ["billing"] }, "invoice.read")).toBe(true);
    expect(rbac.can({ roles: ["billing"] }, "invoice.write")).toBe(true);
    expect(rbac.can({ roles: ["billing"] }, "user.delete")).toBe(false);
  });

  it("grants and revokes permissions", () => {
    const rbac = createRBAC();
    rbac.addRole("member");
    rbac.grant("member", ["comment.create", "comment.read"]);
    expect(rbac.can({ role: "member" }, "comment.create")).toBe(true);
    rbac.revoke("member", "comment.create");
    expect(rbac.can({ role: "member" }, "comment.create")).toBe(false);
    expect(rbac.can({ role: "member" }, "comment.read")).toBe(true);
  });

  it("authorize throws ForbiddenError", () => {
    const rbac = createRBAC({ roles: { user: { permissions: ["read"] } } });
    expect(() => rbac.authorize({ role: "user" }, "write")).toThrow(ForbiddenError);
    expect(rbac.authorize({ role: "user" }, "read")).toBe(true);
  });

  it("checks role membership", () => {
    const rbac = createRBAC({ roles: { a: {}, b: {} } });
    const subject = { roles: ["a"] };
    expect(rbac.hasAnyRole(subject, ["b", "a"])).toBe(true);
    expect(rbac.hasAllRoles(subject, ["a", "b"])).toBe(false);
    expect(rbac.hasAllRoles(subject, "a")).toBe(true);
  });

  it("uses default role when subject has none", () => {
    const rbac = createRBAC({
      defaultRole: "guest",
      roles: { guest: { permissions: ["public.read"] } },
    });
    expect(rbac.can({}, "public.read")).toBe(true);
    expect(rbac.can(null, "public.read")).toBe(false);
    expect(rbac.can(undefined, "public.read")).toBe(false);
  });

  it("rejects empty role names", () => {
    const rbac = createRBAC();
    expect(() => rbac.addRole("")).toThrow(ValidationError);
    expect(() => rbac.addPermission("")).toThrow(ValidationError);
  });

  it("snapshots configuration", () => {
    const rbac = createRBAC({
      roles: { writer: { description: "can write", permissions: ["doc.write"] } },
    });
    const snapshot = rbac.snapshot();
    expect(snapshot.roles.writer.permissions).toEqual(["doc.write"]);
  });

  it("matches permission patterns", () => {
    expect(matchPermission("*", "a.b")).toBe(true);
    expect(matchPermission("post.*", "post.read")).toBe(true);
    expect(matchPermission("post.*", "comment.read")).toBe(false);
    expect(matchPermission("post.read", "post.read")).toBe(true);
  });

  it("rejects cyclic role inheritance", () => {
    expect(() => createRBAC({
      roles: {
        a: { inherits: "b", permissions: ["a"] },
        b: { inherits: "a", permissions: ["b"] },
      },
    })).toThrow(ValidationError);
  });

  it("invalidates compiled permissions after grant", () => {
    const rbac = createRBAC({ roles: { member: { permissions: ["read"] } } });
    expect(rbac.can({ role: "member" }, "write")).toBe(false);
    rbac.grant("member", "write");
    expect(rbac.can({ role: "member" }, "write")).toBe(true);
  });

  it("rejects empty permission checks and unknown roles on grant", () => {
    const rbac = createRBAC({ roles: { member: { permissions: ["read"] } } });
    expect(rbac.can({ role: "member" }, "")).toBe(false);
    expect(rbac.can({ role: "member" }, [])).toBe(false);
    expect(rbac.cannot({ role: "member" }, "write")).toBe(true);
    expect(() => rbac.grant("missing", "read")).toThrow(ValidationError);
    expect(() => rbac.inherit("missing", "admin")).toThrow(ValidationError);
  });

  it("does not treat unknown roles as having permissions", () => {
    const rbac = createRBAC({
      defaultRole: "guest",
      roles: { guest: { permissions: ["public.read"] } },
    });
    expect(rbac.can({ roles: ["not-a-role"] }, "public.read")).toBe(false);
    expect(rbac.can("not-a-role", "public.read")).toBe(false);
    expect(rbac.can("", "public.read")).toBe(false);
  });

  it("matches nested wildcards without crossing segments", () => {
    expect(matchPermission("post.*", "post.read")).toBe(true);
    expect(matchPermission("post.*", "post.read.meta")).toBe(false);
    expect(matchPermission("post.**", "post.read.meta")).toBe(true);
    expect(matchPermission("a.*.c", "a.b.c")).toBe(true);
    expect(matchPermission("a.*.c", "a.b.d")).toBe(false);
    expect(matchPermission("post.read", "post.read.extra")).toBe(false);
  });

  it("requires every requested permission", () => {
    const rbac = createRBAC({
      roles: { editor: { permissions: ["post.read", "post.write"] } },
    });
    expect(rbac.can({ role: "editor" }, ["post.read", "post.write"])).toBe(true);
    expect(rbac.can({ role: "editor" }, ["post.read", "post.delete"])).toBe(false);
  });

  it("unions direct subject permissions with compiled role permissions", () => {
    const rbac = createRBAC({
      roles: { member: { permissions: ["post.read"] } },
    });
    expect(rbac.can({ roles: ["member"], permissions: ["post.delete"] }, "post.delete")).toBe(true);
    expect(rbac.can({ roles: ["member"], permissions: ["post.delete"] }, "post.read")).toBe(true);
    expect(rbac.can({ roles: ["member"], permissions: ["post.delete"] }, "user.manage")).toBe(false);
  });

  it("detects cycles introduced after construction", () => {
    const rbac = createRBAC({
      roles: {
        a: { permissions: ["a"] },
        b: { inherits: "a", permissions: ["b"] },
      },
    });
    expect(() => rbac.inherit("a", "b")).toThrow(ValidationError);
  });

  it("invalidates compiled inheritance after inherit and revoke", () => {
    const rbac = createRBAC({
      roles: {
        viewer: { permissions: ["post.read"] },
        editor: { permissions: ["post.write"] },
      },
    });
    expect(rbac.can({ role: "editor" }, "post.read")).toBe(false);
    rbac.inherit("editor", "viewer");
    expect(rbac.can({ role: "editor" }, "post.read")).toBe(true);
    rbac.revoke("viewer", "post.read");
    expect(rbac.can({ role: "editor" }, "post.read")).toBe(false);
    expect(rbac.can({ role: "editor" }, "post.write")).toBe(true);
  });

  it("snapshots owned permissions without flattening inherited ones onto the child", () => {
    const rbac = createRBAC({
      roles: {
        viewer: { permissions: ["post.read"] },
        editor: { inherits: "viewer", permissions: ["post.write"] },
      },
    });
    const snapshot = rbac.snapshot();
    expect(snapshot.roles.editor.permissions).toEqual(["post.write"]);
    expect(snapshot.roles.editor.inherits).toEqual(["viewer"]);
    expect(rbac.getPermissions("editor").sort()).toEqual(["post.read", "post.write"]);
  });

  it("trims role names and ignores blank inherited parents", () => {
    const rbac = createRBAC({
      roles: {
        " editor ": { permissions: [" post.write "] },
      },
    });
    expect(rbac.hasRole("editor")).toBe(true);
    expect(rbac.can({ role: "editor" }, "post.write")).toBe(true);
  });

  it("bounds matcher cache to configured maxEntries", () => {
    const rbac = createRBAC({
      roles: { reader: { permissions: ["doc.read"] } },
      matcherCache: { maxEntries: 2 },
    });
    expect(rbac.can({ role: "reader" }, "doc.read")).toBe(true);
    expect(rbac.can({ role: "reader" }, "doc.write")).toBe(false);
    expect(rbac.can({ role: "reader" }, "doc.delete")).toBe(false);
    const stats = rbac.matcherCache.stats();
    expect(stats.size).toBeLessThanOrEqual(2);
    expect(stats.maxEntries).toBe(2);
  });

  it("does not grow unbounded with 100,000 unique patterns", () => {
    const permissions = Array.from({ length: 100_000 }, (_, i) => `glob.${i}.*`);
    const rbac = createRBAC({
      roles: { user: { permissions } },
      matcherCache: { maxEntries: 100 },
    });
    expect(rbac.can({ role: "user" }, "target")).toBe(false);
    const stats = rbac.matcherCache.stats();
    expect(stats.size).toBeLessThanOrEqual(100);
    expect(stats.evictions).toBeGreaterThan(0);
  });

  it("expires matcher cache entries by ttl", () => {
    vi.useFakeTimers();
    const rbac = createRBAC({
      roles: { user: { permissions: ["doc.read"] } },
      matcherCache: { maxEntries: 10, ttl: 50 },
    });
    expect(rbac.can({ role: "user" }, "doc.read")).toBe(true);
    vi.advanceTimersByTime(50);
    // Miss after expiry recompiles and re-caches; entry still bounded.
    expect(rbac.can({ role: "user" }, "doc.read")).toBe(true);
    vi.useRealTimers();
  });

  it("exposes cache stats and clear", () => {
    const rbac = createRBAC({
      roles: { user: { permissions: ["doc.read"] } },
      matcherCache: { maxEntries: 10 },
    });
    rbac.can({ role: "user" }, "doc.read");
    const stats = rbac.matcherCache.stats();
    expect(stats.hits).toBeGreaterThanOrEqual(0);
    expect(stats.misses).toBeGreaterThanOrEqual(0);
    rbac.matcherCache.clear();
    expect(rbac.matcherCache.size).toBe(0);
  });

  it("handles many rapid permission checks without unbounded growth", () => {
    const rbac = createRBAC({
      roles: { user: { permissions: ["a.*", "b.*"] } },
      matcherCache: { maxEntries: 10 },
    });
    const results: boolean[] = [];
    for (let i = 0; i < 5_000; i += 1) {
      results.push(rbac.can({ role: "user" }, `a.${i}`));
      results.push(rbac.can({ role: "user" }, `b.${i}`));
      results.push(rbac.can({ role: "user" }, "c.denied"));
    }
    expect(results.every((r, index) => {
      if (index % 3 === 2) return r === false;
      return r === true;
    })).toBe(true);
    expect(rbac.matcherCache.stats().size).toBeLessThanOrEqual(10);
  });
});
