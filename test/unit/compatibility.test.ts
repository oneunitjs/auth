import { describe, it, expect } from "vitest";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

describe("module compatibility", () => {
  it("loads the ESM distribution", async () => {
    // @ts-expect-error -- built dist ships declarations in dist/types, not co-located
    const esm = await import("../../dist/esm/index.js");
    expect(typeof esm.createAuth).toBe("function");
    expect(typeof esm.RBAC).toBe("function");
    expect(typeof esm.matchPermission).toBe("function");
    expect(typeof esm.CacheProvider).toBe("function");
    expect(typeof esm.SharedJwksCache).toBe("function");
  });

  it("loads the CommonJS distribution via require", () => {
    const cjs = require("../../dist/cjs/index.cjs");
    expect(typeof cjs.createAuth).toBe("function");
    expect(typeof cjs.RBAC).toBe("function");
    expect(typeof cjs.matchPermission).toBe("function");
    expect(typeof cjs.CacheProvider).toBe("function");
    expect(typeof cjs.SharedJwksCache).toBe("function");
  });

  it("loads ESM subpath exports", async () => {
    // @ts-expect-error -- built dist ships declarations in dist/types, not co-located
    const rbac = await import("../../dist/esm/rbac/index.js");
    expect(typeof rbac.createRBAC).toBe("function");
  });

  it("loads CommonJS subpath exports via require", () => {
    const rbac = require("../../dist/cjs/rbac/index.cjs");
    expect(typeof rbac.createRBAC).toBe("function");
  });

  it("ESM and CJS expose the same public API surface", async () => {
    // @ts-expect-error -- built dist ships declarations in dist/types, not co-located
    const esm = await import("../../dist/esm/index.js");
    const cjs = require("../../dist/cjs/index.cjs");
    const esmKeys = Object.keys(esm).sort();
    const cjsKeys = Object.keys(cjs).sort();
    expect(cjsKeys).toEqual(esmKeys);
  });
});
