 
import { describe, it, expect } from "vitest";
import { PLATFORM_COMPATIBILITY } from "../../src/index.js";
import { readFileSync } from "node:fs";

describe("platform compatibility", () => {
  it("advertises the verified Node and module matrix", () => {
    const packageJson = JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8")) as {
      type: string;
      engines: { node: string };
    };
    expect(PLATFORM_COMPATIBILITY.runtime.node).toBe(">=20");
    expect(PLATFORM_COMPATIBILITY.modules.esm).toBe(true);
    expect(PLATFORM_COMPATIBILITY.modules.commonjs).toBe(false);
    expect(packageJson.type).toBe("module");
    expect(packageJson.engines.node).toBe(">=20");
  });

  it("is frozen and documents ESM-primary/CommonJS-compatible consumption", () => {
    expect(Object.isFrozen(PLATFORM_COMPATIBILITY)).toBe(true);
    expect(PLATFORM_COMPATIBILITY.runtime.browser).toBe(false);
    expect(PLATFORM_COMPATIBILITY.runtime.edge).toBe(false);
    expect(PLATFORM_COMPATIBILITY.runtime.testedNodeMajors).toEqual([20, 22]);
    expect(PLATFORM_COMPATIBILITY.modules.type).toBe("module");
    expect(PLATFORM_COMPATIBILITY.typescript.minimum).toBe("5.0");
    expect(PLATFORM_COMPATIBILITY.notes.some((note) => note.includes("CommonJS builds are also published"))).toBe(true);
    expect(PLATFORM_COMPATIBILITY.notes.some((note) => note.includes("Argon2id"))).toBe(true);
  });
});
