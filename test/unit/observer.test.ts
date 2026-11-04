 
import { describe, it, expect } from "vitest";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

const scriptUrl = new URL("../../scripts/watch-google-jwks.mjs", import.meta.url);
const hasScript = existsSync(fileURLToPath(scriptUrl));

describe.skipIf(!hasScript)("Google JWKS observer utilities", async () => {
  const observer = hasScript ? await import("../../scripts/watch-google-jwks.mjs" as any) : null;
  if (!observer) {
    return;
  }

  it("normalizes keys and computes a stable fingerprint", () => {
    const first = observer.normalizeKeys({
      keys: [{ kid: "b", kty: "RSA", alg: "RS256", n: "abc", e: "AQAB" }],
    });
    const second = observer.normalizeKeys({
      keys: [{ kid: "b", kty: "RSA", alg: "RS256", n: "abc", e: "AQAB" }],
    });

    expect(first.length).toBe(1);
    expect(first[0].kid).toBe("b");
    expect(first[0].fingerprint).toBe(second[0].fingerprint);
  });

  it("detects added, removed, and changed kids", () => {
    const oldKeys = [
      { kid: "a", fingerprint: "1" },
      { kid: "b", fingerprint: "2" },
    ];
    const newKeys = [
      { kid: "b", fingerprint: "changed" },
      { kid: "c", fingerprint: "3" },
    ];

    const changes = observer.compareKeys(oldKeys, newKeys);

    expect(changes.added.map((key: { kid: string }) => key.kid)).toEqual(["c"]);
    expect(changes.removed.map((key: { kid: string }) => key.kid)).toEqual(["a"]);
    expect(changes.changed.map((key: { kid: string }) => key.kid)).toEqual(["b"]);
  });

  it("decodes a JWT header without validating the token", () => {
    const header = Buffer.from(
      JSON.stringify({ kid: "test-kid", alg: "RS256", typ: "JWT" }),
    ).toString("base64url");
    const token = `${header}.payload.signature`;

    expect(observer.inspectTokenHeader(token)).toEqual({
      kid: "test-kid",
      alg: "RS256",
      typ: "JWT",
    });
  });

  it("validates positive integer parsing", () => {
    expect(observer.parsePositiveInteger("300", 60)).toBe(300);
    expect(() => observer.parsePositiveInteger("0", 60)).toThrow();
    expect(() => observer.parsePositiveInteger("abc", 60)).toThrow();
  });
});
