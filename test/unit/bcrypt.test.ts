import { describe, it, expect } from "vitest";
import {
  createBcryptPasswordHasher,
  BcryptPasswordHasher,
  BcryptNodeBinding,
  isBcryptAvailable,
} from "../../src/index.js";

describe("bcrypt adapter", () => {
  it("hashes and verifies passwords without a custom binding", async () => {
    const hasher = createBcryptPasswordHasher(10);
    const hash = await hasher.hash("correct horse battery staple");
    expect(hash).toMatch(/^\$2[aby]\$10\$/);
    expect(await hasher.verify("correct horse battery staple", hash)).toBe(true);
    expect(await hasher.verify("wrong-password", hash)).toBe(false);
  });

  it("reports needsRehash when rounds differ", async () => {
    const hasher = createBcryptPasswordHasher(10);
    const hash = await hasher.hash("secret");
    expect(hasher.needsRehash(hash)).toBe(false);
    expect(hasher.needsRehash(hash.replace(/\$2[aby]\$\d{2}\$/, "$2b$13$"))).toBe(true);
  });

  it("rejects empty passwords", async () => {
    const hasher = createBcryptPasswordHasher(10);
    await expect(hasher.hash("")).rejects.toThrow();
  });

  it("works through BcryptPasswordHasher with BcryptNodeBinding", async () => {
    const hasher = new BcryptPasswordHasher(new BcryptNodeBinding(), 10);
    const hash = await hasher.hash("secret");
    expect(await hasher.verify("secret", hash)).toBe(true);
    expect(await hasher.verify("wrong", hash)).toBe(false);
  });

  it("isBcryptAvailable returns a boolean", () => {
    expect(typeof isBcryptAvailable()).toBe("boolean");
  });
});
