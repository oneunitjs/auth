 
import { describe, it, expect, afterEach } from "vitest";
import {
  hashPassword,
  verifyPassword,
  needsRehash,
  hashScryptPassword,
  verifyScryptPassword,
  scryptNeedsRehash,
  ScryptPasswordHasher,
  Argon2idPasswordHasher,
  BcryptPasswordHasher,
  CompositePasswordHasher,
  createPasswordHasher,
  getDefaultPasswordHasher,
  setDefaultPasswordHasher,
  ARGON2ID_RECOMMENDED_PROFILE,
  ValidationError,
  ConfigurationError,
} from "../../src/index.js";

const originalHasher = getDefaultPasswordHasher();

afterEach(() => {
  setDefaultPasswordHasher(originalHasher);
});

describe("password hashing (real)", () => {
  it("hashes and verifies passwords with Argon2id by default", async () => {
    const hash = await hashPassword("correct horse battery staple");
    expect(hash).toMatch(/^\$argon2id\$v=19\$m=65536,t=3,p=1\$/);
    expect(await verifyPassword("correct horse battery staple", hash)).toBe(true);
    expect(await verifyPassword("wrong-password", hash)).toBe(false);
  });

  it("uses a unique salt for each hash of the same password", async () => {
    const first = await hashPassword("same-password");
    const second = await hashPassword("same-password");
    expect(first).not.toBe(second);
    expect(await verifyPassword("same-password", first)).toBe(true);
    expect(await verifyPassword("same-password", second)).toBe(true);
  });

  it("verifies unicode passwords", async () => {
    const password = "pässwörd-東京";
    const hash = await hashPassword(password);
    expect(await verifyPassword(password, hash)).toBe(true);
    expect(await verifyPassword("passwörd-東京", hash)).toBe(false);
  });

  it("verifies existing scrypt hashes through the default composite hasher", async () => {
    const hash = await hashScryptPassword("secret", { cost: 16384 });
    expect(hash).toMatch(/^scrypt\$/);
    expect(await verifyPassword("secret", hash)).toBe(true);
    expect(await verifyPassword("wrong", hash)).toBe(false);
    expect(await verifyScryptPassword("secret", hash)).toBe(true);
    expect(needsRehash(hash)).toBe(true);
    expect(scryptNeedsRehash(hash, { cost: 16384 })).toBe(false);
    expect(scryptNeedsRehash(hash, { cost: 32768 })).toBe(true);
  });

  it("creates scrypt hashes only when explicitly requested", async () => {
    const hash = await hashPassword("secret", { algorithm: "scrypt", cost: 16384 });
    expect(hash).toMatch(/^scrypt\$/);
    expect(await verifyPassword("secret", hash)).toBe(true);
  });
});

describe("password hashing (edge)", () => {
  it("rejects empty and non-string passwords", async () => {
    await expect(hashPassword("")).rejects.toThrow(ValidationError);
    await expect(hashPassword(null as unknown as string)).rejects.toThrow(ValidationError);
    await expect(hashPassword(undefined as unknown as string)).rejects.toThrow(ValidationError);
  });

  it("hashes whitespace-only passwords because they are non-empty strings", async () => {
    const hash = await hashPassword("   ");
    expect(await verifyPassword("   ", hash)).toBe(true);
    expect(await verifyPassword("", hash)).toBe(false);
  });

  it("returns false for malformed, truncated, and overlong hashes", async () => {
    expect(await verifyPassword("secret", "not-a-hash")).toBe(false);
    expect(await verifyPassword("secret", null as unknown as string)).toBe(false);
    expect(await verifyPassword("secret", "$argon2id$v=19$m=4096,t=3,p=1$abc")).toBe(false);
    expect(await verifyPassword("secret", "$argon2i$v=19$m=4096,t=3,p=1$YWFhYWFhYWE$YWFhYWFhYWFhYWFhYWFhYQ")).toBe(false);
    expect(await verifyPassword("secret", "$argon2id$v=18$m=4096,t=3,p=1$YWFhYWFhYWFhYWFhYWFhYQ$YWFhYWFhYWFhYWFhYWFhYQ")).toBe(false);
    expect(await verifyPassword("secret", "x".repeat(600))).toBe(false);
  });

  it("treats duplicate or out-of-range argon2id parameters as malformed", async () => {
    const duplicate = "$argon2id$v=19$m=4096,t=3,p=1,m=8$YWFhYWFhYWFhYWFhYWFhYQ$YWFhYWFhYWFhYWFhYWFhYQ";
    const tinyMemory = "$argon2id$v=19$m=1,t=3,p=1$YWFhYWFhYWFhYWFhYWFhYQ$YWFhYWFhYWFhYWFhYWFhYQ";
    expect(await verifyPassword("secret", duplicate)).toBe(false);
    expect(await verifyPassword("secret", tinyMemory)).toBe(false);
    expect(needsRehash(duplicate)).toBe(true);
  });

  it("rejects argon2id hashes above the verification budget without hashing", async () => {
    const highMemory = "$argon2id$v=19$m=131072,t=3,p=1$YWFhYWFhYWFhYWFhYWFhYQ$YWFhYWFhYWFhYWFhYWFhYQ";
    const highIterations = "$argon2id$v=19$m=4096,t=16,p=1$YWFhYWFhYWFhYWFhYWFhYQ$YWFhYWFhYWFhYWFhYWFhYQ";
    const highParallelism = "$argon2id$v=19$m=4096,t=3,p=16$YWFhYWFhYWFhYWFhYWFhYQ$YWFhYWFhYWFhYWFhYWFhYQ";
    expect(await verifyPassword("secret", highMemory)).toBe(false);
    expect(await verifyPassword("secret", highIterations)).toBe(false);
    expect(await verifyPassword("secret", highParallelism)).toBe(false);
  });

  it("rejects argon2id parameters outside policy bounds", async () => {
    const hasher = new Argon2idPasswordHasher();
    await expect(hasher.hash("secret", { memoryKiB: 1 })).rejects.toThrow(ValidationError);
    await expect(hasher.hash("secret", { iterations: 0 })).rejects.toThrow(ValidationError);
    await expect(hasher.hash("secret", { parallelism: 99 })).rejects.toThrow(ValidationError);
    await expect(hasher.hash("secret", { saltBytes: 2 })).rejects.toThrow(ValidationError);
    await expect(hasher.hash("secret", { keyLength: 4 })).rejects.toThrow(ValidationError);
  });

  it("rejects bcrypt passwords over 72 bytes and rounds outside [10, 14]", async () => {
    const binding = {
      async hash() {
        return "$2b$12$aaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
      },
      async compare() {
        return true;
      },
    };
    expect(() => new BcryptPasswordHasher(binding, 9)).toThrow(ValidationError);
    expect(() => new BcryptPasswordHasher(binding, 15)).toThrow(ValidationError);
    const hasher = new BcryptPasswordHasher(binding, 12);
    await expect(hasher.hash("x".repeat(73))).rejects.toThrow(ValidationError);
    expect(await hasher.verify("x".repeat(73), "$2b$12$aaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")).toBe(false);
    expect(await hasher.verify("secret", "$2b$15$aaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")).toBe(false);
  });
});

describe("password hashing (behavior)", () => {
  it("detects when an argon2id hash needs rehashing under a stricter policy", async () => {
    const hasher = new Argon2idPasswordHasher({ memoryKiB: 4096, iterations: 3 });
    const hash = await hasher.hash("secret");
    expect(hasher.needsRehash(hash)).toBe(false);
    expect(hasher.needsRehash(hash, { memoryKiB: 8192 })).toBe(true);
    expect(hasher.needsRehash(hash, { iterations: 4 })).toBe(true);
    expect(needsRehash("bcrypt$thing")).toBe(true);
  });

  it("does not verify an unknown algorithm and does not invent a hasher", async () => {
    const hasher = new CompositePasswordHasher({
      preferred: new ScryptPasswordHasher(),
    });
    const argon = await new Argon2idPasswordHasher().hash("secret");
    expect(await hasher.verify("secret", argon)).toBe(true);
    expect(await hasher.verify("secret", "not-a-hash")).toBe(false);
    expect(hasher.needsRehash(argon)).toBe(true);
  });

  it("refuses bcrypt hashing unless a binding is configured", async () => {
    const hasher = createPasswordHasher();
    expect(() => hasher.hash("secret", { algorithm: "bcrypt" })).toThrow(ConfigurationError);
    expect(await hasher.verify("secret", "$2b$12$aaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")).toBe(false);
  });

  it("dispatches bcrypt hashes only to the bcrypt verifier", async () => {
    const seen: string[] = [];
    const binding = {
      async hash(password: string, rounds: number) {
        seen.push(`hash:${rounds}`);
        return `$2b$${String(rounds).padStart(2, "0")}$aaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`;
      },
      async compare(password: string, hash: string) {
        seen.push("compare");
        return password === "secret" && hash.startsWith("$2b$12$");
      },
    };
    const bcrypt = new BcryptPasswordHasher(binding, 12);
    const hasher = new CompositePasswordHasher({ bcrypt });
    const hash = await hasher.hash("secret", { algorithm: "bcrypt" });
    expect(hash.startsWith("$2b$12$")).toBe(true);
    expect(await hasher.verify("secret", hash)).toBe(true);
    expect(await hasher.verify("wrong", hash)).toBe(false);
    expect(bcrypt.needsRehash(hash)).toBe(false);
    expect(bcrypt.needsRehash(hash.replace("$2b$12$", "$2b$10$"))).toBe(true);
    expect(hasher.needsRehash(hash)).toBe(true);
    expect(seen).toContain("hash:12");
    expect(seen).toContain("compare");
  });

  it("honors a process-wide default hasher replacement", async () => {
    const scrypt = new ScryptPasswordHasher();
    setDefaultPasswordHasher(scrypt);
    const hash = await hashPassword("secret", { cost: 16384 });
    expect(hash).toMatch(/^scrypt\$/);
    expect(await verifyPassword("secret", hash)).toBe(true);
    expect(getDefaultPasswordHasher()).toBe(scrypt);
  });

  it("advertises the recommended argon2id profile separately from the test default", () => {
    expect(ARGON2ID_RECOMMENDED_PROFILE.memoryKiB).toBe(65_536);
    expect(ARGON2ID_RECOMMENDED_PROFILE.iterations).toBe(3);
    expect(ARGON2ID_RECOMMENDED_PROFILE.parallelism).toBe(1);
  });
});
