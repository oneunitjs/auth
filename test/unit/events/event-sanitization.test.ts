import { describe, it, expect } from "vitest";
import {
  sanitizeEventPayload,
  PROHIBITED_KEYS,
  MAX_STRING_LENGTH,
} from "../../../src/index.js";

describe("event sanitization", () => {
  it("passes through safe values unchanged", () => {
    const result = sanitizeEventPayload({ userId: 1, name: "alice" });
    expect(result).toEqual({ userId: 1, name: "alice" });
  });

  it("removes prohibited keys", () => {
    const result = sanitizeEventPayload({
      userId: 1,
      password: "secret123",
      passwordHash: "hash",
      secret: "my-secret",
    });
    expect(result).not.toHaveProperty("password");
    expect(result).not.toHaveProperty("passwordHash");
    expect(result).not.toHaveProperty("secret");
    expect(result).toHaveProperty("userId", 1);
  });

  it("removes prohibited keys case-insensitively", () => {
    const result = sanitizeEventPayload({
      Password: "secret123",
      SECRET: "my-secret",
      AccessToken: "token",
    });
    expect(result).not.toHaveProperty("Password");
    expect(result).not.toHaveProperty("SECRET");
    expect(result).not.toHaveProperty("AccessToken");
  });

  it("bounds string lengths", () => {
    const longString = "x".repeat(1000);
    const result = sanitizeEventPayload({ name: longString });
    expect((result as { name: string }).name).toHaveLength(MAX_STRING_LENGTH);
  });

  it("handles nested objects", () => {
    const result = sanitizeEventPayload({
      user: { id: 1, password: "secret", name: "alice" },
    });
    const nested = result as { user: { id: number; name: string } };
    expect(nested.user.id).toBe(1);
    expect(nested.user.name).toBe("alice");
    expect(nested.user).not.toHaveProperty("password");
  });

  it("handles arrays", () => {
    const result = sanitizeEventPayload({
      tags: ["alpha", "beta", "gamma"],
    });
    expect(result).toEqual({ tags: ["alpha", "beta", "gamma"] });
  });

  it("handles null and undefined values", () => {
    const result = sanitizeEventPayload({
      name: null,
      age: undefined,
    });
    expect(result).toEqual({ name: null, age: undefined });
  });

  it("exposes prohibited keys list", () => {
    expect(PROHIBITED_KEYS.has("password")).toBe(true);
    expect(PROHIBITED_KEYS.has("token")).toBe(true);
    expect(PROHIBITED_KEYS.has("safeKey")).toBe(false);
  });

  it("allows custom prohibited keys", () => {
    const result = sanitizeEventPayload({
      userId: 1,
      internalId: "internal",
    }, { prohibitedKeys: new Set(["internalId"]) });
    expect(result).toHaveProperty("userId", 1);
    expect(result).not.toHaveProperty("internalId");
  });
});
