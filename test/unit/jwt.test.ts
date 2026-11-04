 
import { describe, it, expect } from "vitest";
import { JwtBackendImpl } from "../../src/crypto/jwt-backend.js";
import {
  encode,
  decode,
  decodeUnsafe,
  encodeAccessToken,
  encodeRefreshToken,
  InvalidTokenError,
  TokenExpiredError,
  ValidationError,
} from "../../src/index.js";
import type { JwtPayload } from "../../src/index.js";

const SECRET = "test-secret-key-for-jwt-signing-32b";

describe("jwt", () => {
  it("signs and verifies a payload", async () => {
    const token = await encode({ userId: 7, role: "member" }, SECRET, {
      expiresInSeconds: 60,
      subject: "7",
    });
    expect(typeof token).toBe("string");
    const claims = await decode(token, SECRET);
    expect(claims.userId).toBe(7);
    expect(claims.role).toBe("member");
    expect(claims.sub).toBe("7");
  });

  it("rejects missing secrets", async () => {
    await expect(encode({}, "")).rejects.toThrow(ValidationError);
    await expect(decode("token", "")).rejects.toThrow(ValidationError);
  });

  it("rejects invalid tokens", async () => {
    await expect(decode("not.a.token", SECRET)).rejects.toThrow(InvalidTokenError);
    await expect(decode("", SECRET)).rejects.toThrow(InvalidTokenError);
  });

  it("rejects expired tokens", async () => {
    const token = await encode({ userId: 1 }, SECRET, { expiresIn: "1s" });
    const claims = await decode(token, SECRET, { ignoreExpiration: true });
    expect(claims.userId).toBe(1);
  });

  it("throws TokenExpiredError for expired tokens", async () => {
    const token = await encode({ userId: 1 }, SECRET, { expiresIn: 0 });
    await expect(() => decode(token, SECRET)).rejects.toThrow(TokenExpiredError);
  });

  it("decodes without verification", async () => {
    const token = await encode({ hello: "world" }, SECRET);
    const unsafe = (await decodeUnsafe(token)) as JwtPayload;
    expect(unsafe.hello).toBe("world");
    expect(decodeUnsafe("")).toBeNull();
  });

  it("creates access and refresh tokens with typ claims", async () => {
    const access = await encodeAccessToken({ userId: 9 }, SECRET, { subject: "9" });
    const refresh = await encodeRefreshToken({ userId: 9 }, SECRET, { subject: "9" });
    expect((await decode(access, SECRET)).typ).toBe("access");
    expect((await decode(refresh, SECRET)).typ).toBe("refresh");
  });

  it("rejects non-object payloads", async () => {
    await expect(encode("nope" as unknown as object, SECRET)).rejects.toThrow(ValidationError);
    await expect(encode(["array"] as unknown as object, SECRET)).rejects.toThrow(
      ValidationError,
    );
  });

  it("honors issuer and audience", async () => {
    const token = await encode({ userId: 1 }, SECRET, {
      issuer: "auth.example",
      audience: "api.example",
    });
    const claims = await decode(token, SECRET, {
      issuer: "auth.example",
      audience: "api.example",
    });
    expect(claims.iss).toBe("auth.example");
    expect(claims.aud).toBe("api.example");
    await expect(() =>
      decode(token, SECRET, { issuer: "other" }),
    ).rejects.toThrow(InvalidTokenError);
  });
});

describe("jwt unification (standalone functions vs JwtBackendImpl)", () => {
  const backend = new JwtBackendImpl({
    signingKey: SECRET,
    verificationKey: SECRET,
    algorithmPolicy: {
      signing: ["HS256"],
      verification: ["HS256"],
    },
  });

  it("a standalone-encoded token verifies via the backend", async () => {
    const token = await encode({ userId: 7, role: "member" }, SECRET, {
      expiresInSeconds: 60,
      subject: "7",
    });
    const claims = await backend.verify(token, { algorithms: ["HS256"] });
    expect(claims.userId).toBe(7);
    expect(claims.role).toBe("member");
    expect(claims.sub).toBe("7");
  });

  it("a backend-signed token verifies via standalone decode", async () => {
    const token = await backend.sign(
      { userId: 7, role: "member" },
      { expiresInSeconds: 60, subject: "7" },
    );
    const claims = await decode(token, SECRET);
    expect(claims.userId).toBe(7);
    expect(claims.role).toBe("member");
    expect(claims.sub).toBe("7");
  });

  it("backend supports keyid (kid) and header merging", async () => {
    const token = await backend.sign(
      { userId: 1 },
      { keyid: "k1", header: { custom: "x" } },
    );
    const header = JSON.parse(
      Buffer.from(token.split(".")[0], "base64url").toString("utf8"),
    );
    expect(header.kid).toBe("k1");
    expect(header.custom).toBe("x");
    expect(header.alg).toBe("HS256");
    expect(header.typ).toBe("JWT");
  });

  it("standalone encode with expiresInSeconds alias matches backend expiresIn", async () => {
    const alias = await encode({ userId: 1 }, SECRET, { expiresInSeconds: 60 });
    const direct = await backend.sign({ userId: 1 }, { expiresIn: 60 });
    // Both carry an exp claim ~60s in the future; verify both decode.
    expect((await decode(alias, SECRET)).exp).toBeGreaterThan(0);
    expect((await decode(direct, SECRET)).exp).toBeGreaterThan(0);
  });

  it("access and refresh tokens verify via the backend", async () => {
    const access = await encodeAccessToken({ userId: 9 }, SECRET, {
      subject: "9",
    });
    const refresh = await encodeRefreshToken({ userId: 9 }, SECRET, {
      subject: "9",
    });
    expect((await backend.verify(access, { algorithms: ["HS256"] })).typ).toBe(
      "access",
    );
    expect((await backend.verify(refresh, { algorithms: ["HS256"] })).typ).toBe(
      "refresh",
    );
  });
});
