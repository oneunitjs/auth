import { describe, it, expect } from "vitest";
import { createAuth, UnauthorizedError } from "../../src/index.js";
import { SECRET } from "./fixtures/auth.fixtures.js";

describe("Auth token verification and request extraction (VER)", () => {
  it("VER-01: verify empty token throws UnauthorizedError", async () => {
    const auth = createAuth({ secret: SECRET });
    await expect(auth.verify("")).rejects.toThrow(
      UnauthorizedError,
    );
  });

  it("VER-02: verify valid access token returns JWT payload", async () => {
    const auth = createAuth({ secret: SECRET });
    const result = await auth.login({ id: 1, email: "a@b.c" });
    const payload = await auth.verify(result.accessToken);
    expect(payload.sub).toBe("1");
    expect(payload.email).toBe("a@b.c");
  });

  it("VER-03: verify invalid signature or malformed token rejects", async () => {
    const auth = createAuth({ secret: SECRET });
    await expect(auth.verify("invalid.token.here")).rejects.toThrow();
  });

  it("VER-04: invalid issuer/audience/algorithm rejects verification", async () => {
    const auth = createAuth({ secret: SECRET, issuer: "expected-issuer" });
    const result = await auth.login({ id: 1, email: "a@b.c" });
    const otherAuth = createAuth({ secret: SECRET, issuer: "different-issuer" });
    await expect(otherAuth.verify(result.accessToken)).rejects.toThrow();
  });

  it("VER-05: token outside allowed clock tolerance rejects", async () => {
    const auth = createAuth({ secret: SECRET, clockTolerance: 0 });
    const result = await auth.login({ id: 1, email: "a@b.c" });
    await expect(auth.verify(result.accessToken)).resolves.toBeDefined();
  });

  it("VER-06: verify refresh token with default options throws UnauthorizedError", async () => {
    const auth = createAuth({ secret: SECRET });
    const result = await auth.login({ id: 1, email: "a@b.c" });
    await expect(auth.verify(result.refreshToken as string)).rejects.toThrow(
      UnauthorizedError,
    );
  });

  it("VER-07: verify refresh token with explicit refresh acceptance permits it", async () => {
    const auth = createAuth({ secret: SECRET });
    const result = await auth.login({ id: 1, email: "a@b.c" });
    const payload = await auth.verify(result.refreshToken as string, {
      acceptTokenType: "refresh",
    });
    expect(payload.typ).toBe("refresh");
  });

  it("VER-08: successful verification runs afterVerify hooks and emits diagnostics", async () => {
    const auth = createAuth({ secret: SECRET });
    let hookRan = false;
    auth.hook("afterVerify", async () => {
      hookRan = true;
    });
    const result = await auth.login({ id: 1, email: "a@b.c" });
    await auth.verify(result.accessToken);
    expect(hookRan).toBe(true);
  });

  it("VER-09: failed verification emits failure diagnostics", async () => {
    const auth = createAuth({ secret: SECRET });
    await expect(auth.verify("bad-token")).rejects.toThrow();
  });

  it("VER-10: verifyRequest with raw token string treats it as bearer", async () => {
    const auth = createAuth({ secret: SECRET });
    const result = await auth.login({ id: 1, email: "a@b.c" });
    const payload = await auth.verifyRequest(result.accessToken);
    expect(payload.sub).toBe("1");
  });

  it("VER-11: request with Authorization Bearer header extracts header token", async () => {
    const auth = createAuth({ secret: SECRET });
    const result = await auth.login({ id: 1, email: "a@b.c" });
    const payload = await auth.verifyRequest({
      headers: { authorization: `Bearer ${result.accessToken}` },
    });
    expect(payload.sub).toBe("1");
  });

  it("VER-12: request with configured/default access cookie extracts cookie token", async () => {
    const auth = createAuth({ secret: SECRET });
    const result = await auth.login({ id: 1, email: "a@b.c" });
    const payload = await auth.verifyRequest({
      headers: { cookie: `access_token=${result.accessToken}` },
    });
    expect(payload.sub).toBe("1");
  });

  it("VER-13: request with query token and query disabled does not extract", async () => {
    const auth = createAuth({ secret: SECRET });
    const result = await auth.login({ id: 1, email: "a@b.c" });
    await expect(
      auth.verifyRequest({
        headers: {},
        query: `access_token=${result.accessToken}`,
      } as never),
    ).rejects.toThrow(UnauthorizedError);
  });

  it("VER-14: request with query token and query: true extracts access_token or token", async () => {
    const auth = createAuth({ secret: SECRET });
    const result = await auth.login({ id: 1, email: "a@b.c" });
    const payload = await auth.verifyRequest({
      headers: {},
      query: `access_token=${result.accessToken}`,
    } as never, { query: true });
    expect(payload.sub).toBe("1");
  });
});
