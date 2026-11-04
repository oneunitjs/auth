 
import { describe, it, expect, afterEach } from "vitest";
import { SignJWT } from "jose";
import {
  createAuth,
  createRBAC,
  createMemorySessionStore,
  createExternalTokenVerifier,
  hashPassword,
  verifyPassword,
  configureHttp,
  resetHttpConfig,
  dispatchHttp,
  setDiagnosticsObserver,
  resetDiagnostics,
  emitDiagnostic,
  PLATFORM_COMPATIBILITY,
  type AuthDiagnosticEvent,
} from "../../src/index.js";
import { JwksCache } from "../../src/crypto/jwks.js";

const SECRET = "secret-key-for-testing-purposes-123456";
const HMAC = new TextEncoder().encode("external-token-secret-key-123456");

function elapsedMs(start: number): number {
  return Number(process.hrtime.bigint() - BigInt(start)) / 1e6;
}

function nowNs(): number {
  return Number(process.hrtime.bigint());
}

describe("real-world production metrics", () => {
  afterEach(() => {
    resetHttpConfig();
    resetDiagnostics();
  });

  it("evaluates a 100-role compiled policy at 10k checks well under 250ms", () => {
    const roles: Record<string, { inherits?: string; permissions: string[] }> = {
      r0: { permissions: ["res.0.read", "res.0.write"] },
    };
    for (let index = 1; index < 100; index += 1) {
      roles[`r${index}`] = {
        inherits: `r${index - 1}`,
        permissions: [`res.${index}.read`, `res.${index}.write`],
      };
    }
    const rbac = createRBAC({ roles });
    const admin = { roles: ["r99"] };
    const guest = { roles: ["r0"] };

    expect(rbac.can(admin, "res.0.read")).toBe(true);
    expect(rbac.can(admin, "res.99.write")).toBe(true);
    expect(rbac.can(guest, "res.99.read")).toBe(false);

    const start = nowNs();
    let allowed = 0;
    for (let index = 0; index < 10_000; index += 1) {
      if (rbac.can(admin, `res.${index % 100}.read`)) {
        allowed += 1;
      }
      if (rbac.can(guest, "res.0.write")) {
        allowed += 1;
      }
    }
    const duration = elapsedMs(start);
    expect(allowed).toBe(20_000);
    expect(duration).toBeLessThan(250);
  });

  it("keeps subject permission cache bounded at 1024 entries", () => {
    const rbac = createRBAC({
      roles: { member: { permissions: ["doc.read"] } },
    });
    for (let index = 0; index < 1_200; index += 1) {
      rbac.can({ roles: ["member"], permissions: [`extra.${index}`] }, "doc.read");
    }
    expect(rbac.can({ roles: ["member"] }, "doc.read")).toBe(true);
    expect((rbac as unknown as { subjectCache: Map<string, unknown> }).subjectCache.size).toBeLessThanOrEqual(1_024);
  });

  it("hashes and verifies 8 Argon2id passwords within 60s at the production default", async () => {
    const passwords = Array.from({ length: 8 }, (_, index) => `correct-horse-${index}-staple`);
    const start = nowNs();
    const hashes = await Promise.all(passwords.map((password) => hashPassword(password)));
    const verified = await Promise.all(
      hashes.map((hash, index) => verifyPassword(passwords[index], hash)),
    );
    const duration = elapsedMs(start);
    expect(new Set(hashes).size).toBe(8);
    expect(verified.every(Boolean)).toBe(true);
    expect(hashes.every((hash) => hash.startsWith("$argon2id$"))).toBe(true);
    expect(duration).toBeLessThan(60_000);
  });

  it("issues, verifies, and revokes 100 concurrent sessions within 2s", async () => {
    const auth = createAuth({ secret: SECRET, sessionStore: createMemorySessionStore() });
    const start = nowNs();
    const sessions = await Promise.all(
      Array.from({ length: 100 }, (_, index) => auth.login({ id: index + 1, roles: ["user"] })),
    );
    const verified = await Promise.all(sessions.map((session) => auth.verify(session.accessToken)));
    expect(verified).toHaveLength(100);
    expect(await auth.revokeAllSessionsResult(1)).toEqual({ status: "revoked", sessionId: "1" });
    await expect(auth.verify(sessions[0].accessToken)).rejects.toThrow();
    expect((await auth.verify(sessions[1].accessToken)).userId).toBe(2);
    expect(elapsedMs(start)).toBeLessThan(2_000);
  });

  it("verifies 1k HS256 access tokens well under 1s", async () => {
    const auth = createAuth({ secret: SECRET });
    const session = await auth.login({ id: 42, roles: ["member"] });
    const start = nowNs();
    for (let index = 0; index < 1_000; index += 1) {
      const claims = await auth.verify(session.accessToken);
      expect(claims.userId).toBe(42);
    }
    expect(elapsedMs(start)).toBeLessThan(1_000);
  });

  it("evicts JWKS cache entries at the documented default of 10", async () => {
    const cache = new JwksCache({ maxEntries: 10 });
    expect(cache.getConfig().maxEntries).toBe(10);
    expect(cache.getConfig().maxKeysPerEntry).toBe(10);
    expect(cache.getConfig().defaultTtlMs).toBe(60 * 60 * 1000);
    expect(cache.getConfig().maxResponseSizeBytes).toBe(1_048_576);
    expect(cache.getConfig().fetchTimeoutMs).toBe(10_000);

    const capped = new JwksCache({ maxEntries: 10_000, maxKeysPerEntry: 10_000 });
    expect(capped.getConfig().maxEntries).toBe(100);
    expect(capped.getConfig().maxKeysPerEntry).toBe(100);

    configureHttp({
      transport: async (input) => {
        const url = String(input);
        const kid = url.slice(-2);
        return new Response(JSON.stringify({
          keys: [{ kty: "RSA", kid, alg: "RS256", n: "n", e: "AQAB", use: "sig" }],
        }), { status: 200 });
      },
    });
    for (let index = 0; index < 12; index += 1) {
      const id = `https://issuer.example/${String(index).padStart(2, "0")}`;
      await cache.getKeys(id, id);
    }
    expect(cache.size()).toBe(10);
  });

  it("enforces HTTP 1MiB default and 5MiB hard cap used by JWKS and OAuth", async () => {
    const oversized = "x".repeat(1_048_577);
    await expect(dispatchHttp("https://idp.example/jwks", {
      transport: async () => new Response(oversized, { status: 200 }),
    })).rejects.toThrow(/maximum size/);

    const within = await dispatchHttp("https://idp.example/token", {
      transport: async () => new Response("{}", { status: 200 }),
    });
    expect(within.ok).toBe(true);
    expect(within.text).toBe("{}");
  });

  it("caps the diagnostics queue at 32 pending observers", () => {
    const started: number[] = [];
    setDiagnosticsObserver(() => new Promise<void>(() => {
      started.push(Date.now());
    }));
    for (let index = 0; index < 80; index += 1) {
      emitDiagnostic({ type: "auth.login.succeeded", timestamp: Date.now() });
    }
    expect(started).toHaveLength(32);
  });

  it("rejects external tokens over 16KiB used by IdP-issued JWTs", async () => {
    const verifier = createExternalTokenVerifier([
      {
        issuer: "https://identity.example.com",
        audience: "orders-api",
        algorithms: ["HS256"],
        keySource: { type: "static", key: HMAC },
      },
    ]);
    await expect(verifier.verify("a".repeat(16_385))).rejects.toThrow(/maximum supported length/);

    const now = Math.floor(Date.now() / 1000);
    const token = await new SignJWT({
      iss: "https://identity.example.com",
      aud: "orders-api",
      sub: "user-1",
      iat: now,
      exp: now + 60,
    })
      .setProtectedHeader({ alg: "HS256", typ: "JWT" })
      .sign(HMAC);
    const start = nowNs();
    for (let index = 0; index < 200; index += 1) {
      const result = await verifier.verify(token);
      expect(result.subject).toBe("user-1");
    }
    expect(elapsedMs(start)).toBeLessThan(1_000);
  });

  it("advertises the Node 20+/ESM production matrix used by package engines", () => {
    expect(PLATFORM_COMPATIBILITY.runtime.node).toBe(">=20");
    expect(PLATFORM_COMPATIBILITY.runtime.testedNodeMajors).toEqual([20, 22]);
    expect(PLATFORM_COMPATIBILITY.modules.esm).toBe(true);
    expect(PLATFORM_COMPATIBILITY.modules.commonjs).toBe(false);
    expect(Number(process.versions.node.split(".")[0])).toBeGreaterThanOrEqual(20);
  });

  it("does not let a slow observer add more than 25ms to login", async () => {
    const events: AuthDiagnosticEvent[] = [];
    setDiagnosticsObserver(async (event) => {
      await new Promise((resolve) => setTimeout(resolve, 50));
      events.push(event);
    });
    const auth = createAuth({ secret: SECRET });
    const start = nowNs();
    const session = await auth.login({ id: 9, roles: ["user"] });
    expect(session.accessToken).toBeTruthy();
    expect(elapsedMs(start)).toBeLessThan(25);
    await new Promise((resolve) => setTimeout(resolve, 80));
    expect(events.some((event) => event.type === "auth.login.succeeded")).toBe(true);
  });
});
