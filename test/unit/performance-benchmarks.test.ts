import { describe, it, expect, afterEach } from "vitest";
import {
  createAuth,
  createRBAC,
  hashPassword,
  verifyPassword,
  configureHttp,
  resetHttpConfig,
  dispatchHttp,
  createOAuth,
  createMemorySessionStore,
} from "../../src/index.js";
import { JwksCache } from "../../src/crypto/jwks.js";

const SECRET = "secret-key-for-benchmarking-purposes-1234567890";

function nowNs(): number {
  return Number(process.hrtime.bigint());
}

function elapsedMs(start: number): number {
  return Number(process.hrtime.bigint() - BigInt(start)) / 1e6;
}

function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const rank = (p / 100) * (sorted.length - 1);
  const lower = Math.floor(rank);
  const upper = Math.ceil(rank);
  if (lower === upper) return sorted[lower];
  const frac = rank - lower;
  return sorted[lower] * (1 - frac) + sorted[upper] * frac;
}

function stats(label: string, durations: number[]): void {
  const sorted = [...durations].sort((a, b) => a - b);
  const mean =
    durations.reduce((a, b) => a + b, 0) / Math.max(1, durations.length);
  const used = process.memoryUsage();
  console.log(
    `${label}: n=${durations.length} mean=${mean.toFixed(2)}ms p50=${percentile(
      sorted,
      50,
    ).toFixed(2)}ms p95=${percentile(sorted, 95).toFixed(2)}ms p99=${percentile(
      sorted,
      99,
    ).toFixed(2)}ms max=${sorted[sorted.length - 1].toFixed(2)}ms heap=${(used.heapUsed / 1e6).toFixed(1)}MB rss=${(used.rss / 1e6).toFixed(1)}MB`,
  );
}

describe("production performance benchmarks (PERF)", () => {
  afterEach(() => {
    resetHttpConfig();
  });

  it("PERF-01: password hash and verification latency", async () => {
    const password = "correct-horse-battery-staple";
    const hashDurations: number[] = [];
    const verifyDurations: number[] = [];

    for (let i = 0; i < 8; i += 1) {
      const hs = nowNs();
      const hash = await hashPassword(password);
      hashDurations.push(elapsedMs(hs));

      const vs = nowNs();
      await verifyPassword(password, hash);
      verifyDurations.push(elapsedMs(vs));
    }

    stats("password hash", hashDurations);
    stats("password verify", verifyDurations);

    const hashP99 = percentile(
      hashDurations.sort((a, b) => a - b),
      99,
    );
    const verifyP99 = percentile(
      verifyDurations.sort((a, b) => a - b),
      99,
    );
    expect(hashP99).toBeLessThan(30_000);
    expect(verifyP99).toBeLessThan(30_000);
  });

  it("PERF-02: JWT sign and verify latency", async () => {
    const auth = createAuth({ secret: SECRET });
    const session = await auth.login({ id: 1, roles: ["member"] });
    const token = session.accessToken;

    const signDurations: number[] = [];
    const verifyDurations: number[] = [];

    for (let i = 0; i < 100; i += 1) {
      const hs = nowNs();
      await auth.sign({ sub: "1", roles: ["member"] });
      signDurations.push(elapsedMs(hs));

      const vs = nowNs();
      await auth.verify(token);
      verifyDurations.push(elapsedMs(vs));
    }

    stats("jwt sign", signDurations);
    stats("jwt verify", verifyDurations);

    expect(
      percentile(signDurations.sort((a, b) => a - b), 99),
    ).toBeLessThan(100);
    expect(
      percentile(verifyDurations.sort((a, b) => a - b), 99),
    ).toBeLessThan(100);
  });

  it("PERF-03: refresh-token rotation latency", async () => {
    const auth = createAuth({ secret: SECRET });
    const session = await auth.login({ id: 1, email: "a@b.c" });
    const token = session.refreshToken as string;

    const durations: number[] = [];
    // Rotate through a chain of tokens.
    let current = token;
    for (let i = 0; i < 50; i += 1) {
      const s = nowNs();
      const next = await auth.refresh(current);
      durations.push(elapsedMs(s));
      current = next.refreshToken as string;
    }

    stats("refresh-token rotation", durations);
    expect(percentile(durations.sort((a, b) => a - b), 99)).toBeLessThan(500);
  });

  it("PERF-04: session revocation check latency", async () => {
    const sessionStore = createMemorySessionStore();
    const auth = createAuth({ secret: SECRET, sessionStore });

    const sessions = await Promise.all(
      Array.from({ length: 100 }, (_, i) =>
        auth.login({ id: i + 1, roles: ["user"] }),
      ),
    );

    const durations: number[] = [];
    for (const session of sessions) {
      const s = nowNs();
      await auth.verify(session.accessToken);
      durations.push(elapsedMs(s));
    }

    stats("session revocation check", durations);
    expect(percentile(durations.sort((a, b) => a - b), 99)).toBeLessThan(100);
  });

  it("PERF-05: RBAC authorization latency", async () => {
    const roles: Record<string, { permissions: string[] }> = {};
    for (let i = 0; i < 100; i += 1) {
      roles[`r${i}`] = {
        permissions: [`res.${i}.read`, `res.${i}.write`],
      };
    }
    const rbac = createRBAC({ roles });
    const subject = { roles: ["r99"] };

    const warmup = 100;
    for (let i = 0; i < warmup; i += 1) {
      rbac.can(subject, "res.0.read");
    }

    const durations: number[] = [];
    const iterations = 10_000;
    for (let i = 0; i < iterations; i += 1) {
      const s = nowNs();
      rbac.can(subject, `res.${i % 100}.read`);
      durations.push(elapsedMs(s));
    }

    stats("rbac authorization", durations);
    expect(percentile(durations.sort((a, b) => a - b), 99)).toBeLessThan(1);
  });

  it("PERF-06: JWKS cache hit, miss, and refresh failure", async () => {
    const cache = new JwksCache({ maxEntries: 100 });

    configureHttp({
      transport: async (url) => {
        const kid = String(url).slice(-2);
        return new Response(
          JSON.stringify({
            keys: [{ kty: "RSA", kid, alg: "RS256", n: "n", e: "AQAB" }],
          }),
          { status: 200 },
        );
      },
    });

    // Prime the cache.
    await cache.getKeys("https://issuer.test/a", "https://issuer.test/a");

    const hitDurations: number[] = [];
    for (let i = 0; i < 100; i += 1) {
      const s = nowNs();
      await cache.getKeys("https://issuer.test/a", "https://issuer.test/a");
      hitDurations.push(elapsedMs(s));
    }

    const missDurations: number[] = [];
    for (let i = 0; i < 20; i += 1) {
      const s = nowNs();
      await cache.getKeys(
        `https://issuer.test/miss-${i}`,
        `https://issuer.test/miss-${i}`,
      );
      missDurations.push(elapsedMs(s));
    }

    stats("jwks cache hit", hitDurations);
    stats("jwks cache miss", missDurations);

    // Refresh failure does not poison the cache: a failing fetch keeps the
    // previous valid entry.
    configureHttp({
      transport: async () => {
        throw new Error("jwks endpoint down");
      },
    });
    const recovered = await cache.getKeys(
      "https://issuer.test/a",
      "https://issuer.test/a",
    );
    expect(recovered.size).toBeGreaterThan(0);

    expect(
      percentile(hitDurations.sort((a, b) => a - b), 99),
    ).toBeLessThan(50);
    expect(
      percentile(missDurations.sort((a, b) => a - b), 99),
    ).toBeLessThan(500);
  });

  it("PERF-07: OAuth callback token exchange using a mock provider", async () => {
    let exchangeCalls = 0;
    const oauth = createOAuth({
      stateStore: {
        async set() {},
        async get() {
          return null;
        },
        async delete() {},
        async consume() {
          return {
            provider: "mock",
            redirectUri: "http://localhost/cb",
            codeVerifier: "verifier",
            createdAt: Date.now(),
          };
        },
      },
      providers: {
        mock: {
          clientId: "cid",
          clientSecret: "csecret",
          redirectUri: "http://localhost/cb",
          provider: {
            id: "mock",
            name: "Mock",
            authorizationUrl: "https://mock.test/auth",
            tokenUrl: "https://mock.test/token",
            scopes: [],
            tokenAuthMethod: "body",
            pkce: true,
            createAuthorizationUrl: () => ({
              url: "https://mock.test/auth?state=x",
              state: "x",
              codeVerifier: "verifier",
            }),
            async exchangeCode() {
              exchangeCalls += 1;
              return { access_token: "at", token_type: "Bearer" };
            },
            async fetchProfile() {
              return { provider: "mock", id: "u1", email: "u@example.com" };
            },
          },
          redirectUriPolicy: {
            allowedRedirectUris: ["http://localhost/cb"],
            allowLocalhostHttp: true,
          },
        },
      },
    });

    const durations: number[] = [];
    for (let i = 0; i < 50; i += 1) {
      const s = nowNs();
      await oauth.callback("mock", { code: `code-${i}`, state: "stale" });
      durations.push(elapsedMs(s));
    }

    stats("oauth callback token exchange", durations);
    expect(exchangeCalls).toBe(50);
    expect(percentile(durations.sort((a, b) => a - b), 99)).toBeLessThan(100);
  });

  it("PERF-08: HTTP transport timeout and oversized response handling", async () => {
    const slowDurations: number[] = [];
    const oversizedDurations: number[] = [];

    // Slow endpoint: timeout fires at 1ms.
    for (let i = 0; i < 20; i += 1) {
      const s = nowNs();
      await dispatchHttp("https://slow.test/", {
        transport: async (_input, init) =>
          new Promise((_, reject) => {
            init?.signal?.addEventListener("abort", () => {
              const e = new Error("aborted");
              e.name = "AbortError";
              reject(e);
            });
          }),
        timeoutMs: 1,
      }).catch(() => {});
      slowDurations.push(elapsedMs(s));
    }

    // Oversized response: body exceeds maxResponseBytes.
    const oversized = "x".repeat(1_048_577);
    for (let i = 0; i < 20; i += 1) {
      const s = nowNs();
      await dispatchHttp("https://oversized.test/", {
        transport: async () => new Response(oversized, { status: 200 }),
        maxResponseBytes: 1024,
      }).catch(() => {});
      oversizedDurations.push(elapsedMs(s));
    }

    stats("http timeout (1ms)", slowDurations);
    stats("http oversized response", oversizedDurations);

    expect(
      percentile(slowDurations.sort((a, b) => a - b), 99),
    ).toBeLessThan(100);
    expect(
      percentile(oversizedDurations.sort((a, b) => a - b), 99),
    ).toBeLessThan(100);
  });

  it("PERF-09: memory remains stable under sustained load", async () => {
    const auth = createAuth({ secret: SECRET });
    const initial = process.memoryUsage().heapUsed;

    for (let round = 0; round < 5; round += 1) {
      const sessions = await Promise.all(
        Array.from({ length: 50 }, (_, i) =>
          auth.login({ id: i, roles: ["user"] }),
        ),
      );
      await Promise.all(
        sessions.map((session) => auth.verify(session.accessToken)),
      );
      await Promise.all(
        sessions.map((session) =>
          session.refreshToken
            ? auth.refresh(session.refreshToken)
            : Promise.resolve(null),
        ),
      );
      await globalThis.gc?.();
    }

    const after = process.memoryUsage().heapUsed;
    const growth = after - initial;
    // Heap should not grow without bound under sustained load; allow a
    // generous tolerance for V8 internals.
    expect(growth).toBeLessThan(100 * 1024 * 1024); // 100MB
  });

  it("PERF-10: 100 concurrent refresh attempts using the same refresh token", async () => {
    const auth = createAuth({ secret: SECRET });
    const result = await auth.login({ id: 1, email: "a@b.c" });
    const token = result.refreshToken as string;

    const start = nowNs();
    const outcomes = await Promise.allSettled(
      Array.from({ length: 100 }, () => auth.refresh(token)),
    );
    const elapsed = elapsedMs(start);

    const successes = outcomes.filter((o) => o.status === "fulfilled").length;
    expect(successes).toBe(1);
    stats("100 concurrent refreshes same token", [elapsed]);
    expect(elapsed).toBeLessThan(10_000);
  });
});
