 
import { describe, it, beforeAll, afterAll, expect } from "vitest";
import { GenericContainer } from "testcontainers";
import { StartedRedisContainer } from "@testcontainers/redis";
import { Redis as IORedis } from "ioredis";
import { createAuth } from "../../../src/index.js";
import type { RefreshRecord, RefreshStore } from "../../../src/index.js";
import type { SessionStore } from "../../../src/types/index.js";

const SECRET = "distributed-redis-test-secret-do-not-use-in-production";

let redisContainer: StartedRedisContainer;
let redisUrl: string;
let redis: IORedis;

// ---------------------------------------------------------------------------
// Test-only Redis-backed store implementations
// ---------------------------------------------------------------------------

function createRedisRefreshStore(redis: IORedis, prefix = "auth:rt:"): RefreshStore {
  const consumeScript = `
    local record = redis.call('GET', KEYS[1])
    if not record then return nil end
    local data = cjson.decode(record)
    if data.expires_at and tonumber(data.expires_at) <= tonumber(ARGV[1]) then
      redis.call('DEL', KEYS[1])
      return nil
    end
    redis.call('DEL', KEYS[1])
    return record
  `;

  return {
    async save(record: RefreshRecord) {
      await redis.set(`${prefix}${record.id}`, JSON.stringify({
        userId: record.userId,
        tokenHash: record.tokenHash,
        expiresAt: record.expiresAt,
      }));
      if (record.expiresAt) {
        const ttlSeconds = Math.ceil((record.expiresAt - Date.now()) / 1000);
        if (ttlSeconds > 0) {
          await redis.expire(`${prefix}${record.id}`, ttlSeconds);
        }
      }
    },
    async get(id: string): Promise<RefreshRecord | null> {
      const raw = await redis.get(`${prefix}${id}`);
      if (!raw) return null;
      const data = JSON.parse(raw);
      if (data.expiresAt && data.expiresAt <= Date.now()) {
        await redis.del(`${prefix}${id}`);
        return null;
      }
      return { id, userId: data.userId, tokenHash: data.tokenHash, expiresAt: data.expiresAt } as RefreshRecord;
    },
    async consume(id: string): Promise<RefreshRecord | null> {
      const result = await redis.eval(consumeScript, 1, `${prefix}${id}`, String(Date.now()));
      if (!result) return null;
      const data = JSON.parse(result as string);
      return { id, userId: data.userId, tokenHash: data.tokenHash, expiresAt: data.expiresAt } as RefreshRecord;
    },
    async revoke(id: string) {
      await redis.del(`${prefix}${id}`);
    },
  };
}

function createRedisSessionStore(redis: IORedis, prefix = "auth:ss:"): SessionStore {
  return {
    async getVersion(userId: string | number): Promise<number> {
      const raw = await redis.get(`${prefix}${userId}`);
      return raw ? parseInt(raw, 10) : 0;
    },
    async bumpVersion(userId: string | number): Promise<number> {
      const next = await redis.incr(`${prefix}${userId}`);
      return next;
    },
  };
}

let testNamespace = "";

describe("distributed atomicity with real Redis", () => {
  beforeAll(async () => {
    redisContainer = await new GenericContainer("redis:7-alpine")
      .withExposedPorts(6379)
      .start() as any;
    const redisHost = redisContainer.getHost();
    const redisPort = redisContainer.getMappedPort(6379);
    redisUrl = `redis://${redisHost}:${redisPort}`;
    redis = new IORedis(redisUrl);
    testNamespace = `redis-${Date.now()}`;
  }, 60_000);

  afterAll(async () => {
    await redis.quit();
    await redisContainer.stop();
  });

  it("single-use consumption: only one of two concurrent refreshes succeeds", async () => {
    const store = createRedisRefreshStore(redis, `auth:rt:${testNamespace}:`);
    const auth = createAuth({ secret: SECRET, refreshStore: store });
    const session = await auth.login({ id: 1, roles: ["user"] });
    const refreshToken = session.refreshToken!;

    const results = await Promise.allSettled([auth.refresh(refreshToken), auth.refresh(refreshToken)]);
    const fulfilled = results.filter((r) => r.status === "fulfilled").length;
    const rejected = results.filter((r) => r.status === "rejected").length;

    expect(fulfilled).toBe(1);
    expect(rejected).toBe(1);

    await expect(() => auth.refresh(refreshToken)).rejects.toThrow();
  });

  it("rotation produces exactly one successor token", async () => {
    const store = createRedisRefreshStore(redis, `auth:rt:${testNamespace}:`);
    const auth = createAuth({ secret: SECRET, refreshStore: store });
    const session = await auth.login({ id: 1, roles: ["user"] });
    const firstRefresh = session.refreshToken!;

    const results = await Promise.allSettled([
      auth.refresh(firstRefresh),
      auth.refresh(firstRefresh),
    ]);

    expect(results.filter((r) => r.status === "fulfilled").length).toBe(1);
    expect(results.filter((r) => r.status === "rejected").length).toBe(1);
  });

  it("revoked session cannot refresh", async () => {
    const sessionStore = createRedisSessionStore(redis, `auth:ss:${testNamespace}:`);
    const store = createRedisRefreshStore(redis, `auth:rt:${testNamespace}:`);
    const auth = createAuth({ secret: SECRET, refreshStore: store, sessionStore });

    const session = await auth.login({ id: 1, roles: ["user"] });
    expect(await auth.revokeAllSessions(1)).toBe(true);
    await expect(() => auth.refresh(session.refreshToken!)).rejects.toThrow();
  });

  it("independent sessions are isolated under concurrent refresh", async () => {
    const store = createRedisRefreshStore(redis, `auth:rt:${testNamespace}:`);
    const auth1 = createAuth({ secret: SECRET, refreshStore: store });
    const auth2 = createAuth({ secret: SECRET, refreshStore: store });

    const session1 = await auth1.login({ id: 101, roles: ["user"] });
    const session2 = await auth2.login({ id: 102, roles: ["user"] });

    const results = await Promise.allSettled([
      auth1.refresh(session1.refreshToken!),
      auth2.refresh(session2.refreshToken!),
    ]);

    expect(results.filter((r) => r.status === "fulfilled").length).toBe(2);

    const keysAfter = await redis.keys(`auth:rt:${testNamespace}:*`);
    expect(keysAfter.length).toBeGreaterThanOrEqual(2);
  });

  it("contention stress: 50 concurrent refresh attempts, exactly 1 succeeds", async () => {
    const store = createRedisRefreshStore(redis, `auth:rt:${testNamespace}:`);
    const auth = createAuth({ secret: SECRET, refreshStore: store });
    const session = await auth.login({ id: 1, roles: ["user"] });
    const refreshToken = session.refreshToken!;

    const promises: Array<Promise<string>> = [];
    for (let i = 0; i < 50; i++) {
      promises.push(
        auth.refresh(refreshToken)
          .then(() => `ok-${i}`)
          .catch(() => `rejected-${i}`),
      );
    }
    const results = await Promise.all(promises);
    const successes = results.filter((r) => r.startsWith("ok")).length;
    const failures = results.filter((r) => r.startsWith("rejected")).length;

    expect(successes).toBe(1);
    expect(failures).toBe(49);
  });

  it("reuse of consumed token is rejected", async () => {
    const store = createRedisRefreshStore(redis, `auth:rt:${testNamespace}:`);
    const auth = createAuth({ secret: SECRET, refreshStore: store });
    const session = await auth.login({ id: 1, roles: ["user"] });

    await auth.refresh(session.refreshToken!);
    await expect(() => auth.refresh(session.refreshToken!)).rejects.toThrow();
  });

  it("different sessions are isolated", async () => {
    const store = createRedisRefreshStore(redis, `auth:rt:${testNamespace}:`);
    const auth = createAuth({ secret: SECRET, refreshStore: store });

    const s1 = await auth.login({ id: 201, roles: ["user"] });
    const s2 = await auth.login({ id: 202, roles: ["user"] });

    const r1 = await auth.refresh(s1.refreshToken!);
    const r2 = await auth.refresh(s2.refreshToken!);

    expect(r1.user.id).toBe(201);
    expect(r2.user.id).toBe(202);

    await expect(() => auth.refresh(s1.refreshToken!)).rejects.toThrow();
    await expect(() => auth.refresh(s2.refreshToken!)).rejects.toThrow();
  });
});
