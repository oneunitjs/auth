 
import { describe, it, beforeAll, afterAll, expect } from "vitest";
import { GenericContainer } from "testcontainers";
import { StartedPostgreSqlContainer } from "@testcontainers/postgresql";
import { Pool } from "pg";
import { createAuth } from "../../../src/index.js";
import type { RefreshRecord, RefreshStore } from "../../../src/index.js";
import type { SessionStore } from "../../../src/types/index.js";

const SECRET = "distributed-atomicity-test-secret-do-not-use-in-production";

let pgContainer: StartedPostgreSqlContainer;
let pgPool: Pool;
let pgUrl: string;

// ---------------------------------------------------------------------------
// Test-only PostgreSQL-backed store implementations
// ---------------------------------------------------------------------------

function createPgRefreshStore(pool: Pool): RefreshStore {
  return {
    async save(record: RefreshRecord) {
      await pool.query(
        `INSERT INTO auth_refresh_tokens (id, user_id, token_hash, expires_at)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (id) DO UPDATE SET user_id = EXCLUDED.user_id, token_hash = EXCLUDED.token_hash, expires_at = EXCLUDED.expires_at`,
        [record.id, record.userId, record.tokenHash, record.expiresAt],
      );
    },
    async get(id: string): Promise<RefreshRecord | null> {
      const { rows } = await pool.query(
        "SELECT id, user_id, token_hash, expires_at FROM auth_refresh_tokens WHERE id = $1",
        [id],
      );
      const row = rows[0];
      if (!row) return null;
      if (row.expires_at && Number(row.expires_at) <= Date.now()) {
        await pool.query("DELETE FROM auth_refresh_tokens WHERE id = $1", [id]);
        return null;
      }
      return { id, userId: row.user_id, tokenHash: row.token_hash, expiresAt: Number(row.expires_at) } as RefreshRecord;
    },
    async consume(id: string): Promise<RefreshRecord | null> {
      const { rows } = await pool.query(
        `DELETE FROM auth_refresh_tokens WHERE id = $1 RETURNING id, user_id, token_hash, expires_at`,
        [id],
      );
      const row = rows[0];
      if (!row) return null;
      return { id: row.id, userId: row.user_id, tokenHash: row.token_hash, expiresAt: Number(row.expires_at) } as RefreshRecord;
    },
    async revoke(id: string) {
      await pool.query("DELETE FROM auth_refresh_tokens WHERE id = $1", [id]);
    },
  };
}

function createPgSessionStore(pool: Pool): SessionStore {
  return {
    async getVersion(userId: string | number): Promise<number> {
      const { rows } = await pool.query(
        "SELECT version FROM auth_session_versions WHERE user_id = $1",
        [userId],
      );
      const row = rows[0];
      return row ? Number(row.version) : 0;
    },
    async bumpVersion(userId: string | number): Promise<number> {
      const { rows } = await pool.query(
        `INSERT INTO auth_session_versions (user_id, version) VALUES ($1, 1)
         ON CONFLICT (user_id) DO UPDATE SET version = auth_session_versions.version + 1
         RETURNING version`,
        [userId],
      );
      return Number(rows[0].version);
    },
  };
}

async function setupPgSchema(pool: Pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS auth_refresh_tokens (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      token_hash TEXT NOT NULL,
      expires_at BIGINT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS auth_session_versions (
      user_id TEXT PRIMARY KEY,
      version BIGINT NOT NULL DEFAULT 0
    );
  `);
}

async function cleanupPgSchema(pool: Pool, _namespace: string) {
  await pool.query("DELETE FROM auth_refresh_tokens WHERE id LIKE $1", [`${testNamespace}%`]);
  await pool.query("DELETE FROM auth_session_versions WHERE user_id LIKE $1", [`${testNamespace}%`]);
}

let testNamespace = "";

describe("distributed atomicity with real PostgreSQL", () => {
  beforeAll(async () => {
    pgContainer = await new GenericContainer("postgres:16-alpine")
      .withEnvironment({
        POSTGRES_USER: "postgres",
        POSTGRES_PASSWORD: "postgres",
        POSTGRES_DB: "authdb",
      })
      .withExposedPorts(5432)
      .start() as any;
    const pgHost = pgContainer.getHost();
    const pgPort = pgContainer.getMappedPort(5432);
    pgUrl = `postgres://postgres:postgres@${pgHost}:${pgPort}/authdb`;

    pgPool = new Pool({ connectionString: pgUrl });
    testNamespace = `pg-${Date.now()}`;
    await setupPgSchema(pgPool);
  }, 60_000);

  afterAll(async () => {
    await pgPool.end();
    await pgContainer.stop();
  });

  it("single-use consumption: atomic DELETE ... RETURNING", async () => {
    await cleanupPgSchema(pgPool, testNamespace);
    const store = createPgRefreshStore(pgPool);
    const auth = createAuth({ secret: SECRET, refreshStore: store });
    const session = await auth.login({ id: 1, roles: ["user"] });
    const refreshToken = session.refreshToken!;

    const results = await Promise.allSettled([auth.refresh(refreshToken), auth.refresh(refreshToken)]);
    const fulfilled = results.filter((r) => r.status === "fulfilled").length;
    const rejected = results.filter((r) => r.status === "rejected").length;

    expect(fulfilled).toBe(1);
    expect(rejected).toBe(1);

    const { rows } = await pgPool.query("SELECT COUNT(*) as cnt FROM auth_refresh_tokens WHERE id LIKE $1", [`${testNamespace}%`]);
    expect(Number(rows[0].cnt)).toBe(0);
  });

  it("rotation produces exactly one successor token", async () => {
    await cleanupPgSchema(pgPool, testNamespace);
    await pgPool.query("DELETE FROM auth_refresh_tokens WHERE user_id = $1", [1]);

    const store = createPgRefreshStore(pgPool);
    const auth = createAuth({ secret: SECRET, refreshStore: store });
    const session = await auth.login({ id: 1, roles: ["user"] });

    const results = await Promise.allSettled([
      auth.refresh(session.refreshToken!),
      auth.refresh(session.refreshToken!),
    ]);

    expect(results.filter((r) => r.status === "fulfilled").length).toBe(1);
    expect(results.filter((r) => r.status === "rejected").length).toBe(1);

    const { rows } = await pgPool.query("SELECT COUNT(*) as cnt FROM auth_refresh_tokens WHERE user_id = $1", [1]);
    expect(Number(rows[0].cnt)).toBe(1);
  });

  it("revokeAllSessions bumps version atomically", async () => {
    await cleanupPgSchema(pgPool, testNamespace);
    const sessionStore = createPgSessionStore(pgPool);
    const store = createPgRefreshStore(pgPool);
    const auth = createAuth({ secret: SECRET, refreshStore: store, sessionStore });

    const session = await auth.login({ id: 1, roles: ["user"] });
    expect((await auth.verify(session.accessToken)).sub).toBe("1");

    expect(await auth.revokeAllSessions(1)).toBe(true);
    await expect(() => auth.refresh(session.refreshToken!)).rejects.toThrow(Error);

    const fresh = await auth.login({ id: 1, roles: ["user"] });
    expect((await auth.verify(fresh.accessToken)).sub).toBe("1");
  });

  it("refresh concurrent with session revocation blocks refresh after revocation", async () => {
    await cleanupPgSchema(pgPool, testNamespace);
    const sessionStore = createPgSessionStore(pgPool);
    const store = createPgRefreshStore(pgPool);
    const auth = createAuth({ secret: SECRET, refreshStore: store, sessionStore });

    const session = await auth.login({ id: 1, roles: ["user"] });

    await auth.revokeAllSessions(1);
    await expect(() => auth.refresh(session.refreshToken!)).rejects.toThrow(Error);
  });

  it("failed refresh does not leave partial state", async () => {
    await cleanupPgSchema(pgPool, testNamespace);
    const store = createPgRefreshStore(pgPool);
    const auth = createAuth({ secret: SECRET, refreshStore: store });

    const fakeToken = "invalid.token.withjti.test";
    await expect(() => auth.refresh(fakeToken)).rejects.toThrow(Error);

    const { rows } = await pgPool.query("SELECT COUNT(*) as cnt FROM auth_refresh_tokens WHERE id LIKE $1", [`${testNamespace}%`]);
    expect(Number(rows[0].cnt)).toBe(0);
  });

  it("independent sessions are isolated", async () => {
    await cleanupPgSchema(pgPool, testNamespace);
    const store = createPgRefreshStore(pgPool);
    const auth = createAuth({ secret: SECRET, refreshStore: store });

    const s1 = await auth.login({ id: 301, roles: ["user"] });
    const s2 = await auth.login({ id: 302, roles: ["user"] });

    const r1 = await auth.refresh(s1.refreshToken!);
    const r2 = await auth.refresh(s2.refreshToken!);

    expect(r1.user.id).toBe(301);
    expect(r2.user.id).toBe(302);

    await expect(() => auth.refresh(s1.refreshToken!)).rejects.toThrow(Error);
    await expect(() => auth.refresh(s2.refreshToken!)).rejects.toThrow(Error);
  });

  it("contention stress: 50 concurrent refresh attempts, exactly 1 succeeds", async () => {
    await cleanupPgSchema(pgPool, testNamespace);
    const store = createPgRefreshStore(pgPool);
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
});
