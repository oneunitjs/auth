 
import { describe, it, expect, afterEach } from "vitest";
import {
  createAuth,
  emitDiagnostic,
  getDiagnosticsStats,
  resetDiagnostics,
  setDiagnosticsErrorCallback,
  setDiagnosticsObserver,
  setDiagnosticsOverflowPolicy,
  hashScryptPassword,
  type AuthDiagnosticEvent,
} from "../../src/index.js";

const SECRET = "secret-key-for-testing-purposes-123456";

function memoryUsers(seed: Array<Record<string, unknown>> = []) {
  const users = new Map(seed.map((user) => [String(user.id), { ...user }]));
  let nextId = seed.length + 1;
  return {
    async findById(id: string | number) {
      return users.get(String(id)) ?? null;
    },
    async findByCredentials(identifier: string) {
      return [...users.values()].find((user) => user.email === identifier) ?? null;
    },
    async create(input: Record<string, unknown>) {
      const user = { id: nextId++, ...input };
      users.set(String(user.id), user);
      return user;
    },
    async updatePassword(id: string | number, passwordHash: string) {
      const user = users.get(String(id));
      if (user) user.passwordHash = passwordHash;
    },
  };
}

describe("diagnostics", () => {
  afterEach(() => {
    resetDiagnostics();
  });

  it("emits login events without exposing secrets", async () => {
    const events: AuthDiagnosticEvent[] = [];
    setDiagnosticsObserver((event) => {
      events.push(event);
    });
    const auth = createAuth({ secret: SECRET });
    await auth.login({ id: 1, roles: ["user"] });
    expect(events.some((event) => event.type === "auth.login.succeeded")).toBe(true);
    expect(JSON.stringify(events)).not.toContain(SECRET);
  });

  it("isolates observer failures from authentication", async () => {
    setDiagnosticsObserver(() => {
      throw new Error("observer exploded");
    });
    const auth = createAuth({ secret: SECRET });
    const session = await auth.login({ id: 7, roles: ["user"] });
    expect(session.accessToken).toBeTruthy();
  });

  it("isolates async observer failures from authentication", async () => {
    setDiagnosticsObserver(async () => {
      throw new Error("async observer exploded");
    });
    const auth = createAuth({ secret: SECRET });
    const session = await auth.login({ id: 8, roles: ["user"] });
    expect(session.accessToken).toBeTruthy();
  });

  it("is a no-op without an observer", () => {
    expect(() => emitDiagnostic({ type: "auth.login.succeeded", timestamp: Date.now() })).not.toThrow();
  });

  it("truncates long diagnostic strings", () => {
    const events: AuthDiagnosticEvent[] = [];
    setDiagnosticsObserver((event) => {
      events.push(event);
    });
    emitDiagnostic({
      type: "oauth.authorization.started",
      timestamp: 1,
      providerId: "p".repeat(200),
      operationId: "o".repeat(200),
    });
    const event = events[0] as Extract<AuthDiagnosticEvent, { type: "oauth.authorization.started" }>;
    expect(event.providerId).toHaveLength(128);
    expect(event.operationId).toHaveLength(128);
  });

  it("drops events when the async observer queue is full", async () => {
    const resolvers: Array<() => void> = [];
    setDiagnosticsObserver(() => new Promise<void>((resolve) => {
      resolvers.push(resolve);
    }));
    for (let index = 0; index < 40; index += 1) {
      emitDiagnostic({ type: "auth.login.succeeded", timestamp: Date.now() });
    }
    expect(resolvers.length).toBe(32);
    for (const resolve of resolvers) {
      resolve();
    }
  });

  it("emits login failure and password upgrade events", async () => {
    const events: AuthDiagnosticEvent[] = [];
    setDiagnosticsObserver((event) => {
      events.push(event);
    });
    const legacy = await hashScryptPassword("s3cret-pass", { cost: 16384 });
    const store = memoryUsers([
      { id: 1, email: "user@example.com", passwordHash: legacy },
    ]);
    const auth = createAuth({ secret: SECRET, userStore: store as any });
    await expect(auth.loginWithPassword("missing@example.com", "s3cret-pass")).rejects.toThrow();
    const session = await auth.loginWithPassword("user@example.com", "s3cret-pass");
    expect(session.user.id).toBe(1);
    expect(events.some((event) => event.type === "auth.login.failed")).toBe(true);
    expect(events.some((event) => event.type === "password.hash.upgraded")).toBe(true);
    const updated = await store.findById(1);
    expect(String(updated?.passwordHash)).toMatch(/^\$argon2id\$/);
  });

  it("does not fail login when password upgrade throws", async () => {
    const events: AuthDiagnosticEvent[] = [];
    setDiagnosticsObserver((event) => {
      events.push(event);
    });
    const legacy = await hashScryptPassword("s3cret-pass", { cost: 16384 });
    const store = {
      ...memoryUsers([{ id: 1, email: "user@example.com", passwordHash: legacy }]),
      async updatePassword() {
        throw new Error("store write failed");
      },
    };
    const auth = createAuth({ secret: SECRET, userStore: store as any });
    const session = await auth.loginWithPassword("user@example.com", "s3cret-pass");
    expect(session.accessToken).toBeTruthy();
    expect(events.some((event) => event.type === "password.hash.upgrade.failed")).toBe(true);
  });

  it("tracks emitted, dropped, and failed stats", () => {
    const events: AuthDiagnosticEvent[] = [];
    setDiagnosticsObserver((event) => {
      events.push(event);
    });
    emitDiagnostic({ type: "auth.login.succeeded", timestamp: 1 });
    emitDiagnostic({ type: "auth.login.succeeded", timestamp: 2 });
    const stats = getDiagnosticsStats();
    expect(stats.emitted).toBe(2);
    expect(stats.dropped).toBe(0);
    expect(stats.failed).toBe(0);
    expect(stats.size).toBe(0);
    expect(stats.maxSize).toBe(32);
    expect(stats.overflowPolicy).toBe("drop");
  });

  it("counts dropped events when the async queue is full", async () => {
    const resolvers: Array<() => void> = [];
    setDiagnosticsObserver(() => new Promise<void>((resolve) => {
      resolvers.push(resolve);
    }));
    for (let index = 0; index < 50; index += 1) {
      emitDiagnostic({ type: "auth.login.succeeded", timestamp: Date.now() });
    }
    const stats = getDiagnosticsStats();
    expect(stats.emitted).toBe(50);
    expect(stats.size).toBe(32);
    expect(stats.dropped).toBe(18);
    for (const resolve of resolvers) {
      resolve();
    }
    await Promise.resolve();
    await Promise.resolve();
    const drained = getDiagnosticsStats();
    expect(drained.size).toBe(0);
    expect(drained.dropped).toBe(18);
  });

  it("counts observer failures and does not break authentication", async () => {
    const failing = () => {
      throw new Error("observer exploded");
    };
    setDiagnosticsObserver(failing);
    const auth = createAuth({ secret: SECRET });
    const session = await auth.login({ id: 3, roles: ["user"] });
    expect(session.accessToken).toBeTruthy();
    const stats = getDiagnosticsStats();
    expect(stats.failed).toBeGreaterThan(0);
  });

  it("counts async observer rejections as failures", async () => {
    setDiagnosticsObserver(async () => {
      throw new Error("async observer exploded");
    });
    const auth = createAuth({ secret: SECRET });
    await auth.login({ id: 4, roles: ["user"] });
    await new Promise((resolve) => setTimeout(resolve, 0));
    const stats = getDiagnosticsStats();
    expect(stats.failed).toBeGreaterThan(0);
  });

  it("invokes the error callback on overflow when policy is report", async () => {
    const calls: Array<{ event: AuthDiagnosticEvent; reason: string }> = [];
    setDiagnosticsOverflowPolicy("report");
    setDiagnosticsErrorCallback((event, reason) => {
      calls.push({ event, reason });
    });
    const resolvers: Array<() => void> = [];
    setDiagnosticsObserver(() => new Promise<void>((resolve) => {
      resolvers.push(resolve);
    }));
    for (let index = 0; index < 40; index += 1) {
      emitDiagnostic({ type: "auth.login.succeeded", timestamp: Date.now() });
    }
    const stats = getDiagnosticsStats();
    expect(stats.dropped).toBeGreaterThan(0);
    expect(calls.length).toBe(stats.dropped);
    expect(calls.every((call) => call.reason === "overflow")).toBe(true);
    for (const resolve of resolvers) {
      resolve();
    }
    await Promise.resolve();
    await Promise.resolve();
  });

  it("supports drop policy without invoking the error callback", async () => {
    const calls: Array<unknown> = [];
    setDiagnosticsOverflowPolicy("drop");
    setDiagnosticsErrorCallback(() => {
      calls.push("called");
    });
    const resolvers: Array<() => void> = [];
    setDiagnosticsObserver(() => new Promise<void>((resolve) => {
      resolvers.push(resolve);
    }));
    for (let index = 0; index < 40; index += 1) {
      emitDiagnostic({ type: "auth.login.succeeded", timestamp: Date.now() });
    }
    expect(calls).toHaveLength(0);
    for (const resolve of resolvers) {
      resolve();
    }
    await Promise.resolve();
    await Promise.resolve();
  });

  it("resetDiagnostics clears stats and policy", () => {
    setDiagnosticsOverflowPolicy("report");
    emitDiagnostic({ type: "auth.login.succeeded", timestamp: 1 });
    resetDiagnostics();
    const stats = getDiagnosticsStats();
    expect(stats.emitted).toBe(0);
    expect(stats.dropped).toBe(0);
    expect(stats.failed).toBe(0);
    expect(stats.size).toBe(0);
    expect(stats.overflowPolicy).toBe("drop");
  });

  it("is a no-op without an observer", () => {
    expect(() => emitDiagnostic({ type: "auth.login.succeeded", timestamp: Date.now() })).not.toThrow();
    const stats = getDiagnosticsStats();
    expect(stats.emitted).toBe(0);
  });
});
