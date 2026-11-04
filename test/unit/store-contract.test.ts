 
import { describe, it, expect } from "vitest";
import {
  createAuth,
  createOAuth,
  createMemoryStateStore,
  createMemoryRefreshStore,
} from "../../src/index.js";
import type {
  RefreshRecord,
  StateStore,
  RefreshStore,
} from "../../src/index.js";

// ---------------------------------------------------------------------------
// State store contract
// ---------------------------------------------------------------------------

describe("state store consume contract", () => {
  it("consumes an existing value exactly once", async () => {
    const store = createMemoryStateStore();
    const value = { provider: "test", createdAt: Date.now() };
    await store.set("key-1", value, 60);

    const first = await store.consume("key-1");
    expect(first).toEqual(value);
    expect(await store.consume("key-1")).toBeNull();
  });

  it("returns null for a missing key", async () => {
    const store = createMemoryStateStore();
    expect(await store.consume("missing-key")).toBeNull();
  });

  it("returns null for an expired value", async () => {
    const store = createMemoryStateStore();
    await store.set("expired", { provider: "test", createdAt: Date.now() }, 0);
    expect(await store.get("expired")).toBeNull();
    expect(await store.consume("expired")).toBeNull();
  });

  it("allows exactly one consumer under concurrency", async () => {
    const store = createMemoryStateStore();
    const value = { provider: "test", createdAt: Date.now() };
    await store.set("concurrent", value, 60);

    const results = await Promise.all(
      Array.from({ length: 100 }, async () => await store.consume("concurrent")),
    );

    let successful = 0;
    for (const result of results) {
      if (result !== null) {
        successful += 1;
      }
    }
    expect(successful).toBe(1);
    expect(await store.consume("concurrent")).toBeNull();
  });

  it("recreates a consumable value after a prior consume", async () => {
    const store = createMemoryStateStore();
    const value = { provider: "test", createdAt: Date.now() };
    await store.set("reuse", value, 60);
    expect(await store.consume("reuse")).toBeTruthy();
    await store.set("reuse", value, 60);
    expect(await store.consume("reuse")).toBeTruthy();
  });
});

function refreshRecordMatches(
  actual: RefreshRecord | null | undefined,
  expected: RefreshRecord,
): boolean {
  if (!actual) return false;
  return (
    actual.id === expected.id &&
    actual.userId === expected.userId &&
    actual.tokenHash === expected.tokenHash &&
    actual.expiresAt === expected.expiresAt
  );
}

describe("refresh store consume contract", () => {
  it("consumes an existing record exactly once", async () => {
    const store = createMemoryRefreshStore();
    const record: RefreshRecord = {
      id: "key-1",
      userId: 1,
      tokenHash: "h",
      expiresAt: Date.now() + 60_000,
    };
    await store.save(record);

    const first = await store.consume("key-1");
    expect(refreshRecordMatches(first, record)).toBe(true);
    expect(await store.consume("key-1")).toBeNull();
  });

  it("returns null for a missing id", async () => {
    const store = createMemoryRefreshStore();
    expect(await store.consume("missing-key")).toBeNull();
  });

  it("returns null for an expired record", async () => {
    const store = createMemoryRefreshStore();
    const record: RefreshRecord = {
      id: "expired",
      userId: 1,
      tokenHash: "h",
      expiresAt: Date.now() - 1,
    };
    await store.save(record);
    expect(await store.get("expired")).toBeNull();
    expect(await store.consume("expired")).toBeNull();
  });

  it("allows exactly one consumer under concurrency", async () => {
    const store = createMemoryRefreshStore();
    const record: RefreshRecord = {
      id: "concurrent",
      userId: 1,
      tokenHash: "h",
      expiresAt: Date.now() + 60_000,
    };
    await store.save(record);

    const results = await Promise.all(
      Array.from({ length: 100 }, async () => await store.consume("concurrent")),
    );

    let successful = 0;
    for (const result of results) {
      if (result !== null) {
        successful += 1;
      }
    }
    expect(successful).toBe(1);
    expect(await store.consume("concurrent")).toBeNull();
  });

  it("recreates a consumable record after a prior consume", async () => {
    const store = createMemoryRefreshStore();
    const record: RefreshRecord = {
      id: "reuse",
      userId: 1,
      tokenHash: "h",
      expiresAt: Date.now() + 60_000,
    };
    await store.save(record);
    expect(await store.consume("reuse")).toBeTruthy();
    await store.save(record);
    expect(await store.consume("reuse")).toBeTruthy();
  });
});

async function assertConsumeThrows<T>(
  consume: () => Promise<T | null> | T | null,
  expected: unknown,
): Promise<void> {
  let err: unknown;
  try {
    await consume();
  } catch (e) {
    err = e;
  }
  expect(err).toBe(expected);
}

describe("fault injection", () => {
  it("propagates state-store consume errors instead of treating them as missing state", async () => {
    const boom = new Error("state store down");
    const store: StateStore = {
      set: async () => {},
      get: async () => null,
      delete: async () => {},
      consume: async () => {
        throw boom;
      },
    };

    await assertConsumeThrows(() => store.consume("key"), boom);
  });

  it("propagates refresh-store consume errors instead of treating them as missing tokens", async () => {
    const boom = new Error("refresh store down");
    const store: RefreshStore = {
      save: async () => {},
      get: async () => null,
      consume: async () => {
        throw boom;
      },
    };

    await assertConsumeThrows(() => store.consume("key"), boom);
  });

  it("OAuth callback fails closed when the state store throws during consume", async () => {
    const boom = new Error("state store down");
    const oauth = createOAuth({
      stateStore: {
        set: async () => {},
        get: async () => null,
        delete: async () => {},
        consume: async () => {
          throw boom;
        },
      } as StateStore,
      providers: {
        test: {
          clientId: "client-id",
          provider: {
            id: "test",
            name: "Test",
            authorizationUrl: "https://example.com/authorize",
            tokenUrl: "https://example.com/token",
            scopes: [],
            pkce: false,
            tokenAuthMethod: "body",
            createAuthorizationUrl: () => ({
              url: "https://example.com/authorize?state=x",
              state: "x",
            }),
            async exchangeCode() {
              return { access_token: "token", token_type: "Bearer" };
            },
            async fetchProfile() {
              return { provider: "test", id: "1" };
            },
          },
          redirectUri: "https://example.com/cb",
          redirectUriPolicy: {
            allowedRedirectUris: ["https://example.com/cb"],
            allowLocalhostHttp: false,
          },
        },
      },
    });

    const { state } = await oauth.authorize("test");
    await assertConsumeThrows(() => oauth.callback("test", { code: "code", state }), boom);
  });

  it("refresh fails closed when the refresh store throws during consume", async () => {
    const boom = new Error("refresh store down");
    const auth = createAuth({
      secret: "secret-key-for-testing-purposes-1234567890",
      refreshStore: {
        save: async () => {},
        get: async () => null,
        consume: async () => {
          throw boom;
        },
      } as RefreshStore,
    });

    const session = await auth.login({ id: 1 });
    await assertConsumeThrows(() => auth.refresh(session.refreshToken!), boom);
  });
});
