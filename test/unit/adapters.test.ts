 
import { describe, it, expect } from "vitest";
import {
  createAuth,
  createAdapterRegistry,
  validateStorageAdapter,
  validateEventAdapter,
} from "../../src/index.js";
import type {
  StorageAdapter,
  StorageCapabilities,
  EventAdapters,
  AuthAdapters,
} from "../../src/types/index.js";

// ---------------------------------------------------------------------------
// Adapter registry tests
// ---------------------------------------------------------------------------

describe("adapter registry", () => {
  it("creates an empty registry when no adapters are configured", () => {
    const registry = createAdapterRegistry({});
    expect(registry.storage).toBeUndefined();
    expect(registry.events).toBeUndefined();
    expect(registry.logger).toBeUndefined();
    expect(registry.capabilities).toEqual({
      atomicConsume: false,
      atomicRefreshTokenRotation: false,
      atomicIncrement: false,
      ttl: false,
    });
  });

  it("accepts a storage adapter with declared capabilities", () => {
    const storage: StorageAdapter = {
      keyValue: {
        get: async () => null,
        set: async () => {},
        delete: async () => {},
        consume: async () => null,
      },
    };
    const registry = createAdapterRegistry({
      adapters: { storage },
      capabilities: {
        atomicConsume: true,
        atomicRefreshTokenRotation: true,
        atomicIncrement: true,
        ttl: true,
      },
    });
    expect(registry.storage).toBe(storage);
    expect(registry.capabilities.atomicConsume).toBe(true);
    expect(registry.capabilities.atomicRefreshTokenRotation).toBe(true);
    expect(registry.capabilities.atomicIncrement).toBe(true);
    expect(registry.capabilities.ttl).toBe(true);
  });

  it("accepts an event adapter", () => {
    const events: EventAdapters = {
      publisher: { publish: async () => {} },
      subscriber: { subscribe: async () => async () => {} },
    };
    const registry = createAdapterRegistry({ adapters: { events } });
    expect(registry.events).toBe(events);
  });

  it("accepts a logger adapter", () => {
    const logger: { error?: (payload: unknown, message?: string) => void } = {
      error: () => {},
    };
    const registry = createAdapterRegistry({
      adapters: { logger } as AuthAdapters,
    });
    expect(registry.logger).toBe(logger);
  });
});

// ---------------------------------------------------------------------------
// Storage adapter validation tests
// ---------------------------------------------------------------------------

describe("storage adapter validation", () => {
  const baseCapabilities: StorageCapabilities = {
    atomicConsume: true,
    atomicRefreshTokenRotation: true,
    atomicIncrement: true,
    ttl: true,
  };

  it("accepts a valid key-value store", () => {
    const adapter: StorageAdapter = {
      keyValue: {
        get: async () => null,
        set: async () => {},
        delete: async () => {},
        consume: async () => null,
      },
    };
    expect(validateStorageAdapter(adapter, baseCapabilities)).toBe(adapter);
  });

  it("rejects a key-value store missing get", () => {
    const adapter: StorageAdapter = {
      keyValue: {
        set: async () => {},
        delete: async () => {},
        consume: async () => null,
      } as never,
    };
    expect(() => validateStorageAdapter(adapter, baseCapabilities)).toThrow(
      /keyValue\.get must be a function/,
    );
  });

  it("rejects a key-value store missing consume when atomicConsume is declared", () => {
    const adapter: StorageAdapter = {
      keyValue: {
        get: async () => null,
        set: async () => {},
        delete: async () => {},
      } as never,
    };
    expect(() => validateStorageAdapter(adapter, baseCapabilities)).toThrow(
      /keyValue\.consume must be a function when atomicConsume is declared/,
    );
  });

  it("does not require consume when atomicConsume is not declared", () => {
    const adapter: StorageAdapter = {
      keyValue: {
        get: async () => null,
        set: async () => {},
        delete: async () => {},
      } as never,
    };
    const caps: StorageCapabilities = {
      atomicConsume: false,
      atomicRefreshTokenRotation: true,
      atomicIncrement: true,
      ttl: true,
    };
    expect(validateStorageAdapter(adapter, caps)).toBe(adapter);
  });

  it("rejects a refresh token store missing rotate when rotation is declared", () => {
    const adapter: StorageAdapter = {
      refreshTokens: {
        get: async () => null,
        create: async () => {},
        revoke: async () => {},
      } as never,
    };
    expect(() => validateStorageAdapter(adapter, baseCapabilities)).toThrow(
      /refreshTokens\.rotate must be a function when atomicRefreshTokenRotation is declared/,
    );
  });

  it("rejects a versions store missing increment when atomicIncrement is declared", () => {
    const adapter: StorageAdapter = {
      versions: {
        get: async () => 0,
      } as never,
    };
    expect(() => validateStorageAdapter(adapter, baseCapabilities)).toThrow(
      /versions\.increment must be a function when atomicIncrement is declared/,
    );
  });

  it("accepts an adapter with only some capabilities", () => {
    const adapter: StorageAdapter = {
      sessions: {
        get: async () => null,
        set: async () => {},
        delete: async () => {},
      },
      revocations: {
        revoke: async () => {},
        isRevoked: async () => false,
      },
    };
    const caps: StorageCapabilities = {
      atomicConsume: false,
      atomicRefreshTokenRotation: false,
      atomicIncrement: false,
      ttl: false,
    };
    expect(validateStorageAdapter(adapter, caps)).toBe(adapter);
  });
});

// ---------------------------------------------------------------------------
// Event adapter validation tests
// ---------------------------------------------------------------------------

describe("event adapter validation", () => {
  it("accepts a valid event adapter", () => {
    const adapter: EventAdapters = {
      publisher: { publish: async () => {} },
      subscriber: { subscribe: async () => async () => {} },
    };
    expect(validateEventAdapter(adapter)).toBe(adapter);
  });

  it("rejects a publisher missing publish", () => {
    const adapter: EventAdapters = {
      publisher: {} as never,
    };
    expect(() => validateEventAdapter(adapter)).toThrow(
      /publisher\.publish must be a function/,
    );
  });

  it("rejects a subscriber missing subscribe", () => {
    const adapter: EventAdapters = {
      subscriber: {} as never,
    };
    expect(() => validateEventAdapter(adapter)).toThrow(
      /subscriber\.subscribe must be a function/,
    );
  });
});

// ---------------------------------------------------------------------------
// AuthOptions adapters integration
// ---------------------------------------------------------------------------

describe("createAuth adapter integration", () => {
  it("accepts adapters in createAuth options", () => {
    const auth = createAuth({
      secret: "secret-key-for-testing-purposes-1234567890",
      adapters: {
        storage: {
          keyValue: {
            get: async () => null,
            set: async () => {},
            delete: async () => {},
            consume: async () => null,
          },
        },
        logger: {
          info: () => {},
        },
      },
    });
    expect(auth).toBeTruthy();
    expect(auth.adapters).toBeTruthy();
    expect(auth.adapters.storage).toBeTruthy();
  });

  it("works without adapters (backward compatible)", () => {
    const auth = createAuth({ secret: "secret-key-for-testing-purposes-1234567890" });
    expect(auth).toBeTruthy();
    expect(auth.adapters).toBeTruthy();
    expect(auth.adapters.storage).toBeUndefined();
    expect(auth.adapters.events).toBeUndefined();
    expect(auth.adapters.logger).toBeUndefined();
  });

  it("fails fast when a storage adapter declares capabilities it does not implement", () => {
    expect(() =>
      createAuth({
        secret: "secret-key-for-testing-purposes-1234567890",
        adapters: {
          storage: {
            keyValue: {
              get: async () => null,
              set: async () => {},
              delete: async () => {},
              // consume missing but atomicConsume declared
            } as never,
          },
        },
      }),
    ).toThrow(/consume must be a function/);
  });
});
