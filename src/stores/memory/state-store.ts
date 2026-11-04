import type { StateStore } from "../../types/index.js";

export function createMemoryStateStore(): StateStore {
  const store = new Map<string, { value: unknown; expiresAt: number }>();

  return {
    async set(key, value, ttlSeconds = 600) {
      store.set(key, {
        value,
        expiresAt: Date.now() + ttlSeconds * 1000,
      });
    },
    async get(key) {
      const entry = store.get(key);
      if (!entry) {
        return null;
      }
      if (entry.expiresAt <= Date.now()) {
        store.delete(key);
        return null;
      }
      return entry.value;
    },
    async delete(key) {
      store.delete(key);
    },
    async consume(key) {
      const entry = store.get(key);
      if (!entry) {
        return null;
      }
      // Read and delete in the same synchronous critical section: no await
      // between them, so a concurrent consumer cannot observe the same entry.
      store.delete(key);
      if (entry.expiresAt <= Date.now()) {
        return null;
      }
      return entry.value;
    },
  };
}
