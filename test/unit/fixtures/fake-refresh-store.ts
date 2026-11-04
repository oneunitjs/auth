import type { RefreshStore, RefreshRecord } from "../../src/index.js";

export function fakeRefreshStore() {
  const store = new Map<string, RefreshRecord & { consumed: boolean }>();
  return {
    async save(record: RefreshRecord) {
      store.set(record.id, { ...record, consumed: false });
    },
    async get(id: string) {
      const record = store.get(id);
      return record ?? null;
    },
    async consume(id: string) {
      const record = store.get(id);
      if (!record || record.consumed) {
        return null;
      }
      record.consumed = true;
      return record;
    },
    async revoke(id: string) {
      store.delete(id);
    },
    get size() {
      return store.size;
    },
    clear() {
      store.clear();
    },
  } as RefreshStore;
}

export function refreshingStoreWithoutConsume() {
  return {
    async save() {},
    async get() {
      return null;
    },
    async revoke() {},
  } as RefreshStore;
}
