import type { SessionStore } from "../../src/index.js";

export function fakeSessionStore(initialVersion = 0) {
  let version = initialVersion;
  const revoked = new Set<string>();
  return {
    async getVersion(_userId: string | number) {
      return version;
    },
    async bumpVersion(_userId: string | number) {
      version += 1;
      return version;
    },
    async revokeSession(jti: string) {
      revoked.add(jti);
    },
    async isSessionRevoked(sessionId: string) {
      return revoked.has(sessionId);
    },
    get version() {
      return version;
    },
    set version(v: number) {
      version = v;
    },
    get revokedSet() {
      return revoked;
    },
    clearRevoked() {
      revoked.clear();
    },
  } as SessionStore;
}

export function failingSessionStore() {
  return {
    async getVersion() {
      return 0;
    },
    async bumpVersion() {
      throw new Error("offline");
    },
    async revokeSession() {
      throw new Error("offline");
    },
    async isSessionRevoked() {
      throw new Error("offline");
    },
  } as SessionStore;
}

export function sessionStoreWithoutBumpVersion() {
  return {
    async getVersion() {
      return 0;
    },
    async isSessionRevoked() {
      return false;
    },
  } as SessionStore;
}

export function sessionStoreWithoutRevokeSession() {
  return {
    async getVersion() {
      return 0;
    },
    async bumpVersion() {
      return 1;
    },
  } as SessionStore;
}
