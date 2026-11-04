import type { UserRecord, OAuthProfile, OAuthTokens } from "../../src/index.js";

export const SECRET = "secret-key-for-testing-purposes-1234567890";
export const REFRESH_SECRET = "distinct-refresh-secret-for-testing-0987654321";

export const baseUser: UserRecord = {
  id: 1,
  email: "user@example.com",
  username: "testuser",
  name: "Test User",
  roles: ["member"],
  permissions: ["profile.read"],
};

export function memoryUsers(seed: UserRecord[] = []) {
  const users = new Map(seed.map((user) => [String(user.id), { ...user }]));
  let nextId = seed.length + 1;
  return {
    async findById(id: string | number) {
      return users.get(String(id)) ?? null;
    },
    async findByEmail(email: string) {
      return [...users.values()].find((u) => u.email === email) ?? null;
    },
    async findByUsername(username: string) {
      return [...users.values()].find((u) => u.username === username) ?? null;
    },
    async findByCredentials(identifier: string) {
      return (
        [...users.values()].find(
          (u) => u.email === identifier || u.username === identifier,
        ) ?? null
      );
    },
    async create(input: Record<string, unknown>) {
      const user = { id: nextId++, ...input } as UserRecord;
      users.set(String(user.id), user);
      return user;
    },
    async createFromProvider(
      provider: string,
      profile: OAuthProfile,
      tokens: OAuthTokens,
    ) {
      const user: UserRecord = {
        id: nextId++,
        email: profile.email,
        username: profile.username,
        name: profile.name,
        provider,
        providerId: profile.id,
        roles: ["member"],
      };
      users.set(String(user.id), user);
      return user;
    },
    async updatePassword(id: string | number, passwordHash: string) {
      const user = users.get(String(id));
      if (user) user.passwordHash = passwordHash;
    },
    async findByProvider(provider: string, providerId: string | number) {
      return (
        [...users.values()].find(
          (u) => u.provider === provider && String(u.providerId) === String(providerId),
        ) ?? null
      );
    },
    async linkProvider(id: string | number, provider: string, profile: OAuthProfile) {
      const user = users.get(String(id));
      if (user) {
        user.provider = provider;
        user.providerId = profile.id;
      }
    },
    users,
  };
}

export function makeTokenPayload(overrides: Record<string, unknown> = {}) {
  return {
    sub: "1",
    userId: 1,
    email: "user@example.com",
    roles: ["member"],
    permissions: ["profile.read"],
    typ: "access",
    ...overrides,
  };
}

export function makeRefreshPayload(overrides: Record<string, unknown> = {}) {
  return {
    sub: "1",
    userId: 1,
    typ: "refresh",
    jti: "refresh-jti-1",
    sid: "session-1",
    ...overrides,
  };
}
