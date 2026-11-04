import type { UserStore } from "../../src/index.js";

export function failingUserStore() {
  return {} as UserStore;
}

export function userStoreWithoutCreate() {
  return {
    async findById() {
      return null;
    },
    async findByEmail() {
      return null;
    },
    async findByUsername() {
      return null;
    },
    async findByCredentials() {
      return null;
    },
  } as UserStore;
}

export function userStoreWithoutFindByCredentials() {
  return {
    async findByEmail() {
      return null;
    },
    async findByUsername() {
      return null;
    },
    async create() {
      return { id: 1 } as never;
    },
  } as UserStore;
}

export function userStoreWithoutUpdatePassword() {
  return {
    async findByCredentials() {
      return {
        id: 1,
        email: "user@example.com",
        passwordHash: "existing-hash",
      };
    },
    async create() {
      return { id: 1 } as never;
    },
  } as UserStore;
}
