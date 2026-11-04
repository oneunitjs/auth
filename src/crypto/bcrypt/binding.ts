import type { BcryptBinding } from "../password-hasher.js";

/**
 * Whether the optional `bcrypt` package is installed and loadable.
 *
 * In CommonJS this probes `require.resolve` synchronously. In ESM a
 * synchronous optional-dependency probe is not available, so this returns
 * `false`; the `BcryptNodeBinding` still lazily imports `bcrypt` and reports
 * a clear error when it is absent.
 */
export function isBcryptAvailable(): boolean {
  if (typeof require === "function") {
    try {
      require.resolve("bcrypt");
      return true;
    } catch {
      return false;
    }
  }
  return false;
}

/**
 * Official bcrypt binding backed by the optional `bcrypt` package.
 *
 * Implements {@link BcryptBinding} so applications can use bcrypt without
 * supplying their own binding. Throws a clear error when `bcrypt` is not
 * installed.
 */
export class BcryptNodeBinding implements BcryptBinding {
  private readonly modulePromise: Promise<{
    hash(password: string, saltOrRounds: string | number): Promise<string>;
    compare(password: string, hash: string): Promise<boolean>;
    getRounds(hash: string): number;
  }>;

  constructor() {
    this.modulePromise = this.loadBcrypt();
  }

  private async loadBcrypt(): Promise<{
    hash(password: string, saltOrRounds: string | number): Promise<string>;
    compare(password: string, hash: string): Promise<boolean>;
    getRounds(hash: string): number;
  }> {
    try {
      // Dynamic import works in both ESM and CommonJS and only fails when
      // `bcrypt` is not installed.
      const bcrypt = await import("bcrypt") as {
        hash(password: string, saltOrRounds: string | number): Promise<string>;
        compare(password: string, hash: string): Promise<boolean>;
        getRounds(hash: string): number;
      };
      return bcrypt;
    } catch (error) {
      throw new Error(
        "bcrypt is not installed. Add `bcrypt` to your dependencies or supply a custom BcryptBinding.",
        { cause: error },
      );
    }
  }

  private async module(): Promise<{
    hash(password: string, saltOrRounds: string | number): Promise<string>;
    compare(password: string, hash: string): Promise<boolean>;
    getRounds(hash: string): number;
  }> {
    return this.modulePromise;
  }

  async hash(password: string, rounds: number): Promise<string> {
    const bcrypt = await this.module();
    return bcrypt.hash(password, rounds);
  }

  async compare(password: string, hash: string): Promise<boolean> {
    const bcrypt = await this.module();
    return bcrypt.compare(password, hash);
  }
}
