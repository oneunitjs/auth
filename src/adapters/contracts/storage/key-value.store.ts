/**
 * Key-value storage adapter contract.
 *
 * Operations are string-based and TTL-aware. `consume()` must atomically
 * retrieve and delete a value so a one-time credential cannot be read twice.
 */
export interface KeyValueStore {
  get(key: string): Promise<string | null>;

  set(
    key: string,
    value: string,
    options?: {
      ttlSeconds?: number;
    },
  ): Promise<void>;

  delete(key: string): Promise<void>;

  consume(key: string): Promise<string | null>;
}
