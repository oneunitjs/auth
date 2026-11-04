/**
 * Session storage adapter contract.
 *
 * Stores opaque session data keyed by session id, with TTL support.
 */
export interface SessionStore<T = unknown> {
  get(id: string): Promise<T | null>;

  set(
    id: string,
    session: T,
    options?: {
      ttlSeconds?: number;
    },
  ): Promise<void>;

  delete(id: string): Promise<void>;
}
