/**
 * Refresh-token storage adapter contract.
 *
 * `rotate()` must atomically invalidate the old token and create its
 * replacement; concurrent rotations must not both succeed.
 */
export interface RefreshTokenStore<T = unknown> {
  get(id: string): Promise<T | null>;

  create(
    id: string,
    token: T,
    options?: {
      ttlSeconds?: number;
    },
  ): Promise<void>;

  rotate(
    oldId: string,
    newId: string,
    newToken: T,
    options?: {
      ttlSeconds?: number;
    },
  ): Promise<boolean>;

  revoke(id: string): Promise<void>;
}
