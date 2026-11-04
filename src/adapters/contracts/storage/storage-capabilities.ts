/**
 * Declared storage capabilities.
 *
 * Declarations must represent real guarantees provided by the backing
 * infrastructure. They are used to validate that required capabilities exist
 * before enabling dependent authentication features.
 */
export interface StorageCapabilities {
  /** Atomic get-and-delete (`consume`) is supported. */
  atomicConsume: boolean;
  /** Atomic refresh-token rotation (`rotate`) is supported. */
  atomicRefreshTokenRotation: boolean;
  /** Atomic monotonic increment (`increment`) is supported. */
  atomicIncrement: boolean;
  /** TTL-based expiration is supported. */
  ttl: boolean;
}
