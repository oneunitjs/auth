/**
 * Version storage adapter contract.
 *
 * `increment()` must be atomic and monotonic so session versions cannot
 * regress under concurrent writes.
 */
export interface VersionStore {
  get(subjectId: string): Promise<number>;

  increment(subjectId: string): Promise<number>;
}
