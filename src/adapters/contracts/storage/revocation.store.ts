/**
 * Revocation storage adapter contract.
 */
export interface RevocationStore {
  revoke(
    tokenId: string,
    options?: {
      expiresAt?: number;
    },
  ): Promise<void>;

  isRevoked(tokenId: string): Promise<boolean>;
}
