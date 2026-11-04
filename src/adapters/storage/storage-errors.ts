/**
 * Normalized storage error categories.
 *
 * Infrastructure-specific errors are mapped to these stable categories so
 * core modules do not depend on provider-specific error types. The original
 * cause is preserved where supported.
 */
export type StorageErrorCode =
  | "UNAVAILABLE"
  | "TIMEOUT"
  | "CONFLICT"
  | "NOT_FOUND"
  | "INVALID_DATA"
  | "UNSUPPORTED_OPERATION"
  | "UNKNOWN";

export interface StorageErrorInfo {
  code: StorageErrorCode;
  message: string;
  cause?: unknown;
}
