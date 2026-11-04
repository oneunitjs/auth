import type { Logger } from "./types.js";

const SECRET_KEYS = new Set([
  "password",
  "passwordhash",
  "secret",
  "refreshsecret",
  "accesstoken",
  "refreshtoken",
  "id_token",
  "idtoken",
  "token",
  "authorizationcode",
  "code",
  "verifier",
  "codeverifier",
  "state",
  "clientsecret",
  "client_secret",
  "access_token",
  "refresh_token",
  "idtoken",
  "authorization",
]);

function isSecretKey(key: string): boolean {
  return SECRET_KEYS.has(key.toLowerCase());
}

function sanitizePayload(payload: unknown): unknown {
  if (payload === null || typeof payload !== "object") {
    return payload;
  }
  if (Array.isArray(payload)) {
    return payload.map(sanitizePayload);
  }
  const next: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(payload as Record<string, unknown>)) {
    if (isSecretKey(key)) {
      continue;
    }
    next[key] = sanitizePayload(value);
  }
  return next;
}

/**
 * Wraps a configured Logger so internal modules never invoke logger methods
 * directly.
 *
 * - Missing methods are no-ops.
 * - Synchronous logger exceptions are swallowed so logging never interrupts
 *   library behavior.
 * - Logger failures are not recursively logged.
 * - No retries or asynchronous behavior.
 * - The consumer's logger is not mutated.
 * - Documented secret keys are removed from structured payloads before
 *   forwarding to the underlying logger.
 */
export function createSafeLogger(logger?: Logger): Required<Logger> {
  return {
    debug(payload, message) {
      try {
        logger?.debug?.(sanitizePayload(payload), message);
      } catch {
        // Logging must never interrupt library behavior.
      }
    },
    info(payload, message) {
      try {
        logger?.info?.(sanitizePayload(payload), message);
      } catch {
        // Logging must never interrupt library behavior.
      }
    },
    warn(payload, message) {
      try {
        logger?.warn?.(sanitizePayload(payload), message);
      } catch {
        // Logging must never interrupt library behavior.
      }
    },
    error(payload, message) {
      try {
        logger?.error?.(sanitizePayload(payload), message);
      } catch {
        // Logging must never interrupt library behavior.
      }
    },
  };
}
