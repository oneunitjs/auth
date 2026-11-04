/**
 * Standard authentication event envelope.
 *
 * All fields are required except `metadata`. Payloads must not contain
 * sensitive authentication information (passwords, tokens, codes, state,
 * verifiers, client secrets, private keys).
 */
export interface AuthEvent<T = unknown> {
  /** Globally unique event identifier. */
  id: string;
  /** Stable event type, e.g. `auth.login.succeeded`. */
  type: string;
  /** Explicit schema version. */
  version: number;
  /** ISO 8601 UTC timestamp when the event occurred. */
  occurredAt: string;
  /** Identifiable source of the event, e.g. the service name. */
  source: string;
  /** Event payload, free of sensitive authentication data. */
  payload: T;
  /** Optional tracing and correlation metadata. */
  metadata?: {
    correlationId?: string;
    causationId?: string;
    tenantId?: string;
    traceId?: string;
  };
}
