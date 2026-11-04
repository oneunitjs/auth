import type { AuthEvent } from "./auth-event.js";

/**
 * Event subscriber contract.
 *
 * `subscribe()` returns an unsubscribe function. Duplicate delivery is
 * expected and must be handled idempotently by the handler.
 */
export interface EventSubscriber {
  subscribe(
    eventType: string,
    handler: (event: AuthEvent<unknown>) => Promise<void>,
  ): Promise<Unsubscribe>;
}

export type Unsubscribe = () => Promise<void>;
