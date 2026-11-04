import type { AuthEvent } from "./auth-event.js";

/**
 * Event publisher contract.
 *
 * Publishing is optional. Delivery guarantees (at-most-once, at-least-once,
 * ordering) are documented by the implementing infrastructure.
 */
export interface EventPublisher {
  publish(event: AuthEvent<unknown>): Promise<void>;
}
