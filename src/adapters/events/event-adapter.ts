import type { EventAdapters } from "../../types/index.js";
import { ConfigurationError } from "../../errors/index.js";

/**
 * Validates that an event adapter exposes the methods it claims to support.
 */
export function validateEventAdapter(adapter: EventAdapters): EventAdapters {
  if (adapter.publisher && typeof adapter.publisher.publish !== "function") {
    throw new ConfigurationError("EventAdapters.publisher.publish must be a function", {
      code: "INVALID_ADAPTER",
    });
  }

  if (adapter.subscriber && typeof adapter.subscriber.subscribe !== "function") {
    throw new ConfigurationError("EventAdapters.subscriber.subscribe must be a function", {
      code: "INVALID_ADAPTER",
    });
  }

  return adapter;
}
