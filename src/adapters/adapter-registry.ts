import type { StorageAdapter, EventAdapters, AuthAdapters } from "../types/index.js";
import type { Logger } from "../logging/types.js";
import { validateStorageAdapter } from "./storage/storage-adapter.js";
import { validateEventAdapter } from "./events/event-adapter.js";
import type { StorageCapabilities } from "./contracts/storage/storage-capabilities.js";

/**
 * Adapter registry.
 *
 * Receives adapter configuration, validates interfaces and declared
 * capabilities, constructs safe internal wrappers, and exposes the validated
 * adapters scoped to a single authentication instance.
 *
 * No automatic vendor detection, package discovery, global mutable state, or
 * dynamic module loading is performed.
 */
export interface AdapterRegistry {
  storage: StorageAdapter | undefined;
  events: EventAdapters | undefined;
  logger: Logger | undefined;
  capabilities: StorageCapabilities;
}

export function createAdapterRegistry(config: {
  adapters?: AuthAdapters;
  capabilities?: StorageCapabilities;
}): AdapterRegistry {
  const rawStorage = config.adapters?.storage;
  const rawEvents = config.adapters?.events;
  const logger = config.adapters?.logger;

  const capabilities: StorageCapabilities = {
    atomicConsume: false,
    atomicRefreshTokenRotation: false,
    atomicIncrement: false,
    ttl: false,
    ...config.capabilities,
  };

  let storage: StorageAdapter | undefined;
  if (rawStorage) {
    storage = validateStorageAdapter(rawStorage, capabilities);
  }

  let events: EventAdapters | undefined;
  if (rawEvents) {
    events = validateEventAdapter(rawEvents);
  }

  return {
    storage,
    events,
    logger,
    capabilities,
  };
}
