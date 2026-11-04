import type { Auth } from "../core/auth.js";

import { expressAdapter } from "./express/index.js";
import { fastifyAdapter } from "./fastify/index.js";
import { koaAdapter } from "./koa/index.js";
import { uwsAdapter, snapshotUwsRequest } from "./uws/index.js";

export { expressAdapter, fastifyAdapter, koaAdapter, uwsAdapter, snapshotUwsRequest };

export function createAdapters(auth: Auth) {
  return {
    express: expressAdapter(auth),
    fastify: fastifyAdapter(auth),
    koa: koaAdapter(auth),
    uws: uwsAdapter(auth),
    uWebSockets: uwsAdapter(auth),
  };
}

export {
  validateStorageAdapter,
} from "./storage/storage-adapter.js";

export {
  validateEventAdapter,
} from "./events/event-adapter.js";

export {
  createAdapterRegistry,
  type AdapterRegistry,
} from "./adapter-registry.js";

export type {
  KeyValueStore,
  SessionStore,
  RefreshTokenStore,
  RevocationStore,
  VersionStore,
} from "./contracts/storage/index.js";

export type {
  StorageErrorCode,
  StorageErrorInfo,
} from "./storage/storage-errors.js";

export type {
  StorageCapabilities,
} from "./contracts/storage/storage-capabilities.js";

export type {
  AuthEvent,
  EventPublisher,
  EventSubscriber,
  Unsubscribe,
} from "./contracts/events/index.js";

export type {
  Logger,
} from "../logging/types.js";

export type {
  StorageAdapter,
  EventAdapters,
  AuthAdapters,
} from "../types/index.js";
