export {
  createAuthEvent,
  type CreateAuthEventOptions,
  EVENT_VERSION,
} from "./factory/index.js";

export {
  sanitizeEventPayload,
  type SanitizeEventOptions,
  PROHIBITED_KEYS,
  MAX_STRING_LENGTH,
  MAX_OBJECT_DEPTH,
} from "./sanitization/index.js";
export {
  AUTH_EVENT_TYPES,
  type AuthEventType,
  EVENT_CATEGORIES,
  type EventCategoryMap,
  type LoginSucceededPayload,
  type LoginFailedPayload,
  type RegistrationSucceededPayload,
  type RegistrationFailedPayload,
  type LogoutSucceededPayload,
  type SessionCreatedPayload,
  type SessionRevokedPayload,
  type TokenIssuedPayload,
  type TokenValidationSucceededPayload,
  type TokenValidationFailedPayload,
  type TokenRefreshedPayload,
  type OAuthLoginSucceededPayload,
  type OAuthLoginFailedPayload,
  type AuthEventPayload,
} from "./catalog/index.js";

export {
  EventDispatcher,
  type EventDispatcherConfig,
  type PublishResult,
  type DeliveryMode,
} from "./dispatch/index.js";

export {
  EventTopicRouter,
  type TopicMapping,
  type TopicRouterConfig,
  type ResolvedTopic,
  type EventCategory,
} from "./dispatch/event-topic-router.js";
