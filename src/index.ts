export {
  AuthError,
  InvalidTokenError,
  TokenExpiredError,
  UnauthorizedError,
  ForbiddenError,
  ConfigurationError,
  OAuthError,
  ProviderError,
  ValidationError,
  InvalidRedirectUriError,
} from "./errors/index.js";

export {
  validateRedirectUri,
} from "./oauth/redirect-uri.js";

export {
  encode,
  decode,
  decodeUnsafe,
  encodeAccessToken,
  encodeRefreshToken,
} from "./crypto/index.js";

export {
  SharedJwksCache,
} from "./cache/shared-cache.js";

export type {
  SharedJwksCacheOptions,
  ResolvedSharedJwksCacheOptions,
} from "./cache/shared-cache.js";

export {
  CacheProvider,
  defaultCacheProvider,
} from "./cache/cache-provider.js";

export type {
  CacheProviderOptions,
} from "./cache/cache-provider.js";

export {
  RBAC,
  createRBAC,
  defineRoles,
  matchPermission,
} from "./rbac/index.js";

export {
  createAuthContext,
  getCurrentAuthContext,
  runWithAuthContext,
} from "./core/context.js";

export type { AuthContext } from "./core/context.js";

export {
  hashPassword,
  verifyPassword,
  needsRehash,
  hashScryptPassword,
  verifyScryptPassword,
  scryptNeedsRehash,
  Argon2idPasswordHasher,
  BcryptPasswordHasher,
  CompositePasswordHasher,
  ScryptPasswordHasher,
  createPasswordHasher,
  getDefaultPasswordHasher,
  setDefaultPasswordHasher,
  createBcryptPasswordHasher,
  BcryptNodeBinding,
  isBcryptAvailable,
  ARGON2ID_RECOMMENDED_PROFILE,
} from "./crypto/index.js";

export type {
  PasswordHasher,
  Argon2idPolicy,
  BcryptBinding,
} from "./crypto/index.js";

export {
  configureHttp,
  dispatchHttp,
  dispatchHttpWithRetry,
  getHttpConfig,
  resetHttpConfig,
  HttpClient,
  resolveRetryConfig,
} from "./http/index.js";

export type {
  HttpTransport,
  HttpClientConfig,
  HttpRetryConfig,
  ResolvedHttpRetryConfig,
  DispatchHttpRetryStats,
  DispatchHttpWithRetryOptions,
} from "./http/index.js";

export {
  ExternalTokenVerifier,
  createExternalTokenVerifier,
} from "./external-token/index.js";

export type {
  TrustedIssuerConfig,
  ExternalTokenResult,
  ExternalTokenVerifyOptions,
  ExternalKeySource,
} from "./external-token/index.js";

export {
  emitDiagnostic,
  setDiagnosticsObserver,
  resetDiagnostics,
  getDiagnosticsStats,
  setDiagnosticsOverflowPolicy,
  setDiagnosticsErrorCallback,
} from "./diagnostics/index.js";

export type {
  AuthDiagnosticEvent,
  DiagnosticsObserver,
  DiagnosticFailureCategory,
  DiagnosticsStats,
  DiagnosticsOverflowPolicy,
  DiagnosticsErrorCallback,
} from "./diagnostics/index.js";

export {
  PLATFORM_COMPATIBILITY,
} from "./platform.js";

export {
  OAuth,
  createOAuth,
  createMemoryStateStore,
} from "./oauth/index.js";

export {
  TokenIntrospector,
  createTokenIntrospector,
  IntrospectionError,
} from "./oauth/index.js";

export type {
  IntrospectionConfig,
  IntrospectionResult,
} from "./oauth/index.js";

export {
  createProvider,
  getProvider,
  builtinProviders,
  pkceVerifier,
  pkceChallenge,
  google,
  github,
  instagram,
  facebook,
  twitter,
  discord,
  apple,
  linkedin,
  microsoft,
  reddit,
  twitch,
  slack,
  spotify,
  tiktok,
} from "./oauth/providers/index.js";

export {
  Auth,
  auth,
  createAuth,
  createMemoryRefreshStore,
  createMemorySessionStore,
} from "./core/index.js";

export {
  expressAdapter,
  fastifyAdapter,
  koaAdapter,
  uwsAdapter,
  snapshotUwsRequest,
} from "./adapters/index.js";

export {
  createAdapterRegistry,
  validateStorageAdapter,
  validateEventAdapter,
  createAdapters,
} from "./adapters/index.js";

export type {
  StorageErrorCode,
  StorageErrorInfo,
} from "./adapters/index.js";

export {
  parseExpiresIn,
  isValidExpiresIn,
  randomToken,
  randomState,
  extractBearerToken,
} from "./utils.js";

export type {
  AuthErrorOptions,
  JwtSignOptions,
  JwtVerifyOptions,
  JwtPayload,
  Secret,
  RoleDefinition,
  RBACOptions,
  MatcherCacheOptions,
  AuthSubject,
  PasswordOptions,
  OAuthProfile,
  OAuthTokens,
  OAuthProviderConfig,
  OAuthProvider,
  ProviderDefinition,
  StateStore,
  SessionStore,
  OAuthOptions,
  OAuthAuthorizeOptions,
  UserRecord,
  UserStore,
  RedirectUriPolicy,
  RefreshRecord,
  RefreshStore,
  LoginOptions,
  LoginResult,
  AuthOptions,
  SessionRevocationResult,
  SessionRevocationStatus,
  SessionVersionPolicy,
  PasswordAlgorithm,
  RequestLike,
  ExtractTokenOptions,
  UwsHttpResponse,
  UwsHttpRequest,
  UwsRequestSnapshot,
  UwsHandler,
  ExpressRequestLike,
  ExpressResponseLike,
  ExpressNext,
  KoaContextLike,
  FastifyLike,
  FastifyRequestLike,
  FastifyReplyLike,
  PersistenceAdapter,
  EventAdapter,
  PersistenceErrorCode,
  PersistenceErrorInfo,
  KeyValueStore,
  RevocationStore,
  VersionStore,
  KafkaProducerLike,
  KafkaEventOptions,
} from "./types/index.js";

export type {
  Logger,
} from "./logging/types.js";

export {
  createSafeLogger,
} from "./logging/logger.js";

export {
  createAuthEvent,
  type CreateAuthEventOptions,
  EVENT_VERSION,
  sanitizeEventPayload,
  type SanitizeEventOptions,
  PROHIBITED_KEYS,
  MAX_STRING_LENGTH,
  MAX_OBJECT_DEPTH,
  EVENT_CATEGORIES,
  AUTH_EVENT_TYPES,
  type AuthEventType,
  EventDispatcher,
  EventTopicRouter,
} from "./events/index.js";
