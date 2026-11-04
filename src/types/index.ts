import type { Logger } from "../logging/types.js";
import type { KeyObject } from "node:crypto";

export interface AuthErrorOptions {
  code?: string;
  status?: number;
  cause?: unknown;
}

export interface JwtSignOptions {
  expiresIn?: string | number;
  expiresInSeconds?: number;
  subject?: string | number;
  audience?: string | string[];
  issuer?: string;
  jwtid?: string;
  notBefore?: string | number;
  header?: Record<string, unknown>;
  algorithm?: string;
  keyid?: string;
  backend?: import("../crypto/jwt-backend.js").JwtBackend;
}

export interface JwtVerifyOptions {
  algorithms?: string[];
  audience?: string | string[];
  issuer?: string;
  subject?: string;
  clockTolerance?: number;
  ignoreExpiration?: boolean;
  complete?: boolean;
  acceptTokenType?: "access" | "refresh";
  backend?: import("../crypto/jwt-backend.js").JwtBackend;
  /**
   * Optional auth context to correlate token verification with diagnostics
   * and traces. Falls back to the active AsyncLocalStorage context.
   */
  context?: import("../core/context.js").AuthContext;
}

export type JwtPayload = Record<string, unknown> & {
  sub?: string;
  iat?: number;
  exp?: number;
  nbf?: number;
  aud?: string | string[];
  iss?: string;
  jti?: string;
  typ?: string;
  userId?: string | number;
  email?: string;
  username?: string;
  name?: string;
  roles?: string[];
  permissions?: string[];
  /** Session version, written only when a SessionStore is configured. */
  sv?: number;
  /** Session identifier, written only when a SessionStore is configured. */
  sid?: string;
};

export type Secret = string | Buffer;

/**
 * Cryptographic key material used for signing JWTs.
 */
export type JwtSigningKey = string | Uint8Array | KeyObject;

/**
 * Cryptographic key material used for verifying JWTs.
 */
export type JwtVerificationKey = string | Uint8Array | KeyObject;

export type JwtAlgorithm = "HS256" | "RS256" | "ES256";

export interface JwtAlgorithmPolicy {
  signing: JwtAlgorithm[];
  verification: JwtAlgorithm[];
}

export interface JwtSigningKeyOptions {
  algorithm?: JwtAlgorithm;
  kid?: string;
}

export interface JwtVerificationKeyOptions {
  algorithm?: JwtAlgorithm;
  kid?: string;
  issuer?: string;
  jwksUrl?: string;
  jwksCacheTtlMs?: number;
}

export interface JwtBackendConfig {
  signingKey?: JwtSigningKey;
  verificationKey?: JwtVerificationKey;
  keyResolver?: JwtKeyResolver;
  algorithmPolicy?: JwtAlgorithmPolicy;
}

export interface JwtBackend {
  sign(payload: JwtPayload, options: JwtSignOptions): Promise<string>;
  verify(token: string, options: JwtVerifyOptions): Promise<JwtPayload>;
}

export interface JwtKeyResolver {
  resolveSigningKey(options: JwtSigningKeyOptions): Promise<JwtSigningKey>;
  resolveVerificationKey(options: JwtVerificationKeyOptions): Promise<JwtVerificationKey>;
}

export interface RoleDefinition {
  name?: string;
  description?: string;
  permissions?: string | string[];
  perms?: string | string[];
  inherits?: string | string[];
  parents?: string | string[];
  parent?: string | string[];
}

export interface StoredRole {
  name: string;
  description: string;
}

export interface MatcherCacheOptions {
  /** Maximum number of compiled permission matchers to retain. */
  maxEntries?: number;
  /** Time-to-live in milliseconds for each entry. 0 disables expiry. */
  ttl?: number;
}

export interface RBACOptions {
  defaultRole?: string | null;
  permissions?: string[];
  roles?: Record<string, RoleDefinition> | Array<string | RoleDefinition>;
  matcherCache?: MatcherCacheOptions;
}

export interface AuthSubject {
  id?: string | number;
  role?: string;
  roles?: string | string[];
  permissions?: string | string[];
  [key: string]: unknown;
}

export type PasswordAlgorithm = "argon2id" | "scrypt" | "bcrypt";

export interface PasswordOptions {
  algorithm?: PasswordAlgorithm;
  saltBytes?: number;
  keyLength?: number;
  cost?: number;
  blockSize?: number;
  parallelism?: number;
  memoryKiB?: number;
  iterations?: number;
  salt?: string | Buffer;
}

export type SessionRevocationStatus = "revoked" | "not_found" | "not_configured" | "unavailable";

export type SessionRevocationResult =
  | { status: "revoked"; sessionId?: string }
  | { status: "not_found"; sessionId?: string }
  | { status: "not_configured" }
  | { status: "unavailable" };

export type SessionVersionPolicy = "reject" | "migration" | "disabled";

export interface OAuthProfile {
  provider?: string;
  subject?: string | number;
  id?: string | number;
  email?: string;
  emailVerified?: boolean;
  username?: string;
  name?: string;
  firstName?: string;
  lastName?: string;
  avatar?: string;
  profileUrl?: string;
  locale?: string;
  raw?: unknown;
  [key: string]: unknown;
}

export interface OAuthTokens {
  access_token?: string;
  refresh_token?: string;
  id_token?: string;
  token_type?: string;
  expires_in?: number;
  scope?: string;
  [key: string]: unknown;
}

export type TokenAuthMethod = "body" | "basic";

export interface RedirectUriPolicy {
  /**
   * Allowlist of redirect URIs trusted for this OAuth provider. A candidate
   * URI must match an entry exactly (string equality) to be permitted.
   * An empty array rejects every redirect URI (fail closed).
   */
  allowedRedirectUris: string[];
  /**
   * When true, permits HTTP redirect URIs on loopback hosts only
   * (`localhost`, `127.0.0.1`, `::1`) for local development. HTTPS is
   * required for every other host and in production. Not activated
   * implicitly by environment or request input.
   */
  allowLocalhostHttp?: boolean;
}

export interface OAuthProviderConfig {
  clientId?: string;
  clientSecret?: string;
  redirectUri?: string;
  scopes?: string[];
  /**
   * Whether PKCE (Proof Key for Code Exchange) is required for the
   * authorization-code flow. Defaults to `true`.
   */
  pkce?: boolean;
  /**
   * Local redirect URI policy trusted for this OAuth provider. A redirect
   * URI must match an entry in `allowedRedirectUris` exactly (after
   * validation) to be used in an authorization request or token exchange.
   * An absent or empty policy fails closed: no redirect URI is permitted.
   */
  redirectUriPolicy?: RedirectUriPolicy;
  extraAuthParams?: Record<string, unknown>;
  extraTokenParams?: Record<string, unknown>;
  userInfoHeaders?: Record<string, string>;
  tokenAuthMethod?: TokenAuthMethod;
  provider?: OAuthProvider | (Pick<OAuthProvider, "id"> & Partial<OAuthProvider>);
  /**
   * Where to fetch id_token signing keys. Defaults to Apple's published JWKS
   * endpoint. Only used by providers that carry an id_token in the token
   * response.
   */
  jwksUrl?: string;
  /**
   * Supply signing keys directly instead of fetching them. Useful for tests, for
   * offline environments, and for applications that already maintain their own
   * JWKS cache. Accepts a JWK set or a function returning one.
   */
  jwks?: Record<string, unknown> | (() => Promise<Record<string, unknown>> | Record<string, unknown>);
  /**
   * How long fetched keys are reused before being refreshed, in milliseconds.
   * Defaults to one hour. Apple rotates its keys infrequently, and an unknown
   * `kid` always triggers one immediate refetch regardless of this.
   */
  jwksCacheTtlMs?: number;
  /**
   * Set to false to skip id_token signature verification. Verification is on by
   * default and should stay on: an id_token is a bearer assertion of identity,
   * and accepting one without checking Apple's signature means anyone who can
   * influence the token response can choose the user. Only turn this off in a
   * test harness, never in production.
   */
  verifyIdTokenSignature?: boolean;
  [key: string]: unknown;
}

export interface AuthorizationUrlOptions {
  state?: string;
  redirectUri?: string;
  codeVerifier?: string;
  extraParams?: Record<string, unknown>;
}

export interface AuthorizationUrlResult {
  url: string;
  state?: string;
  codeVerifier?: string;
}

export interface ExchangeCodeOptions {
  code?: string;
  redirectUri?: string;
  codeVerifier?: string;
}

export interface OAuthProvider {
  id: string;
  name: string;
  authorizationUrl: string;
  tokenUrl: string;
  userInfoUrl?: string;
  scopes: string[];
  pkce: boolean;
  tokenAuthMethod: string;
  createAuthorizationUrl(config: OAuthProviderConfig, options?: AuthorizationUrlOptions): AuthorizationUrlResult;
  exchangeCode(config: OAuthProviderConfig, options?: ExchangeCodeOptions): Promise<OAuthTokens>;
  fetchProfile(config: OAuthProviderConfig, tokens: OAuthTokens): Promise<OAuthProfile>;
}

export type ProfileMapValue = string | ((source: Record<string, unknown>) => unknown);

export interface ProviderDefinition {
  id: string;
  name?: string;
  authorizationUrl: string;
  tokenUrl: string;
  userInfoUrl?: string;
  scopes?: string[];
  profileMap?: Record<string, ProfileMapValue>;
  tokenAuthMethod?: TokenAuthMethod;
  pkce?: boolean;
  extraAuthParams?: Record<string, unknown>;
  extraTokenParams?: Record<string, unknown>;
  userInfoHeaders?: Record<string, string>;
  parseProfile?: (tokens: OAuthTokens, config: OAuthProviderConfig) => OAuthProfile | Promise<OAuthProfile>;
}

export interface StateStore {
  set(key: string, value: unknown, ttlSeconds?: number): Promise<void> | void;
  get(key: string): Promise<unknown> | unknown;
  delete(key: string): Promise<void> | void;
  /**
   * Atomically look up and remove a single credential.
   *
   * A successful consume returns the credential exactly once: concurrent
   * consumers of the same key must not both succeed, and every subsequent
   * consume for that key returns null unless a new credential has been
   * created. Expired credentials return null and are removed.
   *
   * Store errors must propagate; they must not be interpreted as a missing
   * credential. Atomicity holds within the consistency boundary of the
   * backing store: the in-memory implementation is synchronous within a
   * single event loop, while distributed stores must use an atomic primitive
   * such as Redis GETDEL, a conditional delete, or a transaction. A store
   * that cannot provide this guarantee must not implement this interface.
   *
   * Supported atomic mechanisms by backend:
   *   - Redis: GETDEL, or a Lua script that reads and deletes atomically
   *   - SQL database: transaction with row locking, or conditional DELETE ... RETURNING
   *   - DynamoDB: conditional delete
   *   - MongoDB: atomic findOneAndDelete
   *   - In-memory Map: synchronous read and delete in one event-loop operation
   *
   * Do not implement atomicity with a separate read followed by delete, and
   * do not present a client-side or process-local mutex as distributed
   * atomicity.
   */
  consume(key: string): Promise<unknown | null> | unknown | null;
}

export interface OAuthOptions {
  redirectUri?: string;
  stateStore?: StateStore;
  providers?: Record<string, OAuthProviderConfig>;
  logger?: Logger;
  http?: import("../http/transport.js").HttpClientConfig;
}

export interface OAuthAuthorizeOptions {
  state?: string;
  redirectUri?: string;
  codeVerifier?: string;
  extraParams?: Record<string, unknown>;
  metadata?: unknown;
  ttlSeconds?: number;
}

export interface OAuthStateRecord {
  provider: string;
  redirectUri?: string;
  codeVerifier?: string;
  createdAt: number;
  metadata?: unknown;
}

export interface UserRecord {
  id: string | number;
  email?: string;
  username?: string;
  name?: string;
  avatar?: string;
  roles?: string[];
  role?: string;
  permissions?: string[];
  passwordHash?: string;
  provider?: string;
  providerId?: string | number;
  [key: string]: unknown;
}

export interface UserStore {
  findById?(id: string | number): Promise<UserRecord | null | undefined> | UserRecord | null | undefined;
  findByEmail?(email: string): Promise<UserRecord | null | undefined> | UserRecord | null | undefined;
  findByUsername?(username: string): Promise<UserRecord | null | undefined> | UserRecord | null | undefined;
  findByCredentials?(identifier: string): Promise<UserRecord | null | undefined> | UserRecord | null | undefined;
  findByProvider?(
    provider: string,
    providerId: string | number,
  ): Promise<UserRecord | null | undefined> | UserRecord | null | undefined;
  create?(input: Record<string, unknown>): Promise<UserRecord> | UserRecord;
  createFromProvider?(
    provider: string,
    profile: OAuthProfile,
    tokens: OAuthTokens,
  ): Promise<UserRecord> | UserRecord;
  linkProvider?(userId: string | number, provider: string, profile: OAuthProfile): Promise<unknown> | unknown;
  updatePassword?(userId: string | number, passwordHash: string): Promise<unknown> | unknown;
}

export interface RefreshRecord {
  id: string;
  userId: string | number;
  tokenHash: string;
  expiresAt: number;
}

export interface RefreshStore {
  save(record: RefreshRecord): Promise<void> | void;
  get(id: string): Promise<RefreshRecord | null | undefined> | RefreshRecord | null | undefined;
  /**
   * Atomically look up and remove a refresh record.
   *
   * A successful consume returns the record exactly once: concurrent
   * consumers of the same id must not both succeed, and every subsequent
   * consume for that id returns null unless a new record has been saved.
   * Expired records return null and are removed.
   *
   * Store errors must propagate; they must not be interpreted as a missing
   * record. Atomicity holds within the consistency boundary of the backing
   * store. A store that cannot provide this guarantee must not implement
   * this interface: refresh rotation must never fall back to get()+revoke().
   *
   * Supported atomic mechanisms by backend:
   *   - Redis: GETDEL, or a Lua script that reads and deletes atomically
   *   - SQL database: transaction with row locking, or conditional DELETE ... RETURNING
   *   - DynamoDB: conditional delete
   *   - MongoDB: atomic findOneAndDelete
   *   - In-memory Map: synchronous read and delete in one event-loop operation
   */
  consume(id: string): Promise<RefreshRecord | null | undefined> | RefreshRecord | null | undefined;
  revoke?(id: string): Promise<void> | void;
}

export interface LoginOptions {
  extractors?: string[];
  additionalClaims?: Record<string, unknown>;
  accessTokenTtl?: string | number;
  refreshTokenTtl?: string | number;
  refresh?: boolean;
  roles?: string[];
  /**
   * The authentication method used for this login. Used for event emission.
   * Defaults to "password" when not specified.
   */
  authenticationMethod?: "password" | "oauth" | "magic-link" | "other";
  /**
   * Optional auth context (request/trace/tenant IDs) to correlate this login
   * with diagnostics and traces. When omitted, the active AsyncLocalStorage
   * context is used; when none is active, the library generates one.
   */
  context?: import("../core/context.js").AuthContext;
}

export interface LoginResult {
  token: string;
  accessToken: string;
  refreshToken: string | null;
  payload: JwtPayload;
  user: {
    id: string | number;
    email?: string;
    username?: string;
    name?: string;
    roles: string[];
    permissions: string[];
  };
  oauth?: {
    provider: string;
    tokens: OAuthTokens;
    profile: OAuthProfile;
    state: unknown;
  };
}

export interface SessionStore {
  /**
   * The user's current session version. Tokens are minted carrying the value
   * that was current at login, and are rejected once it no longer matches, so
   * bumping the number logs out every session issued before that moment.
   * Returning `undefined` or `null` is treated as version 0.
   */
  getVersion(userId: string | number): Promise<number | undefined | null> | number | undefined | null;
  /**
   * Invalidate every session currently issued to this user and return the new
   * version. Called by `revokeAllSessions`.
   */
  bumpVersion?(userId: string | number): Promise<number> | number;
  /**
   * Invalidate one session by its session id. Called by `revokeSession`.
   */
  revokeSession?(jti: string): Promise<void> | void;
  /**
   * Whether a session (identified by its `sid` claim) has been revoked.
   * Implement this (or expose an equivalent revoked-session set/map/array) so
   * the library can reject access tokens whose session was revoked before
   * expiry. When it is unavailable, revocation can only be enforced within the
   * process that recorded it.
   */
  isSessionRevoked?(sessionId: string): Promise<boolean> | boolean;
}

export interface AuthOptions {
  secret: Secret;
  refreshSecret?: Secret;
  issuer?: string;
  audience?: string | string[];
  algorithm?: string;
  expiresIn?: string | number;
  /**
   * Optional JWT backend for replaceable signing/verification. When provided,
   * the library uses it instead of the built-in secret-based JWT backend.
   * When omitted, a default backend is created from `secret`/`refreshSecret`.
   */
  jwtBackend?: JwtBackend;
  accessTokenTtl?: string | number;
  refreshTokenTtl?: string | number;
  clockTolerance?: number;
  /**
   * Copy a `permissions` array from the user record into the access token.
   * Off by default: permissions should come from RBAC roles, otherwise one
   * attacker-writable database field grants arbitrary access.
   */
  trustUserPermissions?: boolean;
  userStore?: UserStore;
  refreshStore?: RefreshStore;
  /**
   * Enables session revocation. Configuring one adds an `sv` claim to minted
   * tokens and costs one store read per verification, which is why it is
   * opt-in: without it, revoking a refresh token only invalidates that one
   * session, and an already-issued access token stays valid until it expires.
   */
  sessionStore?: SessionStore;
  /**
   * How tokens without `sv` are treated when a session store is configured.
   * `migration` (default) accepts them as version 0. `reject` fails closed.
   * `disabled` skips version checks.
   */
  sessionVersionPolicy?: SessionVersionPolicy;
  passwordHasher?: import("../crypto/password-hasher.js").PasswordHasher;
  http?: import("../http/transport.js").HttpClientConfig;
  diagnostics?: import("../diagnostics/types.js").DiagnosticsObserver;
  rbac?: import("../rbac/index.js").RBAC | RBACOptions;
  roles?: RBACOptions | Record<string, RoleDefinition> | Array<string | RoleDefinition>;
  oauth?: import("../oauth/index.js").OAuth | OAuthOptions;
  providers?: Record<string, OAuthProviderConfig>;
  redirectUri?: string;
  /**
   * Optional logger injected by the application. All methods are optional;
   * omitting the logger entirely disables logging. Logger failures are caught
   * internally and never interrupt authentication, authorization, token, or
   * session operations.
   */
  logger?: Logger;
  onLogin?: (result: LoginResult) => unknown;
  onLink?: (event: { user: UserRecord; provider: string; profile: OAuthProfile }) => unknown;
  adapters?: AuthAdapters;
  /**
   * Optional event configuration. Supports a generic event publisher
   * (`publisher`) and/or first-party Kafka publishing (`kafka`).
   * When both `adapters.events` and `events` are provided, publishers from
   * both are combined (fan-out); `events` takes precedence for Kafka-specific
   * settings such as `failureMode` and `onPublishError`.
   */
  events?: EventAdapters;
  /**
   * Optional persistence adapter supplied by the consuming application. When
   * present, the library routes all applicable storage domains through it.
   * When omitted, existing in-memory stores are used (existing behavior).
   * The application owns infrastructure connections, pools, credentials, and
   * lifecycle; the library receives an already-configured adapter and never
   * installs, bundles, or manages infrastructure SDKs.
   */
  persistence?: PersistenceAdapter;
}

export type AuthHookName = "beforeLogin" | "afterLogin" | "afterVerify";
export type AuthHookHandler = (payload: unknown, auth: unknown) => unknown;

export interface RequestLike {
  headers?: Record<string, string | string[] | undefined> | { get?(name: string): string | null };
  cookies?: Record<string, string>;
  query?: string | Record<string, string | string[] | undefined>;
  getHeader?(name: string): string;
  getQuery?(): string;
  forEach?(cb: (key: string, value: string) => void): void;
  [key: string]: unknown;
}

export interface ExtractTokenOptions {
  cookie?: string;
  /**
   * Allow reading the token from `?access_token=` or `?token=`. Off by default:
   * a token in a URL is written to access logs, proxy logs, browser history, and
   * the Referer header sent to third parties, none of which a header or cookie
   * token leaks into. Only enable it for flows that genuinely cannot set a
   * header, such as an EventSource or a file download.
   */
  query?: boolean;
  optional?: boolean;
  passthrough?: boolean;
  audience?: string | string[];
  issuer?: string;
  clockTolerance?: number;
  acceptTokenType?: "access" | "refresh";
}

export interface UwsHttpResponse {
  cork?(cb: () => void): void;
  writeStatus?(status: string): this | void;
  writeHeader?(key: string, value: string): this | void;
  end?(body?: string | ArrayBuffer | Uint8Array): void;
  onAborted?(cb: () => void): void;
  [key: string]: unknown;
}

export interface UwsHttpRequest {
  getHeader?(name: string): string;
  getMethod?(): string;
  getUrl?(): string;
  getQuery?(): string;
  forEach?(cb: (key: string, value: string) => void): void;
  [key: string]: unknown;
}

export interface UwsRequestSnapshot {
  method?: string;
  url?: string;
  query?: string | Record<string, string>;
  headers: Record<string, string>;
  cookies?: Record<string, string>;
  res?: UwsHttpResponse;
  user?: JwtPayload | null;
  token?: string | null;
}

export type UwsHandler = (
  res: UwsHttpResponse,
  req: UwsHttpRequest,
  request?: UwsRequestSnapshot,
) => unknown;

export interface ExpressRequestLike {
  auth?: unknown;
  user?: JwtPayload | null;
  token?: string | null;
  headers?: Record<string, string | undefined>;
  cookies?: Record<string, string>;
  query?: Record<string, string | undefined>;
  [key: string]: unknown;
}

export interface ExpressResponseLike {
  status?(code: number): ExpressResponseLike;
  send?(body: unknown): unknown;
  code?(code: number): ExpressResponseLike;
  body?: unknown;
  [key: string]: unknown;
}

export type ExpressNext = (error?: unknown) => void;

export type ExpressHandler = (
  req: ExpressRequestLike,
  res: ExpressResponseLike,
  next?: ExpressNext,
) => unknown;

export interface KoaContextLike {
  request?: RequestLike;
  state: { user?: JwtPayload | null; token?: string | null;[key: string]: unknown };
  status: number;
  body: unknown;
}

export interface FastifyLike {
  decorate(name: string, value: unknown): void;
  decorateRequest(name: string, value: unknown): void;
  [key: string]: unknown;
}

export interface FastifyRequestLike {
  user?: JwtPayload | null;
  headers?: Record<string, string | undefined>;
  cookies?: Record<string, string>;
  query?: Record<string, string | undefined>;
  [key: string]: unknown;
}

export interface FastifyReplyLike {
  code(status: number): FastifyReplyLike;
  send(body: unknown): unknown;
}

export type {
  Logger,
} from "../logging/types.js";

export interface AuthAdapters {
  storage?: StorageAdapter;
  events?: EventAdapters;
  logger?: Logger;
}

/**
 * Composed storage capabilities. Applications supply only the capabilities
 * they actually need.
 */export interface StorageAdapter {
  keyValue?: import("../adapters/contracts/storage/key-value.store.js").KeyValueStore;
  sessions?: import("../adapters/contracts/storage/session.store.js").SessionStore;
  refreshTokens?: import("../adapters/contracts/storage/refresh-token.store.js").RefreshTokenStore;
  revocations?: import("../adapters/contracts/storage/revocation.store.js").RevocationStore;
  versions?: import("../adapters/contracts/storage/version.store.js").VersionStore;
}

/**
 * Structural shape of the Kafka producer operations used by the Kafka event
 * publisher. Avoids a direct KafkaJS type dependency in the core package.
 */
export interface KafkaProducerLike {
  send(request: {
    topic: string;
    messages: Array<{
      key?: string | null;
      value: string | Buffer;
      headers?: Record<string, string>;
    }>;
  }): Promise<unknown>;
}

/**
 * Kafka event publishing options. KafkaJS `Producer` satisfies
 * `KafkaProducerLike` structurally, so an existing KafkaJS producer can be
 * passed directly.
 */
export interface KafkaEventOptions {
  /**
   * An already-created Kafka producer. The application owns connect() and
   * disconnect().
   */
  producer: KafkaProducerLike;

  /**
   * Topic mapping by event category.
   */
  topics?: {
    authentication?: string;
    security?: string;
    session?: string;
    token?: string;
    [category: string]: string | undefined;
  };

  /**
   * Exact event-type-to-topic overrides, evaluated before category mapping.
   */
  byEventType?: Record<string, string>;

  /**
   * Default topic used when no category or event-type mapping resolves.
   */
  defaultTopic?: string;

  /**
   * Controls what happens when Kafka publishing fails.
   * Defaults to "best-effort".
   */
  failureMode?: "best-effort" | "required";

  /**
   * Optional message key strategy.
   * Defaults to "event-id".
   */
  messageKey?: "event-id" | "user-id" | "session-id";

  /**
   * Optional source/service identifier included in event envelope.
   */
  source?: string;

  /**
   * Optional callback for publishing failures.
   */
  onPublishError?: (error: Error, event: import("../adapters/contracts/events/auth-event.js").AuthEvent<unknown>) => void | Promise<void>;
}

/**
 * Composed event adapter capabilities. Publishing and subscribing are
 * independently configurable.
 */
export interface EventAdapters {
  publisher?: import("../adapters/contracts/events/event-publisher.js").EventPublisher;
  subscriber?: import("../adapters/contracts/events/event-subscriber.js").EventSubscriber;
  kafka?: KafkaEventOptions;
}

/**
 * Declared storage capabilities used for capability validation.
 */
export interface StorageCapabilities {
  atomicConsume: boolean;
  atomicRefreshTokenRotation: boolean;
  atomicIncrement: boolean;
  ttl: boolean;
}

/**
 * Unified persistence adapter contract supplied by the consuming application.
 *
 * The application owns infrastructure connections, pools, credentials, and
 * lifecycle. Each domain is independently optional; the library routes only
 * the domains the adapter provides. Domains not provided fall back to
 * existing in-memory behavior (or are unavailable for features that require
 * them).
 *
 * The library must never assume a particular infrastructure technology. All
 * access goes through these semantic contracts, never vendor SDKs directly.
 */
export interface PersistenceAdapter {
  keyValue?: import("../adapters/contracts/storage/key-value.store.js").KeyValueStore;
  sessions?: SessionStore;
  refreshTokens?: RefreshStore;
  revocations?: import("../adapters/contracts/storage/revocation.store.js").RevocationStore;
  versions?: import("../adapters/contracts/storage/version.store.js").VersionStore;

  users?: UserStore;

  initialize?: () => Promise<void>;
  close?: () => Promise<void>;
}

/**
 * Optional event adapter for publishing authentication lifecycle events.
 * Separate from authoritative persistence; publishing failures must never
 * break authentication.
 */
export interface EventAdapter {
  publish(event: import("../adapters/contracts/events/auth-event.js").AuthEvent<unknown>): Promise<void>;
}

/**
 * Error categories normalized at the persistence boundary. Safe causes are
 * preserved; credentials and connection strings are never exposed.
 */
export type PersistenceErrorCode =
  | "UNAVAILABLE"
  | "TIMEOUT"
  | "CONFLICT"
  | "NOT_FOUND"
  | "INVALID_DATA"
  | "UNSUPPORTED_OPERATION"
  | "CONFIGURATION_ERROR"
  | "ATOMIC_OPERATION_UNSUPPORTED"
  | "UNKNOWN";

export interface PersistenceErrorInfo {
  code: PersistenceErrorCode;
  message: string;
  cause?: unknown;
}

export type {
  KeyValueStore,
} from "../adapters/contracts/storage/key-value.store.js";

export type {
  RefreshTokenStore,
} from "../adapters/contracts/storage/refresh-token.store.js";

export type {
  RevocationStore,
} from "../adapters/contracts/storage/revocation.store.js";

export type {
  VersionStore,
} from "../adapters/contracts/storage/version.store.js";
