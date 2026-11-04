import { ConfigurationError, ProviderError, UnauthorizedError, ValidationError } from "../errors/index.js";
import { JwtBackendImpl } from "../crypto/jwt-backend.js";
import type { JwtBackend } from "../crypto/jwt-backend.js";
import { RBAC } from "../rbac/index.js";
import { createMemoryRefreshStore } from "../stores/memory/refresh-store.js";
import { OAuth } from "../oauth/index.js";
import {
  getDefaultPasswordHasher,
  type PasswordHasher,
} from "../crypto/password-hasher.js";
import { createSafeLogger } from "../logging/logger.js";
import { createAdapterRegistry } from "../adapters/adapter-registry.js";
import { configureHttp } from "../http/transport.js";
import { emitDiagnostic, setDiagnosticsObserver } from "../diagnostics/index.js";
import {
  createAuthContext,
  getCurrentAuthContext,
  runWithAuthContext,
} from "../core/context.js";
import {
  createAuthEvent,
  sanitizeEventPayload,
  EventDispatcher,
} from "../events/index.js";
import type { AuthEventType, AuthEventPayload } from "../events/catalog/index.js";
import type { DeliveryMode } from "../events/dispatch/event-dispatcher.js";
import type {
  KafkaEventOptions,
  KafkaProducerLike,
  EventAdapters,
} from "../types/index.js";
import { KafkaEventPublisher } from "../adapters/events/kafka/kafka-event-publisher.js";
import type {
  AuthHookHandler,
  AuthHookName,
  AuthOptions,
  AuthSubject,
  ExtractTokenOptions,
  JwtPayload,
  JwtSignOptions,
  JwtVerifyOptions,
  LoginOptions,
  LoginResult,
  OAuthAuthorizeOptions,
  PasswordOptions,
  RBACOptions,
  RefreshStore,
  SessionStore,
  SessionRevocationResult,
  SessionVersionPolicy,
  RequestLike,
  RoleDefinition,
  Secret,
  UserRecord,
  UserStore,
  PersistenceAdapter,
} from "../types/index.js";
import type { Logger } from "../logging/types.js";
import {
  extractBearerToken,
  getHeader,
  isPlainObject,
  parseCookieHeader,
  parseExpiresIn,
  parseQueryString,
  randomToken,
  sha256,
  unique,
} from "../utils.js";

const DEFAULT_ACCESS_TTL = "15m";
const DEFAULT_REFRESH_TTL = "7d";
const REVOKED_SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;

/**
 * Claims that define *who* the token speaks for and *what* it may do. These are
 * derived from the authenticated user record and RBAC, so nothing a caller
 * supplies may overwrite them: a token minted for user 42 must never carry
 * `sub: "admin"`.
 */
const RESERVED_CLAIMS: ReadonlySet<string> = new Set([
  "sub",
  "userId",
  "roles",
  "permissions",
  "typ",
  "iss",
  "aud",
  "exp",
  "iat",
  "nbf",
  "jti",
  // Session version. Written by the library from the SessionStore and compared
  // on every verification, so it must not be settable by an extractor or by
  // additionalClaims.
  "sv",
  "sid",
]);

type ClaimExtractor = (user: UserRecord) => unknown;

export class Auth {
  secret: Secret;
  refreshSecret: Secret;
  issuer?: string;
  audience?: string | string[];
  algorithm: string;
  accessTokenTtl: string | number;
  refreshTokenTtl: string | number;
  clockTolerance: number;
  trustUserPermissions: boolean;
  userStore: UserStore | null;
  refreshStore: RefreshStore;
  sessionStore?: SessionStore;
  private revokedSessions = new Map<string, number>();
  onLogin: AuthOptions["onLogin"];
  onLink: AuthOptions["onLink"];
  rbac: RBAC;
  oauth: OAuth;
  claimExtractors = new Map<string, ClaimExtractor>();
  hooks: Record<AuthHookName, AuthHookHandler[]> = {
    beforeLogin: [],
    afterLogin: [],
    afterVerify: [],
  };
  logger: Required<Logger>;
  adapters: ReturnType<typeof createAdapterRegistry>;
  persistenceAdapter?: PersistenceAdapter;
  jwtBackend?: JwtBackend;
  passwordHasher: PasswordHasher;
  sessionVersionPolicy: SessionVersionPolicy;
  initialized = false;
  private eventDispatcher: EventDispatcher | null = null;
  private eventSource: string | null = null;
  private eventFailureMode: DeliveryMode = "best-effort";
  private dummyHashPromise: Promise<string> | null = null;

  constructor(options: Partial<AuthOptions> = {}) {
    if (!options.secret) {
      throw new ConfigurationError("Authentication secret is required");
    }

    const secretBytes =
      typeof options.secret === "string"
        ? Buffer.byteLength(options.secret, "utf8")
        : Buffer.byteLength(options.secret);
    if (secretBytes < 32) {
      throw new ConfigurationError(
        "Authentication secret must be at least 32 bytes (256 bits) of high-entropy material",
      );
    }

    this.secret = options.secret;
    this.refreshSecret = options.refreshSecret ?? options.secret;

    if (options.refreshSecret) {
      const refreshSecretBytes =
        typeof options.refreshSecret === "string"
          ? Buffer.byteLength(options.refreshSecret, "utf8")
          : Buffer.byteLength(options.refreshSecret);
      if (refreshSecretBytes < 32) {
        throw new ConfigurationError(
          "Refresh secret must be at least 32 bytes (256 bits) of high-entropy material",
        );
      }
    }
    this.issuer = options.issuer;
    this.audience = options.audience;
    this.algorithm = options.algorithm ?? "HS256";

    const SUPPORTED_ALGORITHMS = new Set(["HS256", "RS256", "ES256"]);
    if (!SUPPORTED_ALGORITHMS.has(this.algorithm)) {
      throw new ConfigurationError(`Unsupported algorithm: ${this.algorithm}`);
    }
    this.accessTokenTtl = options.accessTokenTtl ?? options.expiresIn ?? DEFAULT_ACCESS_TTL;
    this.refreshTokenTtl = options.refreshTokenTtl ?? DEFAULT_REFRESH_TTL;
    this.clockTolerance = options.clockTolerance ?? 0;
    this.trustUserPermissions = options.trustUserPermissions ?? false;

    this.userStore = options.userStore ?? null;
    this.refreshStore = options.refreshStore ?? createMemoryRefreshStore();
    this.sessionStore = options.sessionStore;
    this.onLogin = options.onLogin;
    this.onLink = options.onLink;

    this.rbac = normalizeRbac(options.rbac ?? options.roles);
    this.passwordHasher = options.passwordHasher ?? getDefaultPasswordHasher();
    this.sessionVersionPolicy = options.sessionVersionPolicy ?? "migration";

    this.logger = createSafeLogger(options.logger);
    if (options.http) {
      configureHttp(options.http);
    }
    if (options.diagnostics) {
      setDiagnosticsObserver(options.diagnostics);
    }

    this.adapters = createAdapterRegistry({
      adapters: options.adapters,
      capabilities: {
        atomicConsume: true,
        atomicRefreshTokenRotation: true,
        atomicIncrement: true,
        ttl: true,
      },
    });

    this.eventSource = (options.events?.kafka?.source ??
      options.adapters?.events?.kafka?.source ??
      "@oneunit/auth");

    // Merge events configuration from both locations. `events` (top-level)
    // takes precedence for Kafka-specific settings; publishers from both
    // locations are combined for fan-out.
    const mergedEvents: EventAdapters = {
      ...options.adapters?.events,
      ...options.events,
      publisher: options.events?.publisher ?? options.adapters?.events?.publisher,
      kafka: options.events?.kafka ?? options.adapters?.events?.kafka,
    };

    this.eventDispatcher = this.createEventDispatcher(mergedEvents);
    this.eventFailureMode = mergedEvents.kafka?.failureMode ?? "best-effort";

    this.oauth = options.oauth instanceof OAuth
      ? options.oauth
      : new OAuth(options.oauth ?? { providers: options.providers, redirectUri: options.redirectUri, logger: this.adapters.logger ?? options.logger });

    if (options.persistence) {
      this.persistenceAdapter = options.persistence;

      // Wire persistence adapter domains into auth stores. Explicitly
      // provided individual stores take precedence over the adapter.
      if (!options.refreshStore && this.persistenceAdapter.refreshTokens) {
        this.refreshStore = this.persistenceAdapter.refreshTokens;
      }
      if (!options.sessionStore && this.persistenceAdapter.sessions) {
        this.sessionStore = this.persistenceAdapter.sessions;
      }
      if (this.persistenceAdapter.users) {
        this.userStore = this.persistenceAdapter.users;
      }
    }

    this.jwtBackend = options.jwtBackend ?? new JwtBackendImpl({
      signingKey: this.secret,
      refreshSigningKey: this.refreshSecret,
      verificationKey: this.secret,
      refreshVerificationKey: this.refreshSecret,
      algorithmPolicy: {
        signing: [this.algorithm as "HS256" | "RS256" | "ES256"],
        verification: [this.algorithm as "HS256" | "RS256" | "ES256"],
      },
    });
  }

  /**
   * Initialize persistence wiring: call the adapter's `initialize()` if
   * provided. Safe to call multiple times; subsequent calls are no-ops.
   */
  async initialize(): Promise<void> {
    if (this.initialized) {
      return;
    }

    if (this.persistenceAdapter?.initialize) {
      await this.persistenceAdapter.initialize();
    }

    this.initialized = true;
  }

  /**
   * Close persistence backend connections cleanly. Safe to call multiple
   * times.
   */
  async close(): Promise<void> {
    if (this.persistenceAdapter?.close) {
      await this.persistenceAdapter.close();
    }
    this.initialized = false;
  }

  registerExtractor(name: string, extractor: ClaimExtractor): this {
    if (typeof extractor !== "function") {
      throw new ValidationError("Claim extractor must be a function");
    }
    if (RESERVED_CLAIMS.has(name)) {
      throw new ValidationError(
        `Claim name "${name}" is reserved and cannot be produced by an extractor. ` +
          "Identity and permission claims are derived from the user record and RBAC.",
      );
    }
    this.claimExtractors.set(name, extractor);
    return this;
  }

  hook(event: AuthHookName, handler: AuthHookHandler): this {
    if (!this.hooks[event]) {
      throw new ValidationError(`Unknown auth hook: ${event}`);
    }
    if (typeof handler !== "function") {
      throw new ValidationError("Hook handler must be a function");
    }
    this.hooks[event].push(handler);
    return this;
  }

  /**
   * Builds the event dispatcher from merged adapter configuration.
   *
   * Precedence policy: `events` (top-level) takes precedence over
   * `adapters.events` (legacy) for Kafka-specific settings
   * (`failureMode`, `onPublishError`). Publishers from both locations are
   * combined, so configuring a generic publisher in `adapters.events` and
   * Kafka in `events` results in fan-out to both transports.
   *
   * Fan-out policy: within a single `events` configuration, both `publisher`
   * (generic EventPublisher) and `kafka` (KafkaEventPublisher) are registered
   * concurrently. Every event is published to all registered publishers. If
   * you want only one transport, configure only one of `publisher` or `kafka`.
   *
   * Failure mode is taken from `events.kafka?.failureMode`, defaulting to
   * "best-effort". The `onPublishError` callback is also taken from Kafka
   * options and applies to all publishers.
   */
  private createEventDispatcher(
    events: EventAdapters | undefined,
  ): EventDispatcher | null {
    if (!events) {
      return null;
    }

    const publishers: Array<{ publish(event: unknown): Promise<void> }> = [];

    if (events.publisher) {
      publishers.push(events.publisher);
    }

    if (events.kafka) {
      publishers.push(this.createKafkaPublisher(events.kafka));
    }

    if (publishers.length === 0) {
      return null;
    }

    return new EventDispatcher({
      publishers: publishers as unknown as Array<{ publish(event: unknown): Promise<void> }>,
      failureMode: events.kafka?.failureMode ?? "best-effort",
      onPublishError: events.kafka?.onPublishError,
      logger: this.logger,
    });
  }

  private createKafkaPublisher(
    options: KafkaEventOptions,
  ): { publish(event: unknown): Promise<void> } {
    // Fail fast on invalid configuration: a misconfigured Kafka adapter is a
    // startup error, not a runtime delivery failure. Best-effort semantics
    // apply to broker failures at publish time, not to invalid setup.
    return new KafkaEventPublisher(options);
  }

  private async emitEvent(
    type: AuthEventType,
    payload: unknown,
    context?: { correlationId?: string; causationId?: string; tenantId?: string; traceId?: string },
  ): Promise<void> {
    if (!this.eventDispatcher || !this.eventSource) {
      return;
    }

    // Automatically propagate the active auth context for correlation,
    // trace, and tenant metadata when no explicit context is provided.
    const authContext = context ?? getCurrentAuthContext();

    const event = createAuthEvent({
      type,
      payload: sanitizeEventPayload(payload) as AuthEventPayload,
      source: this.eventSource,
      context: authContext as import("../core/context.js").AuthContext | undefined,
      correlationId: context?.correlationId,
      causationId: context?.causationId,
      tenantId: context?.tenantId,
      traceId: context?.traceId,
    });

    if (this.eventFailureMode === "required") {
      await this.eventDispatcher.dispatch(event);
      return;
    }

    try {
      await this.eventDispatcher.dispatch(event);
    } catch {
      // Best-effort: dispatch errors are handled internally by the dispatcher.
    }
  }

  async login(user: UserRecord, options: LoginOptions = {}): Promise<LoginResult> {
    if (!user || (user.id !== 0 && !user.id)) {
      throw new ValidationError("User with id is required for login");
    }

    const context = options.context ?? getCurrentAuthContext() ?? createAuthContext();
    return runWithAuthContext(context, async () => {
      this.logger.info(
        { event: "auth.login.started", userId: user.id },
        "Login started",
      );
      emitDiagnostic({ type: "auth.login.started", timestamp: Date.now() });

    await this.runHooks("beforeLogin", { user, options });

    const roles = unique([
      ...(Array.isArray(user.roles) ? user.roles : []),
      ...(user.role ? [user.role] : []),
    ]);
    // Permissions are derived from roles. A `permissions` field on the user
    // record is only honoured when the application opts in, because a single
    // tainted row (or a client-supplied field) would otherwise mint a token
    // carrying arbitrary grants.
    const permissions = unique([
      ...(this.trustUserPermissions && Array.isArray(user.permissions) ? user.permissions : []),
      ...[...this.rbac.subjectPermissions({ ...user, roles, permissions: undefined })],
    ]);

    const extra = await this.collectClaims(user, options.extractors);
    const additional = isPlainObject(options.additionalClaims) ? options.additionalClaims : {};
    for (const key of Object.keys(additional)) {
      if (RESERVED_CLAIMS.has(key)) {
        throw new ValidationError(
          `additionalClaims cannot override the reserved claim "${key}". ` +
            "Identity and permission claims are derived from the user record and RBAC.",
        );
      }
    }

    const payload: JwtPayload = {
      sub: String(user.id),
      userId: user.id,
      ...(user.email !== undefined && { email: user.email }),
      ...(user.username !== undefined && { username: user.username }),
      ...(user.name !== undefined && { name: user.name }),
      roles,
      permissions,
      ...extra,
      ...additional,
    };

    // Only stamped when a SessionStore is configured, so tokens are unchanged
    // for the many deployments that do not opt into session revocation.
    const sessionVersion = await this.currentSessionVersion(user.id);
    if (sessionVersion !== undefined) {
      payload.sv = sessionVersion;
    }
    // A session id links an access token to its session, so a single session
    // can be revoked without bumping the (user-wide) session version.
    const sessionId = this.sessionStore ? randomToken(16) : undefined;
    if (sessionId !== undefined) {
      payload.sid = sessionId;
    }

    const subject = String(user.id);

    const accessToken = await this.jwtBackend!.sign({ ...payload, typ: "access" }, {
      audience: this.audience,
      issuer: this.issuer,
      jwtid: randomToken(16),
      expiresIn: options.accessTokenTtl ?? this.accessTokenTtl,
    });

    let refreshToken: string | null = null;
    if (options.refresh !== false) {
      const jwtid = sessionId ?? randomToken(16);
      refreshToken = await this.jwtBackend!.sign(
        { sub: subject, userId: user.id, roles, ...(sessionVersion !== undefined && { sv: sessionVersion }), ...(sessionId !== undefined && { sid: sessionId }), typ: "refresh" },
        {
          audience: this.audience,
          issuer: this.issuer,
          jwtid,
          expiresIn: options.refreshTokenTtl ?? this.refreshTokenTtl,
        },
      );
      await this.refreshStore.save({
        id: jwtid,
        userId: user.id,
        tokenHash: sha256(refreshToken),
        expiresAt: Date.now() + parseExpiresIn(options.refreshTokenTtl ?? this.refreshTokenTtl) * 1000,
      });
    }

    const result: LoginResult = {
      token: accessToken,
      accessToken,
      refreshToken,
      payload,
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        name: user.name,
        roles,
        permissions,
      },
    };


    await this.runHooks("afterLogin", result);
    if (typeof this.onLogin === "function") {
      await this.onLogin(result);
    }

    this.logger.info(
      { event: "auth.login.succeeded", userId: user.id, roles: result.user.roles },
      "Login succeeded",
    );
    emitDiagnostic({ type: "auth.login.succeeded", timestamp: Date.now() });

    await this.emitEvent("auth.login.succeeded", {
      userId: user.id,
      sessionId: result.payload.sid,
      authenticationMethod: options.authenticationMethod ?? "password",
      provider: typeof result.payload.provider === "string" ? result.payload.provider : undefined,
    });

    if (sessionId) {
      await this.emitEvent("auth.session.created", {
        userId: user.id,
        sessionId,
        tenantId: result.payload.tenantId,
      });
    }

    await this.emitEvent("auth.token.issued", {
      userId: user.id,
      sessionId: result.payload.sid,
      tokenType: "access",
      tenantId: result.payload.tenantId,
    });

    return result;
  });
  }

  async loginWithPassword(identifier: string, password: string, options: LoginOptions = {}): Promise<LoginResult> {
    if (!this.userStore?.findByCredentials && !this.userStore?.findByEmail && !this.userStore?.findByUsername) {
      throw new ConfigurationError("A userStore with credential lookup is required for password login");
    }

    const user = this.userStore.findByCredentials
      ? await this.userStore.findByCredentials(identifier)
      : (await this.userStore.findByEmail?.(identifier)) ?? (await this.userStore.findByUsername?.(identifier));

    if (!user?.passwordHash) {
      await this.verifyDummyHash(password);
      await this.emitEvent("auth.login.failed", {
        reason: "invalid_credentials",
        authenticationMethod: "password",
      });
      emitDiagnostic({ type: "auth.login.failed", timestamp: Date.now(), reason: "invalid_credentials" });
      throw new UnauthorizedError("Invalid credentials");
    }

    const valid = await this.passwordHasher.verify(password, user.passwordHash);
    if (!valid) {
      await this.emitEvent("auth.login.failed", {
        reason: "invalid_credentials",
        authenticationMethod: "password",
      });
      emitDiagnostic({ type: "auth.login.failed", timestamp: Date.now(), reason: "invalid_credentials" });
      throw new UnauthorizedError("Invalid credentials");
    }

    if (this.passwordHasher.needsRehash(user.passwordHash) && this.userStore.updatePassword) {
      try {
        const nextHash = await this.passwordHasher.hash(password);
        await this.userStore.updatePassword(user.id, nextHash);
        emitDiagnostic({ type: "password.hash.upgraded", timestamp: Date.now(), algorithm: this.passwordHasher.algorithm });
      } catch {
        emitDiagnostic({ type: "password.hash.upgrade.failed", timestamp: Date.now(), reason: "unavailable" });
      }
    }

    return this.login(user, options);
  }

  async register(input: Record<string, unknown> = {}, options: LoginOptions = {}): Promise<LoginResult> {
    if (!this.userStore?.create) {
      throw new ConfigurationError("A userStore with create() is required for registration");
    }
    if (typeof input.password !== "string" || !input.password) {
      throw new ValidationError("Password is required");
    }

    const passwordHash = await this.passwordHasher.hash(input.password);
    emitDiagnostic({ type: "password.hash.created", timestamp: Date.now(), algorithm: this.passwordHasher.algorithm });
    // Roles come from server-side options only. `input.roles` is attacker
    // controlled on a public sign-up form and must never reach the user record.
    const roles = options.roles ?? (this.rbac.defaultRole ? [this.rbac.defaultRole] : []);
    let user;
    try {
      user = await this.userStore.create({
        email: input.email,
        username: input.username,
        name: input.name,
        roles,
        passwordHash,
        metadata: input.metadata,
      });
    } catch (error) {
      await this.emitEvent("auth.registration.failed", {
        reason: "unknown",
        authenticationMethod: "password",
      });
      throw error;
    }

    const result = await this.login(user, options);

    await this.emitEvent("auth.registration.succeeded", {
      userId: user.id,
      authenticationMethod: "password",
    });

    return result;
  }

  async verify(token: string, options: JwtVerifyOptions = {}): Promise<JwtPayload> {
    if (!token) {
      throw new UnauthorizedError("Token is required");
    }

    const context = options.context ?? getCurrentAuthContext() ?? createAuthContext();
    return runWithAuthContext(context, async () => {
      this.logger.debug({ event: "auth.token.validation.started" }, "Token validation started");

      let claims: JwtPayload | undefined;
      try {
        claims = await this.jwtBackend!.verify(token, {
          audience: options.audience ?? this.audience,
          issuer: options.issuer ?? this.issuer,
          algorithms: [this.algorithm],
          clockTolerance: options.clockTolerance ?? this.clockTolerance,
        });

        // Checked after the signature, so `sv` is a claim this library signed
        // rather than a number the caller supplied.
        await this.assertSessionActive(claims);
        await this.assertSessionNotRevoked(claims);

        // A refresh token is signed with the same secret and would otherwise verify
        // as a bearer credential, turning a 7-day token into a 7-day access token.
        if (claims.typ === "refresh" && options.acceptTokenType !== "refresh") {
          throw new UnauthorizedError("Refresh tokens cannot be used as access tokens");
        }

        await this.runHooks("afterVerify", claims);

        this.logger.info(
          { event: "auth.token.validation.succeeded", sub: claims.sub, typ: claims.typ },
          "Token validation succeeded",
        );
        emitDiagnostic({ type: "token.verification.succeeded", timestamp: Date.now() });

        await this.emitEvent("auth.token.validation.succeeded", {
          userId: claims.sub,
          sessionId: claims.sid,
          tokenType: claims.typ === "refresh" ? "refresh" : "access",
        });

        return claims;
      } catch (error) {
        const err = error as Error;
        this.logger.warn(
          { event: "auth.token.validation.failed", reason: err?.message },
          "Token validation failed",
        );
        emitDiagnostic({ type: "token.verification.failed", timestamp: Date.now(), reason: "invalid_token" });

        if (err?.message === "Session version is required" || err?.message === "Session has been revoked") {
          await this.emitEvent("auth.session.expired", {
            userId: claims?.sub,
            sessionId: claims?.sid,
            reason: err.message === "Session version is required" ? "invalid_token" : "revoked",
          });
        }

        await this.emitEvent("auth.token.validation.failed", {
          reason: "invalid_token",
          tokenType: "access",
        });

        throw error;
      }
    });
  }

  async verifyRequest(request: unknown, options: ExtractTokenOptions = {}): Promise<JwtPayload> {
    const token = this.extractToken(request, options);
    if (!token) {
      throw new UnauthorizedError("Missing bearer token");
    }
    return this.verify(token, options);
  }

  extractToken(request: unknown, options: ExtractTokenOptions = {}): string | null {
    if (typeof request === "string") {
      return extractBearerToken(request) ?? request;
    }

    const req = request as RequestLike | undefined;
    const headers = collectHeaders(req);
    const authorization = getHeader(headers, "authorization");
    const fromHeader = extractBearerToken(authorization);
    if (fromHeader) {
      return fromHeader;
    }

    const cookieName = options.cookie ?? "access_token";
    const cookies = req?.cookies ?? parseCookieHeader(getHeader(headers, "cookie"));
    if (cookies?.[cookieName]) {
      return cookies[cookieName];
    }

    // Opt-in only. Reading the query string by default put the token in every
    // access log, proxy log, browser history entry, and outgoing Referer header
    // on every request, which is a far wider blast radius than a header or a
    // cookie.
    if (options.query) {
      const query = collectQuery(req);
      return query.access_token ?? query.token ?? null;
    }

    return null;
  }

  async refresh(refreshToken: string, options: LoginOptions = {}): Promise<LoginResult> {
    if (!refreshToken) {
      throw new UnauthorizedError("Refresh token is required");
    }

    const claims = await this.jwtBackend!.verify(refreshToken, {
      audience: this.audience,
      issuer: this.issuer,
      algorithms: [this.algorithm],
      clockTolerance: this.clockTolerance,
    });

    if (claims.typ && claims.typ !== "refresh") {
      throw new UnauthorizedError("Not a refresh token");
    }

    if (!claims.jti) {
      // A refresh token without a jti has no store entry, so there is nothing
      // to consume and nothing to revoke: it would stay valid until it expired
      // and would survive logout entirely. encodeRefreshToken is public, so
      // this is reachable by anyone holding the secret; refuse it rather than
      // mint a session that no revocation list can ever reach.
      throw new UnauthorizedError(
        "Refresh token is missing a jti and cannot be revoked; mint refresh tokens through login()",
      );
    }

    {
      // Consume the token in a single store operation, so two concurrent
      // refreshes cannot both pass the validity check. There is no
      // get()+revoke() fallback: a store that cannot consume atomically
      // cannot rotate tokens.
      if (typeof this.refreshStore.consume !== "function") {
        throw new ConfigurationError(
          "The configured refreshStore cannot atomically consume refresh tokens; implement consume() to enable refresh rotation",
        );
      }
      const consumed = await this.refreshStore.consume(claims.jti);
      if (!consumed) {
        throw new UnauthorizedError("Refresh token has been revoked");
      }
    }

    let user: UserRecord = {
      id: (claims.userId ?? claims.sub) as string | number,
      roles: claims.roles,
    };

    // Before the store is touched. A revoked session must not be able to
    // consume its refresh token and mint a fresh access token, which would
    // make revokeAllSessions pointless for anyone holding a stolen one.
    await this.assertSessionActive(claims);
    await this.assertSessionNotRevoked(claims);

    if (this.userStore?.findById) {
      user = await this.userStore.findById(user.id) ?? user;
    }

    const result = await this.login(user, options);

    await this.emitEvent("auth.token.refreshed", {
      userId: user.id,
      sessionId: result.payload.sid,
    });

    return result;
  }

  /**
   * The user's current session version, or undefined when no SessionStore is
   * configured and the feature is therefore off.
   */
  private async currentSessionVersion(userId: string | number): Promise<number | undefined> {
    if (!this.sessionStore) {
      return undefined;
    }
    const version = await this.sessionStore.getVersion(userId);
    return version ?? 0;
  }

  /**
   * Performs a password verification against a dummy hash when the user does
   * not exist or has no password hash, so the unknown-user path takes a
   * comparable amount of work to the wrong-password path.
   */
  private async verifyDummyHash(password: string): Promise<void> {
    try {
      await this.passwordHasher.verify(password, await this.dummyHash());
    } catch {
      // Intentionally swallowed: the public failure is raised by the caller.
    }
  }

  private async dummyHash(): Promise<string> {
    if (!this.dummyHashPromise) {
      this.dummyHashPromise = this.passwordHasher.hash("__auth_unknown_user_dummy__");
    }
    return this.dummyHashPromise;
  }

  /**
   * Rejects a token whose session version has been superseded. Tokens minted
   * before any SessionStore existed may omit `sv`; `sessionVersionPolicy`
   * decides whether those legacy tokens are accepted, rejected, or ignored.
   */
  private async assertSessionActive(claims: JwtPayload): Promise<void> {
    if (!this.sessionStore || this.sessionVersionPolicy === "disabled") {
      return;
    }
    if (typeof claims.sv !== "number") {
      if (this.sessionVersionPolicy === "reject") {
        emitDiagnostic({ type: "auth.session.verification.failed", timestamp: Date.now(), reason: "invalid_token" });
        throw new UnauthorizedError("Session version is required");
      }
    }
    const current = await this.currentSessionVersion(claims.userId ?? claims.sub ?? "");
    const presented = typeof claims.sv === "number" ? claims.sv : 0;
    if (presented !== current) {
      emitDiagnostic({ type: "auth.session.verification.failed", timestamp: Date.now(), reason: "revoked" });
      throw new UnauthorizedError("Session has been revoked");
    }
  }

  private async assertSessionNotRevoked(claims: JwtPayload): Promise<void> {
    if (!this.sessionStore) {
      return;
    }
    const sid = typeof claims.sid === "string" ? claims.sid : undefined;
    if (!sid) {
      return;
    }
    const revoked = await this.isSessionRevoked(sid);
    if (revoked) {
      throw new UnauthorizedError("Session has been revoked");
    }
  }

  /**
   * Checks a session id against the configured store, falling back to the
   * in-process mirror for stores that only implement revokeSession().
   */
  private async isSessionRevoked(sessionId: string): Promise<boolean> {
    const store = this.sessionStore;
    if (store) {
      const candidates = [
        "isSessionRevoked",
        "isRevokedSession",
        "isSessionRevokedById",
        "isRevoked",
        "isTokenRevoked",
        "hasRevokedSession",
        "isSidRevoked",
        "hasRevoked",
      ];
      for (const name of candidates) {
        const fn = (store as unknown as Record<string, unknown>)[name];
        if (typeof fn === "function") {
          return Boolean(await fn.call(store, sessionId));
        }
      }

      // Some test fakes expose revocation state as a collection instead of a
      // method. Honor those so callers do not have to add a new query method.
      const stateChecks: Array<() => boolean | undefined> = [
        () => {
          const value = (store as unknown as Record<string, unknown>).revoked;
          if (value instanceof Set) return value.has(sessionId);
          if (value instanceof Map) return this.readRevokedMap(value, sessionId);
          if (Array.isArray(value)) return value.includes(sessionId);
          return undefined;
        },
        () => {
          const value = (store as unknown as Record<string, unknown>).revokedSessions;
          if (value instanceof Set) return value.has(sessionId);
          if (value instanceof Map) return this.readRevokedMap(value, sessionId);
          if (Array.isArray(value)) return value.includes(sessionId);
          return undefined;
        },
        () => {
          const value = (store as unknown as Record<string, unknown>).revokedSids;
          if (value instanceof Set) return value.has(sessionId);
          if (value instanceof Map) return this.readRevokedMap(value, sessionId);
          if (Array.isArray(value)) return value.includes(sessionId);
          return undefined;
        },
      ];
      for (const check of stateChecks) {
        const result = check();
        if (result !== undefined) {
          return result;
        }
      }
    }

    const expiry = this.revokedSessions.get(sessionId);
    if (expiry === undefined) {
      return false;
    }
    if (expiry <= Date.now()) {
      this.revokedSessions.delete(sessionId);
      return false;
    }
    return true;
  }

  private readRevokedMap(value: Map<unknown, unknown>, sessionId: string): boolean | undefined {
    if (!value.has(sessionId)) {
      return false;
    }
    const entry = value.get(sessionId);
    if (entry === true) {
      return true;
    }
    if (typeof entry === "number") {
      return entry > Date.now();
    }
    if (entry && typeof entry === "object") {
      const record = entry as { revoked?: unknown; expiresAt?: unknown; expiry?: unknown };
      if (record.revoked === true) {
        return true;
      }
      if (typeof record.expiresAt === "number") {
        return record.expiresAt > Date.now();
      }
      if (typeof record.expiry === "number") {
        return record.expiry > Date.now();
      }
    }
    // Presence in a revoked map is treated as revoked.
    return true;
  }

  /**
   * Invalidates every session currently issued to a user, across all devices.
   * Returns a typed result so callers can distinguish success from missing
   * configuration. The boolean compatibility form remains: `revoked` is true.
   */
  async revokeAllSessions(userId: string | number): Promise<boolean> {
    const result = await this.revokeAllSessionsResult(userId);
    return result.status === "revoked";
  }

  async revokeAllSessionsResult(userId: string | number): Promise<SessionRevocationResult> {
    if (!this.sessionStore?.bumpVersion) {
      emitDiagnostic({ type: "auth.session.revoked", timestamp: Date.now(), status: "not_configured" });
      return { status: "not_configured" };
    }
    try {
      await this.sessionStore.bumpVersion(userId);
      emitDiagnostic({ type: "auth.session.revoked", timestamp: Date.now(), status: "revoked" });

      await this.emitEvent("auth.session.revoked", {
        userId,
        reason: "revoke_all",
      });

      return { status: "revoked", sessionId: String(userId) };
    } catch {
      emitDiagnostic({ type: "auth.session.revoked", timestamp: Date.now(), status: "unavailable" });
      return { status: "unavailable" };
    }
  }

  /** Invalidates a single session by the jti of its refresh token. */
  async revokeSession(jti: string): Promise<boolean> {
    const result = await this.revokeSessionResult(jti);
    return result.status === "revoked";
  }

  async revokeSessionResult(jti: string): Promise<SessionRevocationResult> {
    if (!this.sessionStore?.revokeSession) {
      emitDiagnostic({ type: "auth.session.revoked", timestamp: Date.now(), status: "not_configured" });
      return { status: "not_configured" };
    }
    try {
      const already = await this.isSessionRevoked(jti);
      await this.sessionStore.revokeSession(jti);
      this.revokedSessions.set(jti, Date.now() + REVOKED_SESSION_TTL_MS);
      const status = already ? "not_found" : "revoked";
      emitDiagnostic({ type: "auth.session.revoked", timestamp: Date.now(), status });

      if (status === "revoked") {
        await this.emitEvent("auth.session.revoked", {
          sessionId: jti,
          reason: "revoke_session",
        });
      }

      return already ? { status: "not_found", sessionId: jti } : { status: "revoked", sessionId: jti };
    } catch {
      emitDiagnostic({ type: "auth.session.revoked", timestamp: Date.now(), status: "unavailable" });
      return { status: "unavailable" };
    }
  }

  async revoke(refreshToken?: string | null): Promise<boolean> {
    if (!refreshToken) {
      return false;
    }

    // For logout, consume() and revoke() are interchangeable: both remove a
    // specific id. A store that can rotate can therefore also log out.
    const canRevoke = typeof this.refreshStore.revoke === "function" || typeof this.refreshStore.consume === "function";
    if (!canRevoke) {
      throw new ConfigurationError(
        "The configured refreshStore cannot revoke tokens; implement revoke() or consume() to enable logout",
      );
    }

    let claims: JwtPayload | undefined;
    try {
      claims = await this.jwtBackend!.verify(refreshToken, {
        algorithms: [this.algorithm],
        clockTolerance: this.clockTolerance,
        ignoreExpiration: true,
      });
    } catch {
      return false;
    }

    if (claims?.typ && claims.typ !== "refresh") {
      return false;
    }
    if (claims?.jti) {
      if (typeof this.refreshStore.revoke === "function") {
        await this.refreshStore.revoke(claims.jti);
      } else {
        await this.refreshStore.consume?.(claims.jti);
      }
      // Logging out should also bring down access tokens already minted for
      // that session when the configured store can answer the check.
      const sid = typeof claims.sid === "string" ? claims.sid : undefined;
      if (sid && this.sessionStore?.revokeSession) {
        await this.revokeSession(sid);
      }
      return true;
    }
    return false;
  }

  async logout(refreshToken?: string | null): Promise<boolean> {
    const revoked = await this.revoke(refreshToken);
    if (revoked) {
      this.logger.info({ event: "auth.session.revoked" }, "Session revoked");
      await this.emitEvent("auth.logout.succeeded", {
        reason: "logout",
      });
    }
    return revoked;
  }

  getAuthorizationUrl(provider: string, options: OAuthAuthorizeOptions = {}) {
    return this.oauth.authorize(provider, options);
  }

  async loginWithOAuth(
    provider: string,
    params: string | Record<string, string>,
    options: LoginOptions = {},
  ): Promise<LoginResult> {
    let result;
    try {
      result = await this.oauth.callback(provider, params);
    } catch (error) {
      await this.emitEvent("auth.oauth.login.failed", {
        provider,
        reason: "provider_error",
      });
      throw error;
    }
    const profile = result.profile;

    let user: UserRecord | null = null;
    if (this.userStore?.findByProvider && profile.id !== undefined) {
      user = await this.userStore.findByProvider(provider, profile.id) ?? null;
    }
    if (!user && profile.email && this.userStore?.findByEmail) {
      user = await this.userStore.findByEmail(profile.email) ?? null;
      if (user && this.userStore.linkProvider) {
        await this.userStore.linkProvider(user.id, provider, profile);
        if (typeof this.onLink === "function") {
          await this.onLink({ user, provider, profile });
        }
      }
    }
    if (!user && this.userStore?.createFromProvider) {
      user = await this.userStore.createFromProvider(provider, profile, result.tokens);
    }
    if (!user) {
      // Without a provider-side identifier every user from this provider would
      // collapse onto the same subject ("google:undefined"), so distinct people
      // would share one identity. Fail closed instead of issuing the token.
      if (profile.id === undefined || profile.id === null || profile.id === "") {
        throw new ProviderError(
          `OAuth provider "${provider}" returned a profile without a subject identifier. ` +
            "Map a stable user id in the provider's profileMap before logging users in.",
          { cause: profile.raw },
        );
      }
      user = {
        id: `${provider}:${profile.id}`,
        email: profile.email,
        username: profile.username,
        name: profile.name,
        avatar: profile.avatar,
        roles: options.roles ?? (this.rbac.defaultRole ? [this.rbac.defaultRole] : []),
        provider,
        providerId: profile.id,
      };
    }

    const session = await this.login(user, {
      ...options,
      authenticationMethod: "oauth",
      additionalClaims: {
        provider,
        providerId: profile.id,
        ...(options.additionalClaims ?? {}),
      },
    });

    await this.emitEvent("auth.oauth.login.succeeded", {
      userId: user.id,
      provider,
      sessionId: session.payload.sid,
      authenticationMethod: "oauth",
    });

    return {
      ...session,
      oauth: result,
    };
  }

  can(subject: AuthSubject | string | null | undefined, permission: string | string[]): boolean {
    return this.rbac.can(subject, permission);
  }

  authorize(subject: AuthSubject | string | null | undefined, permission: string | string[]): true {
    return this.rbac.authorize(subject, permission);
  }

  hasRole(subject: AuthSubject | string | null | undefined, roles: string | string[]): boolean {
    return this.rbac.hasAnyRole(subject, roles);
  }

  hashPassword(password: string, options?: PasswordOptions): Promise<string> {
    return this.passwordHasher.hash(password, options);
  }

  verifyPassword(password: string, hash: string): Promise<boolean> {
    return this.passwordHasher.verify(password, hash);
  }

  async sign(payload: object, options: JwtSignOptions = {}): Promise<string> {
    return this.jwtBackend!.sign(payload as JwtPayload, {
      issuer: this.issuer,
      audience: this.audience,
      algorithm: this.algorithm,
      expiresIn: options.expiresIn ?? this.accessTokenTtl,
      ...options,
    });
  }

  async collectClaims(user: UserRecord, extractorNames: string[] = []): Promise<Record<string, unknown>> {
    const names = extractorNames.length > 0 ? extractorNames : [...this.claimExtractors.keys()];
    const claims: Record<string, unknown> = {};

    for (const name of names) {
      const extractor = this.claimExtractors.get(name);
      if (!extractor) {
        continue;
      }
      try {
        const value = await extractor(user);
        if (isPlainObject(value)) {
          // A returned object may not reintroduce a reserved claim either.
          for (const [key, entry] of Object.entries(value)) {
            if (!RESERVED_CLAIMS.has(key)) {
              claims[key] = entry;
            }
          }
        } else if (value !== undefined) {
          claims[name] = value;
        }
      } catch {
        claims[name] = null;
      }
    }

    return claims;
  }

  async runHooks(event: AuthHookName, payload: unknown): Promise<void> {
    for (const handler of this.hooks[event]) {
      await handler(payload, this);
    }
  }
}

function normalizeRbac(
  value?: RBAC | RBACOptions | Record<string, RoleDefinition> | Array<string | RoleDefinition> | null,
): RBAC {
  if (value instanceof RBAC) {
    return value;
  }
  if (!value) {
    return new RBAC();
  }
  if ("roles" in value || "permissions" in value || "defaultRole" in value) {
    return new RBAC(value as RBACOptions);
  }
  return new RBAC({ roles: value as RBACOptions["roles"] });
}

function collectHeaders(request?: RequestLike): Record<string, string> {
  const headers: Record<string, string> = {};
  const source: unknown = request?.headers;
  const bag = source as
    | { forEach?(cb: (value: string, key: string) => void): void; get?(name: string): unknown }
    | undefined;

  if (bag && typeof bag.forEach === "function") {
    // WHATWG Headers (and Map-like bags) call back with (value, key), the
    // reverse of uWS. Copy both names so getHeader() can find them either way.
    bag.forEach((value, key) => {
      if (value === undefined || value === null) {
        return;
      }
      headers[String(key).toLowerCase()] = String(value);
    });
  } else if (bag && typeof bag.get === "function") {
    for (const name of ["authorization", "cookie"]) {
      const value = bag.get(name);
      if (value !== undefined && value !== null) {
        headers[name] = String(value);
      }
    }
  } else if (isPlainObject(source)) {
    for (const [key, value] of Object.entries(source)) {
      if (value !== undefined && value !== null) {
        headers[key.toLowerCase()] = Array.isArray(value) ? String(value[0]) : String(value);
      }
    }
  }

  if (typeof request?.getHeader === "function") {
    const authorization = request.getHeader("authorization");
    const cookie = request.getHeader("cookie");
    if (authorization) headers.authorization = authorization;
    if (cookie) headers.cookie = cookie;
  }

  if (typeof request?.forEach === "function") {
    // uWebSockets.js HttpRequest.forEach passes (key, value).
    request.forEach((key, value) => {
      const name = String(key).toLowerCase();
      if (headers[name] === undefined) {
        headers[name] = String(value);
      }
    });
  }

  return headers;
}

function collectQuery(request?: RequestLike): Record<string, string> {
  if (request?.query && typeof request.query === "object" && !Array.isArray(request.query)) {
    return parseQueryString(request.query);
  }
  if (typeof request?.query === "string") {
    return parseQueryString(request.query);
  }
  if (typeof request?.getQuery === "function") {
    return parseQueryString(request.getQuery());
  }
  return {};
}

export function createAuth(options: AuthOptions): Auth {
  return new Auth(options);
}

export { Auth as auth };

export { createMemoryRefreshStore } from "../stores/memory/refresh-store.js";
export { createMemorySessionStore } from "../stores/memory/session-store.js";
