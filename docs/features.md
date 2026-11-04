# `@oneunit/auth` Feature Reference

This document is the implementation-oriented feature index for `@oneunit/auth` v2.1.0-beta.1. It follows the package architecture and README: the README explains how consumers use the library, `ARCHITECTURE.md` explains module boundaries and runtime behavior, and this file summarizes the implemented capabilities and their public extension points.

> **Accuracy rule:** This file describes package capabilities and contracts. It does not claim that every deployment has configured durable storage, enabled revocation, or completed live-provider verification. Application-owned infrastructure and operational responsibilities are called out explicitly.

## 1. Package overview

`@oneunit/auth` is a framework-agnostic authentication and authorization library for Node.js 20+. It is a library, not a hosted identity service or user directory.

It provides:

- JWT issuance and verification with configurable signing backends and algorithm policies.
- Access-token and refresh-token lifecycle management.
- Refresh-token rotation and replay protection through atomic storage operations.
- Optional session versioning and session revocation.
- RBAC with role inheritance, wildcard permissions, cycle detection, and bounded caches.
- Password hashing with Argon2id as the default, scrypt legacy support, and optional bcrypt.
- OAuth 2.0 / OIDC authorization-code flows, PKCE, state management, and 14 built-in providers.
- External JWT verification against explicitly trusted issuers and JWKS.
- OAuth token introspection (RFC 7662).
- Framework adapters for Express, Fastify, Koa, and uWebSockets.js.
- Replaceable user, refresh-token, session, key-value, revocation, version, and event infrastructure.
- HTTP transport with timeouts, cancellation, response-size limits, and bounded retry.
- Request-scoped auth context, diagnostics, structured safe logging, and typed errors.
- ESM, CommonJS, and TypeScript declaration distribution.

It does **not** provide a managed user directory, MFA, email verification, password-reset workflows, account lockout, or application-level rate limiting. Those remain responsibilities of the integrating application.

## 2. Package and runtime architecture

### Runtime and packaging

- Node.js: `>=20`.
- Runtime dependencies: `jose` and `@noble/hashes`.
- Optional dependency: `bcrypt`, only when using the bcrypt hasher.
- Frameworks and database clients are not runtime dependencies or required framework peer dependencies.
- The package is dual-published as ESM and CommonJS and includes TypeScript declarations.
- `src/index.ts` is the public source entry point; published entry points are defined by `package.json` exports.
- Imports are designed to be side-effect-free. Consumers explicitly construct services using factories such as `createAuth`, `createRBAC`, `createOAuth`, and `createProvider`.

### Architectural layers

| Layer | Main location | Responsibility |
|---|---|---|
| Public API | `src/index.ts`, `src/types/` | Stable exports and public contracts |
| Composition root | `src/core/auth.ts` | Construct and coordinate authentication services |
| Cryptography | `src/crypto/` | JWT, password hashing, signing backends, JWKS |
| Authorization | `src/rbac/` | Roles, inheritance, permission matching |
| OAuth/OIDC | `src/oauth/` | Provider registration, authorization, callback, introspection |
| External token verification | `src/external-token/` | Validate tokens from trusted external issuers |
| HTTP | `src/http/` | Configurable HTTP client, limits, retry |
| Adapters and contracts | `src/adapters/` | Framework translation and storage/event contracts |
| Stores | `src/stores/` | In-memory development/test stores |
| Cache | `src/cache/` | Cache provider and shared JWKS cache support |
| Context and diagnostics | `src/core/context.ts`, `src/diagnostics/` | Request context and operational events |
| Logging and errors | `src/logging/`, `src/errors/` | Secret-safe logging and typed failures |
| Shared helpers | `src/utils.ts`, `src/platform.ts` | Token parsing, randomization, compatibility helpers |

### Dependency direction

The application consumes the public API. The `Auth` core composes lower-level services but does not depend on Express, Fastify, Koa, uWebSockets.js, Redis, PostgreSQL, or another concrete database client.

- Framework adapters translate framework requests into core calls and map typed errors back to framework responses.
- Cryptography modules do not depend on HTTP frameworks or user repositories.
- Persistence and event interfaces are package contracts; concrete infrastructure implementations are supplied by the application.
- Internal modules use the package's NodeNext/ESM-compatible import conventions.
- Only documented package entry points and exports should be treated as public API.

## 3. Authentication core

**Main implementation:** `src/core/auth.ts`  
**Factory:** `createAuth(options)`

`createAuth` constructs the `Auth` facade and validates security-sensitive configuration at initialization, including the required signing secret.

### Core operations

- `login()` — creates an authenticated session and issues access/refresh tokens.
- `verify()` — verifies an access token and its configured claims/type policy.
- `verifyRequest()` — extracts a credential from a request-like object and verifies it.
- `refresh()` — validates and rotates a refresh token.
- `revoke()` / `logout()` — revokes the supplied refresh-token record.
- `revokeSession()` — revokes a single session when the configured store supports it.
- `revokeAllSessions()` — increments the user's session version when a suitable session store is configured.
- `register()` and `loginWithPassword()` — password-based registration/login through a caller-supplied user store.
- `loginWithOAuth()` — integrates OAuth provider profile results with user lookup/linking/creation.
- Authorization helpers — expose RBAC checks through the auth facade when RBAC is configured.

### Extensibility

- Lifecycle hooks: `beforeLogin`, `afterLogin`, and `afterVerify`.
- Custom claim extractors.
- Custom JWT backend.
- Custom password hasher.
- User, refresh-token, session, and unified persistence stores.
- OAuth providers, logger, diagnostics observer, and HTTP configuration.

Reserved identity/security claims are protected from being overwritten by user/profile data or custom claim extraction. The reserved set includes claims such as `sub`, `userId`, `roles`, `permissions`, `typ`, `iss`, `aud`, `exp`, `iat`, `nbf`, `jti`, `sv`, and `sid`.

`Auth` is not a user database. A `UserStore` is an interface supplied by the integrating application.

## 4. JWT issuance and verification

**Main implementation:** `src/crypto/jwt.ts`, `src/crypto/jwt-backend.ts`

### Public operations

- `encode(payload, secret, options)` — signs a JWT.
- `decode(token, secret, options)` — verifies a JWT before returning claims.
- `decodeUnsafe(token)` — decodes without signature verification; inspection only, never for authorization decisions.
- `encodeAccessToken(...)` — issues a token with access-token type separation.
- `encodeRefreshToken(...)` — issues a token with refresh-token type separation.
- `withTyp(...)` — builds token-type-specific options.

### Supported behavior

- HS256 is the default algorithm policy.
- The package supports the configured HS256, RS256, and ES256 algorithm options described in the README.
- Algorithms are pinned by server configuration; a token cannot choose an algorithm that the verifier has not allowed.
- Issuer, audience, subject, expiration, not-before, and clock-tolerance validation are supported where configured.
- Signing and verification keys can be separated.
- Refresh signing/verification keys can be configured separately from access-token keys.
- `kid`-based key resolution is supported through a key resolver.
- Access and refresh tokens have distinct `typ` values.
- Refresh tokens carry a unique `jti` used by refresh-token storage.

### Security notes

- The configured secret is required and must be high-entropy material; the README requires at least 32 bytes.
- A separate `refreshSecret` is supported and recommended.
- `decodeUnsafe` must never be used to authorize a request.
- A valid signature alone does not establish application authorization; RBAC and application policy remain separate.

## 5. Refresh-token lifecycle

**Main implementation:** `src/core/auth.ts`, refresh-store contracts, `src/stores/memory/refresh-store.ts`

Refresh tokens are distinct from access tokens and rotate on use.

### Rotation behavior

1. Verify the refresh token signature, claims, and token type.
2. Require its unique `jti`.
3. Atomically consume the corresponding refresh-token record.
4. Reject missing, expired, revoked, or already-consumed records.
5. Check session-version policy when session versioning is configured.
6. Issue the next access/refresh token pair.

A refresh store used for rotation must implement atomic `consume`. If the required atomic operation is unavailable, refresh rotation must fail rather than silently relying on a non-atomic read-then-delete sequence.

### Replay protection and deployment

- Only one concurrent consumer should be able to consume a given refresh record.
- The storage implementation must preserve that guarantee across all application instances.
- In-memory stores are process-local and are intended for development/test use, not multi-instance production.
- A durable Redis/SQL/other store must implement the contract's atomic operation correctly.
- `revoke()`/`logout()` remove refresh-token records. They do not, by themselves, invalidate already-issued stateless access tokens.

## 6. Session versioning and revocation

**Main implementation:** `src/core/auth.ts`, session/version store contracts

Session revocation is opt-in and depends on configured storage.

### Session versioning

- Tokens can carry an `sv` (session-version) claim.
- Verification and refresh compare the token's version with the current stored version when session versioning is enabled.
- `revokeAllSessions(userId)` increments the user's version to invalidate tokens associated with older versions.
- `sessionVersionPolicy` controls handling of tokens without an `sv` claim: `reject`, `migration`, or `disabled`.

### Single-session revocation

A configured session/revocation store may support revoking an individual session identifier. The exact capability depends on the store contract and implementation supplied by the application.

### Important limitation

Without a suitable shared session store, a signed JWT remains valid until its expiry. Stateless JWT verification cannot retroactively un-sign a token. The README documents that `revokeAllSessions()` returns `false` when the required store is not configured rather than claiming revocation succeeded.

For production deployments requiring cross-instance revocation, use shared durable storage and test the consistency/atomicity behavior of that implementation.

## 7. Password hashing

**Main implementation:** `src/crypto/password.ts`, `src/crypto/password-hasher.ts`

### Algorithms

| Hasher | Status | Notes |
|---|---|---|
| Argon2id | Default | Recommended modern password-hashing path; configurable memory/cost/parallelism parameters |
| scrypt | Legacy and supported | Existing hashes can be verified and upgraded |
| bcrypt | Optional | Requires the optional `bcrypt` binding |

### Public helpers and classes

- `hashPassword`, `verifyPassword`, `needsRehash`
- `hashScryptPassword`, `verifyScryptPassword`, `scryptNeedsRehash`
- `createPasswordHasher`
- `getDefaultPasswordHasher`, `setDefaultPasswordHasher`
- `Argon2idPasswordHasher`
- `ScryptPasswordHasher`
- `BcryptPasswordHasher`
- `CompositePasswordHasher`
- `isBcryptAvailable`
- `ARGON2ID_RECOMMENDED_PROFILE`

`CompositePasswordHasher` dispatches verification based on the stored hash prefix, allowing supported legacy hashes to be verified and upgraded. Unknown formats and out-of-policy cost parameters are rejected safely.

### Application responsibilities

- Store password hashes, never plaintext passwords.
- Use `needsRehash` during successful authentication/migration to upgrade old hashes.
- Apply login rate limiting and abuse controls in the application.
- Benchmark Argon2id settings against the deployment's memory and concurrency budget.
- Do not log passwords or stored hashes.

## 8. RBAC

**Main implementation:** `src/rbac/index.ts`, `src/rbac/matcher-cache.ts`  
**Factory/helper:** `createRBAC`, `defineRoles`, `matchPermission`

RBAC is generic and application-defined. The package ships no product-specific roles.

### Capabilities

- Define roles and permissions.
- Single-parent and multiple-parent role inheritance.
- Detect inheritance cycles.
- Resolve inherited roles and permissions.
- Match permission patterns using wildcards.
- Evaluate `can`, `cannot`, `authorize`, `hasRole`, `hasAnyRole`, and `hasAllRoles`.
- Inspect a detached snapshot of role definitions.
- Cache subject permission resolution with a bounded subject cache.
- Use a bounded LRU/TTL matcher cache with statistics.

### Wildcards

- `*` matches one permission segment.
- `**` matches any suffix.
- Permission segments are delimited by `.` and `:` according to the implementation.
- Literal segments are escaped when compiled for matching.

For example, the README documents `invoice.*` matching `invoice.read` but not `invoice.read.all`.

### Role trust boundary

- Role definitions are supplied by the application.
- Public signup input must not be trusted to assign privileged roles.
- User-record permissions are not trusted by default; `trustUserPermissions` must be explicitly enabled to honor them.
- The optional default role is intended to be unprivileged.

## 9. OAuth 2.0 and OpenID Connect

**Main implementation:** `src/oauth/`, `src/oauth/providers/`, `src/oauth/redirect-uri.ts`

### Authorization-code flow

The OAuth service supports:

- Provider registration and lookup.
- Authorization URL generation.
- Cryptographically random state generation and storage with TTL.
- Authorization-code exchange.
- Provider profile retrieval and mapping.
- Callback validation and state consumption.
- Provider-specific configuration and custom providers.
- Diagnostic events for authorization and callback operations.

### PKCE

- PKCE S256 is enabled by default for authorization-code flows.
- A fresh verifier is generated for each authorization transaction.
- The challenge is sent in the authorization request.
- The verifier is bound to the state transaction and consumed during callback processing.
- The verifier is not sent in the authorization URL.
- Disabling PKCE with `pkce: false` is an explicit security downgrade and should be reserved for providers that cannot support it.

Helpers include `pkceVerifier` and `pkceChallenge`.

### Redirect URI policy

Every authorization-code flow validates its redirect URI against trusted configuration:

- `redirectUriPolicy.allowedRedirectUris` is the trusted allowlist.
- Matching is exact string equality.
- Wildcard host, prefix, suffix, and implicit subdomain matching are not used.
- HTTPS is required except for explicitly enabled loopback development addresses.
- Embedded credentials, malformed URLs, and dangerous schemes are rejected.
- Missing or empty allowlists fail closed.
- The validated URI is bound to the state transaction; callback-supplied redirect values are not trusted.
- Failures use `InvalidRedirectUriError` / `INVALID_REDIRECT_URI`.

### Built-in providers

The package includes 14 providers:

1. Google
2. GitHub
3. Instagram
4. Facebook
5. X/Twitter
6. Discord
7. Apple
8. LinkedIn
9. Microsoft
10. Reddit
11. Twitch
12. Slack
13. Spotify
14. TikTok

Provider definitions include authorization/token endpoints, scopes, profile mapping, and provider-specific parsing where needed.

### Custom providers

`createProvider(definition)` supports:

- Provider ID and authorization/token endpoints.
- Optional user-info endpoint.
- Scopes and profile mapping.
- Custom sync/async profile parsing.
- PKCE configuration.
- Token authentication method (`body` or `basic`).
- Additional authorization/token parameters.
- User-info headers.

### Provider account linking

`Auth.loginWithOAuth` can use optional `UserStore` methods such as:

- `findByProvider`
- `findByEmail`
- `createFromProvider`
- `linkProvider`

Without a user store, the flow can create a synthetic subject based on provider and stable provider subject ID. Empty or unstable provider subject identifiers are rejected rather than silently merging identities.

### OIDC ID-token verification

The architecture documents JWKS-backed ID-token verification for Google and Apple, and also notes Twitter support in the OAuth module. Verification includes the applicable signature, issuer, audience, expiration, nonce, algorithm, and key-ID checks.

JWKS behavior includes URL-keyed caching with configurable TTL and a bounded forced refresh for an unknown `kid`. A refresh does not bypass signature verification.

## 10. External token verification

**Main implementation:** `src/external-token/verifier.ts`  
**Factory:** `createExternalTokenVerifier`

This service verifies JWTs issued by explicitly trusted external identity providers. It is separate from the package's own access/refresh token flow.

### Capabilities

- Configure an allowlist of trusted issuers.
- Configure per-issuer audiences and allowed algorithms.
- Resolve keys from inline JWKS, a sync/async resolver, or a remote JWKS URL.
- Require HTTPS for remote JWKS by default, with an explicit insecure-development override.
- Reject unsupported schemes and `alg: none`.
- Enforce a 16 KiB token-size limit.
- Validate signature, issuer, audience, expiration, not-before, token age, required claims, and expected token type where configured.
- Support `maxTokenAge` at issuer and per-call level.
- Return a structured result containing payload, issuer, and audience.

Unknown keys, invalid signatures, malformed tokens, and untrusted issuers fail closed.

## 11. OAuth token introspection

**Main implementation:** `src/oauth/introspection/`  
**Public API:** `TokenIntrospector`, `createTokenIntrospector`, `IntrospectionError`

The package includes an RFC 7662 token introspection client.

- Sends introspection requests to the configured endpoint.
- Supports client-secret authentication using HTTP Basic or configured body credentials.
- Validates introspection responses.
- Uses a bounded LRU cache for introspection results.
- Requires HTTPS for the endpoint according to the documented security policy.
- Exposes typed introspection failures.

Introspection is distinct from local JWT verification: it asks the configured authorization server to report token activity/metadata.

## 12. Persistence and storage contracts

**Main implementation:** `src/adapters/contracts/`, `src/adapters/adapter-registry.ts`, `src/core/auth.ts`

The package does not bundle database clients. It defines contracts that applications implement using Redis, PostgreSQL, MongoDB, DynamoDB, or custom infrastructure.

### Unified `PersistenceAdapter`

The unified adapter can provide domains such as:

- `keyValue`
- `sessions`
- `refreshTokens`
- `revocations`
- `versions`
- `users`

It may also expose `initialize()` and `close()` lifecycle hooks.

### Ownership model

- The package owns the contracts, validation, routing, and required security semantics.
- The application owns database clients, connections, pools, credentials, migrations, and infrastructure lifecycle.
- Explicit per-domain stores (for example `userStore`, `refreshStore`, or `sessionStore`) take precedence over corresponding adapter-provided domains.
- Omitted domains may fall back to in-memory behavior; that fallback is not durable across restarts and is not suitable for multi-instance production state.
- Adapter capabilities are validated at initialization. Declaring atomic support without implementing the corresponding operation is a configuration error.
- `initialize()` / `close()` coordinate adapter lifecycle; the application remains responsible for ownership and safe shutdown of its connections.

### Storage contracts and atomic capabilities

The architecture defines contracts for key-value, refresh-token, session, revocation, and version storage. Capability declarations include operations such as:

- Atomic consume.
- Atomic refresh-token rotation.
- Atomic increment.
- TTL support.

Operations that protect replay or cross-instance state must be implemented atomically by the backing store. Examples include Redis `GETDEL`/Lua or SQL conditional mutation/`DELETE ... RETURNING`, where appropriate to the data model.

### Error model

Persistence failures are normalized through `PersistenceErrorCode` and `PersistenceErrorInfo`. The application should monitor and handle backend outages; it must not treat a failed security-state lookup as proof that a token is valid.

### Event adapters are separate

`EventAdapter` / `EventAdapters` transport auth lifecycle events. They are not authoritative persistence and must not be used as a substitute for refresh/session state storage.

## 13. In-memory stores

**Main implementation:** `src/stores/memory/`

Exported helpers include:

- `createMemoryRefreshStore`
- `createMemorySessionStore`
- `createMemoryStateStore`

These stores are useful for local development, tests, and single-process examples. They are not durable across process restarts and do not coordinate state across multiple application instances. Production deployments requiring distributed refresh rotation, OAuth state consumption, or session revocation must provide shared stores with the required atomic capabilities.

## 14. HTTP transport and retry

**Main implementation:** `src/http/transport.ts`, `src/http/retry.ts`

### HTTP client

The package provides an injectable HTTP client used by OAuth, JWKS, and related network operations.

Capabilities include:

- Configurable transport.
- Request timeout and `AbortController` cancellation.
- Combining caller-provided abort signals.
- Maximum response-size enforcement using content-length checks and streamed-body accounting.
- Redirect policy (error by default).
- Base URL support for relative endpoints.
- Default and per-request headers.
- Defensive configuration snapshots.
- Per-instance `HttpClient` configuration.

The `HttpClient` class provides isolated per-client configuration. Module-level helpers (`configureHttp`, `dispatchHttp`, `getHttpConfig`, `resetHttpConfig`) operate on the shared default client for backward compatibility. Configuring that shared default client is process-wide; use `new HttpClient(config)` when independent clients need independent settings.

### Retry

`dispatchHttpWithRetry` / `resolveRetryConfig` provide:

- Exponential backoff with full jitter.
- Configurable retryable status codes; documented defaults include 429, 502, 503, and 504.
- Retry handling for selected network failures.
- No retry for aborted requests.
- Idempotent methods (GET/HEAD/OPTIONS) retried by default.
- Non-idempotent retries require explicit opt-in.
- Bounded retry count and optional total deadline.

Retries must be configured with awareness of request idempotency. Retrying a token exchange or another state-changing operation can duplicate effects if explicitly enabled without provider/application guarantees.

## 15. Framework adapters

**Main implementation:** `src/adapters/`

Adapters are thin structural integrations; they do not import the frameworks or require them as package peer dependencies. Install the framework separately in the consuming application.

| Framework | Adapter | Integration |
|---|---|---|
| Express | `expressAdapter(auth)` | Middleware factory |
| Fastify | `fastifyAdapter(auth)` | Plugin and authenticate decorator |
| Koa | `koaAdapter(auth)` | Middleware |
| uWebSockets.js | `uwsAdapter(auth)` | Handler wrappers and JSON response helper |

### Shared behavior

- Extract credentials from supported request structures.
- Use `auth.verifyRequest()` for core verification.
- Attach the verified principal/token to framework request/context state.
- Map typed auth errors to appropriate HTTP status responses.
- Avoid returning secrets, tokens, or stack traces in authentication error responses.
- Support optional-auth behavior where documented.
- Query-string token extraction is disabled by default; opt in explicitly when needed.

### uWebSockets.js handling

Native uWS request objects have lifecycle constraints around asynchronous work. The adapter snapshots request information before awaiting authentication operations using `snapshotUwsRequest`.

### Custom integrations

`verifyRequest` and `extractBearerToken` can be used directly to build integrations for other frameworks or server runtimes.

## 16. Request-scoped auth context

**Main implementation:** `src/core/context.ts`

The package uses Node.js `AsyncLocalStorage` to carry request-scoped metadata across asynchronous operations.

`AuthContext` includes:

- `requestId`
- `traceId`
- `operationId`
- Optional `tenantId`
- Additional application-defined string-keyed properties

Helpers:

- `createAuthContext(init?)`
- `runWithAuthContext(context, fn)`
- `getCurrentAuthContext()`

Missing identifiers can be generated using cryptographically secure random values. `operationId` defaults to `requestId` when not supplied. Nested contexts are scoped to their callback and restore the outer context afterward.

Auth operations, framework adapters, and diagnostics can use the active context to correlate events. Context propagation is correlation metadata, not an authorization boundary; applications must still validate tenant and subject access.

## 17. Diagnostics and observability

**Main implementation:** `src/diagnostics/`

The diagnostics emitter supports:

- Auth lifecycle diagnostic events, including login, token validation, OAuth authorization/callback, and related operations.
- Synchronous or asynchronous observer callbacks.
- A bounded pending-event queue (architecture documents a default capacity of 32).
- Configurable overflow behavior: `drop` or `report`.
- Observer error callback routing.
- Queue/statistics inspection.
- Reset of observer/queue/statistics configuration.

Public helpers include:

- `emitDiagnostic`
- `setDiagnosticsObserver`
- `resetDiagnostics`
- `getDiagnosticsStats`
- `setDiagnosticsOverflowPolicy`
- `setDiagnosticsErrorCallback`

Diagnostics are best-effort operational signals, not a durable audit log. If the application requires durable audit delivery, it must provide and operate an appropriate event pipeline.

## 18. Structured safe logging

**Main implementation:** `src/logging/logger.ts`  
**Helper:** `createSafeLogger`

Logging is optional and disabled by default. The package does not add Pino, Winston, Bunyan, or another logging framework as a runtime dependency.

- Accepts a structurally compatible logger with optional `debug`, `info`, `warn`, and `error` methods.
- Missing methods are no-ops.
- Logger exceptions are isolated so logging does not interrupt authentication operations.
- The logger object is not mutated.
- Known sensitive fields (passwords, hashes, secrets, access/refresh tokens, ID tokens, authorization codes, OAuth state, PKCE verifier fields, and related credentials) are sanitized from nested payloads and arrays.
- Internal events use stable event names and non-sensitive metadata.

Applications remain responsible for reviewing their own logger, transport, and downstream log retention policies.

## 19. Typed errors

**Main implementation:** `src/errors/`

Auth errors extend `AuthError` and expose structured fields such as `code`, `status`, and `cause`, with JSON serialization support.

| Error | Code | Typical HTTP status |
|---|---|---:|
| `AuthError` | `AUTH_ERROR` | 401 |
| `InvalidTokenError` | `INVALID_TOKEN` | 401 |
| `TokenExpiredError` | `TOKEN_EXPIRED` | 401 |
| `UnauthorizedError` | `UNAUTHORIZED` | 401 |
| `ForbiddenError` | `FORBIDDEN` | 403 |
| `ConfigurationError` | `CONFIGURATION_ERROR` | 500 |
| `OAuthError` | `OAUTH_ERROR` | 401 |
| `ProviderError` | `PROVIDER_ERROR` | 502 |
| `ValidationError` | `VALIDATION_ERROR` | 400 |
| `InvalidRedirectUriError` | `INVALID_REDIRECT_URI` | 400 |

Exact adapter response formatting is framework-specific. Internal causes should be retained for diagnostics without exposing stack traces or sensitive upstream response content to clients.

## 20. Utilities and helper exports

The public utility surface includes helpers such as:

- `extractBearerToken`
- `parseExpiresIn`
- `isValidExpiresIn`
- `randomToken`
- `randomState`
- `sha256`
- `pkceVerifier`
- `pkceChallenge`

The package also exports in-memory store factories and provider helpers. Refer to `src/index.ts`, package exports, and the README API reference as the authority for the exact release's public symbol list.

## 21. Verification and test surface

The repository documents Vitest-based tests for:

- JWT signing and verification.
- Password hash algorithms and legacy verification.
- RBAC role inheritance and wildcard matching.
- OAuth state, PKCE, providers, and redirect URI validation.
- OIDC/JWKS behavior and key-rotation scenarios.
- External token verification.
- Framework adapters.
- Session and refresh-token lifecycle.
- Persistence contracts and architecture/public API exports.

The documented quality gates include:

```bash
npm run typecheck
npm run lint
npm test
npm run build
npm run pack:check
```

The repository also documents integration tests using Testcontainers for PostgreSQL and Redis, and provider/live Google verification tooling. Live provider checks are opt-in and are not equivalent to deterministic CI tests.

A test's presence in the repository is not proof that it passed in a particular environment. Release records should retain the actual CI result for the exact commit and package artifact.

## 22. Operational and security boundaries

For production use:

- Generate signing secrets using a cryptographically secure random generator; use at least 32 bytes of high-entropy secret material as documented in the README.
- Prefer a distinct refresh signing secret.
- Keep signing algorithms explicitly configured and pinned.
- Use shared durable stores for refresh rotation and session revocation across instances.
- Ensure required atomic storage capabilities are genuinely atomic in the chosen backend.
- Keep OAuth redirect allowlists exact and use HTTPS outside loopback development.
- Keep PKCE enabled.
- Avoid query-string tokens because URLs can leak through logs, browser history, and referrers.
- Use short access-token lifetimes when appropriate.
- Redact credentials in application logs and telemetry.
- Configure timeouts, response-size limits, and retry policy for external HTTP dependencies.
- Monitor storage, diagnostics queue behavior, provider failures, and authentication latency.

### Application responsibilities not provided by the library

The integrating application is responsible for:

- Login and API rate limiting.
- MFA and step-up authentication.
- Email verification.
- Password reset and account recovery.
- Account lockout and abuse detection.
- CSRF protection when using cookie-based authentication.
- User lifecycle, profile policy, and account deletion.
- Secret provisioning and rotation operations.
- Durable audit storage and delivery.
- Database provisioning, migrations, backups, access control, and connection lifecycle.
- Tenant isolation and application-specific authorization rules.

## 23. Known limitations

- In-memory stores are process-local, non-durable, and unsuitable for multi-instance production deployments.
- Revoking a refresh token does not automatically invalidate already-issued stateless access tokens.
- Immediate access-token/session invalidation requires a correctly configured session/revocation store and verification checks.
- OAuth/OIDC provider capabilities differ; not every provider exposes the same profile fields or ID-token behavior.
- JWKS refresh on unknown key identifiers is bounded; it does not force a provider to rotate keys.
- Live Google key rotation is not considered verified merely because monitoring scripts ran; verification requires observing and successfully validating a previously uncached key.
- Diagnostics are bounded best-effort events, not a durable audit trail.
- The package does not manage user accounts or provide MFA, email verification, password reset, or rate limiting.

## 24. Related documentation

- [`README.md`](../README.md) — installation, quick start, configuration, usage examples, storage integration, security guidance, and API reference.
- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — module boundaries, dependency direction, runtime flows, storage contracts, and architecture decisions.
- [`package.json`](../package.json) and `src/index.ts` — package metadata and exact public exports.

## 25. Documentation maintenance

Update this file when an implemented capability, public export, default, security guarantee, storage contract, adapter behavior, or operational limitation changes.

Before release, verify that:

- Feature claims match implementation and tests.
- README examples and configuration defaults match the public types.
- Architecture diagrams and module names remain current.
- Public exports match `src/index.ts` and `package.json`.
- Security statements distinguish package guarantees from application/store responsibilities.
- Tests are described as coverage, not as passed results unless CI evidence exists.
- Volatile facts (dependency versions, file counts, test totals) are omitted or tied to a specific revision.