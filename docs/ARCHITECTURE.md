# `@oneunit/auth` Architecture

## 1. Overview

`@oneunit/auth` (v2.0.2) is a framework-agnostic authentication and
authorization library for Node.js (>=20). It provides JWT issuance and
verification, access/refresh token lifecycle management, password hashing,
role-based access control (RBAC), OAuth 2.0 / OpenID Connect authorization-code
flows, external token verification, and thin adapters for Express, Fastify,
Koa, and uWebSockets.js.

The package is dual-published as ESM and CommonJS, with TypeScript declaration
files included. The public surface is `src/index.ts`, re-exported through
`package.json` `exports` and subpath mappings.

**Entry points:**
- Main: `src/index.ts` → `dist/cjs/index.cjs` / `dist/esm/index.js`
- Types: `src/types/index.ts` → `dist/types/index.d.ts`
- Subpath `./*` maps built files for all documented entry points

**Runtime dependencies:** `@noble/hashes` (^2.4.0), `jose` (^6.2.15)

**Optional dependencies:** `bcrypt` (^5.1.1)

**Peer/test dependencies:** `tsx`, `vitest`, TypeScript, testcontainers (Kafka,
PostgreSQL, Redis), `ioredis`, `kafkajs`, `pg`

## 2. Repository Structure

```
/src/
  index.ts                      # Public entry point (all exports)
  adapters/
    index.ts                    # expressAdapter, fastifyAdapter, koaAdapter,
                                # uwsAdapter, snapshotUwsRequest,
                                # createAdapters, createAdapterRegistry,
                                # validateStorageAdapter, validateEventAdapter
    adapter-registry.ts         # createAdapterRegistry (validates interfaces
                                # and declared capabilities)
    storage/
      storage-adapter.ts        # validateStorageAdapter
      storage-errors.ts         # InvalidRedirectUriError
    events/
      event-adapter.ts          # validateEventAdapter
    contracts/
      events/
        auth-event.ts           # AuthEvent type
        event-publisher.ts      # EventPublisher interface
        event-subscriber.ts     # EventSubscriber interface
        index.ts
      storage/
        index.ts                # Re-exports KeyValueStore, SessionStore,
                                # RefreshTokenStore, RevocationStore,
                                # VersionStore
        key-value.store.ts      # KeyValueStore (get/set/delete/consume, TTL)
        refresh-token.store.ts  # RefreshTokenStore (get/create/rotate/revoke)
        revocation.store.ts     # RevocationStore (revoke/isRevoked)
        session.store.ts        # SessionStore (get/set/delete, TTL)
        storage-capabilities.ts # StorageCapabilities (atomicConsume,
                                # atomicRefreshTokenRotation, atomicIncrement,
                                # ttl)
        version.store.ts        # VersionStore (get/increment)
    express/index.ts            # expressAdapter (middleware factory)
    fastify/index.ts            # fastifyAdapter (Fastify plugin)
    koa/index.ts                # koaAdapter (Koa middleware)
    uws/index.ts                # uwsAdapter (uWS handler wrapper),
                                # snapshotUwsRequest
  cache/
    cache-provider.ts           # CacheProvider, defaultCacheProvider,
                                # CacheProviderOptions
    shared-cache.ts             # SharedJwksCache, options types
  core/
    index.ts                    # Auth class, auth instance, memory stores
    auth.ts                     # Auth facade (login/verify/refresh/revoke/
                                # hooks/extractors/persistence lifecycle)
    context.ts                  # AuthContext, AsyncLocalStorage,
                                # createAuthContext/getCurrentAuthContext/
                                # runWithAuthContext
  crypto/
    index.ts                    # crypto exports
    jwt.ts                      # encode/decode/decodeUnsafe/encodeAccessToken/
                                # encodeRefreshToken/withTyp/default backend
    jwt-backend.ts              # JwtBackendImpl, DEFAULT_ALGORITHM_POLICY,
                                # key resolution (signing/verification, refresh)
    jwks.ts                     # JWKS inline/remote fetching and caching
    password.ts                 # hashPassword/verifyPassword/needsRehash,
                                # hashScryptPassword/verifyScryptPassword,
                                # legacy scrypt helpers, factories
    password-hasher.ts          # Argon2idPasswordHasher, BcryptPasswordHasher,
                                # ScryptPasswordHasher, CompositePasswordHasher,
                                # ARGON2ID_RECOMMENDED_PROFILE
    bcrypt/
      index.ts                  # BcryptPasswordHasher factory, isBcryptAvailable
      binding.ts                # optional bcrypt binding
      bcrypt-ambient.d.ts
  diagnostics/
    index.ts                    # emitDiagnostic/setDiagnosticsObserver/
                                # resetDiagnostics/getDiagnosticsStats/
                                # setDiagnosticsOverflowPolicy/
                                # setDiagnosticsErrorCallback
    emitter.ts                  # diagnostics emitter implementation
    tracing.ts                  # attachAuthContext
    types.ts                    # DiagnosticsObserver/DiagnosticsStats/...
    opentelemetry.d.ts
  errors/
    index.ts                    # AuthError base + 9 specialized error classes
  external-token/
    index.ts                    # ExternalTokenVerifier,
                                # createExternalTokenVerifier
    types.ts                    # TrustedIssuerConfig/ExternalTokenResult/
                                # ExternalTokenVerifyOptions/ExternalKeySource
    verifier.ts                 # token validation (issuer/algorithm/JWKS/
                                # claims/audience/type/size/maxAge)
  http/
    index.ts                    # configureHttp/dispatchHttp/
                                # dispatchHttpWithRetry/getHttpConfig/
                                # resetHttpConfig/resolveRetryConfig
    transport.ts                # HTTP client, timeouts, response-size limits,
                                # abort signal handling
    retry.ts                    # exponential backoff with jitter,
                                # retryable statuses/network failures
  logging/
    logger.ts                   # createSafeLogger (secret sanitization)
    types.ts                    # Logger type
  oauth/
    index.ts                    # OAuth class (register/authorize/callback/
                                # verifyState), TokenIntrospector,
                                # createTokenIntrospector, IntrospectionError
    introspection/
      client.ts                 # TokenIntrospector implementation
      types.ts                  # IntrospectionConfig/IntrospectionResult
      validator.ts              # response validation
    providers/
      index.ts                  # createProvider/getProvider/builtinProviders
                              # + all 14 built-in providers
      shared.ts                 # shared provider helpers
      google.ts, github.ts, instagram.ts, facebook.ts,
      twitter.ts, discord.ts, apple.ts, linkedin.ts, microsoft.ts,
      reddit.ts, twitch.ts, slack.ts, spotify.ts, tiktok.ts
    redirect-uri.ts             # validateRedirectUri (exact match,
                                # HTTPS-only except loopback opt-in)
  rbac/
    index.ts                    # RBAC class (roles/inheritance/cycle detection/
                                # permission resolution/subject cache)
    matcher-cache.ts            # MatcherCache (LRU/TTL/stats)
  stores/
    index.ts                    # createMemoryRefreshStore,
                                # createMemorySessionStore, createMemoryStateStore
    memory/
      index.ts
      refresh-store.ts          # MemoryRefreshStore
      session-store.ts          # MemorySessionStore
      state-store.ts            # MemoryStateStore (atomic consume)
  types/
    index.ts                    # All public TypeScript interfaces and types
  utils.ts                      # extractBearerToken/getHeader/isPlainObject/
                                # parseCookieHeader/parseExpiresIn/
                                # parseQueryString/randomToken/randomState/
                                # sha256/unique/toArray/normalizeName/...
/docs/
  ARCHITECTURE.md               # This file
  features.md                   # Feature index
  features/01-core-authentication.md ... 13-platform-compatibility.md
  features/README.md
  test/*-test-plan.md           # Test plans for each module
/examples/
  basic.ts                      # Basic usage example
/plans/
  p0-*/plan.md                  # Implementation plans
/plans/
  p0-*/LOGGER.md, PKCE.md, REDIRECT-URI.md
  p1-*/plan.md
  p2-*/plan.md
```

## 3. Module Architecture

### 3.1 Authentication Core (`src/core/`)

**`Auth` class** (`src/core/auth.ts`) — Composition root and primary facade.

Responsibilities:
- Validate required options at construction (`secret` is mandatory).
- Wire token, session, password, RBAC, OAuth, diagnostics, HTTP, and adapter services.
- Expose `login()`, `verify()`, `refresh()`, `revoke()`, `revokeAllSessions()`, `authorize()`, `hasRole()`, `can()`.
- Manage claim extractors, lifecycle hooks (`beforeLogin`, `afterLogin`, `afterVerify`), and reserved-claim protection.
- Wire `PersistenceAdapter` domains into internal stores (explicit individual stores take precedence).
- `initialize()` / `close()` lifecycle for persistence adapters.

**`context.ts`** — Request-scoped `AuthContext` carried via `AsyncLocalStorage`.

- `AuthContext` interface: `requestId`, `traceId`, `tenantId?`, `operationId`, plus string index signature for custom properties.
- `createAuthContext(init?)` — generates `requestId`/`traceId`/`operationId` via `randomToken(16)` when not supplied; `operationId` defaults to `requestId`.
- `runWithAuthContext(context, fn)` — runs `fn` inside `AsyncLocalStorage.run`.
- `getCurrentAuthContext()` — returns the active context or `undefined`.
- Consumed by `Auth.login`, `Auth.verify`, diagnostics emission, and framework adapters.

**`index.ts`** — Re-exports `Auth`, `auth` (alias for `Auth` class), `createAuth`, `createMemoryRefreshStore`, `createMemorySessionStore`.

### 3.2 JWT (`src/crypto/`)

**`jwt.ts`** — Public token issuance/verification helpers.

- `encode(payload, secret, options)` — signs a JWT; supports `expiresIn`, `expiresInSeconds`, `subject`, `audience`, `issuer`, `jwtid`, `notBefore`, `header`, `algorithm`, `keyid`, `backend`.
- `decode(token, secret, options)` — verified decode; supports `algorithms`, `audience`, `issuer`, `subject`, `clockTolerance`, `complete`, `backend`.
- `decodeUnsafe(token)` — unverified payload decoding (never for authorization decisions).
- `encodeAccessToken(payload, secret, options)` — signs with `typ: "access"`.
- `encodeRefreshToken(payload, secret, options)` — signs with `typ: "refresh"`.
- `withTyp(options)` — builds token-type-specific options.

**`jwt-backend.ts`** — `JwtBackendImpl` and `DEFAULT_ALGORITHM_POLICY`.

- Default algorithm policy: `signing: ["HS256"]`, `verification: ["HS256"]`.
- Separate signing/verification keys; optional `refreshSigningKey`/`refreshVerificationKey` selected by token `typ`.
- `keyResolver` support for `kid`-based key resolution.
- `clockTolerance` forwarded to JWT verification.
- `resolveSigningKey`/`resolveVerificationKey` select keys by algorithm policy and `kid`.

**`jwks.ts`** — JWKS inline document and remote HTTPS fetching with cache TTL and unknown-`kid` refetch.

### 3.3 Refresh Tokens

Refresh tokens carry `typ: "refresh"` and a unique `jti`. They are signed/verified with a separate refresh secret when configured. Rotation uses atomic `consume(jti)` — at most one successful consumption per refresh record, preventing replay.

### 3.4 Session Management

Session versioning via `SessionStore.getVersion(userId)` → version number (`getVersion` is required on the `SessionStore` type in `src/types/index.ts`; the adapter contract in `src/adapters/contracts/storage/session.store.ts` declares only `get`/`set`/`delete`). Tokens minted with the current version (`sv` claim). Verification compares token version against the store version; mismatch rejects. `SessionStore.bumpVersion(userId)` invalidates all sessions for a user (optional on the type, required by `revokeAllSessions`). `SessionStore.revokeSession(jti)` invalidates a single session (optional). `SessionStore.isSessionRevoked(sessionId)` checks revocation status (optional; `auth.ts` tries multiple method names plus `revoked`/`revokedSessions`/`revokedSids` properties as fallbacks). `sessionVersionPolicy` ("reject" | "migration" | "disabled") controls handling of tokens without `sv`.

### 3.5 RBAC (`src/rbac/`)

**`RBAC` class** (`src/rbac/index.ts`):
- Roles, permissions, inheritance (single and multiple parents), cycle detection (construction and mutation).
- Compiled parent chains and permission sets with revision tracking.
- Subject cache bounded at 1,024 entries, invalidated on mutation.
- `MatcherCache` with LRU eviction, TTL, hit/miss/size statistics.
- Wildcard matching: `*` matches one segment, `**` matches any suffix; `.` and `:` both treated as segment separators; literal segments regex-escaped.
- `hasRole`, `getRoles`, `getPermissions`, `subjectRoles`, `subjectPermissions`, `can`, `cannot`, `authorize` (throws `ForbiddenError`), `resolveParents`, `resolvePermissions`.
- Snapshot returns a detached plain-object export.

### 3.6 OAuth (`src/oauth/`)

**`OAuth` class** (`src/oauth/index.ts`):
- Provider registration via `use(id, config)`; built-in providers resolved from `builtinProviders`; unknown IDs use `createProvider`.
- Provider ID aliasing under `provider.id` when it differs from registration ID and alias is unused.
- `list()` returns all registered IDs including aliases; `get(id)` returns `ProviderEntry`.
- `authorize(id, options)` — generates state, validates redirect URI against exact-match allowlist, generates S256 PKCE verifier/challenge (enabled by default), stores state transaction with 600s default TTL, emits `oauth.authorization.started` diagnostic.
- `callback(id, params)` — parses URL/path/bare-query params, rejects provider `error`, requires `code`, atomically consumes state, validates provider match, enforces PKCE when enabled, exchanges code via provider, fetches profile, returns `{ provider, tokens, profile, state }`.
- `verifyState(state, expected?)` — non-consuming state lookup.
- Built-in providers (14): google, github, instagram, facebook, twitter, discord, apple, linkedin, microsoft, reddit, twitch, slack, spotify, tiktok. Google, Apple, Twitter support ID-token verification via JWKS.
- `createProvider(definition)` for custom providers with `tokenAuthMethod: "body"` | `"basic"`, `pkce`, `profileMap`, `parseProfile` (sync/async), `userInfoHeaders`, `extraAuthParams`, `extraTokenParams`.
- `TokenIntrospector` / `createTokenIntrospector` — RFC 7662 token introspection with bounded LRU cache, HTTPS requirement, `clientSecret` basic auth or body `client_id`.

**`redirect-uri.ts`** — `validateRedirectUri(uri, policy)`: exact string equality, HTTPS required except explicitly opted-in loopback (`localhost`, `127.0.0.1`, `[::1]` with `allowLocalhostHttp: true`), rejects lookalikes (`localhost.evil.example`), embedded credentials, non-HTTP(S) schemes, malformed URIs.

### 3.7 External Token Verification (`src/external-token/`)

**`ExternalTokenVerifier`** / **`createExternalTokenVerifier`** (`src/external-token/verifier.ts`):
- Trusted issuer allowlist with duplicate rejection at construction.
- Remote JWKS URLs require HTTPS unless `allowInsecureHttp` is explicitly enabled; unsupported schemes (e.g. `ftp://`) rejected at config time.
- 16 KiB hard cap on token size (UTF-8 bytes); whitespace-only tokens rejected.
- `alg: "none"` rejected unconditionally; missing/empty/malformed `alg` rejected.
- Algorithms restricted to per-issuer allowlist.
- Keys resolved from inline JWKS, JWKS resolver function (sync/async), or remote HTTPS JWKS URL by `kid`.
- Unknown `kid`, invalid signature, malformed signature rejected.
- Claims: `exp` (expiration), `nbf` (not-before), `iat` + `maxTokenAge` (issuer-level and per-call override), required claims, audience (string/array, per-call override), `typ` ("id"/"access").
- Returns `ExternalTokenResult` with `payload`, `issuer`, `audience`.
- JWKS resolver failures fail closed; tokens never accepted from untrusted issuers or unverified signatures.

### 3.8 Password Management (`src/crypto/`)

**`password-hasher.ts`**:
- `Argon2idPasswordHasher` — `$argon2id$` prefix, configurable cost/blockSize/parallelism/memoryKiB/keyLength/saltBytes, `needsRehash` uses "below minimum" (`<`) comparison.
- `BcryptPasswordHasher` — `$2b$`/`$2a$`/`$2y$` prefixes, 72-byte UTF-8 input limit, rounds 10-14, `needsRehash` uses strict inequality (`!==`).
- `ScryptPasswordHasher` — `$scrypt$`/`$2$` prefixes.
- `CompositePasswordHasher` — prefix dispatch: `$argon2id$` → Argon2id, `$2b$`/`$2a$`/`$2y$` → Bcrypt, `$2$`/`$scrypt$` → Scrypt; unknown prefixes reject.
- `ARGON2ID_RECOMMENDED_PROFILE` exported.

**`password.ts`** — `hashPassword`, `verifyPassword`, `needsRehash`, `hashScryptPassword`, `verifyScryptPassword`, `scryptNeedsRehash`, factories (`createPasswordHasher`), process-wide default hasher (`getDefaultPasswordHasher`/`setDefaultPasswordHasher`).

**`bcrypt/`** — optional bcrypt binding; `isBcryptAvailable()` detection; binding unavailable handled gracefully.

### 3.9 User Management

`UserStore` interface (optional): `findById`, `findByEmail`, `findByUsername`, `findByCredentials`, `findByProvider`, `create`, `createFromProvider`, `linkProvider`, `updatePassword` — all optional. `UserRecord` has `id` (string|number), optional email/username/name/avatar/roles/role/permissions/passwordHash/provider/providerId, plus string index signature.

### 3.10 Persistence (`src/adapters/` contracts + `src/core/auth.ts`)

**`PersistenceAdapter`** (`src/types/index.ts`): optional `keyValue`, `sessions`, `refreshTokens`, `revocations`, `versions`, `users` domains; optional `initialize()` and `close()` lifecycle hooks. Each domain independently optional; omitted domains fall back to in-memory behavior.

**`StorageAdapter`** / **`EventAdapters`** / **`AuthAdapters`** — validation via `validateStorageAdapter` / `validateEventAdapter` / `createAdapterRegistry`. Capability declarations (`atomicConsume`, `atomicRefreshTokenRotation`, `atomicIncrement`, `ttl`) validated against required methods at construction; mismatches throw `ConfigurationError`.

**In-memory implementations** (`src/stores/memory/`): `MemoryRefreshStore`, `MemorySessionStore`, `MemoryStateStore` (single-process, atomic consume within one event loop).

### 3.11 HTTP Transport (`src/http/`)

**`transport.ts`** — `configureHttp`, `dispatchHttp`, `getHttpConfig`, `resetHttpConfig`, `HttpClient`.

- Per-client isolation: `HttpClient` instances keep their own immutable-per-instance configuration; configuring one client never affects another.
- Module-level helpers operate on a shared default `HttpClient`; per-call `dispatchHttp(url, {...})` overrides remain supported.
- `configureHttp`/`resetHttpConfig` affect only the default client for backward compatibility.

- Global config: `transport`, `timeoutMs` (clamped 1-120000ms, default 15000), `maxResponseBytes` (clamped 1024-5MiB, default 1MiB), `redirect` ("error" default), `baseUrl`, `headers`.
- Relative URLs resolved against configured `baseUrl`.
- Configurable headers merged with per-request headers (per-request wins).
- Response-size limit enforced via `Content-Length` pre-check and streamed-body chunk counting: default `maxResponseBytes` is 1 MiB (`1_048_576`), clamped between 1 KiB and 5 MiB.
- Timeout via `AbortController`; caller-supplied signals combined.
- Config snapshots are defensive copies (nested headers deep-copied).

**`retry.ts`** — `dispatchHttpWithRetry`, `resolveRetryConfig`.

- Exponential backoff with full jitter: `initialDelayMs * 2^attempt`, capped at `maxDelayMs`.
- Retryable statuses: 429, 502, 503, 504 (configurable).
- Network failures (ECONNREFUSED, ENOTFOUND, ETIMEDOUT, ECONNRESET, TypeError) retryable; aborts never retried.
- Idempotent methods (GET/HEAD/OPTIONS) retried by default; non-idempotent require `allowNonIdempotentRetry`.
- `maxRetries` (default 3, hard cap 10); total attempts ≤ maxRetries + 1.
- `deadlineMs` optional total deadline.

### 3.12 Framework Adapters (`src/adapters/`)

| Adapter | Integration | Token Extraction | User/Token Attachment | Error Handling |
|---------|------------|------------------|----------------------|----------------|
| Express | Middleware factory (`initialize` + `authenticate`) | Bearer header from `req.headers.authorization` | `req.user`, `req.token` | `sendError` tries `status().send()`, `code().send()`, or `status`+`body` property; `next()` not called on failure (unless `optional` → `req.user = null; next()`, or `passthrough` → `next(error)`) |
| Fastify | Plugin (`fastify.plugin`) with `authenticate` decorator | Bearer header | `request.user` | Returns `reply.code(status).send({error, message})`; `next()` not called on failure (unless `optional` → `request.user = null; return`) |
| Koa | Middleware factory | Bearer header from `ctx.request` | `ctx.state.user`, `ctx.state.token` | Sets `ctx.status`/`ctx.body`; `next()` outside try block so downstream errors go to Koa's handler; `next()` not called on failure (unless `optional` → `ctx.state.user = null; await next()`) |
| uWS | Handler wrapper | Bearer header or query string (when configured) | `request.user`, `request.token` on snapshot | Calls `jsonResponse(res, status, body)`; handler not called on failure (unless `optional` → handler called with `request.user = null`) |

All adapters:
- Extract credentials with explicit precedence (Bearer header default; query-string disabled by default).
- Call `auth.verifyRequest()` for core verification.
- Attach verified principal to framework request/context.
- Map `AuthError` codes/status to HTTP responses (401/403/5xx).
- Never leak secrets, tokens, or stack traces in responses.
- uWS snapshots request data (method, URL, query, headers, cookies, response ref) before async work via `snapshotUwsRequest`.

**`createAdapters(auth)`** — returns `{ express, fastify, koa, uws, uWebSockets }`.

**`snapshotUwsRequest(res, req, extra?)`** — captures method, URL, query, headers (via `forEach` or `getHeader`), cookies, response reference; immutable after creation.

### 3.13 Auth Context (`src/core/context.ts`)

See 3.1 above. `AsyncLocalStorage`-based, propagates across `await` boundaries, nested contexts replace outer for inner callbacks and restore afterward, no context leaks after callback completion.

### 3.14 Diagnostics (`src/diagnostics/`)

**`emitter.ts`** — bounded async queue (default 32 pending entries), `"drop"` and `"report"` overflow policies, observer callbacks (sync/async), error callback routing for observer failures, hit/miss/size statistics, `resetDiagnostics()` clears stats/queue/observer.

Events emitted by `Auth.login`, `Auth.verify`, OAuth authorize/callback, diagnostics-safe (no secrets/tokens in payloads).

### 3.15 Logging (`src/logging/`)

**`createSafeLogger(logger?)`** — wraps an optional `Logger` (`debug`/`info`/`warn`/`error`, all optional). Missing methods no-op. Synchronous exceptions swallowed. Logger object never mutated. Secret sanitization removes 14 documented keys (`password`, `passwordHash`, `secret`, `refreshSecret`, `accessToken`, `refreshToken`, `id_token`, `token`, `authorizationCode`, `code`, `verifier`, `codeVerifier`, `state`) from payloads before forwarding, including in arrays and nested objects.

### 3.16 Errors (`src/errors/`)

`AuthError` base class with `code`, `status`, `cause`, `toJSON()`. 9 specialized classes:

| Class | Code | Status |
|-------|------|--------|
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

All extend `AuthError`; all have `instanceof` chain; `code`/`status`/`cause` optional typed metadata.

### 3.17 Shared Types (`src/types/index.ts`)

`AuthOptions`, `LoginOptions`, `LoginResult`, `JwtSignOptions`, `JwtVerifyOptions`, `JwtPayload`, `JwtAlgorithmPolicy`, `JwtBackend`, `RBACOptions`, `RoleDefinition`, `AuthSubject`, `MatcherCacheOptions`, `OAuthProvider`, `OAuthProviderConfig`, `OAuthProfile`, `OAuthTokens`, `OAuthOptions`, `RedirectUriPolicy`, `StateStore`, `UserStore`, `UserRecord`, `RefreshStore`, `RefreshRecord`, `SessionStore`, `PersistenceAdapter`, `EventAdapters`, `AuthAdapters`, `StorageCapabilities`, `HttpClientConfig`, `HttpRetryConfig`, `DispatchHttpOptions`, `ExtractTokenOptions`, `RequestLike`, `ExpressRequestLike`, `ExpressResponseLike`, `KoaContextLike`, `FastifyLike`, `FastifyRequestLike`, `FastifyReplyLike`, `UwsHttpRequest`, `UwsHttpResponse`, `UwsRequestSnapshot`, `UwsHandler`, `AuthContext`, `Logger`, `PasswordAlgorithm`, `PasswordOptions`, `SessionVersionPolicy`, `SessionRevocationResult`, `PersistenceErrorCode`, `PersistenceErrorInfo`, `KeyValueStore`, `RevocationStore`, `VersionStore`.

## 4. Module Dependency Direction

```
Consumer[Application Code]
PublicAPI[src/index.ts - Public Exports]
Core[src/core/auth.ts - Auth Facade]
Crypto[src/crypto/ - JWT, Password, JWKS]
RBAC[src/rbac/ - Role-Based Access Control]
OAuth[src/oauth/ - OAuth/OIDC Providers]
ExternalToken[src/external-token/ - External JWT Verification]
Http[src/http/ - Transport & Retry]
Adapters[src/adapters/ - Framework & Storage Adapters]
Diagnostics[src/diagnostics/ - Event Emitter]
Logging[src/logging/ - Safe Logger]
Errors[src/errors/ - Error Hierarchy]
Types[src/types/ - Shared Type Definitions]
Stores[src/stores/ - In-Memory Stores]
Utils[src/utils.ts - Shared Utilities]
Ports[Storage/Event Contracts]
Implementations[Redis/SQL/Memory - App-Owned]
Frameworks[Express/Fastify/Koa/uWS - App-Owned]

Consumer --> PublicAPI
PublicAPI --> Core
PublicAPI --> Crypto
PublicAPI --> RBAC
PublicAPI --> OAuth
PublicAPI --> ExternalToken
PublicAPI --> Http
PublicAPI --> Adapters
PublicAPI --> Diagnostics
PublicAPI --> Logging
PublicAPI --> Errors
PublicAPI --> Types
Core --> Crypto
Core --> RBAC
Core --> OAuth
Core --> Http
Core --> Diagnostics
Core --> Logging
Core --> Errors
Core --> Types
Core --> Stores
Core --> Utils
Crypto --> Types
Crypto --> Utils
Crypto --> Errors
RBAC --> Types
RBAC --> Utils
RBAC --> Errors
OAuth --> Crypto
OAuth --> Http
OAuth --> Diagnostics
OAuth --> Logging
OAuth --> Errors
OAuth --> Types
OAuth --> Utils
ExternalToken --> Crypto
ExternalToken --> Http
ExternalToken --> Diagnostics
ExternalToken --> Errors
ExternalToken --> Types
Http --> Types
Http --> Errors
Adapters --> Core
Adapters --> Crypto
Adapters --> OAuth
Adapters --> Http
Adapters --> Diagnostics
Adapters --> Logging
Adapters --> Errors
Adapters --> Types
Diagnostics --> Types
Diagnostics --> Errors
Logging --> Types
Errors --> Types
Stores --> Types
Utils --> Types
Implementations -.-> Ports
Frameworks -.-> Adapters
```

**Hard rules verified in implementation:**
- `core/` never imports Express, Fastify, Koa, uWebSockets.js, Redis, or any concrete database client.
- Adapters only translate requests → core calls and map typed errors → HTTP responses.
- `crypto/` knows nothing about HTTP, users, or frameworks.
- Only `index.ts` (and declared subpath exports) are public.
- Internal modules import via relative `.js` extensions (ESM/NodeNext resolution).

### 4.4 Runtime Flow Diagrams

#### 4.4.1 Authentication & Authorization Lifecycle

```mermaid
flowchart TD
    A[Incoming Framework Request] --> B[Adapter: Extract Bearer Token]
    B --> C{Token Present?}
    C -->|No| D[Return 401 Unauthorized]
    C -->|Yes| E[Adapter: Call auth.verifyRequest()]
    E --> F[JWT Backend: Verify Signature & Claims]
    F --> G{Valid Signature?}
    G -->|No| H[Return 401 InvalidTokenError]
    G -->|Yes| I[Session Store: Check sv Version]
    I --> J{Version Matches?}
    J -->|No| K[Return 401 Session Revoked]
    J -->|Yes| L[Session Store: Check sid Revocation]
    L --> M{Session Revoked?}
    M -->|Yes| N[Return 401 Session Revoked]
    M -->|No| O[RBAC: Resolve Subject Permissions]
    O --> P{Permission Granted?}
    P -->|No| Q[Return 403 ForbiddenError]
    P -->|Yes| R[Attach User/Token to Request Context]
    R --> S[Downstream Handler]
    
    style D fill:#ff9999
    style H fill:#ff9999
    style K fill:#ff9999
    style N fill:#ff9999
    style Q fill:#ff9999
    style S fill:#99ff99
```

#### 4.4.2 Refresh Token Rotation Flow

```mermaid
flowchart TD
    A[Client Presents Refresh Token] --> B[Verify Refresh JWT]
    B --> C{Valid & typ=refresh?}
    C -->|No| D[Return 401 Unauthorized]
    C -->|Yes| E[Check jti Present]
    E -->|No| F[Return 401: jti Required]
    E -->|Yes| G[refreshStore.consume(jti) - Atomic]
    G -->|Consumed|null H[Return 401: Token Revoked/Replayed]
    G -->|Record| I[Check Session Version (sv)]
    I -->|Mismatch| J[Return 401: Session Revoked]
    I -->|Match| K[Mint New Access + Refresh Token Pair]
    K --> L[Save New Refresh Record]
    L --> M[Return New Tokens to Client]
    
    style D fill:#ff9999
    style F fill:#ff9999
    style H fill:#ff9999
    style J fill:#ff9999
    style M fill:#99ff99
```

#### 4.4.3 Persistence & Adapter Integration

```mermaid
flowchart TD
    A[Auth Facade] --> B{Persistence Adapter?}
    B -->|Yes| C[Use Adapter-Provided Stores]
    B -->|No| D[Use In-Memory Stores]
    
    C --> C1[KeyValueStore]
    C --> C2[SessionStore]
    C --> C3[RefreshTokenStore]
    C --> C4[RevocationStore]
    C --> C5[VersionStore]
    C --> C6[UserStore]
    
    D --> D1[MemoryKeyValueStore]
    D --> D2[MemorySessionStore]
    D --> D3[MemoryRefreshStore]
    
    C1 --> E[OAuth State, General Cache]
    C2 --> F[Session Versioning, Revocation]
    C3 --> G[Refresh Token Rotation]
    C4 --> H[Token Revocation Lookup]
    C5 --> I[Session Version Increment]
    C6 --> J[User Lookup & Creation]
    
    D1 --> E
    D2 --> F
    D3 --> G
    
    A --> K[Framework Adapters: Express/Fastify/Koa/uWS]
    K --> L[auth.verifyRequest()]
    L --> M[Core Auth Logic]
    
    style A fill:#e1f5fe
    style C fill:#fff3e0
    style D fill:#fff3e0
    style E fill:#e8f5e9
    style F fill:#e8f5e9
    style G fill:#e8f5e9
    style H fill:#e8f5e9
    style I fill:#e8f5e9
    style J fill:#e8f5e9
```

**Diagram validation notes:**
- All component names match public interfaces in `src/types/index.ts`
- Directional arrows represent real import/call relationships verified in source
- Optional/configurable components are described in accompanying text
- External systems (frameworks, databases) are shown outside the package boundary

## 5. Runtime Execution Flows

### 5.1 Package Initialization

```
Application calls createAuth(options)
    │
    ▼
validate secret present (ConfigurationError if missing)
    │
    ├─ configure refreshSecret (defaults to secret)
    ├─ configure RBAC (normalizeRbac)
    ├─ configure password hasher (default Argon2id)
    ├─ configure safe logger (createSafeLogger)
    ├─ configure HTTP (configureHttp if options.http)
    ├─ configure diagnostics observer (setDiagnosticsObserver if options.diagnostics)
    ├─ create adapter registry (validateStorageAdapter/validateEventAdapter)
    ├─ create OAuth instance
    ├─ wire persistence adapter domains into stores
    ├─ create JWT backend (JwtBackendImpl with HS256 policy)
    │
    ▼
Auth instance ready
```

### 5.2 User Login

```
Application calls auth.login(user, options)
    │
    ├─ validate user.id present
    ├─ resolve context (options.context ?? getCurrentAuthContext() ?? createAuthContext())
    ├─ runWithAuthContext(context, async () => {
    │   ├─ emitDiagnostic(auth.login.started)
    │   ├─ run beforeLogin hooks
    │   ├─ resolve roles (user.roles + user.role)
    │   ├─ derive permissions (trustUserPermissions ? user.permissions : []) ∪ rbac.subjectPermissions()
    │   ├─ collect claims via registered extractors (reserved claims rejected)
    │   ├─ build payload (sub, userId, email?, username?, name?, roles, permissions, ...)
    │   ├─ issue access token via jwtBackend.sign (typ: "access")
    │   ├─ if refresh enabled: create refresh record, issue refresh token (typ: "refresh")
    │   ├─ persist refresh record BEFORE returning
    │   ├─ run afterLogin hooks
    │   ├─ emitDiagnostic(auth.login.succeeded)
    │   │
    │   ▼
    │   return LoginResult { token, accessToken, refreshToken, payload, user, oauth? }
    │
    ├─ onLogin hook fires
    │
    ▼
LoginResult returned to caller
```

### 5.3 Access Token Verification

```
Application calls auth.verify(token, options)
    │
    ├─ validate token present
    ├─ resolve context
    ├─ runWithAuthContext(context, async () => {
    │   ├─ jwtBackend.verify(token, {algorithms, issuer, audience, clockTolerance, acceptTokenType})
    │   │   ├─ resolve verification key (typ-based refresh key selection)
    │   │   ├─ verify signature with jose jwtVerify
    │   │   ├─ check exp, nbf with clock tolerance
    │   │   ├─ check issuer/audience constraints
    │   │   ├─ check token type (typ) against acceptTokenType
    │   │   │
    │   │   ▼
    │   │   claims
    │   ├─ assertSessionActive(claims) - check sv version against SessionStore
    │   ├─ assertSessionNotRevoked(claims) - check isSessionRevoked
    │   ├─ reject refresh tokens used as access tokens (typ check)
    │   ├─ run afterVerify hooks
    │   ├─ emitDiagnostic(token.verification.succeeded)
    │   │
    │   ▼
    │   return claims
    │
    ├─ on any error:
    │   ├─ emitDiagnostic(token.verification.failed)
    │   ├─ throw error (UnauthorizedError/InvalidTokenError/TokenExpiredError/ForbiddenError)
    │
    ▼
claims returned or error thrown
```

### 5.4 Token Refresh

```
Application calls auth.refresh(refreshToken)
    │
    ├─ verify refresh token (typ: "refresh", refresh verification key)
    ├─ check sv version if session store configured
    ├─ consume refresh token atomically via refreshStore.consume(jti)
    │   ├─ if consume returns null → reject (replay/expired/invalid)
    │   │
    ├─ issue new access + refresh token pair
    ├─ persist new refresh record before returning
    │
    ▼
new LoginResult returned
```

### 5.5 Session Revocation

```
Application calls auth.revokeAllSessions(userId) or auth.revokeSession(jti)
    │
    ├─ bumpVersion(userId) via SessionStore (invalidates all tokens with stale sv)
    ├─ or revokeSession(jti) via SessionStore
    │
    ▼
subsequent verifications reject stale-version tokens
```

### 5.6 Authorization (RBAC)

```
Application calls auth.can(subject, permission) or auth.authorize(subject, permission)
    │
    ├─ resolve subject roles (rbac.subjectRoles)
    ├─ resolve subject permissions (rbac.subjectPermissions)
    ├─ check wildcard matching (MatcherCache)
    ├─ return true/false (can) or throw ForbiddenError (authorize)
    │
    ▼
boolean or error
```

### 5.7 OAuth Authorization Code Flow

```
Application calls oauth.authorize(id, options)
    │
    ├─ resolve provider (builtin or custom)
    ├─ generate state (randomState)
    ├─ validate redirect URI against exact-match allowlist
    ├─ generate PKCE verifier/challenge (S256, default enabled)
    ├─ stateStore.set(state, {provider, redirectUri, codeVerifier, createdAt}, ttlSeconds=600)
    ├─ emitDiagnostic(oauth.authorization.started)
    │
    ▼
return { url, state, provider, codeVerifier }

Application calls oauth.callback(id, params)
    │
    ├─ parse params (URL/path/bare-query)
    ├─ reject if provider error
    ├─ require code
    ├─ stateStore.consume(state) atomically
    ├─ validate provider match
    ├─ validate PKCE code verifier when enabled
    ├─ provider.exchangeCode(code, redirectUri, verifier)
    ├─ provider.fetchProfile(config, tokens)
    │
    ▼
return { provider, tokens, profile, state }
```

### 5.8 External Token Verification

```
Application calls verifier.verify(token, issuer, options)
    │
    ├─ reject if token > 16 KiB
    ├─ reject whitespace-only token
    ├─ parse JWT structure (3 segments, valid base64url, valid JSON)
    ├─ extract iss from payload; reject if not in trusted allowlist
    ├─ extract alg from header; reject "none", missing, empty, malformed
    ├─ check alg against issuer allowlist
    ├─ resolve key by kid from issuer's JWKS source (inline/resolver/remote HTTPS)
    ├─ verify signature with jose
    ├─ check exp, nbf with clock tolerance
    ├─ check iat + maxTokenAge (issuer-level or per-call override)
    ├─ check required claims
    ├─ check audience (issuer-level or per-call override)
    ├─ check typ against expectedTokenType ("id"/"access")
    │
    ▼
return ExternalTokenResult { payload, issuer, audience }
```

### 5.9 Framework Request Authentication (Express example)

```
Express middleware (expressAdapter(auth).authenticate(options))
    │
    ├─ create AuthContext from x-request-id / x-trace-id headers
    ├─ runWithAuthContext(context, () => auth.verifyRequest(req, options))
    │   ├─ extractBearerToken from Authorization header
    │   ├─ auth.verify(token, options)
    │   │
    │   ▼
    │   JwtPayload
    │
    ├─ set req.user = payload, req.token = raw token
    ├─ call next()
    │
    ├─ on UnauthorizedError:
    │   ├─ options.optional ? req.user = null, next()
    │   ├─ options.passthrough ? next(error)
    │   ├─ else sendError(res, error) → 401 JSON
    │
    ▼
downstream handler or error response
```

## 6. Configuration Architecture

### 6.1 `AuthOptions`

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `secret` | `string \| Buffer` | Yes | — | at least 32 bytes (256 bits) high-entropy material |
| `refreshSecret` | `string \| Buffer` | No | `secret` | if provided, at least 32 bytes |
| `issuer` | `string` | No | `undefined` |
| `audience` | `string \| string[]` | No | `undefined` |
| `algorithm` | `"HS256" \| "RS256" \| "ES256"` | No | `"HS256"` | unsupported values rejected at construction; RS256/ES256 require caller-supplied appropriate key material or custom `jwtBackend` |
| `clockTolerance` | `number` | No | `0` | strict default; suggest 5–30 seconds in multi-host deployments |
| `accessTokenTtl` | `string \| number` | No | `"15m"` |
| `refreshTokenTtl` | `string \| number` | No | `"7d"` |
| `clockTolerance` | `number` | No | `0` |
| `trustUserPermissions` | `boolean` | No | `false` |
| `sessionVersionPolicy` | `"reject" \| "migration" \| "disabled"` | No | `"migration"` |

Optional: `jwtBackend`, `userStore`, `refreshStore`, `sessionStore`, `passwordHasher`, `http`, `diagnostics`, `rbac`/`roles`, `oauth`/`providers`, `redirectUri`, `logger`, `onLogin`, `onLink`, `adapters`, `persistence`, `claimExtractors`, hooks.

### 6.2 `OAuthOptions`

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `redirectUri` | `string` | No | `null` |
| `stateStore` | `StateStore` | No | `createMemoryStateStore()` |
| `providers` | `Record<string, OAuthProviderConfig>` | No | `{}` |
| `logger` | `Logger` | No | safe no-op logger |
| `http` | `HttpClientConfig` | No | global defaults |

### 6.3 `HttpClientConfig`

| Field | Type | Required | Default | Constraints |
|-------|------|----------|---------|-------------|
| `transport` | `HttpTransport` | No | `globalThis.fetch` |
| `timeoutMs` | `number` | No | `15000` | clamped [1, 120000] |
| `maxResponseBytes` | `number` | No | `1048576` | clamped [1024, 5242880] |
| `redirect` | `"error" \| "follow" \| "manual"` | No | `"error"` |
| `baseUrl` | `string` | No | `""` |
| `headers` | `Record<string, string>` | No | `{}` |

### 6.4 `HttpRetryConfig`

| Field | Type | Required | Default |
|-------|------|----------|---------|
| `maxRetries` | `number` | No | `3` (hard cap 10) |
| `initialDelayMs` | `number` | No | `200` |
| `maxDelayMs` | `number` | No | `3000` |
| `jitter` | `boolean` | No | `true` |
| `retryableStatuses` | `number[]` | No | `[429, 502, 503, 504]` |
| `allowNonIdempotentRetry` | `boolean` | No | `false` |
| `deadlineMs` | `number` | No | `undefined` |

### 6.5 Configuration Precedence

1. Construction-time options in `AuthOptions` / `OAuthOptions` / `HttpClientConfig`.
2. Per-call options override global config in `dispatchHttp`, `dispatchHttpWithRetry`, `auth.verify`, `oauth.authorize`.
3. `resetHttpConfig()` restores defaults; `resetDiagnostics()` clears diagnostics state.

### 6.6 Validation at Construction

- Missing `secret` → `ConfigurationError`.
- Invalid redirect URIs in provider `redirectUriPolicy.allowedRedirectUris` → fail at `use()`.
- Adapter capability mismatches (declared but unimplemented methods) → `ConfigurationError` at `createAdapterRegistry` / `createAuth`.
- PKCE disabled (`pkce: false`) → security-downgrade warning logged (not an error).
- Algorithm policy enforced at sign/verify time; algorithms outside policy rejected.

## 7. Data and Persistence Architecture

### 7.1 Store Interfaces

| Store | Methods | Optional? | Sync/Async |
|-------|---------|-----------|------------|
| `KeyValueStore` | `get`, `set` (with `ttlSeconds?`), `delete`, `consume` | Partial domain | Both |
| `SessionStore` | `get`, `set` (with `ttlSeconds?`), `delete` in adapter contract; `getVersion` (required), `bumpVersion?`, `revokeSession?`, `isSessionRevoked?` on `types/index.ts` type | Partial domain | Both |
| `RefreshTokenStore` (adapter) | `get`, `create`, `rotate` (must be atomic), `revoke` | Partial domain | Both |
| `RefreshStore` (core type) | `save`, `get`, `consume` (must be atomic), `revoke?` | Required `consume()` | Both |
| `RevocationStore` | `revoke`, `isRevoked` | Partial domain | Both |
| `VersionStore` | `get`, `increment` | Partial domain | Both |
| `UserStore` | `findById`, `findByEmail`, `findByUsername`, `findByCredentials`, `findByProvider`, `create`, `createFromProvider`, `linkProvider`, `updatePassword` | All optional | Both |

All store methods may return `Promise<T>` or `T` directly (synchronous implementations supported).

There are two refresh-related contracts:
- **`RefreshStore` (from `src/types/index.ts`) is used by `Auth` for token rotation.** It requires `consume(id)` to be atomic (synchronous read+delete in the in-memory implementation; GETDEL/conditional DELETE in distributed stores). If `consume` is missing, `Auth.refresh` raises `ConfigurationError`.
- **`RefreshTokenStore` (from `src/adapters/contracts/storage/refresh-token.store.ts`) is an adapter-domain contract exposing `create`/`rotate`/`revoke`.** `rotate()` must atomically invalidate the old id and create its replacement.

Adapter-backed persistence and explicitly provided individual stores are configured by `PersistenceAdapter`: individual stores take precedence over adapter-provided domains. Atomicity guarantees belong to the backing implementation, not to the interface alone.

### 7.2 In-Memory Implementations

- `MemoryRefreshStore` — `save`, `get`, `consume`, `revoke`.
- `MemorySessionStore` — `get`, `set` (with TTL), `delete`, plus `getVersion`, `bumpVersion`, `revokeSession`, `isSessionRevoked`.
- `MemoryStateStore` — `set`, `get`, `delete`, `consume` (atomic, single-process).

Single-process only; not suitable for multi-instance production.

### 7.3 Record Structures

**`UserRecord`**: `id` (string\|number), optional `email`/`username`/`name`/`avatar`/`roles`/`role`/`permissions`/`passwordHash`/`provider`/`providerId`, string index signature.

**`RefreshRecord`**: `id`, `userId`, `tokenHash`, `expiresAt`.

**`OAuthStateRecord`**: `provider`, `redirectUri?`, `codeVerifier?`, `createdAt`, `metadata?`.

**`LoginResult`**: `token`, `accessToken`, `refreshToken` (string\|null), `payload` (JwtPayload), `user` ({id, email?, username?, name?, roles, permissions}), `oauth?` ({provider, tokens, profile, state}).

### 7.4 Production Deployment Considerations

#### 7.4.1 In-Memory Store Suitability

In-memory stores (`MemoryRefreshStore`, `MemorySessionStore`, `MemoryStateStore`) are **process-local only**:

- Data is lost when the process restarts.
- Multiple application instances do not automatically share state.
- Appropriate for tests, examples, and explicitly single-process deployments.
- Not suitable for multi-instance production deployments without a shared external store.

#### 7.4.2 Distributed-Store Requirements

When running multiple application instances, the following stores must be shared (backed by a common database, Redis, or similar):

| Store | Why Shared | Required Atomic Operations |
|-------|-----------|---------------------------|
| `RefreshTokenStore` | Refresh rotation across instances | `consume(jti)` must be atomic (single GETDEL/DELETE RETURNING) |
| `SessionStore` | Session version/revocation across instances | `bumpVersion(userId)` must be atomic and monotonic |
| `RevocationStore` | Session revocation across instances | `revoke(tokenId)`, `isRevoked(tokenId)` |
| `VersionStore` | Session version increment | `increment(subjectId)` must be atomic |
| `KeyValueStore` | OAuth state across instances | `consume(key)` must be atomic |

#### 7.4.3 Storage Failure Behavior

| Failure | Operation Affected | Expected Package Behavior | Application Responsibility |
|---------|-------------------|--------------------------|---------------------------|
| Store unavailable | Verify/refresh/revoke | Errors propagate; token not accepted | Retry, alert, fail-closed/open policy |
| Atomic operation unsupported | Refresh rotation, OAuth state | `ConfigurationError` at construction or runtime | Implement required capability |
| Expired/missing record | Relevant lifecycle | Documented rejection (e.g., "token revoked") | Configure TTL and retention |
| Partial persistence failure | Multi-step operation | No implicit rollback; behavior varies by operation | Monitor and reconcile if needed |

No retry, rollback, or fail-closed guarantees are made beyond what the implementation explicitly documents. Behavior not guaranteed by the package is marked as application responsibility.

#### 7.4.4 Deployment Topology

A minimal multi-instance deployment:

```
[Application Instance 1]      [Application Instance 2]
           |                           |
           +---------------+-----------+
                           |
                 [Shared External Persistence]
                 (Redis/PostgreSQL/etc.)
                           |
                 [Shared Signing/Verification Keys]
                           |
                 [External Identity Provider]
                 (OAuth/OIDC JWKS, if used)
```

All instances must share the same `secret`/`refreshSecret` for JWT verification to work across instances. All instances must point to the same shared persistence for refresh rotation and session revocation to work correctly.

## 8. Framework Integration Architecture

Adapters translate framework requests → `auth.verifyRequest()` → framework response. Each adapter:

1. Extracts bearer token from `Authorization` header (default) or query string (opt-in).
2. Calls core verification.
3. Attaches `user` and `token` to framework request/context.
4. On failure: returns appropriate HTTP status (401/403) with JSON error body; does not invoke the downstream handler (`next()` not called in Express/Koa, response returned in Fastify, handler not invoked in uWS).
5. On unexpected errors: Express falls through to its error handler if `sendError` cannot write a response; Fastify/Koa/uWS write the error response directly.

**uWS-specific:** `snapshotUwsRequest()` captures method, URL, query, headers, cookies, response reference before async work; verification uses snapshot values; response written through captured response object.

## 9. Security Architecture

### 9.1 JWT
- Algorithms pinned to `["HS256"]` for both signing and verification (configurable via `algorithmPolicy`).
- `alg: "none"` rejected unconditionally in external token verification.
- Access (`typ: "access"`) and refresh (`typ: "refresh"`) tokens distinguished; refresh tokens rejected in access-token paths.
- Separate refresh signing/verification keys when `refreshSecret` differs from `secret`.
- `kid`-based key resolution via `JwtBackendImpl.resolveSigningKey`/`resolveVerificationKey`.
- Clock tolerance configurable; expiration and not-before enforced.

### 9.2 OAuth
- PKCE (S256) required by default for all clients; `pkce: false` is an explicit security-downgrade opt-out with warning.
- State consumed atomically via `consume()`; get-then-delete is rejected.
- Redirect URI validated against exact-match allowlist before authorization URL construction; HTTPS required except opted-in loopback.
- Callback uses stored redirect URI, never callback-supplied input.
- ID-token signature verification for Google, Apple, Twitter via JWKS.
- Provider profiles never used to assign application roles/permissions.

### 9.3 Password
- Argon2id default with `ARGON2ID_RECOMMENDED_PROFILE`.
- Bcrypt 72-byte UTF-8 input limit enforced.
- Constant-time comparison via `jose`/`@noble/hashes`.
- Malformed hashes reject without unbounded work.
- `needsRehash` identifies below-policy hashes.

### 9.4 Sessions & Refresh
- Atomic `consume(jti)` prevents refresh token replay.
- Session version (`sv`) invalidates all prior tokens on `bumpVersion`.
- `revokeAllSessions` fails closed when policy promises online revocation.
- Store failures never masquerade as successful revocation.

### 9.5 Secrets
- Safe logger sanitizes 14 documented secret keys from payloads.
- Errors never serialize secrets, tokens, or connection strings in public data.
- `cause` preserved for diagnostics but not exposed as plaintext secrets.

## 10. Error Handling and Observability

### 10.1 Error Hierarchy

`AuthError` → all specialized errors. Each has `code`, `status`, `cause`, `toJSON()`.

| Error | Typical Use | Status |
|-------|-------------|--------|
| `UnauthorizedError` | Invalid/missing credentials, bad token | 401 |
| `ForbiddenError` | Insufficient permission/role | 403 |
| `InvalidTokenError` | Malformed JWT | 401 |
| `TokenExpiredError` | Expired JWT | 401 |
| `ValidationError` | Invalid input, missing field, adapter capability mismatch | 400 |
| `ConfigurationError` | Missing secret, bad config, adapter capability mismatch | 500 |
| `OAuthError` | OAuth callback/state failure | 401 |
| `ProviderError` | Provider-specific failure (missing subject, etc.) | 502 |
| `InvalidRedirectUriError` | Redirect URI outside allowlist | 400 |

### 10.2 Diagnostics

- `emitDiagnostic(event)` — bounded async queue (32 entries).
- Overflow: `"drop"` (silent) or `"report"` (error callback).
- Observer: `onEvent` (sync or async), failures routed to error callback.
- Statistics: `emitted`, `dropped`, `failed`, `overflowPolicy`, `queueSize`.
- `resetDiagnostics()` clears all state.

### 10.3 Logging

- `createSafeLogger()` wraps optional `Logger`.
- All four methods (`debug`/`info`/`warn`/`error`) optional; missing methods no-op.
- Synchronous logger exceptions swallowed.
- Secret sanitization before forwarding payloads.
- Logger object never mutated.

## 11. Extension Points and Custom Implementations

| Extension Point | Interface | Validation |
|-----------------|-----------|------------|
| JWT backend | `JwtBackend` (`sign`, `verify`) | `auth.jwtBackend` option |
| Password hasher | `PasswordHasher` | `auth.passwordHasher` option |
| HTTP transport | `HttpTransport` | `configureHttp({transport})` |
| User store | `UserStore` (all optional) | `auth.userStore` option |
| Refresh store | `RefreshStore` | `auth.refreshStore` option |
| Session store | `SessionStore` | `auth.sessionStore` option |
| Persistence adapter | `PersistenceAdapter` | `auth.options.persistence` |
| Storage adapter | `StorageAdapter` | `validateStorageAdapter()` |
| Event adapter | `EventAdapters` | `validateEventAdapter()` |
| OAuth provider | `OAuthProvider` | `oauth.use(id, config)` / `createProvider()` |
| Claim extractor | `(user) => unknown` | `auth.registerExtractor()` |
| Auth hook | `(payload, auth) => unknown` | `auth.hook("beforeLogin\|afterLogin\|afterVerify", handler)` |
| Diagnostics observer | `DiagnosticsObserver` | `setDiagnosticsObserver()` |
| Error callback | `DiagnosticsErrorCallback` | `setDiagnosticsErrorCallback()` |
| Logger | `Logger` | `createSafeLogger(logger)` |

## 12. Build and Distribution Architecture

**Build:** `tsc -p tsconfig.build.esm.json` → `dist/esm/`, `tsc -p tsconfig.build.cjs.json` → `dist/cjs/`, then `node scripts/fix-cjs-imports.cjs`.

**Package exports:**
- `.` → `dist/types/index.d.ts` (types), `dist/esm/index.js` (import), `dist/cjs/index.cjs` (require)
- `./*` → subpath mappings for all entry points

**`files`:** `dist`, `src`, `examples`, `LICENSE`, `README.md`, `CHANGELOG.md`, `docs`

**Scripts:**
- `npm run build` — clean build (ESM + CJS + fix imports)
- `npm test` — vitest run (42 test files, 489 tests)
- `npm run typecheck` — `tsc --noEmit`
- `npm run lint` — eslint on `src` and `test`
- `npm run dev` — `tsc -w`
- `npm run example` — build + run `examples/basic.ts`

**Side effects:** `false` (tree-shakeable).

## 13. Testing Architecture

42 test files across:
- `test/unit/` — JWT, password, RBAC, OAuth, HTTP, adapters, diagnostics, logging, context, external-token, compatibility, store contracts, matcher cache, shared cache, observer, platform, exports, real-world metrics, bcrypt, uWS.
- `test/oauth/` — OAuth flows, PKCE, redirect URI, advanced revocation.
- `test/providers/` — OIDC Google, JWKS, live providers.
- `test/integration/` — Kafka events, PostgreSQL distributed, Redis state (require Docker/testcontainers).
- `test/security/` — Security regression.

**Test infrastructure:** vitest, tsx, testcontainers (Docker-dependent), ioredis, kafkajs, pg.

**Skipped/conditional:** Kafka and OIDC live tests require external services/Docker containers not available in all environments.

## 14. External Dependencies

**Required (production):**
- `@noble/hashes` ^2.4.0 — cryptographic primitives
- `jose` ^6.2.15 — JWT signing/verification, JWKS

**Optional (production):**
- `bcrypt` ^5.1.1 — bcrypt password hasher binding (gracefully degraded when absent)

**Dev only:**
- TypeScript, vitest, tsx, eslint
- testcontainers (Kafka, PostgreSQL, Redis)
- ioredis, kafkajs, pg (integration tests)
- @vitest/coverage-v8, @types/node, @types/pg

## 15. Limitations and Known Constraints

- In-memory stores are single-process only; not suitable for multi-instance production.
- Query-string token extraction is disabled by default in framework adapters.
- Bcrypt is optional; bcrypt hasher unavailable when binding is absent.
- Kafka and OIDC live tests require Docker/testcontainers.
- `sessionVersionPolicy: "migration"` accepts tokens without `sv` as version 0.
- Clock tolerance defaults to 0; must be explicitly configured for skew tolerance.
- OAuth state store TTL defaults to 600 seconds.
- Response size limit defaults to 1 MiB (hard cap 5 MiB).
- HTTP timeout defaults to 15 seconds (max 120 seconds).
- Retry maxRetries defaults to 3 (hard cap 10).

## 16. Source File Reference

| File | Responsibility |
|------|---------------|
| `src/index.ts` | Public entry point, all exports |
| `src/core/auth.ts` | Auth facade, login/verify/refresh/revoke, hooks, persistence lifecycle |
| `src/core/context.ts` | AuthContext, AsyncLocalStorage, context propagation |
| `src/core/index.ts` | Core exports (Auth, memory stores) |
| `src/crypto/jwt.ts` | Token encode/decode, access/refresh wrappers |
| `src/crypto/jwt-backend.ts` | JwtBackendImpl, algorithm policy, key resolution |
| `src/crypto/jwks.ts` | JWKS inline/remote, caching |
| `src/crypto/password.ts` | hash/verify/rehash, scrypt legacy, factories |
| `src/crypto/password-hasher.ts` | Argon2id/Bcrypt/Scrypt/Composite hashers |
| `src/crypto/bcrypt/` | Optional bcrypt binding |
| `src/crypto/index.ts` | Crypto exports |
| `src/rbac/index.ts` | RBAC class, roles/inheritance/cycle detection |
| `src/rbac/matcher-cache.ts` | MatcherCache LRU/TTL/stats |
| `src/oauth/index.ts` | OAuth class, TokenIntrospector, introspection exports |
| `src/oauth/introspection/` | Token introspection client/types/validator |
| `src/oauth/providers/` | 14 built-in providers + createProvider/getProvider |
| `src/oauth/redirect-uri.ts` | Redirect URI validation |
| `src/external-token/verifier.ts` | External JWT verification |
| `src/external-token/types.ts` | External token types |
| `src/http/transport.ts` | HTTP client, config, timeouts, size limits |
| `src/http/retry.ts` | Retry with exponential backoff + jitter |
| `src/http/index.ts` | HTTP exports |
| `src/adapters/` | Framework adapters, storage/event contracts, registry |
| `src/diagnostics/` | Diagnostics emitter, observer, stats |
| `src/logging/` | Safe logger with secret sanitization |
| `src/errors/` | Error hierarchy (10 classes) |
| `src/stores/memory/` | In-memory refresh/session/state stores |
| `src/types/index.ts` | All public TypeScript types |
| `src/utils.ts` | Shared utilities (token extraction, hashing, randomization, etc.) |
| `src/platform.ts` | Platform compatibility constants |
| `examples/basic.ts` | Basic usage example |

---

## 16. Where to Find Details

Use these authoritative locations for exhaustive detail rather than duplicating
it in this document:

- **Feature catalog:** `docs/features.md` and files under `docs/features/`.
- **Configuration defaults and limits:** implementation defaults in
  `src/crypto/password-hasher.ts`, `src/crypto/jwks.ts`, `src/http/transport.ts`,
  and `src/http/retry.ts`; types in `src/types/index.ts`.
- **Provider guide:** `docs/features/04-oauth-social-login.md`.
- **External-token guide:** `docs/features/05-external-token-verification.md`.
- **Adapter behavior:** `docs/features/10-adapters.md`.
- **Types reference:** `docs/features/12-types.md`.
- **Platform compatibility:** `docs/features/13-platform-compatibility.md` and
  `src/platform.ts`.
- **Tests:** commands and plans under `docs/test/`; run via
  `npm run test:unit`, `npm run test:security`, `npm run test:oauth`,
  `npm run test:providers`, `npm run test:integration`.
- **Adapter test plans:** `docs/test/adapters-test-plan.md`, etc.
- **Examples:** `examples/basic.ts` and `examples/`.
- **Package metadata:** `package.json`, lockfile, and `src/index.ts` exports.

## 17. Documentation Maintenance

An architecture-document review is required when a change affects any of the
following: public exports or package entry points; module boundaries or major
dependencies; authentication or token lifecycle; security guarantees or
defaults; store contracts or atomicity; adapter behavior; configuration
defaults or validation; error semantics; or build and distribution behavior.

### Release verification checklist

- [ ] Package version and Node.js engine are current.
- [ ] Public exports and package `exports` map agree.
- [ ] Source tree matches the repository structure section.
- [ ] Defaults and limits match implementation.
- [ ] Security claims match code and tests.
- [ ] Store contracts and atomicity descriptions are accurate.
- [ ] Adapter error behavior matches each framework.
- [ ] Diagrams match current dependencies and flows.
- [ ] All internal documentation links resolve.
- [ ] Examples compile or run where applicable.
- [ ] Test commands and volatile counts are current or omitted.

### Avoiding volatile facts

Prefer links to package metadata, source, tests, and feature documents over
duplicating dependency versions, file counts, or exact test totals. If an
exact figure is useful, state the revision or date at which it was verified.
