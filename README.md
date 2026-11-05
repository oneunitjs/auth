# @oneunit/auth

Framework-agnostic TypeScript authentication for Node.js. Use it from a plain
script or plug it into Express, Fastify, Koa, or uWebSockets.js.

[![CI](https://github.com/oneunitjs/actions/workflows/auth.yml/badge.svg)](https://github.com/mayank040902/framework/actions/workflows/auth.yml)
[![npm](https://img.shields.io/npm/v/@oneunit/auth.svg)](https://www.npmjs.com/package/@oneunit/auth)
[![license](https://img.shields.io/npm/l/@oneunit/auth.svg)](./LICENSE)

## What is this?

`@oneunit/auth` (v2.1.0-beta.1) is a library, not an identity service. It provides the
building blocks your application uses to authenticate users, authorize access,
and manage sessions:

- **JWT issuance and verification** (HS256 by default; injectable backend)
- **Access and refresh tokens** with rotation and replay protection
- **Role-based access control (RBAC)** with inheritance and wildcard permissions
- **Password hashing** (Argon2id default; scrypt and optional bcrypt)
- **OAuth 2.0 / OIDC social login** with PKCE for 14 built-in providers
- **External token verification** against trusted issuer JWKS
- **Session versioning and revocation**
- **Framework adapters** for Express, Fastify, Koa, and uWebSockets.js
- **Replaceable persistence**: user, refresh-token, session, key-value, and event stores

It is **not** a managed identity platform, a user directory, or an email/password
reset service. Account lifecycle, rate limiting, MFA, and email verification are
your application's responsibility.

## Who is it for?

Use `@oneunit/auth` when you:

- Need JWT-based authentication in a Node.js backend (Node 20+)
- Want refresh-token rotation with replay protection
- Need role/permission authorization (RBAC) with inheritance
- Integrate with OAuth providers (Google, GitHub, Apple, and 11 more)
- Want replaceable storage so you are not locked into a database
- Use Express, Fastify, Koa, or uWebSockets.js (or none — it works standalone)

It is **less appropriate** if you need a hosted auth service with managed user
profiles, magic links, or MFA out of the box. Those remain application concerns.

## Quick start

```bash
npm install @oneunit/auth
```

```ts
import { createAuth, createRBAC, createMemoryRefreshStore } from "@oneunit/auth";

const rbac = createRBAC({
  roles: {
    member: { permissions: ["profile.read"] },
    editor: { inherits: "member", permissions: ["post.write"] },
    admin: { inherits: "editor", permissions: ["user.manage"] },
  },
});

const auth = createAuth({
  secret: process.env.AUTH_SECRET!, // required
  issuer: "my-app",
  audience: "my-api",
  accessTokenTtl: "15m",
  refreshTokenTtl: "7d",
  refreshStore: createMemoryRefreshStore(), // dev/test; use a shared store in production
  rbac,
});

const { accessToken, refreshToken, payload } = await auth.login({
  id: 42,
  email: "ada@example.com",
  roles: ["editor"],
});

const claims = await auth.verify(accessToken);
console.log(claims.sub); // "42"

const next = await auth.refresh(refreshToken!);
await auth.revoke(refreshToken!);
```

There are no built-in product roles. Pass whatever role names your app uses.

## Installation

```bash
npm install @oneunit/auth
```

Requires Node.js 20+. Runtime dependencies are `jose` and `@noble/hashes`; `bcrypt`
is optional and only needed if you use the bcrypt hasher.

## Feature overview

| Capability | Status | What it does |
|---|---|---|
| Authentication core | Built-in | `login`, `verify`, `refresh`, `revoke`, hooks, claim extractors |
| JWT | Built-in | Sign/verify with pinned algorithms; `typ` separation for access vs refresh |
| Refresh tokens | Built-in | Atomic consume on rotation; custom `RefreshStore` supported |
| Session revocation | Opt-in | `SessionStore` enables `revokeAllSessions` / `revokeSession`; stateless without one |
| RBAC | Built-in | Roles, inheritance, cycle detection, wildcard permissions, bounded subject cache |
| OAuth / social login | Built-in | 14 built-in providers, custom providers, PKCE, state management, redirect-URI allowlist |
| External token verification | Built-in | Verify third-party JWTs against trusted issuer JWKS |
| Password hashing | Built-in | Argon2id default; scrypt legacy; optional bcrypt |
| User management | Interface | `UserStore` contract you implement |
| HTTP transport | Built-in | Injectable client with timeout, retry, response-size limits |
| Framework adapters | Built-in | Express, Fastify, Koa, uWebSockets.js |
| Auth context | Built-in | `AsyncLocalStorage`-based request context (`requestId`, `traceId`, `operationId`) |
| Diagnostics | Built-in | Event emission with stats, overflow policy, error callback |
| Logging | Built-in | Safe logger with secret sanitization |
| Errors | Built-in | Typed `AuthError` hierarchy with `code`/`status`/`cause` |
| Persistence adapters | Interface | `PersistenceAdapter` contract you implement |

## Core usage guides

### Configure authentication

```ts
import { createAuth } from "@oneunit/auth";

const auth = createAuth({
  secret: process.env.AUTH_SECRET!, // required — generate with a CSPRNG
  refreshSecret: process.env.REFRESH_SECRET, // optional; defaults to secret
  issuer: "https://api.example.com",
  audience: "my-api",
  algorithm: "HS256",
  accessTokenTtl: "15m",
  refreshTokenTtl: "7d",
  clockTolerance: 0, // seconds; set only if you have clock skew
  trustUserPermissions: false, // permissions come from RBAC, not the user row
  sessionVersionPolicy: "migration", // "reject" | "migration" | "disabled"
});
```

`secret` is required. All other options have documented defaults.

### Authenticate a user

```ts
const { accessToken, refreshToken, payload, user } = await auth.login({
  id: 42,
  email: "ada@example.com",
  roles: ["editor"],
});
```

### Verify an access token

```ts
const claims = await auth.verify(accessToken);
console.log(claims.sub); // "42"
```

A refresh token is never accepted by `verify()` unless you explicitly set
`acceptTokenType: "refresh"`.

### Refresh a token

```ts
const next = await auth.refresh(refreshToken!);
await auth.revoke(refreshToken!);
```

Refresh tokens rotate on every use: `auth.refresh()` invalidates the token it
consumes. Presenting the same refresh token twice rejects the second attempt.

### Revoke sessions

```ts
await auth.revokeAllSessions(userId); // every device, access + refresh
await auth.revokeSession(sessionId);  // one session only
```

Requires a configured `SessionStore`. Without one, `revokeAllSessions()` returns
`false` instead of claiming success — stateless JWT verification cannot un-sign
an already-issued access token.

### Define roles and permissions

```ts
import { createRBAC, defineRoles } from "@oneunit/auth";

const rbac = createRBAC({
  defaultRole: "viewer",
  roles: [
    { name: "viewer", permissions: ["doc.read"] },
    { name: "editor", permissions: ["doc.write"], inherits: ["viewer"] },
    { name: "admin", permissions: ["*"], inherits: ["editor"] },
  ],
});

rbac.can({ roles: ["editor"] }, "doc.write"); // true
rbac.authorize({ roles: ["viewer"] }, "doc.write"); // throws ForbiddenError
```

Wildcards: `*` matches one dot-delimited segment; `**` matches any suffix.
`invoice.*` matches `invoice.read` but not `invoice.read.all`.

### Password hashing

```ts
import { hashPassword, verifyPassword, needsRehash } from "@oneunit/auth";

const hash = await hashPassword("correct horse battery staple");
const ok = await verifyPassword("correct horse battery staple", hash);
if (needsRehash(hash)) {
  const next = await hashPassword("correct horse battery staple");
  await userStore.updatePassword(userId, next);
}
```

Argon2id is the default algorithm. Scrypt is supported for legacy hashes.
Bcrypt requires the optional `bcrypt` binding.

### Register and login with a custom user store

```ts
import { createAuth } from "@oneunit/auth";

const users = new Map();
const userStore = {
  async create(input) {
    const user = { id: users.size + 1, ...input };
    users.set(user.id, user);
    return user;
  },
  async findByCredentials(identifier) {
    return [...users.values()].find((u) => u.email === identifier || u.username === identifier);
  },
  async findByEmail(email) {
    return [...users.values()].find((u) => u.email === email);
  },
  async updatePassword(id, hash) {
    const u = users.get(id);
    if (u) u.passwordHash = hash;
  },
};

const auth = createAuth({ secret: process.env.AUTH_SECRET!, userStore });

await auth.register(
  { email: "bob@example.com", password: "s3cret-pass" },
  { roles: ["member"] },
);
const result = await auth.loginWithPassword("bob@example.com", "s3cret-pass");
```

Roles come from the server-side `options.roles` argument — never from the
public signup payload. A `permissions` field on the user record is ignored unless
you opt in with `trustUserPermissions: true`.

### OAuth social login

Built-in providers: `google`, `github`, `instagram`, `facebook`, `twitter`,
`discord`, `apple`, `linkedin`, `microsoft`, `reddit`, `twitch`, `slack`,
`spotify`, `tiktok`.

```ts
import { createAuth } from "@oneunit/auth";

const auth = createAuth({
  secret: process.env.AUTH_SECRET!,
  providers: {
    google: {
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      redirectUri: "https://app.example.com/auth/google/callback",
      redirectUriPolicy: {
        allowedRedirectUris: ["https://app.example.com/auth/google/callback"],
      },
      scopes: ["openid", "email", "profile"],
    },
  },
});

// 1. Redirect the user
const { url, state } = await auth.getAuthorizationUrl("google");

// 2. Handle the callback
const { tokens, profile, state: stored } = await auth.loginWithOAuth("google", {
  code: query.code,
  state: query.state,
});
```

PKCE (S256) is enabled by default for all providers. `pkce: false` is an
explicit security downgrade and logs a warning. Redirect URIs are matched
exactly against a configured allowlist; HTTPS is required except for explicitly
opted-in loopback (`localhost`, `127.0.0.1`, `[::1]`).

### Custom OAuth provider

```ts
import { createOAuth, createProvider } from "@oneunit/auth";

const acme = createProvider({
  id: "acme",
  authorizationUrl: "https://acme.example/oauth/authorize",
  tokenUrl: "https://acme.example/oauth/token",
  userInfoUrl: "https://acme.example/me",
  scopes: ["profile"],
  profileMap: { id: "id", email: "email", name: "name" },
});

const oauth = createOAuth();
oauth.use("acme", {
  provider: acme,
  clientId: "...",
  clientSecret: "...",
  redirectUri: "https://app.example.com/cb",
  redirectUriPolicy: { allowedRedirectUris: ["https://app.example.com/cb"] },
});

const { url } = await oauth.authorize("acme");
```

### Verify an external (IdP-issued) token

```ts
import { createExternalTokenVerifier } from "@oneunit/auth";

const verifier = createExternalTokenVerifier({
  issuers: [
    {
      issuer: "https://accounts.google.com",
      audiences: ["MY_GOOGLE_CLIENT_ID"],
      algorithms: ["RS256"],
      jwks: { keys: [...] }, // inline JWKS, or jwksUrl for remote
    },
  ],
});

const result = await verifier.verify(idToken, {
  expectedTokenType: "id",
  maxTokenAge: 3600,
});
// result.payload, result.issuer, result.audience
```

Unknown `kid`, invalid signature, missing issuer, or disallowed algorithm are
rejected. Remote JWKS URLs require HTTPS unless explicitly allowed.

## Framework adapters

Adapters are thin translation layers: extract the bearer token, call
`auth.verifyRequest()`, attach the principal, and map errors to HTTP responses.
No framework is a peer dependency — install your framework separately.

### Express

```ts
import { createAuth, expressAdapter } from "@oneunit/auth";
import express from "express";

const auth = createAuth({ secret: process.env.AUTH_SECRET! });
const { authenticate, requireRole, requirePermission } = expressAdapter(auth);
const app = express();

app.get("/me", authenticate(), (req, res) => res.json(req.user));
app.get("/admin", authenticate(), requireRole("admin"), handler);
app.get("/reports", authenticate(), requirePermission("report.read"), handler);
```

### Fastify

```ts
import { createAuth, fastifyAdapter } from "@oneunit/auth";
import Fastify from "fastify";

const auth = createAuth({ secret: process.env.AUTH_SECRET! });
const fastify = Fastify();

await fastify.register(fastifyAdapter(auth));
fastify.get("/me", { preHandler: [fastify.authenticate()] }, async (req) => req.user);
```

### Koa

```ts
import { createAuth, koaAdapter } from "@oneunit/auth";
import Koa from "koa";

const auth = createAuth({ secret: process.env.AUTH_SECRET! });
const app = new Koa();

const { authenticate, requirePermission } = koaAdapter(auth);
app.use(authenticate());
app.use(requirePermission("report.read"));
```

### uWebSockets.js

uWS request/response objects are invalid after the first `await`. The adapter
snapshots headers and query before async work:

```ts
import uWS from "uWebSockets.js";
import { createAuth, uwsAdapter } from "@oneunit/auth";

const auth = createAuth({ secret: process.env.AUTH_SECRET! });
const { authenticate, requirePermission, json } = uwsAdapter(auth);

uWS.App()
  .get("/me", authenticate()((res, _req, request) => {
    json(res, 200, { user: request.user });
  }))
  .listen(3000);
```

### Standalone (no framework)

```ts
const claims = await auth.verifyRequest(req);
```

Tokens are read from `Authorization: Bearer` or an `access_token` cookie. Query
string extraction is **not** enabled by default — opt in per call:

```ts
await auth.verifyRequest(req, { query: true });
```

## Configuration reference

| Option | Type | Required | Default | Purpose |
|---|---|---|---|---|
| `secret` | `string \| Buffer` | Yes | — | JWT signing secret; must be at least 32 bytes (256 bits) high-entropy material |
| `refreshSecret` | `string \| Buffer` | No | `secret` | Refresh-token signing key; if provided, at least 32 bytes |
| `issuer` | `string` | No | `undefined` | JWT `iss` claim |
| `audience` | `string \| string[]` | No | `undefined` | JWT `aud` claim |
| `algorithm` | `"HS256" \| "RS256" \| "ES256"` | No | `"HS256"` | Signing algorithm; unsupported values rejected at construction |
| `accessTokenTtl` | `string \| number` | No | `"15m"` | Access token lifetime |
| `refreshTokenTtl` | `string \| number` | No | `"7d"` | Refresh token lifetime |
| `clockTolerance` | `number` | No | `0` | JWT time validation tolerance (seconds); set 5-30 seconds when hosts are not perfectly synchronized |
| `trustUserPermissions` | `boolean` | No | `false` | Honor `permissions` on user records |
| `sessionVersionPolicy` | `"reject" \| "migration" \| "disabled"` | No | `"migration"` | How to handle tokens without `sv` |
| `jwtBackend` | `JwtBackend` | No | `JwtBackendImpl` | Custom signing/verification backend |
| `userStore` | `UserStore` | No | `undefined` | Custom user lookup/creation |
| `refreshStore` | `RefreshStore` | No | in-memory | Refresh token storage |
| `sessionStore` | `SessionStore` | No | `undefined` | Session versioning/revocation |
| `passwordHasher` | `PasswordHasher` | No | Argon2id default | Password hashing |
| `rbac` / `roles` | `RBACOptions` | No | empty | Role/permission definitions |
| `oauth` / `providers` | `OAuthOptions` | No | `{}` | OAuth provider config |
| `redirectUri` | `string` | No | `undefined` | Default OAuth redirect URI |
| `logger` | `Logger` | No | no-op | Structured logger |
| `diagnostics` | `DiagnosticsObserver` | No | `undefined` | Event observer |
| `http` | `HttpClientConfig` | No | defaults | HTTP client config |
| `adapters` | framework adapters | No | `undefined` | Framework adapter instances |
| `persistence` | `PersistenceAdapter` | No | `undefined` | Unified persistence domains |

## Customization and extension points

| Extension point | Contract | How to plug in |
|---|---|---|
| JWT backend | `JwtBackend` | `auth.jwtBackend` option |
| Password hasher | `PasswordHasher` | `auth.passwordHasher` option |
| HTTP transport | `HttpTransport` / `HttpClient` | `configureHttp(...)` for the default client, or `new HttpClient(config)` for isolated per-client config |
| User store | `UserStore` | `auth.userStore` option |
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

## Persistent storage with Redis / PostgreSQL

`@oneunit/auth` does not ship database clients. You implement the store
interfaces yourself and pass them in. The package validates the shape and
falls back to in-memory stores for any domain you omit.

### Redis (ioredis) — refresh token store with atomic consume

```ts
import { createAuth } from "@oneunit/auth";
import { Redis } from "ioredis";
import type { RefreshRecord, RefreshStore } from "@oneunit/auth";

const redis = new Redis(process.env.REDIS_URL!);
const PREFIX = "auth:rt:";

// Lua script: read + delete atomically (exactly-once consume)
const CONSUME_SCRIPT = `
  local record = redis.call('GET', KEYS[1])
  if not record then return nil end
  local data = cjson.decode(record)
  if data.expires_at and tonumber(data.expires_at) <= tonumber(ARGV[1]) then
    redis.call('DEL', KEYS[1])
    return nil
  end
  redis.call('DEL', KEYS[1])
  return record
`;

export const redisRefreshStore: RefreshStore = {
  async save(record: RefreshRecord) {
    await redis.set(`${PREFIX}${record.id}`, JSON.stringify(record));
    const ttl = Math.ceil((record.expiresAt - Date.now()) / 1000);
    if (ttl > 0) await redis.expire(`${PREFIX}${record.id}`, ttl);
  },
  async get(id: string) {
    const raw = await redis.get(`${PREFIX}${id}`);
    if (!raw) return null;
    const data = JSON.parse(raw) as RefreshRecord;
    if (data.expiresAt && data.expiresAt <= Date.now()) {
      await redis.del(`${PREFIX}${id}`);
      return null;
    }
    return data;
  },
  async consume(id: string) {
    const result = await redis.eval(CONSUME_SCRIPT, 1, `${PREFIX}${id}`, String(Date.now()));
    if (!result) return null;
    return JSON.parse(result as string) as RefreshRecord;
  },
  async revoke(id: string) {
    await redis.del(`${PREFIX}${id}`);
  },
};

const auth = createAuth({
  secret: process.env.AUTH_SECRET!,
  refreshStore: redisRefreshStore,   // required for refresh + rotation
});
```

### PostgreSQL (pg) — session store + refresh store

```ts
import { createAuth } from "@oneunit/auth";
import { Pool } from "pg";
import type { RefreshRecord, RefreshStore } from "@oneunit/auth";
import type { SessionStore } from "@oneunit/auth/types";

const pool = new Pool({ connectionString: process.env.DATABASE_URL! });

// Run once during migration/setup:
// CREATE TABLE IF NOT EXISTS auth_refresh_tokens (
//   id TEXT PRIMARY KEY,
//   user_id TEXT NOT NULL,
//   token_hash TEXT NOT NULL,
//   expires_at BIGINT NOT NULL
// );
// CREATE TABLE IF NOT EXISTS auth_session_versions (
//   user_id TEXT PRIMARY KEY,
//   version BIGINT NOT NULL DEFAULT 0
// );

export const pgRefreshStore: RefreshStore = {
  async save(record: RefreshRecord) {
    await pool.query(
      `INSERT INTO auth_refresh_tokens (id, user_id, token_hash, expires_at)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (id) DO UPDATE SET
         user_id = EXCLUDED.user_id,
         token_hash = EXCLUDED.token_hash,
         expires_at = EXCLUDED.expires_at`,
      [record.id, record.userId, record.tokenHash, record.expiresAt],
    );
  },
  async get(id: string) {
    const { rows } = await pool.query(
      "SELECT id, user_id, token_hash, expires_at FROM auth_refresh_tokens WHERE id = $1",
      [id],
    );
    const row = rows[0];
    if (!row) return null;
    if (row.expires_at && Number(row.expires_at) <= Date.now()) {
      await pool.query("DELETE FROM auth_refresh_tokens WHERE id = $1", [id]);
      return null;
    }
    return { id: row.id, userId: row.user_id, tokenHash: row.token_hash, expiresAt: Number(row.expires_at) } as RefreshRecord;
  },
  async consume(id: string) {
    // Atomic: DELETE ... RETURNING (exactly once under concurrency)
    const { rows } = await pool.query(
      `DELETE FROM auth_refresh_tokens WHERE id = $1 RETURNING id, user_id, token_hash, expires_at`,
      [id],
    );
    const row = rows[0];
    if (!row) return null;
    return { id: row.id, userId: row.user_id, tokenHash: row.token_hash, expiresAt: Number(row.expires_at) } as RefreshRecord;
  },
  async revoke(id: string) {
    await pool.query("DELETE FROM auth_refresh_tokens WHERE id = $1", [id]);
  },
};

export const pgSessionStore: SessionStore = {
  async getVersion(userId: string | number) {
    const { rows } = await pool.query(
      "SELECT version FROM auth_session_versions WHERE user_id = $1",
      [userId],
    );
    return rows[0] ? Number(rows[0].version) : null;
  },
  async bumpVersion(userId: string | number) {
    await pool.query(
      `INSERT INTO auth_session_versions (user_id, version) VALUES ($1, 1)
       ON CONFLICT (user_id) DO UPDATE SET version = auth_session_versions.version + 1`,
      [userId],
    );
  },
};

const auth = createAuth({
  secret: process.env.AUTH_SECRET!,
  refreshStore: pgRefreshStore,
  sessionStore: pgSessionStore,
});
```

### Unified StorageAdapter (both Redis + PostgreSQL)

```ts
import type { StorageAdapter } from "@oneunit/auth/types";

export const myStorageAdapter: StorageAdapter = {
  keyValue: {
    get: async (key: string) => { /* redis get */ },
    set: async (key: string, value: unknown, ttlSeconds?: number) => { /* redis set + ttl */ },
    delete: async (key: string) => { /* redis del */ },
    consume: async (key: string) => { /* redis GETDEL / Lua */ },
  },
  sessions: pgSessionStore,
  refreshTokens: {
    get: pgRefreshStore.get,
    create: pgRefreshStore.save,
    revoke: pgRefreshStore.revoke,
    rotate: async (id: string) => { /* pg atomic rotate */ },
  },
  revocations: {
    revoke: async (id: string) => { /* mark revoked */ },
    isRevoked: async (id: string) => { /* check revocation */ },
  },
  versions: {
    get: pgSessionStore.getVersion,
    increment: pgSessionStore.bumpVersion,
  },
};

const auth = createAuth({
  secret: process.env.AUTH_SECRET!,
  persistence: myStorageAdapter,
});
```

### Key rules

- **`consume()` must be atomic.** Use Redis `GETDEL`/Lua, SQL `DELETE ... RETURNING`, or DynamoDB conditional delete. A store without atomic `consume()` cannot rotate refresh tokens and `auth.refresh()` throws `ConfigurationError`.
- **`sessionStore` is required for session revocation.** Without it, access tokens remain valid until expiry and `revokeAllSessions()` reports `not_configured`.
- **Omitted domains fall back to in-memory.** You only need to implement the stores you actually use.

## Security and production guidance

- **Generate secrets with a CSPRNG.** `secret` and `refreshSecret` must be at least 32 bytes (256 bits) of high-entropy material — use environment variables, never hardcoded.
- **Restrict signing algorithms.** Only `HS256`, `RS256`, and `ES256` are accepted. `algorithm` is pinned to verification on every `verify()` call; tokens cannot override it.
- **Use distinct refresh secrets.** Set `refreshSecret` separately from `secret`
  so compromise of one does not compromise the other.
- **Rotate refresh tokens atomically.** `auth.refresh()` consumes the old token
  via `consume(jti)`. A store without `consume()` cannot rotate tokens and
  `auth.refresh()` throws `ConfigurationError`.
- **Session revocation requires a `SessionStore`.** Without one, access tokens
  remain valid until expiry and `revokeAllSessions()` returns `false`. For
  immediate revocation, configure a session store and keep access TTLs short.
- **HTTPS for OAuth.** Redirect URIs require HTTPS except for explicitly opted-in
  loopback. Loopback lookalikes (`localhost.evil.example`) are rejected.
- **PKCE is on by default.** `pkce: false` is a security downgrade and logs a
  warning.
- **Never log secrets.** The safe logger strips 14 documented secret keys
  (passwords, tokens, authorization codes, OAuth state, etc.) from payloads.
- **Access tokens are stateless.** They remain valid until expiry unless a
  `SessionStore` can answer revocation checks.

Application responsibilities not covered by this package: rate limiting, MFA,
email verification, password reset flows, account lockout, CSRF for cookie-based
auth, durable audit delivery, and secret rotation operations.

See [SECURITY.md](./docs/SECURITY.md) for supported versions, vulnerability
reporting, and disclosure expectations.

## Errors and troubleshooting

All errors extend `AuthError` and expose `code` and `status`:

| Class | Code | Status | Typical cause |
|---|---|---|---|
| `InvalidTokenError` | `INVALID_TOKEN` | 401 | Malformed JWT |
| `TokenExpiredError` | `TOKEN_EXPIRED` | 401 | Expired JWT |
| `UnauthorizedError` | `UNAUTHORIZED` | 401 | Invalid/missing credentials |
| `ForbiddenError` | `FORBIDDEN` | 403 | Insufficient permission |
| `ValidationError` | `VALIDATION_ERROR` | 400 | Invalid input / missing field |
| `ConfigurationError` | `CONFIGURATION_ERROR` | 500 | Missing secret / bad config / adapter mismatch |
| `OAuthError` | `OAUTH_ERROR` | 401 | OAuth callback / state failure |
| `ProviderError` | `PROVIDER_ERROR` | 502 | Provider-specific failure |
| `InvalidRedirectUriError` | `INVALID_REDIRECT_URI` | 400 | Redirect URI outside allowlist |

**Troubleshooting:**

| Symptom | Check | Action |
|---|---|---|
| Invalid or expired token | Issuer, audience, expiry, `typ` | Verify token was issued by this `auth` instance with matching config |
| Refresh fails | `refreshStore`, `consume(jti)` | Ensure store implements atomic consume |
| Session rejected | Session version / revocation | Configure `SessionStore`; check `sv` claim |
| OAuth callback rejected | State, redirect URI, PKCE | Verify allowlist matches exactly; PKCE verifier bound to state |
| Request unauthenticated | Adapter registration | Verify middleware is registered and token extraction works |

## API reference

The full public export surface from `@oneunit/auth`:

**Core:** `createAuth`, `Auth`, `auth`, `createMemoryRefreshStore`,
`createMemorySessionStore`

**JWT:** `encode`, `decode`, `decodeUnsafe`, `encodeAccessToken`,
`encodeRefreshToken`

**RBAC:** `createRBAC`, `RBAC`, `defineRoles`, `matchPermission`

**Passwords:** `hashPassword`, `verifyPassword`, `needsRehash`,
`hashScryptPassword`, `verifyScryptPassword`, `scryptNeedsRehash`,
`createPasswordHasher`, `getDefaultPasswordHasher`, `setDefaultPasswordHasher`,
`Argon2idPasswordHasher`, `BcryptPasswordHasher`, `CompositePasswordHasher`,
`ScryptPasswordHasher`, `BcryptNodeBinding`, `isBcryptAvailable`,
`ARGON2ID_RECOMMENDED_PROFILE`

**OAuth:** `OAuth`, `createOAuth`, `createMemoryStateStore`,
`TokenIntrospector`, `createTokenIntrospector`, `IntrospectionError`,
`createProvider`, `getProvider`, `builtinProviders`, `pkceVerifier`,
`pkceChallenge`, and all 14 built-in providers

**Adapters:** `expressAdapter`, `fastifyAdapter`, `koaAdapter`, `uwsAdapter`,
`snapshotUwsRequest`, `createAdapters`, `createAdapterRegistry`,
`validateStorageAdapter`, `validateEventAdapter`

**HTTP:** `configureHttp`, `dispatchHttp`, `dispatchHttpWithRetry`,
`getHttpConfig`, `resetHttpConfig`, `resolveRetryConfig`

**External token:** `ExternalTokenVerifier`, `createExternalTokenVerifier`

**Diagnostics:** `emitDiagnostic`, `setDiagnosticsObserver`,
`resetDiagnostics`, `getDiagnosticsStats`, `setDiagnosticsOverflowPolicy`,
`setDiagnosticsErrorCallback`

**Logging:** `createSafeLogger`

**Context:** `createAuthContext`, `getCurrentAuthContext`,
`runWithAuthContext`, `AuthContext`

**Errors:** `AuthError`, `InvalidTokenError`, `TokenExpiredError`,
`UnauthorizedError`, `ForbiddenError`, `ConfigurationError`, `OAuthError`,
`ProviderError`, `ValidationError`, `InvalidRedirectUriError`

**Utilities:** `extractBearerToken`, `parseExpiresIn`, `isValidExpiresIn`,
`randomToken`, `randomState`

**Types:** `AuthOptions`, `LoginOptions`, `LoginResult`, `JwtPayload`,
`JwtSignOptions`, `JwtVerifyOptions`, `Secret`, `RoleDefinition`,
`RBACOptions`, `MatcherCacheOptions`, `AuthSubject`, `PasswordOptions`,
`OAuthProfile`, `OAuthTokens`, `OAuthProviderConfig`, `OAuthProvider`,
`ProviderDefinition`, `StateStore`, `SessionStore`, `OAuthOptions`,
`OAuthAuthorizeOptions`, `UserRecord`, `UserStore`, `RedirectUriPolicy`,
`RefreshRecord`, `RefreshStore`, `LoginOptions`, `LoginResult`,
`AuthHookName`, `AuthHookHandler`, `RequestLike`, `ExtractTokenOptions`,
`UwsHttpResponse`, `UwsHttpRequest`, `UwsRequestSnapshot`, `UwsHandler`,
`ExpressRequestLike`, `ExpressResponseLike`, `ExpressNext`, `KoaContextLike`,
`FastifyLike`, `FastifyRequestLike`, `FastifyReplyLike`, `PersistenceAdapter`,
`EventAdapters`, `PersistenceErrorCode`, `PersistenceErrorInfo`,
`KeyValueStore`, `RevocationStore`, `VersionStore`, `Logger`, `AuthContext`

## Development

```bash
npm test          # all tests (vitest)
npm run typecheck # tsc --noEmit
npm run lint      # eslint
npm run build     # clean ESM + CJS build
npm run pack:check # npm pack --dry-run
```

CI runs typecheck, tests, build, and `pack:check` on Node 20, 22, and 24, then
installs the packed tarball into a clean project and exercises the public API
against it.

## License

[MIT](LICENSE). Copyright (c) 2026 mayank.

## More documentation

- [Architecture](./docs/ARCHITECTURE.md) — module dependency maps and execution flows
- [Features](./docs/features.md) — feature index and deep dives
- [Changelog](./CHANGELOG.md) — release history and 2.0.0 migration notes

# auth
