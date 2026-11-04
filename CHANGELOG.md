# Changelog

All notable changes to this package are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Security

### Security

- **OAuth PKCE is now enabled by default.** Every authorization-code flow uses
  PKCE with the S256 challenge method unless a provider explicitly opts out with
  `pkce: false`. A fresh code verifier is generated per authorization
  transaction, bound to the OAuth state transaction, and consumed atomically
  during callback token exchange. Missing, expired, mismatched, or replayed
  state/verifier rejects the callback. This removes the previous implicit
  PKCE-disabled fallback.

- **OAuth redirect URI validation is now required.** Every authorization-code
  flow validates its redirect URI against a trusted local allowlist
  (`redirectUriPolicy.allowedRedirectUris`) with exact string matching before
  the authorization URL is constructed. HTTPS is required except for an
  explicitly opted-in localhost development exception. The validated URI is
  bound to the OAuth state transaction and used during callback processing;
  callback-supplied URIs are never trusted. Missing or empty allowlists fail
  closed. Validation failures return a typed `InvalidRedirectUriError`.

- **Optional structured logging added.** A `Logger` type (`debug`, `info`,
  `warn`, `error` — all optional) can be injected via `createAuth({ logger })`.
  Logging is disabled by default, adds no logging framework dependency, swallows
  logger exceptions, and never includes secrets (passwords, tokens, codes, state,
  verifiers, client secrets) in logged payloads. Internal lifecycle events use
  structured event names (e.g. `auth.login.succeeded`,
  `auth.token.validation.succeeded`, `auth.oauth.callback.received`,
  `auth.session.revoked`).

- **Infrastructure adapter architecture added.** `src/adapters/contracts/`
  defines storage (`KeyValueStore`, `SessionStore`, `RefreshTokenStore`,
  `RevocationStore`, `VersionStore`), event (`EventPublisher`, `EventSubscriber`,
  `AuthEvent`, `EventProcessingStore`), and logger (`Logger`) adapter contracts,
  composed into `StorageAdapter` and `EventAdapters`. Unified configuration via
  `AuthAdapters` / `AuthConfig`, passed through `createAuth({ adapters })`. The
  `createAdapterRegistry()` registry validates interfaces and declared
  `StorageCapabilities` at initialization and fails fast on missing required
  methods. `StorageErrorCode` and `EventErrorCode` normalize infrastructure
  errors. No Redis client, database driver, ORM, message broker client, or
  logging framework is added as a runtime dependency; the application owns
  connections, pools, credentials, and lifecycle.

<!--
Categories, in the order they appear below:
- Security — a vulnerability fix. Say what was exploitable and how.
- Added — new public API.
- Changed — behavior a user can observe differently.
- Fixed — a bug, with no security consequence.
-->

## 2.0.1

Security fixes and session revocation. One breaking change: tokens are no longer
read from the query string unless you opt in.

### Security

- **Password hashing parameters taken from a stored hash are now bounded.** The
  `N`, `r`, `p`, and `keyLength` fields are parsed out of the stored hash string,
  so they are attacker-influenced wherever an attacker can write a user row.
  Node's own `maxmem` guard only covers the `128 * N * r` memory block, which
  left the other two unbounded: a single stored hash of
  `scrypt$16384$8$1$1073741824$...` cost **25.3 seconds of CPU** on a default
  configuration, repeatable on every login attempt, for one string of attacker
  input. All four parameters are now range-checked before scrypt runs, on both
  the hashing and the verifying path, and an out-of-range hash is reported as
  malformed instead of computed. `N` must additionally be a power of two and
  `N * r` must fit in 24MB of working memory, so a parameter set the platform
  would reject is refused up front rather than throwing from inside OpenSSL.
  A floor is enforced too: a stored hash asking for trivial work (`N=2, r=1`)
  verifies instantly and is a brute-force shortcut, so it is rejected.
- **Apple `id_token` signatures are now verified.** The claims in an Apple
  `id_token` are now checked against Apple's published JWKS before anything is
  read out of them. Previously the payload was decoded and trusted, so
  `iss`, `aud`, and `exp` were only as trustworthy as the token's own contents:
  anyone able to influence the token response could choose the subject, the
  audience, and the expiry. Verification pins `RS256` and requires a `kid`, so
  `alg: "none"` and JWT algorithm-confusion are refused. Keys are cached for an
  hour and an unknown `kid` triggers one refetch, so a routine Apple key
  rotation is invisible to callers. `exp` is now required rather than checked
  when present, since a token with no usable `exp` was previously treated as
  never expiring.
- **Refresh tokens without a `jti` are refused.** `refresh()` only consulted the
  refresh store when the token carried a `jti`, so a token without one skipped
  the store entirely and could never be revoked — it stayed valid until it
  expired and survived logout. `encodeRefreshToken` is a public export, so this
  was reachable by anyone holding the secret. A missing `jti` is now an
  `UnauthorizedError`. Refresh tokens minted by `login()` always have one, so
  this only affects tokens you built yourself.
- **Tokens are no longer read from the query string by default.**
  `extractToken()` fell through to `?access_token=` or `?token=` on every
  request, putting the token in access logs, proxy logs, browser history, and
  the `Referer` header sent to third parties. Pass `{ query: true }` to restore
  it, for flows that genuinely cannot set a header (EventSource, file
  download). Header and cookie extraction are unchanged and remain the default.

### Added

- **Session revocation.** Configure a `sessionStore` and tokens carry an `sv`
  claim, so a session can be invalidated before its token expires:

  ```js
  const auth = createAuth({
    secret,
    sessionStore: {
      getVersion: (userId) => db.getVersion(userId) ?? 0,
      bumpVersion: (userId) => db.incrementVersion(userId),
      revokeSession: (jti) => db.deleteSession(jti),
    },
  });

  await auth.revokeAllSessions(userId); // every device
  await auth.revokeSession(jti);        // one session
  ```

  `refresh()` is covered as well as `verify()`, so a revoked session cannot mint
  a fresh access token. This is opt-in and costs one store read per
  verification; without a `sessionStore`, `revokeAllSessions()` returns `false`
  rather than silently appearing to succeed. Numeric and string user ids
  resolve to the same version.

### Changed

- `verifyIdTokenSignature`, `jwksUrl`, `jwks`, and `jwksCacheTtlMs` are
  available on the Apple provider for key-cache control. Signature verification
  is on by default; `verifyIdTokenSignature: false` exists for test harnesses
  and should not be used in production.
- `hashPassword` now throws `ValidationError` for out-of-range parameters
  instead of letting the error escape from OpenSSL.
- Tests run entirely offline: the Apple suite signs real tokens with a generated
  RSA key pair rather than reaching Apple's JWKS endpoint.

## 2.0.0

Security hardening. Every breaking change below is a case where the previous
behavior was exploitable or silently incorrect. Upgrade notes follow the
release.

### Security

- **Identity and permission claims can no longer be overridden.** Extractors and
  `additionalClaims` are applied after the derived claims, so a name collision
  silently replaced them: `login(user, { additionalClaims: { sub: "admin" } })`
  minted a token claiming `sub: admin` for user 42, and an extractor named `sub`
  rewrote the subject outright. `sub`, `userId`, `roles`, `permissions`, `typ`,
  `iss`, `aud`, `exp`, `iat`, `nbf`, and `jti` are now reserved —
  `registerExtractor()` throws on a reserved name, reserved keys returned in an
  extractor's object are dropped, and `login()` rejects an `additionalClaims`
  entry naming one. Non-reserved names such as `name`, `email`, `tier`, or
  `tenantId` are unaffected.
- **Apple `id_token` claims are validated.** Apple is the only built-in provider
  whose profile comes from a token in the code-exchange response rather than a
  server-side userinfo call, so its `iss`, `aud`, and `exp` were read with no
  validation at all — a token with a wrong issuer, a wrong audience, or an
  expired `exp` was accepted. They are now checked against the configured
  `clientId` and the current time, and a mismatch throws `ProviderError`. The
  RS256 signature is still not verified; see `ARCHITECTURE.md` for why that is
  not reachable through `loginWithOAuth()`, and what to do if you forward an
  `id_token` from elsewhere.
- **Refresh tokens are no longer accepted as access tokens.** `verify()` and
  `verifyRequest()` reject a token whose `typ` is `refresh`. Access and refresh
  tokens share a signing key by default, so a 7-day refresh token previously
  authenticated as a bearer credential on every protected route.
- **`register()` ignores caller-supplied roles.** A `roles` field in the input
  argument is discarded. A public sign-up form posts directly into that
  argument, so the field let any caller mint themselves a privileged role.
- **Access token permissions come from RBAC roles only.** A `permissions` array
  on the user record is no longer copied into the token, where it would have
  been indistinguishable from a role-derived grant.
- **`logout()` no longer reports success when nothing was revoked.** If the
  configured `refreshStore` implements neither `consume` nor `revoke`,
  `revoke()`, `logout()`, and `refresh()` throw `ConfigurationError` instead of
  returning a `true` that invalidated nothing. A store implementing only
  `consume()` can both rotate and log out, since the two are interchangeable for
  removing a specific id.
- **Refresh rotation is atomic.** `refresh()` uses the new `RefreshStore.consume()`
  when present, so one token can no longer be redeemed twice by concurrent
  requests. Stores without `consume` fall back to `get()` + `revoke()` and now
  require `revoke()`.
- **The Koa adapter no longer masks downstream errors.** `next()` moved outside
  the `try` block, so a handler error propagates to Koa's error handling instead
  of being rewritten as a `401 AUTH_ERROR` response.

### Fixed

- Token extraction reads `Authorization` and `Cookie` from a WHATWG `Headers`
  object, whose `forEach` passes `(value, key)`. Both arguments were previously
  inverted, so such requests produced no headers and always returned 401.
  uWebSockets.js `(key, value)` handling is unchanged.
- `fastifyAdapter` honors `optional` configured on the plugin, not only when
  passed per route.
- `revoke()` pins `algorithm` and `clockTolerance` to the configured values
  instead of defaulting to HS256 with no leeway, and rejects non-refresh tokens.
- `refresh()` now honors `clockTolerance`.
- Registering an aliased OAuth provider no longer overwrites the canonical
  provider entry.
- `matchPermission` supports `**` as a multi-segment wildcard, so `posts.**`
  matches `posts.a.b`. `*` still stays within a single segment.
- An unparsable `expiresIn` (`"1y"`, `"2 hours"`) throws `ValidationError`
  instead of silently defaulting to 24 hours in one place and failing in
  another, which let a token's real expiry diverge from a locally computed one.
- **OAuth login now fails closed when the profile carries no subject id.**
  Previously the fallback user id was `` `${provider}:${profile.id}` ``, so a
  provider response missing the id produced the subject `"google:undefined"` and
  every social user collapsed onto one identity. `loginWithOAuth()` now throws
  `ProviderError`. Map a stable id in the provider's `profileMap`.
- `loginWithOAuth()` accepts a bare query string (`"code=abc&state=xyz"`). The
  `URL` constructor parsed it as a path with no query, so the code silently came
  back empty and the call failed with "missing authorization code". Full URLs,
  paths with a query, and a leading `?` continue to work.
- `package.json` and `.npmignore` end with a trailing newline.

### Added

- `pkceVerifier()` and `pkceChallenge()` are now exported from the package entry
  point. Public clients implementing PKCE by hand had no supported way to
  generate a verifier or compute the S256 challenge, even though
  `OAuthAuthorizeOptions.codeVerifier` and `authorize()`'s returned
  `codeVerifier` are public API.
- `ARCHITECTURE.md` — module layout, token lifecycle, refresh-store contract,
  trust boundaries, and the security invariants the test suite enforces.
- `RefreshStore.consume(id)` — optional atomic read-and-delete. Preferred over
  `get()` + `revoke()`.
- `AuthOptions.trustUserPermissions` — opt back in to copying a user record's
  `permissions` into the access token. Defaults to `false`.
- `JwtVerifyOptions.acceptTokenType` — accept a `refresh` token in `verify()`.
  Defaults to rejecting it.
- `isValidExpiresIn()` — exported TTL validator.
- `test/security.test.ts` — regression tests for each fix above, plus
  `alg: none`, cross-secret, cross-algorithm, concurrent-rotation, hostile
  scrypt parameters, OAuth identity-collapse, callback parameter shapes,
  RBAC cycle/deep-chain/wildcard-boundary, and PKCE RFC 7636 cases.
- GitHub Actions workflow running typecheck, tests, build, `pack:check`, and
  `pnpm audit` on Node 20/22/24, then installing the packed tarball into a clean
  project to verify the public API and the shipped examples.
- `npm run example`, `example:standalone`, and `example:oauth` scripts.

### Changed

- **Shipped examples import `@oneunit/auth` instead of `../src/index.js`.**
  `src/` is not published, so every example previously failed with
  `ERR_MODULE_NOT_FOUND` for anyone who installed from npm. A `paths` mapping in
  `tsconfig.json` keeps in-repo typechecking pointed at source, and Node's
  package self-reference resolves the built `dist/` at runtime.
- **Removed the `express`, `fastify`, and `koa` peer dependencies.** The adapters
  never import any of them — they duck-type the request and response objects —
  so the peers misrepresented the contract. The package now has one runtime
  dependency, `jsonwebtoken`.
- Replaced the `bootstrap-framework` npm keyword with `oneunit`.
- Deleted `.npmignore`. The `files` array in `package.json` is authoritative and
  two competing lists would drift.

### Migration

**If you call `auth.register(input)` and relied on `input.roles`:**

```diff
- await auth.register({ email, password, roles: ["member"] });
+ await auth.register({ email, password }, { roles: ["member"] });
```

**If you store permissions on the user record and expect them in the token:**

```diff
- const auth = createAuth({ secret });
+ const auth = createAuth({ secret, trustUserPermissions: true });
```

Prefer granting those permissions through an RBAC role instead.

**If you use a custom `refreshStore`:**

Implement `revoke()` at minimum. Implement `consume()` as a single atomic
operation (`GETDEL`, `DELETE ... RETURNING`, `findOneAndDelete`) so concurrent
refreshes cannot both succeed.

```ts
const refreshStore = {
  async save(record) { /* ... */ },
  async get(id) { /* ... */ },
  async consume(id) { /* atomic read + delete */ },
  async revoke(id) { /* ... */ },
};
```

**If you have `@oneunit/auth` in `peerDependencies` or `optionalDependencies`:**

Remove it. The adapters never import a web framework, so there is nothing to
satisfy. Keeping it forces an unnecessary install.

**If you vendor or fork the examples:**

They now import from `@oneunit/auth` rather than `../src/index.js`, because
`src/` is not published. Copy them into your own project and the import already
resolves.

**If you call `auth.verify()` on a refresh token:**

Use `auth.refresh()` instead. Pass `{ acceptTokenType: "refresh" }` only if you
genuinely need the raw claims.

**If your login route passes a request body into `auth.login()`:**

`login()` is a low-level primitive and never validated roles. Resolve the user
through a store first. See `examples/express.ts` for the correct shape.

## 1.0.0

- Published independently as `@oneunit/auth` (renamed from `@bootstrap-framework/auth`)
- Node.js 20+, MIT, author mayank

## Previous releases

Released as `@bootstrap-framework/auth`.

### 2.2.0

- Convert the package to TypeScript with generated `.d.ts` declarations
- Publish compiled ESM from `dist/` (`main`, `types`, and `exports`)
- Add `typescript` / `@types/node` / `@types/jsonwebtoken` / `tsx` for build and tests
- Type adapters, tests, and examples

### 2.1.0

- Add uWebSockets.js adapter with request snapshots (required after `await`)
- Read tokens from uWS `getHeader` / `getQuery` and header maps
- Optional `uWebSockets.js` peer dependency
- npm packaging: `exports`, `prepack`, and `package.json` export

### 2.0.0

- Independent, framework-agnostic auth package
- Replace `@fastify/jwt` with `jsonwebtoken`
- Remove workspace and framework runtime dependencies
- Generic RBAC (consumer-defined roles and permissions)
- Social OAuth 2.0 / OIDC providers (Google, GitHub, Instagram, and others)
- Password hashing via Node.js `scrypt`
- Express, Fastify, and Koa adapters
- Access and refresh tokens
- Tests, examples, types, and npm package metadata
