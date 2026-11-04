import { OAuthError, ValidationError, ConfigurationError } from "../errors/index.js";
import { builtinProviders, createProvider, getProvider, pkceVerifier } from "./providers/index.js";
import { createMemoryStateStore } from "../stores/memory/state-store.js";
import { validateRedirectUri } from "./redirect-uri.js";
import { createSafeLogger } from "../logging/logger.js";
import type {
  OAuthAuthorizeOptions,
  OAuthOptions,
  OAuthProfile,
  OAuthProvider,
  OAuthProviderConfig,
  OAuthStateRecord,
  OAuthTokens,
  StateStore,
} from "../types/index.js";
import type { Logger } from "../logging/types.js";
import { randomState, timingSafeEqualString } from "../utils.js";
import { configureHttp } from "../http/transport.js";
import { emitDiagnostic } from "../diagnostics/index.js";

interface ProviderEntry {
  provider: OAuthProvider;
  config: OAuthProviderConfig;
}

export class OAuth {
  providers = new Map<string, ProviderEntry>();
  defaultRedirectUri: string | null;
  stateStore: StateStore;
  logger: Required<Logger>;

  constructor(options: OAuthOptions = {}) {
    this.defaultRedirectUri = options.redirectUri ?? null;
    this.stateStore = options.stateStore ?? createMemoryStateStore();
    this.logger = createSafeLogger(options.logger);
    if (options.http) {
      configureHttp(options.http);
    }

    const configured = options.providers ?? {};
    for (const [id, config] of Object.entries(configured)) {
      this.use(id, config);
    }
  }

  use(id: string, config: OAuthProviderConfig = {}): this {
    const provider: OAuthProvider = (config.provider as OAuthProvider | undefined) ??
      (id in builtinProviders
        ? getProvider(id)
        : createProvider({
          id,
          authorizationUrl: String(config.authorizationUrl ?? ""),
          tokenUrl: String(config.tokenUrl ?? ""),
          ...config,
        }));

    const entry: ProviderEntry = {
      provider,
      config: {
        clientId: config.clientId,
        clientSecret: config.clientSecret,
        redirectUri: config.redirectUri ?? this.defaultRedirectUri ?? undefined,
        scopes: config.scopes,
        pkce: config.pkce,
        redirectUriPolicy: config.redirectUriPolicy,
        extraAuthParams: config.extraAuthParams,
        extraTokenParams: config.extraTokenParams,
        userInfoHeaders: config.userInfoHeaders,
        tokenAuthMethod: config.tokenAuthMethod,
        jwksUrl: config.jwksUrl,
        jwks: config.jwks,
        jwksCacheTtlMs: config.jwksCacheTtlMs,
        verifyIdTokenSignature: config.verifyIdTokenSignature,
      },
    };

    // Fail fast at provider setup: every explicitly allowed redirect URI must
    // already pass the validation policy. An empty allowlist is intentional
    // and rejects all redirect URIs at flow time.
    if (entry.config.redirectUriPolicy) {
      for (const uri of entry.config.redirectUriPolicy.allowedRedirectUris) {
        validateRedirectUri(uri, entry.config.redirectUriPolicy);
      }
    }

    if (config.pkce === false) {
      this.logger.warn(
        {
          event: "auth.oauth.pkce.disabled",
          provider: id,
        },
        `PKCE is disabled for OAuth provider "${id}". This is a security downgrade: authorization-code flows will not use a code verifier. Set pkce: true (or omit it) to require PKCE with S256.`,
      );
    }

    this.providers.set(id, entry);
    // Also expose the provider under its own id when registered via an alias,
    // but never overwrite an entry that was configured explicitly.
    if (provider.id && provider.id !== id && !this.providers.has(provider.id)) {
      this.providers.set(provider.id, entry);
    }

    return this;
  }

  list(): string[] {
    return [...this.providers.keys()];
  }

  get(id: string): ProviderEntry {
    const entry = this.providers.get(id);
    if (!entry) {
      throw new ValidationError(`OAuth provider "${id}" is not configured`);
    }
    return entry;
  }

  async authorize(id: string, options: OAuthAuthorizeOptions = {}): Promise<{
    url: string;
    state: string;
    provider: string;
    codeVerifier?: string;
  }> {
    const { provider, config } = this.get(id);
    const state = options.state ?? randomState();
    const redirectUri = validateRedirectUri(options.redirectUri ?? config.redirectUri, config.redirectUriPolicy ?? {
      allowedRedirectUris: [],
      allowLocalhostHttp: false,
    });
    const pkceEnabled = config.pkce ?? provider.pkce ?? true;
    const codeVerifier = pkceEnabled ? (options.codeVerifier ?? pkceVerifier()) : undefined;

    this.logger.info(
      { event: "auth.oauth.authorization.started", provider: id },
      "OAuth authorization started",
    );
    emitDiagnostic({ type: "oauth.authorization.started", timestamp: Date.now(), providerId: id });

    const authorization = provider.createAuthorizationUrl(config, {
      state,
      redirectUri,
      codeVerifier,
      extraParams: options.extraParams,
    });

    await this.stateStore.set(state, {
      provider: id,
      redirectUri,
      codeVerifier: authorization.codeVerifier ?? codeVerifier,
      createdAt: Date.now(),
      metadata: options.metadata ?? {},
    } satisfies OAuthStateRecord, options.ttlSeconds ?? 600);

    return {
      url: authorization.url,
      state,
      provider: id,
      codeVerifier: authorization.codeVerifier ?? codeVerifier,
    };
  }

  async callback(id: string, params: string | Record<string, string> = {}): Promise<{
    provider: string;
    tokens: OAuthTokens;
    profile: OAuthProfile;
    state: OAuthStateRecord | null;
  }> {
    const query = normalizeCallbackParams(params);
    if (query.error) {
      throw new OAuthError(query.error_description || query.error);
    }

    if (!query.code) {
      throw new ValidationError("OAuth callback is missing authorization code");
    }

    this.logger.info(
      { event: "auth.oauth.callback.received", provider: id },
      "OAuth callback received",
    );

    const { provider, config } = this.get(id);
    const pkceEnabled = config.pkce ?? provider.pkce ?? true;
    let stored: OAuthStateRecord | null = null;

    if (query.state) {
      if (typeof this.stateStore.consume !== "function") {
        throw new ConfigurationError(
          "The configured stateStore must implement consume() for atomic OAuth state consumption; get()+delete() is not a secure substitute",
        );
      }
      stored = (await this.stateStore.consume(query.state)) as OAuthStateRecord | null;
      if (!stored) {
        this.logger.warn(
          { event: "auth.oauth.state.validation_failed", provider: id, reason: "state_not_found" },
          "OAuth state validation failed",
        );
        throw new OAuthError("Invalid or expired OAuth state");
      }
      if (stored.provider && stored.provider !== id) {
        this.logger.warn(
          { event: "auth.oauth.state.validation_failed", provider: id, reason: "provider_mismatch" },
          "OAuth provider mismatch",
        );
        throw new OAuthError("OAuth provider mismatch");
      }
      if (pkceEnabled && !stored.codeVerifier) {
        this.logger.warn(
          { event: "auth.oauth.state.validation_failed", provider: id, reason: "missing_verifier" },
          "Missing PKCE code verifier for state transaction",
        );
        throw new OAuthError("Missing PKCE code verifier for state transaction");
      }
    } else if (pkceEnabled) {
      throw new OAuthError("OAuth state is required");
    }

    // State is mandatory for every authorization-code callback, independent of
    // PKCE. PKCE and state protect against different classes of attacks, so
    // disabling PKCE must never weaken CSRF protection.
    if (!query.state) {
      throw new OAuthError("OAuth state is required");
    }

    const tokens = await provider.exchangeCode(config, {
      code: query.code,
      redirectUri: stored?.redirectUri ?? config.redirectUri,
      codeVerifier: stored?.codeVerifier,
    });

    const profile = await provider.fetchProfile(config, tokens);

    this.logger.info(
      { event: "auth.oauth.callback.succeeded", provider: id },
      "OAuth callback succeeded",
    );

    return {
      provider: id,
      tokens,
      profile: {
        ...profile,
        provider: profile.provider ?? id,
        subject: profile.subject ?? profile.id,
      },
      state: stored,
    };
  }

  async verifyState(state: string, expected?: string): Promise<boolean> {
    const stored = await this.stateStore.get(state) as OAuthStateRecord | null;
    if (!stored) {
      return false;
    }
    if (expected && !timingSafeEqualString(stored.provider, expected)) {
      return false;
    }
    return true;
  }
}

function normalizeCallbackParams(params: string | Record<string, string>): Record<string, string> {
  if (typeof params === "string") {
    const trimmed = params.trim();
    // Accepts a full URL ("https://host/cb?code=..."), a path with a query
    // ("/cb?code=..." or "cb?code=..."), a leading "?code=...", or a bare query
    // string ("code=..."). Only the bare form needs special handling: the URL
    // constructor reads it as a path, and reading it as a query string is the
    // only way to find the code.
    const isBareQuery = trimmed !== "" && !trimmed.includes("?") && !trimmed.includes("://") && !trimmed.startsWith("/");
    if (isBareQuery) {
      return Object.fromEntries(new URLSearchParams(trimmed));
    }
    const url = trimmed.includes("://") ? new URL(trimmed) : new URL(trimmed, "http://localhost");
    return Object.fromEntries(url.searchParams.entries());
  }
  return params ?? {};
}

export function createOAuth(options: OAuthOptions = {}): OAuth {
  return new OAuth(options);
}

export { createMemoryStateStore } from "../stores/memory/state-store.js";

export {
  TokenIntrospector,
  createTokenIntrospector,
} from "./introspection/client.js";

export {
  IntrospectionError,
} from "./introspection/types.js";

export type {
  IntrospectionConfig,
  IntrospectionResult,
  ResolvedIntrospectionConfig,
} from "./introspection/types.js";
