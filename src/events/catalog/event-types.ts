export const AUTH_EVENT_TYPES = {
  LOGIN_SUCCEEDED: "auth.login.succeeded",
  LOGIN_FAILED: "auth.login.failed",
  REGISTRATION_SUCCEEDED: "auth.registration.succeeded",
  REGISTRATION_FAILED: "auth.registration.failed",
  LOGOUT_SUCCEEDED: "auth.logout.succeeded",
  SESSION_CREATED: "auth.session.created",
  SESSION_REVOKED: "auth.session.revoked",
  SESSION_EXPIRED: "auth.session.expired",
  TOKEN_ISSUED: "auth.token.issued",
  TOKEN_VALIDATION_SUCCEEDED: "auth.token.validation.succeeded",
  TOKEN_VALIDATION_FAILED: "auth.token.validation.failed",
  TOKEN_REFRESHED: "auth.token.refreshed",
  OAUTH_LOGIN_SUCCEEDED: "auth.oauth.login.succeeded",
  OAUTH_LOGIN_FAILED: "auth.oauth.login.failed",
} as const;

export type AuthEventType = (typeof AUTH_EVENT_TYPES)[keyof typeof AUTH_EVENT_TYPES];

export interface EventCategoryMap {
  [eventType: string]: "authentication" | "security" | "session" | "token";
}

export const EVENT_CATEGORIES: EventCategoryMap = {
  [AUTH_EVENT_TYPES.LOGIN_SUCCEEDED]: "authentication",
  [AUTH_EVENT_TYPES.LOGIN_FAILED]: "security",
  [AUTH_EVENT_TYPES.REGISTRATION_SUCCEEDED]: "authentication",
  [AUTH_EVENT_TYPES.REGISTRATION_FAILED]: "security",
  [AUTH_EVENT_TYPES.LOGOUT_SUCCEEDED]: "session",
  [AUTH_EVENT_TYPES.SESSION_CREATED]: "session",
  [AUTH_EVENT_TYPES.SESSION_REVOKED]: "session",
  [AUTH_EVENT_TYPES.SESSION_EXPIRED]: "session",
  [AUTH_EVENT_TYPES.TOKEN_ISSUED]: "token",
  [AUTH_EVENT_TYPES.TOKEN_VALIDATION_SUCCEEDED]: "token",
  [AUTH_EVENT_TYPES.TOKEN_VALIDATION_FAILED]: "security",
  [AUTH_EVENT_TYPES.TOKEN_REFRESHED]: "token",
  [AUTH_EVENT_TYPES.OAUTH_LOGIN_SUCCEEDED]: "authentication",
  [AUTH_EVENT_TYPES.OAUTH_LOGIN_FAILED]: "security",
};

export interface LoginSucceededPayload {
  userId: string | number;
  sessionId?: string;
  authenticationMethod: "password" | "oauth" | "magic-link" | "other";
  provider?: string;
  tenantId?: string;
  ipAddress?: string;
  userAgent?: string;
}

export interface LoginFailedPayload {
  reason:
    | "invalid_credentials"
    | "account_disabled"
    | "account_locked"
    | "provider_error"
    | "unknown";
  authenticationMethod: string;
  provider?: string;
  tenantId?: string;
  ipAddress?: string;
  userAgent?: string;
}

export interface RegistrationSucceededPayload {
  userId: string | number;
  authenticationMethod: "password" | "oauth" | "magic-link" | "other";
  provider?: string;
  tenantId?: string;
  ipAddress?: string;
  userAgent?: string;
}

export interface RegistrationFailedPayload {
  reason:
    | "invalid_input"
    | "user_exists"
    | "provider_error"
    | "unknown";
  authenticationMethod: string;
  provider?: string;
  tenantId?: string;
  ipAddress?: string;
  userAgent?: string;
}

export interface LogoutSucceededPayload {
  userId?: string | number;
  sessionId?: string;
  tenantId?: string;
}

export interface SessionCreatedPayload {
  userId: string | number;
  sessionId: string;
  tenantId?: string;
}

export interface SessionRevokedPayload {
  userId?: string | number;
  sessionId?: string;
  reason: "logout" | "revoke_all" | "revoke_session" | "expired";
  tenantId?: string;
}

export interface TokenIssuedPayload {
  userId: string | number;
  sessionId?: string;
  tokenType: "access" | "refresh";
  tenantId?: string;
}

export interface TokenValidationSucceededPayload {
  userId?: string | number;
  sessionId?: string;
  tokenType: "access" | "refresh";
  tenantId?: string;
}

export interface TokenValidationFailedPayload {
  reason: "invalid_token" | "expired_token" | "revoked" | "unknown";
  tokenType?: "access" | "refresh";
  tenantId?: string;
}

export interface TokenRefreshedPayload {
  userId: string | number;
  sessionId?: string;
  tenantId?: string;
}

export interface OAuthLoginSucceededPayload {
  userId: string | number;
  provider: string;
  sessionId?: string;
  tenantId?: string;
}

export interface OAuthLoginFailedPayload {
  provider: string;
  reason: "provider_error" | "invalid_profile" | "unknown";
  tenantId?: string;
}

export type AuthEventPayload =
  | LoginSucceededPayload
  | LoginFailedPayload
  | RegistrationSucceededPayload
  | RegistrationFailedPayload
  | LogoutSucceededPayload
  | SessionCreatedPayload
  | SessionRevokedPayload
  | TokenIssuedPayload
  | TokenValidationSucceededPayload
  | TokenValidationFailedPayload
  | TokenRefreshedPayload
  | OAuthLoginSucceededPayload
  | OAuthLoginFailedPayload;
