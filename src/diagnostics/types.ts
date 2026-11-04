export type DiagnosticFailureCategory =
  | "invalid_credentials"
  | "invalid_token"
  | "expired_token"
  | "revoked"
  | "not_configured"
  | "unavailable"
  | "validation"
  | "provider"
  | "configuration"
  | "unknown";

export type AuthDiagnosticEvent =
  | {
      type: "auth.login.started";
      timestamp: number;
      operationId?: string;
    }
  | {
      type: "auth.login.succeeded";
      timestamp: number;
      operationId?: string;
    }
  | {
      type: "auth.login.failed";
      timestamp: number;
      reason: DiagnosticFailureCategory;
      operationId?: string;
    }
  | {
      type: "auth.session.revoked";
      timestamp: number;
      status: "revoked" | "not_found" | "not_configured" | "unavailable";
      operationId?: string;
    }
  | {
      type: "auth.session.verification.failed";
      timestamp: number;
      reason: DiagnosticFailureCategory;
      operationId?: string;
    }
  | {
      type: "token.verification.succeeded";
      timestamp: number;
      operationId?: string;
    }
  | {
      type: "token.verification.failed";
      timestamp: number;
      reason: DiagnosticFailureCategory;
      operationId?: string;
    }
  | {
      type: "oauth.authorization.started";
      timestamp: number;
      providerId?: string;
      operationId?: string;
    }
  | {
      type: "oauth.callback.failed";
      timestamp: number;
      providerId?: string;
      reason: DiagnosticFailureCategory;
      operationId?: string;
    }
  | {
      type: "oauth.introspection.completed";
      timestamp: number;
      operationId?: string;
    }
  | {
      type: "oauth.introspection.failed";
      timestamp: number;
      reason: DiagnosticFailureCategory;
      operationId?: string;
    }
  | {
      type: "password.hash.created";
      timestamp: number;
      algorithm: string;
      operationId?: string;
    }
  | {
      type: "password.hash.upgraded";
      timestamp: number;
      algorithm: string;
      operationId?: string;
    }
  | {
      type: "password.hash.upgrade.failed";
      timestamp: number;
      reason: DiagnosticFailureCategory;
      operationId?: string;
    }
  | {
      type: "jwks.refresh.failed";
      timestamp: number;
      reason: DiagnosticFailureCategory;
      operationId?: string;
    }
  | {
      type: "http.request.failed";
      timestamp: number;
      httpStatus?: number;
      reason: DiagnosticFailureCategory;
      operationId?: string;
    }
  | {
      type: "store.operation.failed";
      timestamp: number;
      reason: DiagnosticFailureCategory;
      operationId?: string;
    };

export type DiagnosticsObserver = (event: AuthDiagnosticEvent) => void | Promise<void>;

export type DiagnosticsOverflowPolicy = "drop" | "report";

export type DiagnosticsErrorCallback = (
  event: AuthDiagnosticEvent,
  reason: "overflow" | "observer-failure",
  error?: unknown,
) => void;

export interface DiagnosticsStats {
  emitted: number;
  dropped: number;
  failed: number;
  size: number;
  maxSize: number;
  overflowPolicy: DiagnosticsOverflowPolicy;
}
