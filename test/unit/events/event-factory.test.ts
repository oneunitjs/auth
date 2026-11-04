import { describe, it, expect } from "vitest";
import {
  createAuthEvent,
  AUTH_EVENT_TYPES,
  EVENT_CATEGORIES,
  EVENT_VERSION,
  type AuthEventType,
} from "../../../src/index.js";

describe("event factory", () => {
  it("creates an event with a unique id", () => {
    const a = createAuthEvent({
      type: AUTH_EVENT_TYPES.LOGIN_SUCCEEDED,
      payload: { userId: 1, authenticationMethod: "password" },
      source: "test-service",
    });
    const b = createAuthEvent({
      type: AUTH_EVENT_TYPES.LOGIN_SUCCEEDED,
      payload: { userId: 1, authenticationMethod: "password" },
      source: "test-service",
    });
    expect(a.id).not.toBe(b.id);
    expect(a.id).toMatch(/^evt_/);
  });

  it("sets stable event type and version", () => {
    const event = createAuthEvent({
      type: AUTH_EVENT_TYPES.LOGIN_SUCCEEDED,
      payload: { userId: 1, authenticationMethod: "password" },
      source: "test-service",
    });
    expect(event.type).toBe("auth.login.succeeded");
    expect(event.version).toBe(EVENT_VERSION);
  });

  it("sets a valid ISO timestamp", () => {
    const event = createAuthEvent({
      type: AUTH_EVENT_TYPES.LOGIN_SUCCEEDED,
      payload: { userId: 1, authenticationMethod: "password" },
      source: "test-service",
    });
    const date = new Date(event.occurredAt);
    expect(date.toISOString()).toBe(event.occurredAt);
  });

  it("sets source", () => {
    const event = createAuthEvent({
      type: AUTH_EVENT_TYPES.LOGIN_SUCCEEDED,
      payload: { userId: 1, authenticationMethod: "password" },
      source: "my-service",
    });
    expect(event.source).toBe("my-service");
  });

  it("includes only documented payload fields", () => {
    const event = createAuthEvent({
      type: AUTH_EVENT_TYPES.LOGIN_SUCCEEDED,
      payload: {
        userId: 1,
        sessionId: "sess_123",
        authenticationMethod: "password",
      },
      source: "test-service",
    });
    expect(event.payload.userId).toBe(1);
    expect(event.payload.sessionId).toBe("sess_123");
    expect(event.payload.authenticationMethod).toBe("password");
  });

  it("handles optional metadata", () => {
    const event = createAuthEvent({
      type: AUTH_EVENT_TYPES.LOGIN_SUCCEEDED,
      payload: { userId: 1, authenticationMethod: "password" },
      source: "test-service",
      correlationId: "corr_123",
      causationId: "cause_123",
      tenantId: "tenant_123",
      traceId: "trace_123",
    });
    expect(event.metadata?.correlationId).toBe("corr_123");
    expect(event.metadata?.causationId).toBe("cause_123");
    expect(event.metadata?.tenantId).toBe("tenant_123");
    expect(event.metadata?.traceId).toBe("trace_123");
  });

  it("exposes all event type constants", () => {
    expect(AUTH_EVENT_TYPES.LOGIN_SUCCEEDED).toBe("auth.login.succeeded");
    expect(AUTH_EVENT_TYPES.LOGIN_FAILED).toBe("auth.login.failed");
    expect(AUTH_EVENT_TYPES.REGISTRATION_SUCCEEDED).toBe("auth.registration.succeeded");
    expect(AUTH_EVENT_TYPES.SESSION_REVOKED).toBe("auth.session.revoked");
    expect(AUTH_EVENT_TYPES.TOKEN_VALIDATION_SUCCEEDED).toBe("auth.token.validation.succeeded");
  });

  it("maps event types to categories", () => {
    expect(EVENT_CATEGORIES["auth.login.succeeded"]).toBe("authentication");
    expect(EVENT_CATEGORIES["auth.login.failed"]).toBe("security");
    expect(EVENT_CATEGORIES["auth.session.revoked"]).toBe("session");
    expect(EVENT_CATEGORIES["auth.token.validation.failed"]).toBe("security");
  });
});
