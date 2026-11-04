 
import { describe, it, expect } from "vitest";
import {
  createAuth,
  createOAuth,
  createMemoryStateStore,
} from "../../src/index.js";
import type { Logger } from "../../src/types/index.js";
import { createSafeLogger } from "../../src/logging/logger.js";

// ---------------------------------------------------------------------------
// Type compatibility tests
// ---------------------------------------------------------------------------

describe("Logger type compatibility", () => {
  it("accepts a logger implementing all four methods", () => {
    const logger: Logger = {
      debug: () => {},
      info: () => {},
      warn: () => {},
      error: () => {},
    };
    const auth = createAuth({ secret: "secret-key-for-testing-purposes-1234567890", logger });
    expect(auth).toBeTruthy();
  });

  it("accepts a logger implementing only error", () => {
    const logger: Logger = {
      error: () => {},
    };
    const auth = createAuth({ secret: "secret-key-for-testing-purposes-1234567890", logger });
    expect(auth).toBeTruthy();
  });

  it("accepts a logger implementing only warn", () => {
    const logger: Logger = {
      warn: () => {},
    };
    const auth = createAuth({ secret: "secret-key-for-testing-purposes-1234567890", logger });
    expect(auth).toBeTruthy();
  });

  it("accepts an empty object as a logger", () => {
    const logger: Logger = {};
    const auth = createAuth({ secret: "secret-key-for-testing-purposes-1234567890", logger });
    expect(auth).toBeTruthy();
  });

  it("accepts undefined as a logger (logging disabled)", () => {
    const auth = createAuth({ secret: "secret-key-for-testing-purposes-1234567890" });
    expect(auth).toBeTruthy();
  });

  it("accepts a structurally compatible third-party logger without importing its types", () => {
    const thirdPartyLogger = {
      debug: (payload: unknown, message?: string) => {
        console.debug(`[DEBUG] ${message ?? ""}`, payload);
      },
      info: (payload: unknown, message?: string) => {
        console.info(`[INFO] ${message ?? ""}`, payload);
      },
    };
    const auth = createAuth({ secret: "secret-key-for-testing-purposes-1234567890", logger: thirdPartyLogger });
    expect(auth).toBeTruthy();
  });
});

// ---------------------------------------------------------------------------
// Runtime tests
// ---------------------------------------------------------------------------

describe("createSafeLogger runtime behavior", () => {
  it("invokes each configured method with the original payload and message", () => {
    let receivedPayload: unknown;
    let receivedMessage: string | undefined;
    const logger = createSafeLogger({
      debug: (payload: unknown, message?: string) => {
        receivedPayload = payload;
        receivedMessage = message;
      },
    });

    logger.debug({ event: "test.event" }, "test message");
    expect(receivedPayload).toEqual({ event: "test.event" });
    expect(receivedMessage).toBe("test message");
  });

  it("missing methods do not throw", () => {
    const logger = createSafeLogger({});
    expect(() => logger.debug({ x: 1 }, "msg")).not.toThrow();
    expect(() => logger.info({ x: 1 }, "msg")).not.toThrow();
    expect(() => logger.warn({ x: 1 }, "msg")).not.toThrow();
    expect(() => logger.error({ x: 1 }, "msg")).not.toThrow();
  });

  it("undefined logger produces no-op methods", () => {
    const logger = createSafeLogger(undefined);
    expect(() => logger.debug({ x: 1 })).not.toThrow();
    expect(() => logger.info({ x: 1 })).not.toThrow();
    expect(() => logger.warn({ x: 1 })).not.toThrow();
    expect(() => logger.error({ x: 1 })).not.toThrow();
  });

  it("logger that throws synchronously does not break library operations", async () => {
    const auth = createAuth({
      secret: "secret-key-for-testing-purposes-1234567890",
      logger: {
        error: () => {
          throw new Error("logger failure");
        },
      } as Logger,
    });

    const session = await auth.login({ id: 1 });
    expect(session.user.id).toBe(1);
  });

  it("logger exceptions during login do not affect the result", async () => {
    const auth = createAuth({
      secret: "secret-key-for-testing-purposes-1234567890",
      logger: {
        info: () => {
          throw new Error("info logger broken");
        },
      } as Logger,
    });

    const session = await auth.login({ id: 1 });
    expect(session.user.id).toBe(1);
  });

  it("does not mutate the supplied logger", () => {
    const logger: Logger = {
      info: () => {},
    };
    const auth = createAuth({ secret: "secret-key-for-testing-purposes-1234567890", logger });
    expect(auth).toBeTruthy();
    expect(Object.keys(logger).length).toBe(1);
    expect(typeof logger.info).toBe("function");
  });

  it("logging does not change authentication outcomes", async () => {
    const auth = createAuth({ secret: "secret-key-for-testing-purposes-1234567890" });
    const session1 = await auth.login({ id: 1, roles: ["admin"] });

    const loggerCalls: string[] = [];
    const auth2 = createAuth({
      secret: "secret-key-for-testing-purposes-1234567890",
      logger: {
        info: () => {
          loggerCalls.push("info");
        },
      } as Logger,
    });
    const session2 = await auth2.login({ id: 1, roles: ["admin"] });

    expect(session1.payload.sub).toBe(session2.payload.sub);
    expect(JSON.stringify(session1.user.roles)).toBe(JSON.stringify(session2.user.roles));
    expect(loggerCalls.length > 0).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Security tests: sensitive data must never reach the logger
// ---------------------------------------------------------------------------

describe("Logger security: no secrets in payloads", () => {
  it("login does not log passwords or tokens", async () => {
    const loggedPayloads: unknown[] = [];
    const loggedMessages: string[] = [];
    const auth = createAuth({
      secret: "secret-key-for-testing-purposes-1234567890",
      logger: {
        info: (payload, message) => {
          loggedPayloads.push(payload);
          loggedMessages.push(message ?? "");
        },
        error: (payload, message) => {
          loggedPayloads.push(payload);
          loggedMessages.push(message ?? "");
        },
      } as Logger,
    });

    const session = await auth.login({ id: 1, email: "user@example.com", password: "hunter2" });

    const loggedJson = JSON.stringify({ payloads: loggedPayloads, messages: loggedMessages });

    expect(loggedJson).not.toContain("hunter2");
    expect(loggedJson).not.toContain(session.accessToken);
    expect(
      session.refreshToken ? !loggedJson.includes(session.refreshToken) : true,
      "refresh token must not be logged",
    ).toBe(true);
  });

  it("token verification does not log raw tokens", async () => {
    const loggedPayloads: unknown[] = [];
    const auth = createAuth({
      secret: "secret-key-for-testing-purposes-1234567890",
      logger: {
        debug: (payload) => {
          loggedPayloads.push(payload);
        },
        warn: (payload) => {
          loggedPayloads.push(payload);
        },
      } as Logger,
    });

    const session = await auth.login({ id: 1 });
    await auth.verify(session.accessToken);

    const loggedJson = JSON.stringify(loggedPayloads);
    expect(loggedJson).not.toContain(session.accessToken);
    expect(
      session.refreshToken ? !loggedJson.includes(session.refreshToken) : true,
      "raw refresh token must not be logged",
    ).toBe(true);
  });

  it("OAuth callback does not log authorization codes or state", async () => {
    const loggedPayloads: unknown[] = [];
    const oauth = createOAuth({
      stateStore: createMemoryStateStore(),
      providers: {
        test: {
          clientId: "client-id",
          provider: {
            id: "test",
            name: "Test",
            authorizationUrl: "https://example.com/auth",
            tokenUrl: "https://example.com/token",
            scopes: [],
            pkce: true,
            tokenAuthMethod: "body",
            createAuthorizationUrl: () => ({
              url: "https://example.com/auth?state=x",
              state: "x",
            }),
            async exchangeCode() {
              return { access_token: "token", token_type: "Bearer" };
            },
            async fetchProfile() {
              return { provider: "test", id: "1" };
            },
          },
          redirectUri: "https://app.example.com/cb",
          redirectUriPolicy: {
            allowedRedirectUris: ["https://app.example.com/cb"],
            allowLocalhostHttp: false,
          },
        },
      },
      logger: {
        info: (payload) => {
          loggedPayloads.push(payload);
        },
        warn: (payload) => {
          loggedPayloads.push(payload);
        },
      } as Logger,
    });

    const { state } = await oauth.authorize("test", { state: "test-state-123" });
    await oauth.callback("test", { code: "auth-code-456", state });

    const loggedJson = JSON.stringify(loggedPayloads);
    expect(loggedJson).not.toContain("auth-code-456");
    expect(loggedJson).not.toContain("test-state-123");
  });
});
