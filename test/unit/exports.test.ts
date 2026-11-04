 
import { describe, it, expect } from "vitest";
import * as api from "../../src/index.js";

describe("public api", () => {
  it("exports core constructors and factories", () => {
    expect(typeof api.createAuth).toBe("function");
    expect(typeof api.createMemorySessionStore).toBe("function");
    expect(typeof api.Auth).toBe("function");
    expect(typeof api.createRBAC).toBe("function");
    expect(typeof api.createOAuth).toBe("function");
    expect(typeof api.createProvider).toBe("function");
    expect(typeof api.encode).toBe("function");
    expect(typeof api.decode).toBe("function");
    expect(typeof api.hashPassword).toBe("function");
    expect(typeof api.expressAdapter).toBe("function");
    expect(typeof api.fastifyAdapter).toBe("function");
    expect(typeof api.koaAdapter).toBe("function");
    expect(typeof api.uwsAdapter).toBe("function");
    expect(typeof api.snapshotUwsRequest).toBe("function");
    expect(typeof api.createExternalTokenVerifier).toBe("function");
    expect(typeof api.configureHttp).toBe("function");
    expect(typeof api.dispatchHttp).toBe("function");
    expect(typeof api.setDiagnosticsObserver).toBe("function");
    expect(typeof api.emitDiagnostic).toBe("function");
    expect(typeof api.createPasswordHasher).toBe("function");
    expect(typeof api.Argon2idPasswordHasher).toBe("function");
    expect(api.PLATFORM_COMPATIBILITY.runtime.node).toBe(">=20");
  });

  it("exports social providers", () => {
    const exported = api as Record<string, { id?: string }>;
    for (const name of [
      "google",
      "github",
      "instagram",
      "facebook",
      "twitter",
      "discord",
      "apple",
      "linkedin",
      "microsoft",
    ]) {
      expect(exported[name].id === name || exported[name].id === "twitter").toBe(true);
    }
  });

  it("exports error classes", () => {
    const exported = api as Record<string, unknown>;
    for (const name of [
      "AuthError",
      "InvalidTokenError",
      "TokenExpiredError",
      "UnauthorizedError",
      "ForbiddenError",
      "ConfigurationError",
      "OAuthError",
      "ProviderError",
      "ValidationError",
    ]) {
      expect(typeof exported[name]).toBe("function");
    }
  });
});
