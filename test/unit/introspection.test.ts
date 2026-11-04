import { describe, it, expect, afterEach, beforeEach } from "vitest";
import {
  configureHttp,
  resetHttpConfig,
  TokenIntrospector,
  createTokenIntrospector,
  IntrospectionError,
  type IntrospectionConfig,
} from "../../src/index.js";

const SECRET = "client-secret-123";

function transportFactory(captured: { url?: string; init?: RequestInit | undefined }) {
  return async (input: string | URL, init?: RequestInit) => {
    captured.url = String(input);
    captured.init = init;
    return new Response(JSON.stringify({ active: true, scope: "read write", sub: "user-1" }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };
}

describe("TokenIntrospector", () => {
  let captured: { url?: string; init?: RequestInit | undefined };

  beforeEach(() => {
    captured = {};
  });

  afterEach(() => {
    resetHttpConfig();
  });

  it("introspects an active token and returns the parsed result", async () => {
    configureHttp({ transport: transportFactory(captured) });
    const introspector = new TokenIntrospector({
      endpoint: "https://auth.example.com/introspect",
      clientId: "service-a",
      clientSecret: SECRET,
    });
    const result = await introspector.introspect("token-abc");
    expect(result.active).toBe(true);
    expect(result.sub).toBe("user-1");
    expect(result.scope).toBe("read write");
  });

  it("sends RFC 7662 form body with token and optional hint", async () => {
    configureHttp({ transport: transportFactory(captured) });
    const introspector = new TokenIntrospector({
      endpoint: "https://auth.example.com/introspect",
      clientId: "service-a",
      clientSecret: SECRET,
      tokenTypeHint: "access_token",
    });
    await introspector.introspect("token-abc");
    expect(captured.init?.method).toBe("POST");
    const headers = captured.init?.headers as Record<string, string> | undefined;
    expect(headers?.["content-type"]).toBe("application/x-www-form-urlencoded");
    const body = captured.init?.body as string;
    expect(new URLSearchParams(body).get("token")).toBe("token-abc");
    expect(new URLSearchParams(body).get("token_type_hint")).toBe("access_token");
  });

  it("uses HTTP Basic auth when clientSecret is provided", async () => {
    configureHttp({ transport: transportFactory(captured) });
    const introspector = new TokenIntrospector({
      endpoint: "https://auth.example.com/introspect",
      clientId: "service-a",
      clientSecret: SECRET,
    });
    await introspector.introspect("token-abc");
    const expected = "Basic " + Buffer.from("service-a:client-secret-123").toString("base64");
    expect((captured.init?.headers as Record<string, string> | undefined)?.Authorization).toBe(expected);
  });

  it("sends client_id in the body when no clientSecret", async () => {
    configureHttp({ transport: transportFactory(captured) });
    const introspector = new TokenIntrospector({
      endpoint: "https://auth.example.com/introspect",
      clientId: "service-a",
    });
    await introspector.introspect("token-abc");
    const body = captured.init?.body as string;
    expect(new URLSearchParams(body).get("client_id")).toBe("service-a");
    expect((captured.init?.headers as Record<string, string> | undefined)?.Authorization).toBeUndefined();
  });

  it("returns active false for an inactive token", async () => {
    configureHttp({
      transport: async () => new Response(JSON.stringify({ active: false }), { status: 200 }),
    });
    const introspector = new TokenIntrospector({
      endpoint: "https://auth.example.com/introspect",
      clientId: "service-a",
    });
    const result = await introspector.introspect("token-abc");
    expect(result.active).toBe(false);
  });

  it("treats a token whose exp is in the past as inactive", async () => {
    const past = Math.floor(Date.now() / 1000) - 100;
    configureHttp({
      transport: async () =>
        new Response(JSON.stringify({ active: true, exp: past }), { status: 200 }),
    });
    const introspector = new TokenIntrospector({
      endpoint: "https://auth.example.com/introspect",
      clientId: "service-a",
    });
    const result = await introspector.introspect("token-abc");
    expect(result.active).toBe(false);
    expect(result.exp).toBe(past);
  });

  it("throws IntrospectionError on network failure and does not validate the token", async () => {
    configureHttp({
      transport: async () => {
        throw new Error("connection refused");
      },
    });
    const introspector = new TokenIntrospector({
      endpoint: "https://auth.example.com/introspect",
      clientId: "service-a",
    });
    await expect(introspector.introspect("token-abc")).rejects.toBeInstanceOf(IntrospectionError);
  });

  it("throws IntrospectionError on non-ok response", async () => {
    configureHttp({
      transport: async () => new Response("unavailable", { status: 502 }),
    });
    const introspector = new TokenIntrospector({
      endpoint: "https://auth.example.com/introspect",
      clientId: "service-a",
    });
    await expect(introspector.introspect("token-abc")).rejects.toBeInstanceOf(IntrospectionError);
  });

  it("throws IntrospectionError on malformed JSON", async () => {
    configureHttp({
      transport: async () => new Response("not-json", { status: 200 }),
    });
    const introspector = new TokenIntrospector({
      endpoint: "https://auth.example.com/introspect",
      clientId: "service-a",
    });
    await expect(introspector.introspect("token-abc")).rejects.toBeInstanceOf(IntrospectionError);
  });

  it("throws IntrospectionError when active field is missing", async () => {
    configureHttp({
      transport: async () => new Response(JSON.stringify({ scope: "read" }), { status: 200 }),
    });
    const introspector = new TokenIntrospector({
      endpoint: "https://auth.example.com/introspect",
      clientId: "service-a",
    });
    await expect(introspector.introspect("token-abc")).rejects.toBeInstanceOf(IntrospectionError);
  });

  it("caches results and returns the cached copy", async () => {
    let calls = 0;
    configureHttp({
      transport: async () => {
        calls += 1;
        return new Response(JSON.stringify({ active: true, sub: "user-1" }), { status: 200 });
      },
    });
    const introspector = new TokenIntrospector({
      endpoint: "https://auth.example.com/introspect",
      clientId: "service-a",
      maxCacheEntries: 10,
    });
    const first = await introspector.introspect("token-abc");
    const second = await introspector.introspect("token-abc");
    expect(first).toEqual(second);
    expect(calls).toBe(1);
    expect(introspector.cacheSize()).toBe(1);
  });

  it("bounds the cache to maxEntries", async () => {
    configureHttp({
      transport: async () =>
        new Response(JSON.stringify({ active: true }), { status: 200 }),
    });
    const introspector = new TokenIntrospector({
      endpoint: "https://auth.example.com/introspect",
      clientId: "service-a",
      maxCacheEntries: 2,
    });
    await introspector.introspect("token-1");
    await introspector.introspect("token-2");
    await introspector.introspect("token-3");
    expect(introspector.cacheSize()).toBeLessThanOrEqual(2);
  });

  it("rejects empty token", async () => {
    const introspector = new TokenIntrospector({
      endpoint: "https://auth.example.com/introspect",
      clientId: "service-a",
    });
    await expect(introspector.introspect("")).rejects.toBeInstanceOf(IntrospectionError);
  });

  it("rejects missing endpoint config", () => {
    expect(() => new TokenIntrospector({ clientId: "service-a" } as IntrospectionConfig)).toThrow(
      IntrospectionError,
    );
  });

  it("createTokenIntrospector factory works", async () => {
    configureHttp({ transport: transportFactory(captured) });
    const introspector = createTokenIntrospector({
      endpoint: "https://auth.example.com/introspect",
      clientId: "service-a",
      clientSecret: SECRET,
    });
    const result = await introspector.introspect("token-abc");
    expect(result.active).toBe(true);
    expect(introspector).toBeInstanceOf(TokenIntrospector);
  });
});
