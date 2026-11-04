 
import { describe, it, expect, afterEach } from "vitest";
import { configureHttp, resetHttpConfig, dispatchHttp, getHttpConfig, HttpClient } from "../../src/index.js";
import { requestJson } from "../../src/utils.js";

describe("http transport", () => {
  afterEach(() => {
    resetHttpConfig();
  });

  it("uses an injected transport instead of global fetch", async () => {
    const transport = async () => new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
    configureHttp({ transport });
    const result = await requestJson("https://example.test/token");
    expect(result.ok).toBe(true);
    expect(result.body).toEqual({ ok: true });
  });

  it("rejects oversized responses from the body stream", async () => {
    const transport = async () => new Response("x".repeat(2048), { status: 200 });
    await expect(dispatchHttp("https://example.test/jwks", {
      transport,
      maxResponseBytes: 1024,
    })).rejects.toThrow(/maximum size/);
  });

  it("rejects oversized responses from content-length before reading", async () => {
    const transport = async () => new Response("ok", {
      status: 200,
      headers: { "content-length": "99999" },
    });
    await expect(dispatchHttp("https://example.test/jwks", {
      transport,
      maxResponseBytes: 1024,
    })).rejects.toThrow(/maximum size/);
  });

  it("does not fall back to global fetch when the injected transport fails", async () => {
    const transport = async () => {
      throw new Error("injected transport failed");
    };
    configureHttp({ transport });
    await expect(requestJson("https://example.test/token")).rejects.toThrow("injected transport failed");
  });

  it("passes redirect error by default and honors per-call transport", async () => {
    let seen: RequestInit | undefined;
    const configured = async () => {
      throw new Error("configured transport should not run");
    };
    configureHttp({ transport: configured, redirect: "error" });
    const transport = async (_input: string | URL, init?: RequestInit) => {
      seen = init;
      return new Response("{}", { status: 200 });
    };
    const result = await dispatchHttp("https://example.test/token", { transport });
    expect(result.ok).toBe(true);
    expect(seen?.redirect).toBe("error");
  });

  it("aborts when the transport honors the timeout signal", async () => {
    const transport = (_input: string | URL, init?: RequestInit) => new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener("abort", () => {
        const error = new Error("aborted");
        error.name = "AbortError";
        reject(error);
      });
    });
    await expect(dispatchHttp("https://example.test/slow", {
      transport,
      timeoutMs: 1,
    })).rejects.toThrow(/aborted/);
  });

  it("clamps timeout and response size to documented bounds", () => {
    const low = configureHttp({ timeoutMs: 0, maxResponseBytes: 1 });
    expect(low.timeoutMs).toBe(1);
    expect(low.maxResponseBytes).toBe(1024);
    const high = configureHttp({ timeoutMs: 999_999, maxResponseBytes: 50 * 1_048_576 });
    expect(high.timeoutMs).toBe(120_000);
    expect(high.maxResponseBytes).toBe(5 * 1_048_576);
  });

  it("returns a copy of config so callers cannot mutate internals", () => {
    configureHttp({ timeoutMs: 5_000 });
    const copy = getHttpConfig();
    copy.timeoutMs = 1;
    expect(getHttpConfig().timeoutMs).toBe(5_000);
  });

  it("returns non-JSON bodies as text and preserves error status", async () => {
    const transport = async () => new Response("not-json", { status: 502 });
    const result = await requestJson("https://example.test/token", { transport });
    expect(result.ok).toBe(false);
    expect(result.status).toBe(502);
    expect(result.body).toBe("not-json");
  });

  it("returns a null body for empty responses", async () => {
    const transport = async () => new Response(null, { status: 200 });
    const result = await requestJson("https://example.test/token", { transport });
    expect(result.status).toBe(200);
    expect(result.body).toBeNull();
  });

  it("restores fetch defaults on reset", () => {
    configureHttp({ timeoutMs: 2_000, maxResponseBytes: 2048, redirect: "manual" });
    resetHttpConfig();
    const config = getHttpConfig();
    expect(config.timeoutMs).toBe(15_000);
    expect(config.maxResponseBytes).toBe(1_048_576);
    expect(config.redirect).toBe("error");
  });
});

describe("http client isolation", () => {
  it("two clients with different base URLs use their own URLs", async () => {
    const seen: string[] = [];
    const a = new HttpClient({ baseUrl: "https://a.test", transport: async (url) => { seen.push(String(url)); return new Response("{}", { status: 200 }); } });
    const b = new HttpClient({ baseUrl: "https://b.test", transport: async (url) => { seen.push(String(url)); return new Response("{}", { status: 200 }); } });

    await a.dispatch("/token");
    await b.dispatch("/token");
    expect(seen).toContain("https://a.test/token");
    expect(seen).toContain("https://b.test/token");
  });

  it("two clients with different headers do not see each other's headers", async () => {
    const capturedA: Record<string, string>[] = [];
    const capturedB: Record<string, string>[] = [];
    const a = new HttpClient({ headers: { "x-client": "a" }, transport: async (_url, init) => { capturedA.push(init?.headers as unknown as Record<string, string>); return new Response("{}", { status: 200 }); } });
    const b = new HttpClient({ headers: { "x-client": "b" }, transport: async (_url, init) => { capturedB.push(init?.headers as unknown as Record<string, string>); return new Response("{}", { status: 200 }); } });

    await a.dispatch("https://example.test/");
    await b.dispatch("https://example.test/");
    expect(capturedA[0]?.["x-client"]).toBe("a");
    expect(capturedB[0]?.["x-client"]).toBe("b");
    expect(capturedA[0]?.["x-client"]).not.toBe("b");
    expect(capturedB[0]?.["x-client"]).not.toBe("a");
  });

  it("different timeout and response-size policies remain isolated", () => {
    const a = new HttpClient({ timeoutMs: 1_000, maxResponseBytes: 1_024 });
    const b = new HttpClient({ timeoutMs: 60_000, maxResponseBytes: 5 * 1_048_576 });
    expect(a.getConfig().timeoutMs).toBe(1_000);
    expect(a.getConfig().maxResponseBytes).toBe(1_024);
    expect(b.getConfig().timeoutMs).toBe(60_000);
    expect(b.getConfig().maxResponseBytes).toBe(5 * 1_048_576);
  });

  it("parallel clients with different transport stubs are deterministic", async () => {
    const results: string[] = [];
    const a = new HttpClient({ transport: async () => { results.push("a"); return new Response("A", { status: 200 }); } });
    const b = new HttpClient({ transport: async () => { results.push("b"); return new Response("B", { status: 200 }); } });

    const [ra, rb] = await Promise.all([a.dispatch("https://x.test/"), b.dispatch("https://x.test/")]);
    expect(ra.text).toBe("A");
    expect(rb.text).toBe("B");
  });

  it("reconfiguring one instance does not alter another instance", () => {
    const a = new HttpClient({ timeoutMs: 1_000 });
    const b = new HttpClient({ timeoutMs: 60_000 });
    a.configure({ timeoutMs: 2_000 });
    expect(a.getConfig().timeoutMs).toBe(2_000);
    expect(b.getConfig().timeoutMs).toBe(60_000);
  });

  it("module-level configureHttp does not leak into an independent client", () => {
    const client = new HttpClient({ timeoutMs: 5_000 });
    configureHttp({ timeoutMs: 999_999 });
    expect(client.getConfig().timeoutMs).toBe(5_000);
    resetHttpConfig();
  });
});
