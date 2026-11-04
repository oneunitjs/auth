import { describe, it, expect, afterEach, beforeEach, vi } from "vitest";
import {
  configureHttp,
  resetHttpConfig,
  dispatchHttpWithRetry,
  type DispatchHttpWithRetryOptions,
} from "../../src/index.js";

function transportFactory(scenario: {
  statuses: number[];
  failCount: number;
  captured: { urls: string[]; attempts: number };
}) {
  return async (_url: string | URL, _init?: RequestInit) => {
    scenario.captured.urls.push(_url.toString());
    scenario.captured.attempts += 1;
    const status = scenario.statuses.shift() ?? 200;
    if (scenario.failCount > 0) {
      scenario.failCount -= 1;
      throw new Error("ECONNREFUSED connection refused");
    }
    return new Response(JSON.stringify({ ok: true }), { status });
  };
}

function mockImmediateSetTimeout(capturedDelays: number[]) {
  const orig = globalThis.setTimeout;
  const spy = vi
    .spyOn(globalThis, "setTimeout")
    .mockImplementation((handler: any, ms?: number) => {
      if (typeof ms === "number" && ms > 0 && ms <= 4000) {
        capturedDelays.push(ms);
        // Fire the callback immediately so awaiting sleep() resolves.
        if (typeof handler === "function") {
          handler();
        }
      }
      return orig.call(globalThis, handler, ms) as any;
    });
  return spy;
}

describe("http retry", () => {
  let captured: { urls: string[]; attempts: number };

  beforeEach(() => {
    captured = { urls: [], attempts: 0 };
  });

  afterEach(() => {
    resetHttpConfig();
    vi.restoreAllMocks();
  });

  it("succeeds on first attempt without retrying", async () => {
    configureHttp({
      transport: transportFactory({ statuses: [200], failCount: 0, captured }),
    });
    const { result, stats } = await dispatchHttpWithRetry("https://example.test/token");
    expect(result.ok).toBe(true);
    expect(stats.attempts).toBe(1);
    expect(stats.retries).toBe(0);
    expect(stats.totalDelayMs).toBe(0);
  });

  it("recovers from a transient network failure", async () => {
    configureHttp({
      transport: transportFactory({ statuses: [200], failCount: 1, captured }),
    });
    const { result, stats } = await dispatchHttpWithRetry("https://example.test/token");
    expect(result.ok).toBe(true);
    expect(stats.attempts).toBe(2);
    expect(stats.retries).toBe(1);
    expect(stats.totalDelayMs).toBeGreaterThanOrEqual(0);
  });

  it("retries on retryable statuses 502/503/504 then recovers", async () => {
    configureHttp({
      transport: transportFactory({
        statuses: [502, 503, 504, 200],
        failCount: 0,
        captured,
      }),
    });
    const { result, stats } = await dispatchHttpWithRetry("https://example.test/token");
    expect(result.ok).toBe(true);
    expect(stats.attempts).toBe(4);
    expect(stats.retries).toBe(3);
  });

  it("does not retry non-retryable 4xx statuses", async () => {
    configureHttp({
      transport: transportFactory({ statuses: [400, 200], failCount: 0, captured }),
    });
    const { result, stats } = await dispatchHttpWithRetry("https://example.test/token");
    expect(result.ok).toBe(false);
    expect(result.status).toBe(400);
    expect(stats.attempts).toBe(1);
    expect(stats.retries).toBe(0);
  });

  it("retries 429 (rate limited)", async () => {
    configureHttp({
      transport: transportFactory({ statuses: [429, 200], failCount: 0, captured }),
    });
    const { result, stats } = await dispatchHttpWithRetry("https://example.test/token");
    expect(result.ok).toBe(true);
    expect(stats.attempts).toBe(2);
  });

  it("does not retry non-idempotent POST by default", async () => {
    configureHttp({
      transport: transportFactory({ statuses: [502, 200], failCount: 0, captured }),
    });
    const { result, stats } = await dispatchHttpWithRetry("https://example.test/token", {
      method: "POST",
    });
    expect(result.ok).toBe(false);
    expect(result.status).toBe(502);
    expect(stats.attempts).toBe(1);
  });

  it("retries non-idempotent POST when allowNonIdempotentRetry is set", async () => {
    configureHttp({
      transport: transportFactory({ statuses: [502, 200], failCount: 0, captured }),
    });
    const { result, stats } = await dispatchHttpWithRetry("https://example.test/token", {
      method: "POST",
      retry: { allowNonIdempotentRetry: true },
    });
    expect(result.ok).toBe(true);
    expect(stats.attempts).toBe(2);
  });

  it("applies exponential backoff with jitter", async () => {
    const delays: number[] = [];
    mockImmediateSetTimeout(delays);
    configureHttp({
      transport: transportFactory({ statuses: [502, 502, 200], failCount: 0, captured }),
    });
    await dispatchHttpWithRetry("https://example.test/token");
    expect(delays.length).toBe(2);
    // First retry ~200ms, second ~400ms (capped at maxDelay 3000).
    expect(delays[0]).toBeGreaterThanOrEqual(0);
    expect(delays[0]).toBeLessThanOrEqual(200);
    expect(delays[1]).toBeGreaterThanOrEqual(0);
    expect(delays[1]).toBeLessThanOrEqual(400);
  });

  it("exhausts max retries and returns last result", async () => {
    configureHttp({
      transport: transportFactory({ statuses: [502, 502, 502], failCount: 0, captured }),
    });
    const { result, stats } = await dispatchHttpWithRetry("https://example.test/token", {
      retry: { maxRetries: 2 },
    });
    expect(result.ok).toBe(false);
    expect(result.status).toBe(502);
    expect(stats.attempts).toBe(3);
    expect(stats.retries).toBe(2);
  });

  it("throws on persistent network failure after max retries", async () => {
    configureHttp({
      transport: transportFactory({ statuses: [], failCount: 3, captured }),
    });
    await expect(
      dispatchHttpWithRetry("https://example.test/token", { retry: { maxRetries: 2 } }),
    ).rejects.toThrow();
  });

  it("honors a custom maxRetries of 0 (single attempt)", async () => {
    configureHttp({
      transport: transportFactory({ statuses: [502], failCount: 0, captured }),
    });
    const { result, stats } = await dispatchHttpWithRetry("https://example.test/token", {
      retry: { maxRetries: 0 },
    });
    expect(result.ok).toBe(false);
    expect(stats.attempts).toBe(1);
    expect(stats.retries).toBe(0);
  });

  it("uses per-call retry config over global", async () => {
    configureHttp({ transport: transportFactory({ statuses: [502, 200], failCount: 0, captured }) });
    const { stats } = await dispatchHttpWithRetry("https://example.test/token", {
      retry: { maxRetries: 5, initialDelayMs: 50, maxDelayMs: 100 },
    });
    expect(stats.attempts).toBe(2);
  });

  it("DispatchHttpWithRetryOptions accepts retry config", () => {
    const opts: DispatchHttpWithRetryOptions = {
      method: "GET",
      retry: { maxRetries: 3, jitter: false },
    };
    expect(opts.retry?.maxRetries).toBe(3);
    expect(opts.retry?.jitter).toBe(false);
  });
});
