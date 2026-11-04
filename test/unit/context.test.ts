import { describe, it, expect, afterEach } from "vitest";
import {
  createAuthContext,
  getCurrentAuthContext,
  runWithAuthContext,
  emitDiagnostic,
  resetDiagnostics,
  setDiagnosticsObserver,
  getDiagnosticsStats,
  type AuthContext,
} from "../../src/index.js";

describe("auth context", () => {
  afterEach(() => {
    resetDiagnostics();
  });

  it("generates a context with requestId, traceId and operationId", () => {
    const ctx = createAuthContext();
    expect(typeof ctx.requestId).toBe("string");
    expect(ctx.requestId.length).toBeGreaterThan(0);
    expect(typeof ctx.traceId).toBe("string");
    expect(ctx.traceId.length).toBeGreaterThan(0);
    expect(ctx.operationId).toBe(ctx.requestId);
    expect(ctx.tenantId).toBeUndefined();
  });

  it("honours supplied context fields", () => {
    const ctx = createAuthContext({
      requestId: "req-1",
      traceId: "trace-1",
      tenantId: "tenant-1",
      operationId: "op-1",
    });
    expect(ctx.requestId).toBe("req-1");
    expect(ctx.traceId).toBe("trace-1");
    expect(ctx.tenantId).toBe("tenant-1");
    expect(ctx.operationId).toBe("op-1");
  });

  it("is undefined outside of a runWithAuthContext block", () => {
    expect(getCurrentAuthContext()).toBeUndefined();
  });

  it("survives async boundaries within runWithAuthContext", async () => {
    let captured: AuthContext | undefined;
    await runWithAuthContext(createAuthContext({ requestId: "req-async" }), async () => {
      expect(getCurrentAuthContext()?.requestId).toBe("req-async");
      await new Promise((resolve) => setTimeout(resolve, 5));
      captured = getCurrentAuthContext();
    });
    expect(captured?.requestId).toBe("req-async");
    expect(getCurrentAuthContext()).toBeUndefined();
  });

  it("returns its own result through runWithAuthContext", async () => {
    const result = await runWithAuthContext(createAuthContext(), () => 42);
    expect(result).toBe(42);
  });

  it("attaches context operationId to diagnostic events", () => {
    const events: Array<{ type: string; operationId?: string }> = [];
    setDiagnosticsObserver((event) => {
      events.push(event as { type: string; operationId?: string });
    });
    runWithAuthContext(createAuthContext({ requestId: "req-diag" }), () => {
      emitDiagnostic({ type: "auth.login.succeeded", timestamp: 1 });
    });
    expect(events[0].operationId).toBe("req-diag");
  });

  it("does not override an explicitly set operationId", () => {
    const events: Array<{ type: string; operationId?: string }> = [];
    setDiagnosticsObserver((event) => {
      events.push(event as { type: string; operationId?: string });
    });
    runWithAuthContext(createAuthContext({ requestId: "req-diag" }), () => {
      emitDiagnostic({
        type: "auth.login.succeeded",
        timestamp: 1,
        operationId: "explicit-op",
      });
    });
    expect(events[0].operationId).toBe("explicit-op");
  });

  it("prefers explicit context over ambient context", async () => {
    const events: Array<{ operationId?: string }> = [];
    setDiagnosticsObserver((event) => {
      events.push(event as { operationId?: string });
    });
    // Ambient context with a different id.
    await runWithAuthContext(createAuthContext({ requestId: "ambient" }), async () => {
      const explicit = createAuthContext({ requestId: "explicit" });
      await runWithAuthContext(explicit, () => {
        emitDiagnostic({ type: "auth.login.succeeded", timestamp: 1 });
      });
    });
    expect(events[0].operationId).toBe("explicit");
  });

  it("getDiagnosticsStats shape is stable", () => {
    const stats = getDiagnosticsStats();
    expect(typeof stats.emitted).toBe("number");
    expect(typeof stats.dropped).toBe("number");
    expect(typeof stats.failed).toBe("number");
    expect(typeof stats.size).toBe("number");
    expect(stats.maxSize).toBe(32);
    expect(["drop", "report"].includes(stats.overflowPolicy)).toBe(true);
  });
});
