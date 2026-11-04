import type { AuthDiagnosticEvent } from "./types.js";
import { getCurrentAuthContext } from "../core/context.js";

/**
 * Merge the active auth context (request/trace/tenant IDs) into a diagnostic
 * event so every event emitted during a request carries the same correlation
 * IDs. Only non-sensitive identifiers are attached; credentials, tokens, and
 * PII are never included.
 */
export function attachAuthContext(event: AuthDiagnosticEvent): AuthDiagnosticEvent {
  const context = getCurrentAuthContext();
  if (!context) {
    return event;
  }
  const next: AuthDiagnosticEvent = { ...event };
  if (!next.operationId) {
    next.operationId = context.operationId;
  }
  if (
    "requestId" in next &&
    (next as Record<string, unknown>).requestId === undefined
  ) {
    (next as Record<string, unknown>).requestId = context.requestId;
  }
  if (
    "traceId" in next &&
    (next as Record<string, unknown>).traceId === undefined
  ) {
    (next as Record<string, unknown>).traceId = context.traceId;
  }
  if (
    "tenantId" in next &&
    (next as Record<string, unknown>).tenantId === undefined &&
    context.tenantId !== undefined
  ) {
    (next as Record<string, unknown>).tenantId = context.tenantId;
  }
  return next;
}

/**
 * Optional OpenTelemetry integration.
 *
 * Returns a tracer when the `opentelemetry` package is installed, otherwise a
 * no-op tracer so the rest of the library never depends on it. Only
 * non-sensitive attributes (requestId, traceId, tenantId) are ever recorded.
 */
let otelTracerPromise:
  | Promise<{
      startSpan: (
        name: string,
        attrs?: Record<string, unknown>,
      ) => { end: () => void };
    }>
  | undefined;

export async function getOtelTracer() {
  if (otelTracerPromise) {
    return otelTracerPromise;
  }
  const promise = (async () => {
    let traceModule: unknown;
    try {
      traceModule = await import("opentelemetry");
    } catch {
      traceModule = undefined;
    }
    const tracer =
      traceModule &&
      typeof traceModule === "object" &&
      "trace" in traceModule &&
      typeof (traceModule as { trace?: unknown }).trace === "object" &&
      (traceModule as { trace: { getTracer?: unknown } }).trace?.getTracer
        ? (traceModule as { trace: { getTracer: (name: string) => unknown } }).trace.getTracer(
            "@oneunit/auth",
          )
        : { startSpan: () => ({ end: () => undefined }) };
    return tracer as {
      startSpan: (
        name: string,
        attrs?: Record<string, unknown>,
      ) => { end: () => void };
    };
  })();
  otelTracerPromise = promise;
  return promise;
}

/**
 * Run `fn` inside an OpenTelemetry span named after the operation, annotated
 * with the current auth context IDs. Degrades to a no-op when OpenTelemetry is
 * not installed or the active context is unavailable.
 */
export async function withAuthContextSpan<T>(
  name: string,
  fn: () => T | Promise<T>,
): Promise<T> {
  const context = getCurrentAuthContext();
  const tracer = await getOtelTracer();
  const span = tracer.startSpan(name, {
    "auth.requestId": context?.requestId,
    "auth.traceId": context?.traceId,
    ...(context?.tenantId ? { "auth.tenantId": context.tenantId } : {}),
  });
  try {
    const result = await fn();
    span.end();
    return result;
  } catch (error) {
    span.end();
    throw error;
  }
}
