import type {
  AuthDiagnosticEvent,
  DiagnosticsErrorCallback,
  DiagnosticsObserver,
  DiagnosticsOverflowPolicy,
  DiagnosticsStats,
} from "./types.js";
import { attachAuthContext } from "./tracing.js";
import { ValidationError } from "../errors/index.js";

const MAX_STRING = 128;
const MAX_QUEUE = 32;

let observer: DiagnosticsObserver | undefined;
let pending = 0;

let overflowPolicy: DiagnosticsOverflowPolicy = "drop";
let errorCallback: DiagnosticsErrorCallback | undefined;

let emitted = 0;
let dropped = 0;
let failed = 0;

function boundString(value: string | undefined): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }
  return value.length > MAX_STRING ? value.slice(0, MAX_STRING) : value;
}

function sanitize(event: AuthDiagnosticEvent): AuthDiagnosticEvent {
  const next = { ...event, timestamp: event.timestamp || Date.now() };
  if ("operationId" in next) {
    next.operationId = boundString(next.operationId);
  }
  if ("providerId" in next) {
    next.providerId = boundString(next.providerId);
  }
  if ("algorithm" in next) {
    next.algorithm = boundString(next.algorithm) ?? "unknown";
  }
  return next;
}

function recordDropped(event: AuthDiagnosticEvent): void {
  dropped += 1;
  if (overflowPolicy === "report" && errorCallback) {
    try {
      errorCallback(event, "overflow");
    } catch {
      // Diagnostics error callback must never affect authentication.
    }
  }
}

function recordFailed(event: AuthDiagnosticEvent, error?: unknown): void {
  failed += 1;
  if (overflowPolicy === "report" && errorCallback) {
    try {
      errorCallback(event, "observer-failure", error);
    } catch {
      // Diagnostics error callback must never affect authentication.
    }
  }
}

export function setDiagnosticsObserver(next?: DiagnosticsObserver): void {
  observer = next;
}

export function getDiagnosticsObserver(): DiagnosticsObserver | undefined {
  return observer;
}

export function setDiagnosticsOverflowPolicy(policy: DiagnosticsOverflowPolicy): void {
  if (policy !== "drop" && policy !== "report") {
    throw new ValidationError(
      `Invalid diagnostics overflow policy: ${String(policy)}`,
    );
  }
  overflowPolicy = policy;
}

export function getDiagnosticsOverflowPolicy(): DiagnosticsOverflowPolicy {
  return overflowPolicy;
}

export function setDiagnosticsErrorCallback(
  next?: DiagnosticsErrorCallback,
): void {
  errorCallback = next;
}

export function getDiagnosticsStats(): DiagnosticsStats {
  return {
    emitted,
    dropped,
    failed,
    size: pending,
    maxSize: MAX_QUEUE,
    overflowPolicy,
  };
}

export function resetDiagnostics(): void {
  observer = undefined;
  pending = 0;
  overflowPolicy = "drop";
  errorCallback = undefined;
  emitted = 0;
  dropped = 0;
  failed = 0;
}

export function emitDiagnostic(event: AuthDiagnosticEvent): void {
  if (!observer) {
    return;
  }
  const safe = attachAuthContext(sanitize(event));
  emitted += 1;

  if (pending >= MAX_QUEUE) {
    recordDropped(safe);
    return;
  }

  pending += 1;
  try {
    const result = observer(safe);
    if (result && typeof (result as Promise<void>).then === "function") {
      Promise.resolve(result)
        .catch((error) => {
          recordFailed(safe, error);
        })
        .finally(() => {
          pending -= 1;
        });
      return;
    }
  } catch (error) {
    recordFailed(safe, error);
    pending -= 1;
    return;
  }
  pending -= 1;
}
