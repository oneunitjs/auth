import { AsyncLocalStorage } from "node:async_hooks";
import { randomToken } from "../utils.js";

export interface AuthContext {
  /** Correlates every diagnostic and log event for a single incoming request. */
  readonly requestId: string;
  /** Distributed-trace identifier propagated across service boundaries. */
  readonly traceId: string;
  /** Optional tenant identifier for multi-tenant isolation in traces. */
  readonly tenantId?: string;
  /** Stable operation identifier derived from the request when not supplied. */
  readonly operationId: string;
  /** Additional custom properties carried on the context. */
  readonly [key: string]: unknown;
}

function createContext(init?: Partial<AuthContext>): AuthContext {
  const requestId = init?.requestId ?? randomToken(16);
  const traceId = init?.traceId ?? randomToken(16);
  const { requestId: _, traceId: __, tenantId, operationId, ...extra } = init ?? {};
  return {
    requestId,
    traceId,
    tenantId,
    operationId: operationId ?? requestId,
    ...extra,
  };
}

/**
 * AsyncLocalStorage that carries the active auth context across asynchronous
 * operations within a single request. All auth operations (login, verify,
 * diagnostics) read the store so events can be correlated without the caller
 * threading a context through every argument.
 */
const storage = new AsyncLocalStorage<AuthContext>();

/**
 * Run `fn` within `context`. The context (and therefore the request/trace IDs)
 * is available to any auth operation that runs synchronously or asynchronously
 * inside `fn`, including after `await` boundaries.
 */
export function runWithAuthContext<T>(context: AuthContext, fn: () => T): T {
  return storage.run(context, fn);
}

/**
 * Returns the context active on the current async chain, or `undefined` when
 * no request context has been established.
 */
export function getCurrentAuthContext(): AuthContext | undefined {
  return storage.getStore();
}

/**
 * Create a fresh auth context. Use this at the edge of an application (e.g. in
 * an HTTP adapter middleware) to assign a request/trace ID to every auth
 * operation downstream of the request.
 */
export function createAuthContext(init?: Partial<AuthContext>): AuthContext {
  return createContext(init);
}
