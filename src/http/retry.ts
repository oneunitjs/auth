import {
  dispatchHttp,
  type DispatchHttpOptions,
  type DispatchHttpResult,
} from "./transport.js";

export type RetryableStatus = number;

export interface HttpRetryConfig {
  /** Maximum number of retry attempts. Default 3, hard cap 10. */
  maxRetries?: number;
  /** Initial backoff delay in ms. Default 200. */
  initialDelayMs?: number;
  /** Maximum backoff delay in ms. Default 3000. */
  maxDelayMs?: number;
  /** Add randomized jitter to each backoff delay. Default true. */
  jitter?: boolean;
  /** HTTP status codes considered retryable. Default [429, 502, 503, 504]. */
  retryableStatuses?: number[];
  /** Retry non-idempotent methods (POST/PUT/PATCH/DELETE). Default false. */
  allowNonIdempotentRetry?: boolean;
  /** Total deadline for all attempts including backoff, in ms. Default disabled. */
  deadlineMs?: number;
}

export interface ResolvedHttpRetryConfig {
  maxRetries: number;
  initialDelayMs: number;
  maxDelayMs: number;
  jitter: boolean;
  retryableStatuses: Set<number>;
  allowNonIdempotentRetry: boolean;
  deadlineMs?: number;
}

const DEFAULT_MAX_RETRIES = 3;
const DEFAULT_INITIAL_DELAY_MS = 200;
const DEFAULT_MAX_DELAY_MS = 3000;
const DEFAULT_RETRYABLE_STATUSES: number[] = [429, 502, 503, 504];
const HARD_MAX_RETRIES = 10;
const MIN_DELAY_MS = 1;
const MAX_DELAY_MS = 60_000;

const IDEMPOTENT_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

function clamp(value: number, min: number, max: number): number {
  return Math.min(Math.max(value, min), max);
}

function resolveRetryConfig(config?: HttpRetryConfig): ResolvedHttpRetryConfig {
  return {
    maxRetries: clamp(config?.maxRetries ?? DEFAULT_MAX_RETRIES, 0, HARD_MAX_RETRIES),
    initialDelayMs: clamp(config?.initialDelayMs ?? DEFAULT_INITIAL_DELAY_MS, MIN_DELAY_MS, MAX_DELAY_MS),
    maxDelayMs: clamp(config?.maxDelayMs ?? DEFAULT_MAX_DELAY_MS, MIN_DELAY_MS, MAX_DELAY_MS),
    jitter: config?.jitter ?? true,
    retryableStatuses: new Set(config?.retryableStatuses ?? DEFAULT_RETRYABLE_STATUSES),
    allowNonIdempotentRetry: config?.allowNonIdempotentRetry ?? false,
    deadlineMs: config?.deadlineMs,
  };
}

function isRetryableStatus(status: number, config: ResolvedHttpRetryConfig): boolean {
  return config.retryableStatuses.has(status);
}

/**
 * Classify whether an HTTP error or response status warrants a retry.
 *
 * Network failures and timeouts are retryable. Idempotent methods (GET/HEAD/OPTIONS)
 * may be retried on retryable statuses; non-idempotent methods are only retried
 * when `allowNonIdempotentRetry` is set, to avoid repeating unsafe mutations.
 */
function isRetryable(error: unknown, status: number | undefined, method: string | undefined, config: ResolvedHttpRetryConfig): boolean {
  if (error) {
    const name = error instanceof Error ? error.name : "";
    const message = error instanceof Error ? error.message : String(error);
    // Abort/cancellation is never retried.
    if (name === "AbortError" || message === "aborted") {
      return false;
    }
    // Network / DNS / connection failures are retryable.
    if (name === "TypeError" || /ECONNREFUSED|ENOTFOUND|ETIMEDOUT|ECONNRESET/.test(message)) {
      return true;
    }
    return false;
  }
  if (status === undefined) {
    return false;
  }
  if (!isRetryableStatus(status, config)) {
    return false;
  }
  const upper = (method ?? "GET").toUpperCase();
  if (IDEMPOTENT_METHODS.has(upper)) {
    return true;
  }
  return config.allowNonIdempotentRetry;
}

function backoffDelay(attempt: number, config: ResolvedHttpRetryConfig): number {
  // attempt is 0-based for the first retry.
  const exponential = config.initialDelayMs * Math.pow(2, attempt);
  const capped = Math.min(exponential, config.maxDelayMs);
  if (!config.jitter) {
    return capped;
  }
  // Full jitter: random value in [0, capped].
  return Math.floor(Math.random() * (capped + 1));
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export interface DispatchHttpWithRetryOptions extends DispatchHttpOptions {
  retry?: HttpRetryConfig;
}

export interface DispatchHttpRetryStats {
  attempts: number;
  retries: number;
  totalDelayMs: number;
}

/**
 * Execute an HTTP request with exponential backoff and jitter retries.
 *
 * Retries network failures and retryable statuses (429, 502, 503, 504 by
 * default). Non-idempotent methods are not retried unless explicitly allowed.
 * Respects timeout, cancellation (AbortSignal), and response-size bounds.
 * Never retries a cancelled request.
 */
export async function dispatchHttpWithRetry(
  url: string,
  options: DispatchHttpWithRetryOptions = {},
): Promise<{ result: DispatchHttpResult; stats: DispatchHttpRetryStats }> {
  const retryConfig = resolveRetryConfig(options.retry);

  const method = options.method ?? "GET";
  const upperMethod = method.toUpperCase();

  if (!retryConfig.allowNonIdempotentRetry && !IDEMPOTENT_METHODS.has(upperMethod)) {
    // Non-idempotent without explicit opt-in: run a single attempt.
    const result = await dispatchHttp(url, options);
    return { result, stats: { attempts: 1, retries: 0, totalDelayMs: 0 } };
  }

  const deadline = retryConfig.deadlineMs ? Date.now() + retryConfig.deadlineMs : undefined;

  let attempts = 0;
  let retries = 0;
  let totalDelayMs = 0;
  let lastError: unknown;

  while (true) {
    attempts += 1;
    const remaining = deadline ? deadline - Date.now() : undefined;
    if (remaining !== undefined && remaining <= 0) {
      throw lastError ?? new Error("HTTP request deadline exceeded before first attempt");
    }

    const attemptOptions: DispatchHttpOptions = { ...options };
    if (remaining !== undefined) {
      attemptOptions.timeoutMs = Math.min(attemptOptions.timeoutMs ?? retryConfig.maxDelayMs ?? 15_000, remaining);
    }

    let result: DispatchHttpResult;
    try {
      result = await dispatchHttp(url, attemptOptions);
    } catch (error) {
      lastError = error;
      if (attempts > retryConfig.maxRetries || !isRetryable(error, undefined, upperMethod, retryConfig)) {
        throw error;
      }
      retries += 1;
      const delay = backoffDelay(retries - 1, retryConfig);
      totalDelayMs += delay;
      await sleep(delay);
      continue;
    }

    if (result.ok || !isRetryable(undefined, result.status, upperMethod, retryConfig)) {
      return { result, stats: { attempts, retries, totalDelayMs } };
    }

    if (attempts > retryConfig.maxRetries) {
      return { result, stats: { attempts, retries, totalDelayMs } };
    }

    retries += 1;
    const delay = backoffDelay(retries - 1, retryConfig);
    totalDelayMs += delay;
    await sleep(delay);
  }
}

export { resolveRetryConfig };
