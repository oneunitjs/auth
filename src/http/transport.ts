import { ValidationError } from "../errors/index.js";

export type HttpTransport = (
  input: string | URL,
  init?: RequestInit,
) => Promise<Response>;

export type HttpRedirect = "error" | "follow" | "manual";

export interface HttpClientConfig {
  transport?: HttpTransport;
  timeoutMs?: number;
  maxResponseBytes?: number;
  redirect?: HttpRedirect;
  baseUrl?: string;
  headers?: Record<string, string>;
}

export interface DispatchHttpOptions extends RequestInit {
  transport?: HttpTransport;
  timeoutMs?: number;
  maxResponseBytes?: number;
  baseUrl?: string;
}

export interface DispatchHttpResult {
  ok: boolean;
  status: number;
  headers: Headers;
  text: string;
}

export interface ResolvedHttpConfig {
  transport: HttpTransport;
  timeoutMs: number;
  maxResponseBytes: number;
  redirect: HttpRedirect;
  baseUrl: string;
  headers: Record<string, string>;
}

const DEFAULT_TIMEOUT_MS = 15_000;
const DEFAULT_MAX_RESPONSE_BYTES = 1_048_576;
const MIN_TIMEOUT_MS = 1;
const MAX_TIMEOUT_MS = 120_000;
const MIN_RESPONSE_BYTES = 1_024;
const MAX_RESPONSE_BYTES = 5 * 1_048_576;

function defaultFetch(input: string | URL, init?: RequestInit): Promise<Response> {
  return globalThis.fetch(input, init);
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(Math.max(value, min), max);
}

function resolveConfig(config: HttpClientConfig, fallback: ResolvedHttpConfig): ResolvedHttpConfig {
  return {
    transport: config.transport ?? fallback.transport,
    timeoutMs: clamp(config.timeoutMs ?? fallback.timeoutMs, MIN_TIMEOUT_MS, MAX_TIMEOUT_MS),
    maxResponseBytes: clamp(
      config.maxResponseBytes ?? fallback.maxResponseBytes,
      MIN_RESPONSE_BYTES,
      MAX_RESPONSE_BYTES,
    ),
    redirect: config.redirect ?? fallback.redirect,
    baseUrl: config.baseUrl ?? fallback.baseUrl,
    headers: { ...fallback.headers, ...(config.headers ?? {}) },
  };
}

function cloneConfig(config: ResolvedHttpConfig): ResolvedHttpConfig {
  return {
    transport: config.transport,
    timeoutMs: config.timeoutMs,
    maxResponseBytes: config.maxResponseBytes,
    redirect: config.redirect,
    baseUrl: config.baseUrl,
    headers: { ...config.headers },
  };
}

/**
 * An HTTP client with its own isolated configuration. Multiple clients in the
 * same process do not share mutable state, so reconfiguring one client never
 * affects another.
 */
class HttpClient {
  private config: ResolvedHttpConfig;

  constructor(config: HttpClientConfig = {}) {
    this.config = resolveConfig(config, {
      transport: defaultFetch,
      timeoutMs: DEFAULT_TIMEOUT_MS,
      maxResponseBytes: DEFAULT_MAX_RESPONSE_BYTES,
      redirect: "error",
      baseUrl: "",
      headers: {},
    });
  }

  configure(config: HttpClientConfig = {}): ResolvedHttpConfig {
    this.config = resolveConfig(config, this.config);
    return cloneConfig(this.config);
  }

  getConfig(): ResolvedHttpConfig {
    return cloneConfig(this.config);
  }

  reset(): void {
    this.config = {
      transport: defaultFetch,
      timeoutMs: DEFAULT_TIMEOUT_MS,
      maxResponseBytes: DEFAULT_MAX_RESPONSE_BYTES,
      redirect: "error",
      baseUrl: "",
      headers: {},
    };
  }

  async dispatch(url: string, options: DispatchHttpOptions = {}): Promise<DispatchHttpResult> {
    const current = this.getConfig();
    const timeoutMs = clamp(options.timeoutMs ?? current.timeoutMs, MIN_TIMEOUT_MS, MAX_TIMEOUT_MS);
    const maxResponseBytes = clamp(
      options.maxResponseBytes ?? current.maxResponseBytes,
      MIN_RESPONSE_BYTES,
      MAX_RESPONSE_BYTES,
    );
    const transport = options.transport ?? current.transport;
    const redirect = options.redirect ?? current.redirect;

    const resolvedUrl = options.baseUrl ?? current.baseUrl
      ? new URL(url, options.baseUrl ?? current.baseUrl).toString()
      : url;

    const mergedHeaders: Record<string, string> = { ...current.headers };
    if (options.headers) {
      if (options.headers instanceof Headers) {
        for (const [key, value] of options.headers.entries()) {
          mergedHeaders[key] = value;
        }
      } else if (Array.isArray(options.headers)) {
        for (const [key, value] of options.headers) {
          mergedHeaders[key] = value;
        }
      } else {
        Object.assign(mergedHeaders, options.headers);
      }
    }

    const timeoutController = new AbortController();
    const timer = setTimeout(() => timeoutController.abort(), timeoutMs);
    const signal = combineSignals([options.signal ?? undefined, timeoutController.signal]);

    try {
      const response = await transport(resolvedUrl, {
        ...options,
        headers: mergedHeaders,
        redirect,
        signal,
      });
      const text = await readBoundedBody(response, maxResponseBytes);
      return {
        ok: response.ok,
        status: response.status,
        headers: response.headers,
        text,
      };
    } finally {
      clearTimeout(timer);
    }
  }
}

function combineSignals(signals: Array<AbortSignal | undefined>): AbortSignal | undefined {
  const active = signals.filter((signal): signal is AbortSignal => Boolean(signal));
  if (active.length === 0) {
    return undefined;
  }
  if (active.length === 1) {
    return active[0];
  }
  const anyFn = (AbortSignal as unknown as { any?: (input: AbortSignal[]) => AbortSignal }).any;
  if (typeof anyFn === "function") {
    return anyFn(active);
  }
  const controller = new AbortController();
  const onAbort = (): void => {
    controller.abort();
  };
  for (const signal of active) {
    if (signal.aborted) {
      controller.abort();
      return controller.signal;
    }
    signal.addEventListener("abort", onAbort, { once: true });
  }
  return controller.signal;
}

async function readBoundedBody(response: Response, maxBytes: number): Promise<string> {
  const declared = response.headers.get("content-length");
  if (declared !== null) {
    const size = Number(declared);
    if (!Number.isNaN(size) && size > maxBytes) {
      throw new ValidationError(`HTTP response exceeded maximum size of ${maxBytes} bytes`);
    }
  }

  if (response.body && typeof response.body.getReader === "function") {
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) {
          break;
        }
        if (value) {
          total += value.byteLength;
          if (total > maxBytes) {
            try {
              await reader.cancel();
            } catch {
              // ignore cancel failures
            }
            throw new ValidationError(`HTTP response exceeded maximum size of ${maxBytes} bytes`);
          }
          chunks.push(value);
        }
      }
    } finally {
      reader.releaseLock();
    }
    return Buffer.concat(chunks.map((chunk) => Buffer.from(chunk))).toString("utf8");
  }

  const buffer = Buffer.from(await response.arrayBuffer());
  if (buffer.length > maxBytes) {
    throw new ValidationError(`HTTP response exceeded maximum size of ${maxBytes} bytes`);
  }
  return buffer.toString("utf8");
}

/* ------------------------------------------------------------------ */
/* Backward-compatible module-level API backed by a default client.   */
/* ------------------------------------------------------------------ */

const defaultClient = new HttpClient();

export function configureHttp(config: HttpClientConfig = {}): ResolvedHttpConfig {
  return defaultClient.configure(config);
}

export function getHttpConfig(): ResolvedHttpConfig {
  return defaultClient.getConfig();
}

export function resetHttpConfig(): void {
  defaultClient.reset();
}

export async function dispatchHttp(url: string, options: DispatchHttpOptions = {}): Promise<DispatchHttpResult> {
  return defaultClient.dispatch(url, options);
}

export { HttpClient };
