import { InvalidRedirectUriError } from "../errors/index.js";

export interface RedirectUriPolicy {
  allowedRedirectUris: string[];
  allowLocalhostHttp?: boolean;
}

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "::1"]);

function isLoopbackHost(host: string): boolean {
  // Strip IPv6 brackets before comparison: URL.hostname returns "[::1]" for ::1.
  const normalized = host.replace(/^\[(.*)\]$/, "$1");
  return LOOPBACK_HOSTS.has(normalized.toLowerCase());
}

function parseUri(candidate: string): URL {
  try {
    return new URL(candidate);
  } catch {
    throw new InvalidRedirectUriError(
      `Malformed redirect URI: ${candidate}`,
      { code: "MALFORMED_REDIRECT_URI" },
    );
  }
}

/**
 * Validate a redirect URI against a trusted local policy.
 *
 * Comparison is exact string equality after validation: no prefix, suffix,
 * substring, wildcard-host, or implicit subdomain matching. Hostnames,
 * ports, paths, query strings, fragments, percent-encoding, and trailing
 * slashes are not normalized before comparison.
 *
 * Throws `InvalidRedirectUriError` for any disallowed URI. Fail closed:
 * missing or empty allowlists reject every candidate.
 */
export function validateRedirectUri(
  candidate: string | undefined,
  policy: RedirectUriPolicy,
): string {
  if (!candidate) {
    throw new InvalidRedirectUriError(
      "Missing redirect URI",
      { code: "MISSING_REDIRECT_URI" },
    );
  }

  const parsed = parseUri(candidate);

  if (parsed.username || parsed.password) {
    throw new InvalidRedirectUriError(
      "Redirect URI must not contain embedded credentials",
      { code: "EMBEDDED_CREDENTIALS" },
    );
  }

  const scheme = parsed.protocol;
  if (scheme !== "https:" && scheme !== "http:") {
    throw new InvalidRedirectUriError(
      `Unsupported redirect URI scheme: ${scheme}`,
      { code: "UNSUPPORTED_SCHEME" },
    );
  }

  if (scheme === "http:") {
    if (!policy.allowLocalhostHttp) {
      throw new InvalidRedirectUriError(
        "HTTP redirect URIs require an explicit allowLocalhostHttp: true",
        { code: "LOCALHOST_HTTP_NOT_ALLOWED" },
      );
    }
    if (!isLoopbackHost(parsed.hostname)) {
      throw new InvalidRedirectUriError(
        "HTTP redirect URIs are only permitted for loopback hosts",
        { code: "NON_LOCALHOST_HTTP" },
      );
    }
  }

  const allowed = policy.allowedRedirectUris ?? [];
  if (allowed.length === 0) {
    throw new InvalidRedirectUriError(
      "No redirect URIs are allowed",
      { code: "EMPTY_ALLOWLIST" },
    );
  }

  if (!allowed.includes(candidate)) {
    throw new InvalidRedirectUriError(
      `Redirect URI is not in the allowlist: ${candidate}`,
      { code: "NOT_ALLOWED" },
    );
  }

  return candidate;
}
