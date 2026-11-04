const MAX_STRING_LENGTH = 512;
const MAX_OBJECT_DEPTH = 5;

const PROHIBITED_KEYS = new Set([
  "password",
  "passwordhash",
  "secret",
  "refreshsecret",
  "accesstoken",
  "access_token",
  "refreshtoken",
  "refresh_token",
  "id_token",
  "token",
  "authorizationcode",
  "authorization_code",
  "code",
  "verifier",
  "codeverifier",
  "code_verifier",
  "state",
  "clientsecret",
  "client_secret",
  "privatekey",
  "private_key",
  "credentials",
  "authorization",
  "cookie",
]);

function isProhibitedKey(key: string): boolean {
  return PROHIBITED_KEYS.has(key.toLowerCase());
}

function sanitizeValue(
  value: unknown,
  depth: number,
  maxStringLength: number,
  prohibitedKeys: Set<string>,
): unknown {
  if (value === null || value === undefined) {
    return value;
  }

  if (typeof value === "string") {
    if (value.length > maxStringLength) {
      return value.slice(0, maxStringLength);
    }
    return value;
  }

  if (typeof value === "number" || typeof value === "boolean") {
    return value;
  }

  if (Array.isArray(value)) {
    if (depth >= MAX_OBJECT_DEPTH) {
      return value
        .slice(0, 10)
        .map((item) => sanitizeValue(item, depth, maxStringLength, prohibitedKeys));
    }
    return value.map((item) =>
      sanitizeValue(item, depth + 1, maxStringLength, prohibitedKeys),
    );
  }

  if (typeof value === "object") {
    if (depth >= MAX_OBJECT_DEPTH) {
      return {};
    }
    const next: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(value as Record<string, unknown>)) {
      if (prohibitedKeys.has(key.toLowerCase())) {
        continue;
      }
      next[key] = sanitizeValue(
        val,
        depth + 1,
        maxStringLength,
        prohibitedKeys,
      );
    }
    return next;
  }

  return value;
}

export interface SanitizeEventOptions {
  maxStringLength?: number;
  prohibitedKeys?: Set<string>;
}

export function sanitizeEventPayload(
  payload: unknown,
  options: SanitizeEventOptions = {},
): unknown {
  const maxStringLength = options.maxStringLength ?? MAX_STRING_LENGTH;
  const prohibitedKeys = new Set(
    Array.from(options.prohibitedKeys ?? PROHIBITED_KEYS).map((k) =>
      k.toLowerCase(),
    ),
  );
  return sanitizeValue(payload, 0, maxStringLength, prohibitedKeys);
}

export { PROHIBITED_KEYS, MAX_STRING_LENGTH, MAX_OBJECT_DEPTH };
