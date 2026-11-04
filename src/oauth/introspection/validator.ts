import type { IntrospectionResult } from "./types.js";

/**
 * Required RFC 7662 introspection response fields.
 */
const REQUIRED_FIELDS = ["active"];

/**
 * Parse and validate an RFC 7662 introspection response body.
 *
 * The response MUST contain an `active` boolean. Anything else is optional.
 * Returns a normalized {@link IntrospectionResult}.
 */
export function validateIntrospectionResponse(body: unknown): IntrospectionResult {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new Error("Introspection response is not a JSON object");
  }

  const record = body as Record<string, unknown>;

  for (const field of REQUIRED_FIELDS) {
    if (!(field in record)) {
      throw new Error(`Introspection response is missing required field "${field}"`);
    }
  }

  const active = record.active;
  if (typeof active !== "boolean") {
    throw new Error("Introspection response field 'active' must be a boolean");
  }

  const result: IntrospectionResult = { active };

  const optionalFields: Array<keyof IntrospectionResult> = [
    "scope",
    "clientId",
    "username",
    "tokenType",
    "exp",
    "iat",
    "nbf",
    "sub",
    "aud",
    "iss",
    "jti",
  ];

  for (const field of optionalFields) {
    const value = record[field];
    if (value !== undefined) {
      result[field] = value;
    }
  }

  // Carry through any additional RFC 7662 extension fields.
  for (const [key, value] of Object.entries(record)) {
    if (!(key in result)) {
      result[key] = value;
    }
  }

  return result;
}
