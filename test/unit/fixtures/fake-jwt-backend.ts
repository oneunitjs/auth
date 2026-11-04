import type { JwtBackend, JwtPayload, JwtSignOptions, JwtVerifyOptions } from "../../src/index.js";

export function fakeJwtBackend(overrides: {
  signResult?: string;
  verifyResult?: JwtPayload;
  signError?: Error;
  verifyError?: Error;
} = {}) {
  const calls: Array<{ method: "sign" | "verify"; args: unknown[] }> = [];
  return {
    calls,
    async sign(payload: JwtPayload, options: JwtSignOptions) {
      calls.push({ method: "sign", args: [payload, options] });
      if (overrides.signError) throw overrides.signError;
      return overrides.signResult ?? "fake-token";
    },
    async verify(token: string, options: JwtVerifyOptions) {
      calls.push({ method: "verify", args: [token, options] });
      if (overrides.verifyError) throw overrides.verifyError;
      return overrides.verifyResult ?? { sub: "1", userId: 1, typ: "access" };
    },
    lastSignCall() {
      return calls[calls.length - 1];
    },
    lastVerifyCall() {
      return calls[calls.length - 1];
    },
  } as JwtBackend;
}
