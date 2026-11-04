export const PLATFORM_COMPATIBILITY = Object.freeze({
  runtime: {
    node: ">=20",
    testedNodeMajors: [20, 22] as const,
    browser: false,
    edge: false,
  },
  modules: {
    esm: true,
    commonjs: false,
    type: "module" as const,
  },
  typescript: {
    minimum: "5.0",
    recommended: "5.7",
  },
notes: [
  "Primary distribution is ESM. CommonJS builds are also published for compatibility.",
  "Framework adapters are optional and do not change core runtime requirements.",
  "Argon2id hashing uses @noble/hashes. scrypt remains available for legacy hashes.",
],
});

export type PlatformCompatibility = typeof PLATFORM_COMPATIBILITY;
