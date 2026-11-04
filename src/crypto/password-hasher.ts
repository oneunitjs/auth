import { randomBytes, timingSafeEqual } from "node:crypto";
import { ConfigurationError, ValidationError } from "../errors/index.js";
import {
  hashPassword as hashScryptPassword,
  needsRehash as scryptNeedsRehash,
  verifyPassword as verifyScryptPassword,
} from "./password.js";
import type { PasswordOptions } from "../types/index.js";

export interface PasswordHasher {
  readonly algorithm: "argon2id" | "scrypt" | "bcrypt" | "composite";
  hash(password: string, options?: PasswordOptions): Promise<string>;
  verify(password: string, encodedHash: string): Promise<boolean>;
  needsRehash(encodedHash: string, options?: PasswordOptions): boolean;
}

export const ARGON2ID_RECOMMENDED_PROFILE = Object.freeze({
  algorithm: "argon2id" as const,
  version: 19,
  memoryKiB: 65_536,
  iterations: 3,
  parallelism: 1,
  saltBytes: 16,
  hashLength: 32,
});

const DEFAULT_MEMORY_KIB = 65_536;
const DEFAULT_ITERATIONS = 3;
const DEFAULT_PARALLELISM = 1;
const DEFAULT_SALT_BYTES = 16;
const DEFAULT_HASH_LENGTH = 32;
const MIN_MEMORY_KIB = 8;
const MAX_MEMORY_KIB = 1_048_576;
const MIN_ITERATIONS = 1;
const MAX_ITERATIONS = 16;
const MIN_PARALLELISM = 1;
const MAX_PARALLELISM = 16;
const MIN_SALT_BYTES = 8;
const MAX_SALT_BYTES = 64;
const MIN_HASH_LENGTH = 16;
const MAX_HASH_LENGTH = 64;
const MAX_ENCODED_LENGTH = 512;
const VERIFY_MAX_MEMORY_KIB = 65_536;
const VERIFY_MAX_ITERATIONS = 3;
const VERIFY_MAX_PARALLELISM = 1;

export interface Argon2idPolicy {
  memoryKiB?: number;
  iterations?: number;
  parallelism?: number;
  saltBytes?: number;
  hashLength?: number;
}

function clampInt(value: number, min: number, max: number): number | null {
  if (!Number.isInteger(value)) {
    return null;
  }
  if (value < min || value > max) {
    return null;
  }
  return value;
}

function parseArgon2idHash(encoded: string): {
  version: number;
  memoryKiB: number;
  iterations: number;
  parallelism: number;
  salt: Buffer;
  hash: Buffer;
} | null {
  if (typeof encoded !== "string" || encoded.length === 0 || encoded.length > MAX_ENCODED_LENGTH) {
    return null;
  }
  const parts = encoded.split("$");
  if (parts.length !== 6 || parts[0] !== "" || parts[1] !== "argon2id") {
    return null;
  }
  const versionPart = parts[2];
  const paramPart = parts[3];
  if (!versionPart.startsWith("v=")) {
    return null;
  }
  const version = Number.parseInt(versionPart.slice(2), 10);
  if (version !== 19) {
    return null;
  }
  const params: Record<string, number> = {};
  for (const item of paramPart.split(",")) {
    const [key, raw] = item.split("=");
    if (!key || raw === undefined || params[key] !== undefined) {
      return null;
    }
    const value = Number.parseInt(raw, 10);
    if (!Number.isInteger(value)) {
      return null;
    }
    params[key] = value;
  }
  const memoryKiB = params.m;
  const iterations = params.t;
  const parallelism = params.p;
  if (
    memoryKiB === undefined ||
    iterations === undefined ||
    parallelism === undefined ||
    clampInt(memoryKiB, MIN_MEMORY_KIB, MAX_MEMORY_KIB) === null ||
    clampInt(iterations, MIN_ITERATIONS, MAX_ITERATIONS) === null ||
    clampInt(parallelism, MIN_PARALLELISM, MAX_PARALLELISM) === null
  ) {
    return null;
  }
  try {
    const salt = fromPhcB64(parts[4]);
    const hash = fromPhcB64(parts[5]);
    if (salt.length < MIN_SALT_BYTES || salt.length > MAX_SALT_BYTES) {
      return null;
    }
    if (hash.length < MIN_HASH_LENGTH || hash.length > MAX_HASH_LENGTH) {
      return null;
    }
    return { version, memoryKiB, iterations, parallelism, salt, hash };
  } catch {
    return null;
  }
}

function toPhcB64(buffer: Buffer): string {
  return buffer.toString("base64").replace(/=+$/, "");
}

function fromPhcB64(value: string): Buffer {
  const padded = value + "=".repeat((4 - (value.length % 4)) % 4);
  return Buffer.from(padded, "base64");
}

function encodeArgon2id(params: {
  memoryKiB: number;
  iterations: number;
  parallelism: number;
  salt: Buffer;
  hash: Buffer;
}): string {
  return [
    "",
    "argon2id",
    "v=19",
    `m=${params.memoryKiB},t=${params.iterations},p=${params.parallelism}`,
    toPhcB64(params.salt),
    toPhcB64(params.hash),
  ].join("$");
}

type NobleArgon2id = (
  password: Uint8Array | string,
  salt: Uint8Array,
  options: { t: number; m: number; p: number; dkLen: number },
) => Uint8Array;

let nobleArgon2id: NobleArgon2id | undefined;
let nobleLoad: Promise<NobleArgon2id> | undefined;

async function loadNobleArgon2id(): Promise<NobleArgon2id> {
  if (nobleArgon2id) {
    return nobleArgon2id;
  }
  if (!nobleLoad) {
    nobleLoad = (async () => {
      try {
        const mod = await import("@noble/hashes/argon2.js") as { argon2id?: NobleArgon2id };
        if (typeof mod.argon2id !== "function") {
          throw new Error("missing argon2id export");
        }
        nobleArgon2id = mod.argon2id;
        return nobleArgon2id;
      } catch (error) {
        nobleLoad = undefined;
        throw new ConfigurationError(
          "Argon2id support requires the optional dependency @noble/hashes",
          { cause: error },
        );
      }
    })();
  }
  return nobleLoad;
}

function resolveArgon2idParams(options: PasswordOptions = {}): {
  memoryKiB: number;
  iterations: number;
  parallelism: number;
  saltBytes: number;
  hashLength: number;
} {
  const memoryKiB = clampInt(options.memoryKiB ?? DEFAULT_MEMORY_KIB, MIN_MEMORY_KIB, MAX_MEMORY_KIB);
  const iterations = clampInt(options.iterations ?? DEFAULT_ITERATIONS, MIN_ITERATIONS, MAX_ITERATIONS);
  const parallelism = clampInt(options.parallelism ?? DEFAULT_PARALLELISM, MIN_PARALLELISM, MAX_PARALLELISM);
  const saltBytes = clampInt(options.saltBytes ?? DEFAULT_SALT_BYTES, MIN_SALT_BYTES, MAX_SALT_BYTES);
  const hashLength = clampInt(options.keyLength ?? DEFAULT_HASH_LENGTH, MIN_HASH_LENGTH, MAX_HASH_LENGTH);
  if (!memoryKiB || !iterations || !parallelism || !saltBytes || !hashLength) {
    throw new ValidationError(
      "Argon2id parameters are out of range: " +
        `memoryKiB in [${MIN_MEMORY_KIB}, ${MAX_MEMORY_KIB}], ` +
        `iterations in [${MIN_ITERATIONS}, ${MAX_ITERATIONS}], ` +
        `parallelism in [${MIN_PARALLELISM}, ${MAX_PARALLELISM}], ` +
        `saltBytes in [${MIN_SALT_BYTES}, ${MAX_SALT_BYTES}], ` +
        `hashLength in [${MIN_HASH_LENGTH}, ${MAX_HASH_LENGTH}]`,
    );
  }
  return { memoryKiB, iterations, parallelism, saltBytes, hashLength };
}

export class Argon2idPasswordHasher implements PasswordHasher {
  readonly algorithm = "argon2id" as const;
  private readonly policy: Required<Argon2idPolicy>;

  constructor(policy: Argon2idPolicy = {}) {
    this.policy = {
      memoryKiB: policy.memoryKiB ?? DEFAULT_MEMORY_KIB,
      iterations: policy.iterations ?? DEFAULT_ITERATIONS,
      parallelism: policy.parallelism ?? DEFAULT_PARALLELISM,
      saltBytes: policy.saltBytes ?? DEFAULT_SALT_BYTES,
      hashLength: policy.hashLength ?? DEFAULT_HASH_LENGTH,
    };
  }

  async hash(password: string, options: PasswordOptions = {}): Promise<string> {
    if (typeof password !== "string" || password.length === 0) {
      throw new ValidationError("Password must be a non-empty string");
    }
    const params = resolveArgon2idParams({
      memoryKiB: options.memoryKiB ?? this.policy.memoryKiB,
      iterations: options.iterations ?? this.policy.iterations,
      parallelism: options.parallelism ?? this.policy.parallelism,
      saltBytes: options.saltBytes ?? this.policy.saltBytes,
      keyLength: options.keyLength ?? this.policy.hashLength,
    });
    const salt = options.salt
      ? (Buffer.isBuffer(options.salt) ? options.salt : Buffer.from(String(options.salt), "utf8"))
      : randomBytes(params.saltBytes);
    if (salt.length < MIN_SALT_BYTES || salt.length > MAX_SALT_BYTES) {
      throw new ValidationError(`saltBytes must be in [${MIN_SALT_BYTES}, ${MAX_SALT_BYTES}]`);
    }
    const argon2id = await loadNobleArgon2id();
    const derived = argon2id(password, salt, {
      t: params.iterations,
      m: params.memoryKiB,
      p: params.parallelism,
      dkLen: params.hashLength,
    });
    return encodeArgon2id({
      memoryKiB: params.memoryKiB,
      iterations: params.iterations,
      parallelism: params.parallelism,
      salt,
      hash: Buffer.from(derived),
    });
  }

  async verify(password: string, encodedHash: string): Promise<boolean> {
    if (typeof password !== "string" || typeof encodedHash !== "string") {
      return false;
    }
    const parsed = parseArgon2idHash(encodedHash);
    if (!parsed) {
      return false;
    }
    if (
      parsed.memoryKiB > VERIFY_MAX_MEMORY_KIB ||
      parsed.iterations > VERIFY_MAX_ITERATIONS ||
      parsed.parallelism > VERIFY_MAX_PARALLELISM
    ) {
      return false;
    }
    try {
      const argon2id = await loadNobleArgon2id();
      const actual = Buffer.from(argon2id(password, parsed.salt, {
        t: parsed.iterations,
        m: parsed.memoryKiB,
        p: parsed.parallelism,
        dkLen: parsed.hash.length,
      }));
      if (actual.length !== parsed.hash.length) {
        return false;
      }
      return timingSafeEqual(actual, parsed.hash);
    } catch {
      return false;
    }
  }

  needsRehash(encodedHash: string, options: PasswordOptions = {}): boolean {
    const parsed = parseArgon2idHash(encodedHash);
    if (!parsed) {
      return true;
    }
    const params = {
      memoryKiB: options.memoryKiB ?? this.policy.memoryKiB,
      iterations: options.iterations ?? this.policy.iterations,
      parallelism: options.parallelism ?? this.policy.parallelism,
      hashLength: options.keyLength ?? this.policy.hashLength,
    };
    return (
      parsed.memoryKiB < params.memoryKiB ||
      parsed.iterations < params.iterations ||
      parsed.parallelism < params.parallelism ||
      parsed.hash.length < params.hashLength
    );
  }
}

export class ScryptPasswordHasher implements PasswordHasher {
  readonly algorithm = "scrypt" as const;

  hash(password: string, options: PasswordOptions = {}): Promise<string> {
    return hashScryptPassword(password, options);
  }

  verify(password: string, encodedHash: string): Promise<boolean> {
    return verifyScryptPassword(password, encodedHash);
  }

  needsRehash(encodedHash: string, options: PasswordOptions = {}): boolean {
    return scryptNeedsRehash(encodedHash, options);
  }
}

export interface BcryptBinding {
  hash(password: string, rounds: number): Promise<string>;
  compare(password: string, hash: string): Promise<boolean>;
}

const BCRYPT_PREFIXES = ["$2a$", "$2b$", "$2y$"];
const MAX_BCRYPT_ROUNDS = 14;
const BCRYPT_MAX_PASSWORD_BYTES = 72;

export class BcryptPasswordHasher implements PasswordHasher {
  readonly algorithm = "bcrypt" as const;
  private readonly rounds: number;
  private readonly binding: BcryptBinding;

  constructor(binding: BcryptBinding, rounds = 12) {
    if (rounds < 10 || rounds > MAX_BCRYPT_ROUNDS) {
      throw new ValidationError(`bcrypt rounds must be in [10, ${MAX_BCRYPT_ROUNDS}]`);
    }
    this.binding = binding;
    this.rounds = rounds;
  }

  async hash(password: string): Promise<string> {
    if (typeof password !== "string" || password.length === 0) {
      throw new ValidationError("Password must be a non-empty string");
    }
    if (Buffer.byteLength(password, "utf8") > BCRYPT_MAX_PASSWORD_BYTES) {
      throw new ValidationError(`bcrypt passwords cannot exceed ${BCRYPT_MAX_PASSWORD_BYTES} bytes`);
    }
    return this.binding.hash(password, this.rounds);
  }

  async verify(password: string, encodedHash: string): Promise<boolean> {
    if (typeof password !== "string" || typeof encodedHash !== "string") {
      return false;
    }
    if (!BCRYPT_PREFIXES.some((prefix) => encodedHash.startsWith(prefix))) {
      return false;
    }
    const rounds = Number.parseInt(encodedHash.slice(4, 6), 10);
    if (!Number.isInteger(rounds) || rounds > MAX_BCRYPT_ROUNDS) {
      return false;
    }
    if (Buffer.byteLength(password, "utf8") > BCRYPT_MAX_PASSWORD_BYTES) {
      return false;
    }
    try {
      return await this.binding.compare(password, encodedHash);
    } catch {
      return false;
    }
  }

  needsRehash(encodedHash: string): boolean {
    if (!BCRYPT_PREFIXES.some((prefix) => encodedHash.startsWith(prefix))) {
      return true;
    }
    const rounds = Number.parseInt(encodedHash.slice(4, 6), 10);
    return rounds !== this.rounds;
  }
}

function identifyAlgorithm(encodedHash: string): "argon2id" | "scrypt" | "bcrypt" | "unknown" {
  if (typeof encodedHash !== "string") {
    return "unknown";
  }
  if (encodedHash.startsWith("$argon2id$")) {
    return "argon2id";
  }
  if (encodedHash.startsWith("scrypt$")) {
    return "scrypt";
  }
  if (BCRYPT_PREFIXES.some((prefix) => encodedHash.startsWith(prefix))) {
    return "bcrypt";
  }
  return "unknown";
}

export class CompositePasswordHasher implements PasswordHasher {
  readonly algorithm = "composite" as const;
  private readonly preferred: PasswordHasher;
  private readonly verifiers: Map<string, PasswordHasher>;

  constructor(options: {
    preferred?: PasswordHasher;
    argon2id?: Argon2idPasswordHasher;
    scrypt?: ScryptPasswordHasher;
    bcrypt?: BcryptPasswordHasher;
  } = {}) {
    const argon2id = options.argon2id ?? new Argon2idPasswordHasher();
    const scrypt = options.scrypt ?? new ScryptPasswordHasher();
    this.preferred = options.preferred ?? argon2id;
    this.verifiers = new Map<string, PasswordHasher>([
      ["argon2id", argon2id],
      ["scrypt", scrypt],
    ]);
    if (options.bcrypt) {
      this.verifiers.set("bcrypt", options.bcrypt);
    }
  }

  hash(password: string, options: PasswordOptions = {}): Promise<string> {
    if (options.algorithm === "scrypt") {
      const scrypt = this.verifiers.get("scrypt");
      if (!scrypt) {
        throw new ConfigurationError("scrypt hasher is not configured");
      }
      return scrypt.hash(password, options);
    }
    if (options.algorithm === "bcrypt") {
      const bcrypt = this.verifiers.get("bcrypt");
      if (!bcrypt) {
        throw new ConfigurationError("bcrypt hasher is not configured");
      }
      return bcrypt.hash(password, options);
    }
    return this.preferred.hash(password, options);
  }

  async verify(password: string, encodedHash: string): Promise<boolean> {
    const algorithm = identifyAlgorithm(encodedHash);
    if (algorithm === "unknown") {
      return false;
    }
    const hasher = this.verifiers.get(algorithm);
    if (!hasher) {
      return false;
    }
    return hasher.verify(password, encodedHash);
  }

  needsRehash(encodedHash: string, options: PasswordOptions = {}): boolean {
    const algorithm = identifyAlgorithm(encodedHash);
    if (algorithm === "unknown" || algorithm !== this.preferred.algorithm) {
      return true;
    }
    return this.preferred.needsRehash(encodedHash, options);
  }
}

let defaultHasher: PasswordHasher = new CompositePasswordHasher();

export function setDefaultPasswordHasher(hasher: PasswordHasher): void {
  defaultHasher = hasher;
}

export function getDefaultPasswordHasher(): PasswordHasher {
  return defaultHasher;
}

export function createPasswordHasher(
  options: ConstructorParameters<typeof CompositePasswordHasher>[0] = {},
): PasswordHasher {
  return new CompositePasswordHasher(options);
}

export async function hashPassword(password: string, options: PasswordOptions = {}): Promise<string> {
  return getDefaultPasswordHasher().hash(password, options);
}

export async function verifyPassword(password: string, storedHash: string): Promise<boolean> {
  return getDefaultPasswordHasher().verify(password, storedHash);
}

export function needsRehash(storedHash: string, options: PasswordOptions = {}): boolean {
  return getDefaultPasswordHasher().needsRehash(storedHash, options);
}
