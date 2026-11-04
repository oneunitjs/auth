import type { StorageAdapter } from "../../types/index.js";
import type { StorageCapabilities } from "../contracts/storage/storage-capabilities.js";
import { ConfigurationError } from "../../errors/index.js";

/**
 * Validates that a storage adapter exposes the methods it claims to support.
 * Returns the adapter unchanged when valid, or throws when a declared method
 * is missing or not a function.
 */
export function validateStorageAdapter(
  adapter: StorageAdapter,
  capabilities: StorageCapabilities,
): StorageAdapter {
  if (adapter.keyValue) {
    if (typeof adapter.keyValue.get !== "function") {
      throw new ConfigurationError("StorageAdapter.keyValue.get must be a function", {
        code: "INVALID_ADAPTER",
      });
    }
    if (typeof adapter.keyValue.set !== "function") {
      throw new ConfigurationError("StorageAdapter.keyValue.set must be a function", {
        code: "INVALID_ADAPTER",
      });
    }
    if (typeof adapter.keyValue.delete !== "function") {
      throw new ConfigurationError("StorageAdapter.keyValue.delete must be a function", {
        code: "INVALID_ADAPTER",
      });
    }
    if (capabilities.atomicConsume && typeof adapter.keyValue.consume !== "function") {
      throw new ConfigurationError(
        "StorageAdapter.keyValue.consume must be a function when atomicConsume is declared",
        { code: "INVALID_ADAPTER" },
      );
    }
    if (capabilities.ttl && typeof adapter.keyValue.set !== "function") {
      throw new ConfigurationError(
        "StorageAdapter.keyValue.set must accept TTL options when ttl is declared",
        { code: "INVALID_ADAPTER" },
      );
    }
  }

  if (adapter.refreshTokens) {
    if (typeof adapter.refreshTokens.get !== "function") {
      throw new ConfigurationError("StorageAdapter.refreshTokens.get must be a function", {
        code: "INVALID_ADAPTER",
      });
    }
    if (typeof adapter.refreshTokens.create !== "function") {
      throw new ConfigurationError("StorageAdapter.refreshTokens.create must be a function", {
        code: "INVALID_ADAPTER",
      });
    }
    if (capabilities.atomicRefreshTokenRotation && typeof adapter.refreshTokens.rotate !== "function") {
      throw new ConfigurationError(
        "StorageAdapter.refreshTokens.rotate must be a function when atomicRefreshTokenRotation is declared",
        { code: "INVALID_ADAPTER" },
      );
    }
    if (typeof adapter.refreshTokens.revoke !== "function") {
      throw new ConfigurationError("StorageAdapter.refreshTokens.revoke must be a function", {
        code: "INVALID_ADAPTER",
      });
    }
  }

  if (adapter.sessions) {
    if (typeof adapter.sessions.get !== "function") {
      throw new ConfigurationError("StorageAdapter.sessions.get must be a function", {
        code: "INVALID_ADAPTER",
      });
    }
    if (typeof adapter.sessions.set !== "function") {
      throw new ConfigurationError("StorageAdapter.sessions.set must be a function", {
        code: "INVALID_ADAPTER",
      });
    }
    if (typeof adapter.sessions.delete !== "function") {
      throw new ConfigurationError("StorageAdapter.sessions.delete must be a function", {
        code: "INVALID_ADAPTER",
      });
    }
  }

  if (adapter.revocations) {
    if (typeof adapter.revocations.revoke !== "function") {
      throw new ConfigurationError("StorageAdapter.revocations.revoke must be a function", {
        code: "INVALID_ADAPTER",
      });
    }
    if (typeof adapter.revocations.isRevoked !== "function") {
      throw new ConfigurationError("StorageAdapter.revocations.isRevoked must be a function", {
        code: "INVALID_ADAPTER",
      });
    }
  }

  if (adapter.versions) {
    if (typeof adapter.versions.get !== "function") {
      throw new ConfigurationError("StorageAdapter.versions.get must be a function", {
        code: "INVALID_ADAPTER",
      });
    }
    if (capabilities.atomicIncrement && typeof adapter.versions.increment !== "function") {
      throw new ConfigurationError(
        "StorageAdapter.versions.increment must be a function when atomicIncrement is declared",
        { code: "INVALID_ADAPTER" },
      );
    }
  }

  return adapter;
}
