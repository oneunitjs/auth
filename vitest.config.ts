import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    exclude: ["node_modules", "dist"],
    testTimeout: 60_000,
    hookTimeout: 60_000,
    teardownTimeout: 120_000,
    isolate: true,
    globals: false,
    environment: "node",
    // Defer container startup: each infra test file starts its own containers
    // via testcontainers' `startedTestContainers` or explicit `start()`.
  },
  esbuild: {
    target: "node20",
  },
});
