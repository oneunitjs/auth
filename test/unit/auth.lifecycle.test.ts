import { describe, it, expect } from "vitest";
import { createAuth } from "../../src/index.js";
import { SECRET } from "./fixtures/auth.fixtures.js";

describe("Auth persistence lifecycle (LIFE)", () => {
  it("LIFE-01: initialize with persistence adapter calls adapter initialization", async () => {
    let initialized = false;
    const auth = createAuth({
      secret: SECRET,
      persistence: {
        async initialize() {
          initialized = true;
        },
        async close() {},
      },
    });
    await auth.initialize();
    expect(initialized).toBe(true);
    expect(auth.initialized).toBe(true);
  });

  it("LIFE-02: initialize more than once occurs only once until closed", async () => {
    let count = 0;
    const auth = createAuth({
      secret: SECRET,
      persistence: {
        async initialize() {
          count += 1;
        },
        async close() {},
      },
    });
    await auth.initialize();
    await auth.initialize();
    expect(count).toBe(1);
  });

  it("LIFE-03: close calls adapter close and resets initialized to false", async () => {
    let closed = false;
    const auth = createAuth({
      secret: SECRET,
      persistence: {
        async initialize() {},
        async close() {
          closed = true;
        },
      },
    });
    await auth.initialize();
    await auth.close();
    expect(closed).toBe(true);
    expect(auth.initialized).toBe(false);
  });

  it("LIFE-04: initialize after close can be initialized again", async () => {
    let count = 0;
    const auth = createAuth({
      secret: SECRET,
      persistence: {
        async initialize() {
          count += 1;
        },
        async close() {},
      },
    });
    await auth.initialize();
    await auth.close();
    await auth.initialize();
    expect(count).toBe(2);
  });
});
