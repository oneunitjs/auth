import { describe, it, expect } from "vitest";
import { EventDispatcher } from "../../../src/index.js";

function makePublisher(shouldFail = false): { publish: (event: unknown) => Promise<void>; name: string; calls: unknown[] } {
  const calls: unknown[] = [];
  return {
    name: shouldFail ? "failing" : "success",
    calls,
    publish: async (event: unknown) => {
      calls.push(event);
      if (shouldFail) {
        throw new Error("publish failed");
      }
    },
  };
}

describe("event dispatcher", () => {

  it("dispatches to all publishers", async () => {
    const p1 = makePublisher();
    const p2 = makePublisher();
    const dispatcher = new EventDispatcher({
      publishers: [p1, p2],
    });

    const event = { id: "evt_1", type: "auth.login.succeeded", version: 1, payload: {} };
    const result = await dispatcher.dispatch(event as never);

    expect(result.published).toBe(2);
    expect(result.failed).toBe(0);
    expect(p1.calls).toHaveLength(1);
    expect(p2.calls).toHaveLength(1);
  });

  it("handles publisher failures in best-effort mode", async () => {
    const p1 = makePublisher();
    const p2 = makePublisher(true);
    const dispatcher = new EventDispatcher({
      publishers: [p1, p2],
      failureMode: "best-effort",
    });

    const event = { id: "evt_1", type: "auth.login.succeeded", version: 1, payload: {} };
    const result = await dispatcher.dispatch(event as never);

    expect(result.published).toBe(1);
    expect(result.failed).toBe(1);
    expect(result.errors).toHaveLength(1);
  });

  it("throws on publisher failure in required mode", async () => {
    const p1 = makePublisher();
    const p2 = makePublisher(true);
    const dispatcher = new EventDispatcher({
      publishers: [p1, p2],
      failureMode: "required",
    });

    const event = { id: "evt_1", type: "auth.login.succeeded", version: 1, payload: {} };
    await expect(dispatcher.dispatch(event as never)).rejects.toThrow("publish failed");
  });

  it("returns empty result with no publishers", async () => {
    const dispatcher = new EventDispatcher({ publishers: [] });
    const event = { id: "evt_1", type: "auth.login.succeeded", version: 1, payload: {} };
    const result = await dispatcher.dispatch(event as never);

    expect(result.published).toBe(0);
    expect(result.failed).toBe(0);
  });

  it("calls onPublishError callback on failure", async () => {
    const errors: Array<{ error: Error; event: unknown }> = [];
    const p1 = makePublisher(true);
    const dispatcher = new EventDispatcher({
      publishers: [p1],
      failureMode: "best-effort",
      onPublishError: (error, event) => {
        errors.push({ error, event });
      },
    });

    const event = { id: "evt_1", type: "auth.login.succeeded", version: 1, payload: {} };
    await dispatcher.dispatch(event as never);

    expect(errors).toHaveLength(1);
    expect(errors[0].error).toBeInstanceOf(Error);
    expect(errors[0].event).toBe(event);
  });
});
