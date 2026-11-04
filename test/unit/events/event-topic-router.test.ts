import { describe, it, expect } from "vitest";
import { EventTopicRouter } from "../../../src/index.js";

describe("event topic router", () => {
  it("resolves category-based topic", () => {
    const router = new EventTopicRouter({
      topics: {
        authentication: "auth.events",
        security: "security.events",
      },
    });

    const resolved = router.resolve({
      id: "evt_1",
      type: "auth.login.succeeded",
      version: 1,
      occurredAt: "2024-01-01T00:00:00.000Z",
      source: "test",
      payload: {},
    });
    expect(resolved.topic).toBe("auth.events");
    expect(resolved.category).toBe("authentication");
  });

  it("resolves event-type override before category", () => {
    const router = new EventTopicRouter({
      topics: {
        authentication: "auth.events",
        security: "security.events",
      },
      byEventType: {
        "auth.login.failed": "security.audit",
      },
    });

    const resolved = router.resolve({
      id: "evt_1",
      type: "auth.login.failed",
      version: 1,
      occurredAt: "2024-01-01T00:00:00.000Z",
      source: "test",
      payload: {},
    });
    expect(resolved.topic).toBe("security.audit");
    expect(resolved.category).toBe("security");
  });

  it("falls back to default topic", () => {
    const router = new EventTopicRouter({
      defaultTopic: "auth.events",
    });

    const resolved = router.resolve({
      id: "evt_1",
      type: "auth.login.succeeded",
      version: 1,
      occurredAt: "2024-01-01T00:00:00.000Z",
      source: "test",
      payload: {},
    });
    expect(resolved.topic).toBe("auth.events");
  });

  it("throws when no topic can be resolved", () => {
    const router = new EventTopicRouter({
      topics: {
        authentication: "auth.events",
      },
    });

    expect(() => {
      router.resolve({
        id: "evt_1",
        type: "auth.token.validation.succeeded",
        version: 1,
        occurredAt: "2024-01-01T00:00:00.000Z",
        source: "test",
        payload: {},
      });
    }).toThrow();
  });

  it("throws when no topics or default are configured", () => {
    expect(() => new EventTopicRouter({})).toThrow();
  });

  it("validates non-empty topic strings", () => {
    expect(() => new EventTopicRouter({
      topics: { authentication: "" },
    })).toThrow();
  });

  it("gets category for an event type", () => {
    const router = new EventTopicRouter({ defaultTopic: "events" });
    expect(router.getCategory("auth.login.succeeded")).toBe("authentication");
    expect(router.getCategory("auth.session.revoked")).toBe("session");
    expect(router.getCategory("unknown.event")).toBeUndefined();
  });
});
