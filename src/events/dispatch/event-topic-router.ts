import type { AuthEvent } from "../../adapters/contracts/events/auth-event.js";
import {
  AUTH_EVENT_TYPES,
  EVENT_CATEGORIES,
  type AuthEventType,
} from "../catalog/index.js";

export type EventCategory = "authentication" | "security" | "session" | "token";

export interface TopicMapping {
  authentication?: string;
  security?: string;
  session?: string;
  token?: string;
  [category: string]: string | undefined;
}

export interface TopicRouterConfig {
  topics?: TopicMapping;
  defaultTopic?: string;
  byEventType?: Record<string, string>;
}

export interface ResolvedTopic {
  topic: string;
  category: EventCategory | undefined;
}

export class EventTopicRouter {
  private readonly topics: TopicMapping;
  private readonly defaultTopic?: string;
  private readonly byEventType: Record<string, string>;

  constructor(config: TopicRouterConfig = {}) {
    this.topics = config.topics ?? {};
    this.defaultTopic = config.defaultTopic;
    this.byEventType = config.byEventType ?? {};

    this.validate();
  }

  private validate(): void {
    for (const [category, topic] of Object.entries(this.topics)) {
      if (typeof topic !== "string" || topic.length === 0) {
        throw new Error(
          `Topic for category "${category}" must be a non-empty string`,
        );
      }
    }

    for (const [eventType, topic] of Object.entries(this.byEventType)) {
      if (typeof topic !== "string" || topic.length === 0) {
        throw new Error(
          `Topic for event type "${eventType}" must be a non-empty string`,
        );
      }
    }

    if (!this.defaultTopic && Object.keys(this.topics).length === 0) {
      throw new Error(
        "EventTopicRouter requires at least one topic mapping or a default topic",
      );
    }
  }

  resolve(event: AuthEvent<unknown>): ResolvedTopic {
    // 1. Exact event-type mapping takes precedence
    if (this.byEventType[event.type]) {
      return {
        topic: this.byEventType[event.type],
        category: this.categoryForEvent(event.type),
      };
    }

    // 2. Category mapping
    const category = this.categoryForEvent(event.type);
    if (category && this.topics[category]) {
      return { topic: this.topics[category]!, category };
    }

    // 3. Default topic
    if (this.defaultTopic) {
      return { topic: this.defaultTopic, category };
    }

    // 4. No topic can be resolved
    throw new Error(
      `No topic configured for event type "${event.type}" (category: ${category ?? "unknown"})`,
    );
  }

  private categoryForEvent(eventType: string): EventCategory | undefined {
    return (EVENT_CATEGORIES as Record<string, EventCategory | undefined>)[
      eventType
    ];
  }

  getCategory(eventType: string): EventCategory | undefined {
    return this.categoryForEvent(eventType);
  }
}
