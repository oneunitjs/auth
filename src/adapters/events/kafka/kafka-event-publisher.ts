import type { AuthEvent } from "../../../adapters/contracts/events/auth-event.js";
import type { EventPublisher } from "../../../adapters/contracts/events/event-publisher.js";
import type {
  KafkaEventOptions,
  KafkaProducerLike,
} from "../../../types/index.js";
import { EventTopicRouter } from "../../../events/dispatch/event-topic-router.js";
import { sanitizeEventPayload } from "../../../events/sanitization/sanitize-auth-event.js";
import { EVENT_VERSION } from "../../../events/factory/create-auth-event.js";

/**
 * Kafka event publisher adapter.
 *
 * Implements the `EventPublisher` contract by serializing `AuthEvent`
 * envelopes to JSON and publishing them to Kafka through an
 * application-supplied producer. The application owns producer lifecycle
 * (connect/disconnect); this adapter only calls `send()`.
 *
 * Publishing failures are propagated to the caller (the `EventDispatcher`),
 * which applies best-effort or required failure semantics. The `onPublishError`
 * callback is invoked by the dispatcher, not by this adapter, to avoid
 * double-invocation.
 */
export class KafkaEventPublisher implements EventPublisher {
  private readonly producer: KafkaProducerLike;
  private readonly router: EventTopicRouter;
  private readonly messageKey: "event-id" | "user-id" | "session-id";
  private readonly source: string;

  constructor(options: KafkaEventOptions) {
    if (!options.producer || typeof options.producer.send !== "function") {
      throw new Error("KafkaEventPublisher requires a producer with a send() method");
    }

    this.producer = options.producer;
    this.router = new EventTopicRouter({
      topics: options.topics,
      defaultTopic: options.defaultTopic,
      byEventType: options.byEventType,
    });
    this.messageKey = options.messageKey ?? "event-id";
    this.source = options.source ?? "@oneunit/auth";
  }

  async publish(event: AuthEvent<unknown>): Promise<void> {
    let topic: string;
    try {
      const resolved = this.router.resolve(event);
      topic = resolved.topic;
    } catch (error) {
      const err =
        error instanceof Error ? error : new Error(String(error));
      throw err;
    }

    const key = this.resolveMessageKey(event);
    const headers = this.buildHeaders(event);
    const safeEvent = {
      ...event,
      payload: sanitizeEventPayload(event.payload),
    };
    const value = JSON.stringify(safeEvent);

    try {
      await this.producer.send({
        topic,
        messages: [{ key, value, headers }],
      });
    } catch (error) {
      const err =
        error instanceof Error ? error : new Error(String(error));
      throw err;
    }
  }

  private resolveMessageKey(event: AuthEvent<unknown>): string | undefined {
    if (this.messageKey === "user-id") {
      const payload = event.payload as { userId?: string | number } | undefined;
      if (payload?.userId !== undefined) {
        return String(payload.userId);
      }
    }
    if (this.messageKey === "session-id") {
      const payload = event.payload as { sessionId?: string } | undefined;
      if (payload?.sessionId) {
        return payload.sessionId;
      }
    }
    return event.id;
  }

  private buildHeaders(event: AuthEvent<unknown>): Record<string, string> {
    return {
      "event-id": event.id,
      "event-type": event.type,
      "event-version": String(event.version),
      "event-source": event.source ?? this.source,
      "content-type": "application/json",
    };
  }
}
