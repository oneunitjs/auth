import type { AuthEvent } from "../../adapters/contracts/events/auth-event.js";
import type { EventPublisher } from "../../adapters/contracts/events/event-publisher.js";
import type { Logger } from "../../logging/types.js";

export type DeliveryMode = "best-effort" | "required";

export interface PublishResult {
  published: number;
  failed: number;
  errors: Array<{ publisher: string; error: Error }>;
}

export interface EventDispatcherConfig {
  publishers: EventPublisher[];
  failureMode?: DeliveryMode;
  onPublishError?: (error: Error, event: AuthEvent) => void | Promise<void>;
  logger?: Logger;
}

export class EventDispatcher {
  private readonly publishers: EventPublisher[];
  private readonly failureMode: DeliveryMode;
  private readonly onPublishError?: (error: Error, event: AuthEvent) => void | Promise<void>;
  private readonly logger: Required<Logger>;

  constructor(config: EventDispatcherConfig) {
    this.publishers = config.publishers;
    this.failureMode = config.failureMode ?? "best-effort";
    this.onPublishError = config.onPublishError;
    this.logger = {
      debug: () => {},
      info: () => {},
      warn: () => {},
      error: () => {},
      ...config.logger,
    };
  }

  get publisherCount(): number {
    return this.publishers.length;
  }

  async dispatch(event: AuthEvent<unknown>): Promise<PublishResult> {
    const result: PublishResult = { published: 0, failed: 0, errors: [] };

    if (this.publishers.length === 0) {
      return result;
    }

    const errors: Array<{ publisher: string; error: Error }> = [];

    await Promise.all(
      this.publishers.map(async (publisher) => {
        const publisherName = publisher.constructor.name ?? "unknown";
        try {
          await publisher.publish(event);
          result.published += 1;
        } catch (error) {
          const err = error instanceof Error ? error : new Error(String(error));
          result.failed += 1;
          errors.push({ publisher: publisherName, error: err });

          this.logger.error(
            { eventId: event.id, eventType: event.type, publisher: publisherName },
            "Event publish failed",
          );

          if (this.onPublishError) {
            try {
              await this.onPublishError(err, event);
            } catch {
              // onPublishError must never interrupt the dispatch flow.
            }
          }
        }
      }),
    );

    result.errors = errors;

    if (this.failureMode === "required" && result.failed > 0) {
      const firstError = errors[0];
      if (firstError) {
        throw firstError.error;
      }
    }

    return result;
  }
}
