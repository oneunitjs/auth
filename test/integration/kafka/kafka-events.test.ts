import { describe, it, beforeAll, afterAll, expect, beforeEach } from "vitest";
import { KafkaContainer } from "@testcontainers/kafka";
import { Kafka, logLevel } from "kafkajs";
import { createAuth, createMemorySessionStore } from "../../../src/index.js";

const SECRET = "kafka-events-test-secret-do-not-use-in-production";

let kafkaContainer: any;
let kafka: Kafka;
let producer: any;
let consumer: any;
let receivedEvents: any[] = [];
const testTopic = "auth.events";

function waitForEvent(predicate: (event: any) => boolean, timeoutMs = 5000): Promise<any> {
  return new Promise((resolve, reject) => {
    const start = Date.now();
    const check = () => {
      const match = receivedEvents.find(predicate);
      if (match) {
        resolve(match);
        return;
      }
      if (Date.now() - start > timeoutMs) {
        reject(new Error(`Timed out waiting for event matching predicate`));
        return;
      }
      setTimeout(check, 50);
    };
    check();
  });
}

describe("Kafka event integration", () => {
  beforeAll(async () => {
    kafkaContainer = await new KafkaContainer("confluentinc/cp-kafka:7.5.0").start();

    const host = kafkaContainer.getHost();
    const port = kafkaContainer.getMappedPort(9093);
    kafka = new Kafka({
      clientId: "auth-test",
      brokers: [`${host}:${port}`],
      logLevel: logLevel.WARN,
    });

    producer = kafka.producer();
    await producer.connect();

    consumer = kafka.consumer({ groupId: "auth-test-group" });
    await consumer.connect();
    await consumer.subscribe({ topic: testTopic, fromBeginning: false });

    await consumer.run({
      eachMessage: async ({ message }: { message: any }) => {
        if (message.value) {
          receivedEvents.push(JSON.parse(message.value.toString()));
        }
      },
    });
  }, 60_000);

  afterAll(async () => {
    await consumer.stop();
    await producer.disconnect();
    await kafkaContainer.stop();
  });

  beforeEach(() => {
    receivedEvents = [];
  });

  it("publishes full auth.login.succeeded envelope on successful login", async () => {
    const auth = createAuth({
      secret: SECRET,
      events: {
        kafka: {
          producer: producer as any,
          topics: {
            authentication: testTopic,
          },
        },
      },
    });
    await auth.login({ id: 1, email: "user@example.com", roles: ["user"] });

    const loginEvent = await waitForEvent((e) => e.type === "auth.login.succeeded");
    expect(loginEvent).toBeDefined();
    expect(loginEvent.id).toBeDefined();
    expect(loginEvent.type).toBe("auth.login.succeeded");
    expect(loginEvent.version).toBe(1);
    expect(loginEvent.occurredAt).toBeDefined();
    expect(loginEvent.source).toBe("@oneunit/auth");
    expect(loginEvent.payload.userId).toBe(1);
    expect(loginEvent.payload.authenticationMethod).toBe("password");
  });

  it("publishes auth.login.failed event on failed login", async () => {
    const users = new Map<string, any>();
    users.set("1", {
      id: 1,
      email: "user@example.com",
      passwordHash: "$argon2id$v=19$m=65536,t=3,p=4$test",
    });

    const auth = createAuth({
      secret: SECRET,
      userStore: {
        async findByCredentials() {
          return users.get("1");
        },
      } as any,
      events: {
        kafka: {
          producer: producer as any,
          topics: {
            security: testTopic,
          },
        },
      },
    });

    // Hash a wrong password so verification fails
    await expect(() =>
      auth.loginWithPassword("user@example.com", "wrong-password")
    ).rejects.toThrow();

    const loginFailedEvent = await waitForEvent((e) => e.type === "auth.login.failed");
    expect(loginFailedEvent).toBeDefined();
    expect(loginFailedEvent.payload.reason).toBe("invalid_credentials");
    expect(loginFailedEvent.payload.authenticationMethod).toBe("password");
  });

  it("publishes auth.token.validation.succeeded event on valid token", async () => {
    const auth = createAuth({
      secret: SECRET,
      events: {
        kafka: {
          producer: producer as any,
          topics: {
            token: testTopic,
          },
        },
      },
    });
    const session = await auth.login({ id: 1, roles: ["user"] });
    await auth.verify(session.accessToken);

    const validationEvent = await waitForEvent(
      (e) => e.type === "auth.token.validation.succeeded",
    );
    expect(validationEvent).toBeDefined();
    expect(validationEvent.payload.userId).toBe("1");
    expect(validationEvent.payload.tokenType).toBe("access");
  });

  it("publishes auth.logout.succeeded event on logout", async () => {
    const auth = createAuth({
      secret: SECRET,
      events: {
        kafka: {
          producer: producer as any,
          topics: {
            session: testTopic,
          },
        },
      },
    });
    const session = await auth.login({ id: 1, roles: ["user"] });
    await auth.logout(session.refreshToken);

    const logoutEvent = await waitForEvent((e) => e.type === "auth.logout.succeeded");
    expect(logoutEvent).toBeDefined();
    expect(logoutEvent.payload.reason).toBe("logout");
  });

  it("publishes auth.token.issued and auth.session.created events on login", async () => {
    const auth = createAuth({
      secret: SECRET,
      sessionStore: createMemorySessionStore(),
      events: {
        kafka: {
          producer: producer as any,
          topics: {
            token: testTopic,
            session: testTopic,
          },
        },
      },
    });
    await auth.login({ id: 1, roles: ["user"] });

    const tokenEvent = await waitForEvent((e) => e.type === "auth.token.issued");
    expect(tokenEvent).toBeDefined();
    expect(tokenEvent.payload.userId).toBe(1);
    expect(tokenEvent.payload.tokenType).toBe("access");

    const sessionEvent = await waitForEvent((e) => e.type === "auth.session.created");
    expect(sessionEvent).toBeDefined();
    expect(sessionEvent.payload.userId).toBe(1);
    expect(sessionEvent.payload.sessionId).toBeDefined();
  });

  it("serializes the full event envelope in the Kafka message body", async () => {
    const auth = createAuth({
      secret: SECRET,
      events: {
        kafka: {
          producer: producer as any,
          topics: {
            authentication: testTopic,
          },
        },
      },
    });
    await auth.login({ id: 1, roles: ["user"] });

    const loginEvent = await waitForEvent((e) => e.type === "auth.login.succeeded");
    expect(loginEvent.id).toMatch(/^evt_/);
    expect(loginEvent.version).toBe(1);
    expect(new Date(loginEvent.occurredAt).toISOString()).toBe(loginEvent.occurredAt);
    expect(loginEvent.source).toBe("@oneunit/auth");
    expect(loginEvent.metadata).toBeDefined();
  });
});
