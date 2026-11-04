import type { AuthEvent } from "../../adapters/contracts/events/auth-event.js";
import type { AuthContext } from "../../core/context.js";
import { randomToken } from "../../utils.js";
import { MAX_STRING_LENGTH } from "../sanitization/sanitize-auth-event.js";
import type {
  AuthEventPayload,
  AuthEventType,
} from "../catalog/index.js";

const EVENT_VERSION = 1;

export interface CreateAuthEventOptions {
  type: AuthEventType;
  payload: AuthEventPayload;
  source: string;
  context?: AuthContext;
  correlationId?: string;
  causationId?: string;
  tenantId?: string;
  traceId?: string;
}

function generateId(): string {
  return `evt_${randomToken(16)}`;
}

function nowIso(): string {
  return new Date().toISOString();
}

function boundMetadata(value: string | undefined): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }
  if (value.length > MAX_STRING_LENGTH) {
    return value.slice(0, MAX_STRING_LENGTH);
  }
  return value;
}

export function createAuthEvent(options: CreateAuthEventOptions): AuthEvent<AuthEventPayload> {
  const event: AuthEvent<AuthEventPayload> = {
    id: generateId(),
    type: options.type,
    version: EVENT_VERSION,
    occurredAt: nowIso(),
    source: options.source,
    payload: options.payload,
  };

  const metadata: Record<string, string> = {};
  if (options.context) {
    const rid = boundMetadata(options.context.requestId);
    const tid = boundMetadata(options.context.traceId);
    const tnt = boundMetadata(options.context.tenantId);
    const oid = boundMetadata(options.context.operationId);
    if (rid) metadata.correlationId = rid;
    if (tid) metadata.traceId = tid;
    if (tnt) metadata.tenantId = tnt;
    if (oid) metadata.causationId = oid;
  }
  const corr = boundMetadata(options.correlationId);
  const caus = boundMetadata(options.causationId);
  const ten = boundMetadata(options.tenantId);
  const trc = boundMetadata(options.traceId);
  if (corr) metadata.correlationId = corr;
  if (caus) metadata.causationId = caus;
  if (ten) metadata.tenantId = ten;
  if (trc) metadata.traceId = trc;

  if (Object.keys(metadata).length > 0) {
    event.metadata = metadata as {
      correlationId?: string;
      causationId?: string;
      tenantId?: string;
      traceId?: string;
    };
  }

  return event;
}

export { EVENT_VERSION };
