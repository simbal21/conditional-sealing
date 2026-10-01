import { randomUUID } from "node:crypto";
import { pickSafeRefs } from "../redaction/safe-refs.js";
import {
  WEBHOOK_EVENT_TYPES,
  type WebhookDataBinding,
  type WebhookEnvelope,
  type WebhookEventType,
} from "../types/webhook-events.js";
import {
  REASON_LABEL,
  REASON_VISIBILITY,
  formatRefusalCodeHex,
  type RefusalCodeValue,
} from "../types/refusal.js";

export type WebhookSubscriber = (envelope: WebhookEnvelope) => unknown | Promise<unknown>;

export class InMemoryWebhookEventBus {
  private readonly subscribers = new Set<WebhookSubscriber>();
  private readonly emitted: WebhookEnvelope[] = [];

  subscribe(subscriber: WebhookSubscriber): () => void {
    this.subscribers.add(subscriber);
    return () => this.subscribers.delete(subscriber);
  }

  async emit<T extends WebhookDataBinding & Record<string, unknown>>(input: {
    readonly event_type: WebhookEventType;
    readonly partner_id: string;
    readonly pda_id: string;
    readonly data: T;
    readonly event_id?: string;
    readonly created_at?: string;
    readonly schema_version?: string;
  }): Promise<WebhookEnvelope> {
    assertKnownEvent(input.event_type);
    const envelope: WebhookEnvelope = {
      event_id: input.event_id ?? randomUUID(),
      schema_version: input.schema_version ?? "s2-5.1",
      event_type: input.event_type,
      created_at: input.created_at ?? new Date().toISOString(),
      partner_id: input.partner_id,
      pda_id: input.pda_id,
      data: sanitizeWebhookData(input.data),
    };
    this.emitted.push(envelope);
    for (const subscriber of this.subscribers) await subscriber(envelope);
    return envelope;
  }

  list(): readonly WebhookEnvelope[] {
    return this.emitted;
  }
}

export function buildG4RefusedData(input: {
  readonly h_commit?: string;
  readonly authorizationId?: string;
  readonly reason_code: RefusalCodeValue;
  readonly encrypted_reason_ref?: string;
}): WebhookDataBinding & Record<string, unknown> {
  const visibility = REASON_VISIBILITY[input.reason_code];
  const base: Record<string, unknown> = {
    reason_code: formatRefusalCodeHex(input.reason_code),
    reason_label: REASON_LABEL[input.reason_code],
    reason_visibility: visibility,
    retryable: false,
  };
  if (input.h_commit) base.h_commit = input.h_commit;
  if (input.authorizationId) base.authorizationId = input.authorizationId;
  if (visibility === "encrypted") {
    base.encrypted_reason_ref = input.encrypted_reason_ref ?? `enc_reason_${formatRefusalCodeHex(input.reason_code)}`;
  }
  return base as WebhookDataBinding & Record<string, unknown>;
}

export function sanitizeWebhookData(data: WebhookDataBinding & Record<string, unknown>): Record<string, unknown> {
  const safe = pickSafeRefs(data);
  const out: Record<string, unknown> = { ...safe };
  for (const key of [
    "status",
    "state",
    "reason_code",
    "reason_label",
    "reason_visibility",
    "encrypted_reason_ref",
    "encrypted_diagnostic_ref",
    "retryable",
  ]) {
    const value = data[key];
    if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
      out[key] = value;
    }
  }
  if (!("h_commit" in out) && !("authorizationId" in out)) {
    throw new Error("Webhook data must carry h_commit, authorizationId, or both.");
  }
  return out;
}

function assertKnownEvent(eventType: WebhookEventType): void {
  if (!WEBHOOK_EVENT_TYPES.includes(eventType)) {
    throw new Error(`Unknown webhook event type: ${eventType}`);
  }
}
