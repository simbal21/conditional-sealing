// Webhook event taxonomy — verbatim from S2-5 §7.1 (lines 805-824).
//
// LOCKED at Phase A. Spec body grep-verified 2026-05-11: 18 entries.
// Phase A foundation test asserts count = 18.

export const WEBHOOK_EVENT_TYPES = [
  "commit.finalized",
  "commit.failed",
  "sd.completed",
  "sd.partial_failure",
  "reveal.authorized",
  "challenge.opened",
  "challenge.resolved",
  "reveal.ready_for_gate_signing",
  "reveal.finalized",
  "reveal.failed",
  "g4.refused",
  "shred.authorized",
  "shred.challenge_opened",
  "shred.finalized",
  "halt.triggered",
  "registry.deprecated",
  "vault.retention_expiring",
  "vault.shredded",
] as const;

export type WebhookEventType = (typeof WEBHOOK_EVENT_TYPES)[number];

export const WEBHOOK_EVENT_COUNT: number = WEBHOOK_EVENT_TYPES.length;

/**
 * Webhook envelope shape — verbatim from §7.1 line 826.
 *
 * Each event has `event_id, schema_version, event_type, created_at,
 * partner_id, pda_id, data`. `data` discriminator: must contain either
 * `h_commit`, `authorizationId`, or both depending on event type.
 */
export interface WebhookEnvelope<T = Record<string, unknown>> {
  event_id: string;
  schema_version: string;
  event_type: WebhookEventType;
  created_at: string;
  partner_id: string;
  pda_id: string;
  data: T;
}

/**
 * Webhook headers — verbatim from §7.2 lines 832-835.
 */
export interface WebhookDeliveryHeaders {
  "x-cealis-signature": string; // sha256=<hex>
  "x-cealis-timestamp": string; // unix seconds (utf8 string)
  "x-cealis-event": string; // event_type
  "x-cealis-delivery": string; // event_id
}

/**
 * Retry policy — verbatim from §7.3 lines 840-846.
 */
export const WEBHOOK_RETRY_INTERVALS_MS = [1000, 2000, 4000, 8000, 16000] as const;
export const WEBHOOK_RETRY_MAX = 5;
export const WEBHOOK_DELIVERY_SUCCESS_WINDOW_MS = 30_000;
export const WEBHOOK_METADATA_RETENTION_DAYS = 90; // §15.3 + internal legal-constraints rules line 47
export const WEBHOOK_REPLAY_WINDOW_SECONDS = 300; // §7.2 line 837 + §1.2 line 175

/**
 * Discriminator type — every event payload data must contain one of these
 * binding keys (per §7.1 last sentence + §7.4 event_key construction).
 */
export type WebhookDataBinding =
  | { h_commit: string; authorizationId?: string }
  | { authorizationId: string; h_commit?: string }
  | { h_commit: string; authorizationId: string };

/**
 * Event-key construction per §7.4:
 *   event_key = event_id + ":" + (h_commit || authorizationId)
 */
export function buildEventKey(
  event_id: string,
  binding: { h_commit?: string; authorizationId?: string },
): string {
  const ref = binding.h_commit ?? binding.authorizationId;
  if (!ref) {
    throw new Error("WebhookDataBinding requires h_commit or authorizationId.");
  }
  return `${event_id}:${ref}`;
}
