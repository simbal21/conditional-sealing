import {
  asRefusalCode,
  formatRefusalCodeHex,
  isBlockingRefusal,
  REASON_LABEL,
  REASON_VISIBILITY,
  type RefusalCodeValue,
} from "../types/refusal.js";
import type { WebhookEnvelope } from "../types/webhook-events.js";
import type { Hex32 } from "../types/reveal-artifact-bundle.js";

export interface G4RefusalEntry {
  readonly refusal_id: string;
  readonly authorization_id: Hex32;
  readonly h_commit: Hex32;
  readonly partner_id: string;
  readonly pda_id: string;
  readonly reason_code: RefusalCodeValue;
  readonly reason_code_hex: string;
  readonly reason_label: string;
  readonly reason_visibility: "encrypted" | "plaintext";
  readonly encrypted_reason_ref?: string;
  readonly refused_at: string;
  readonly blocking: boolean;
}

export interface G4RefusalStore {
  insertG4Refusal(entry: G4RefusalEntry): Promise<void> | void;
}

export interface G4RefusalEventBus {
  emit(event: WebhookEnvelope<Record<string, unknown>>): Promise<void> | void;
}

export interface HandleG4RefusalInput {
  readonly authorizationId: Hex32;
  readonly h_commit: Hex32;
  readonly partner_id: string;
  readonly pda_id: string;
  readonly reason_code: RefusalCodeValue | number;
  readonly encrypted_reason_ref?: string;
  readonly refused_at?: string;
}

export interface G4RefusalHandlingResult {
  readonly entry: G4RefusalEntry;
  readonly blocking: boolean;
  readonly advisory: boolean;
}

export async function handleG4Refusal(
  input: HandleG4RefusalInput,
  deps: {
    readonly store: G4RefusalStore;
    readonly eventBus?: G4RefusalEventBus;
    readonly now?: () => Date;
    readonly idFactory?: () => string;
  },
): Promise<G4RefusalHandlingResult> {
  const code = typeof input.reason_code === "number" ? asRefusalCode(input.reason_code) : input.reason_code;
  const visibility = REASON_VISIBILITY[code];
  if (visibility === "encrypted" && input.encrypted_reason_ref === undefined) {
    throw new Error("Encrypted G4 refusal reasons require encrypted_reason_ref.");
  }
  const blocking = isBlockingRefusal(code);
  const refusedAt = input.refused_at ?? (deps.now?.() ?? new Date()).toISOString();
  const entry: G4RefusalEntry = {
    refusal_id: deps.idFactory?.() ?? `${input.authorizationId}:${formatRefusalCodeHex(code)}`,
    authorization_id: input.authorizationId,
    h_commit: input.h_commit,
    partner_id: input.partner_id,
    pda_id: input.pda_id,
    reason_code: code,
    reason_code_hex: formatRefusalCodeHex(code),
    reason_label: REASON_LABEL[code],
    reason_visibility: visibility,
    ...(input.encrypted_reason_ref === undefined ? {} : { encrypted_reason_ref: input.encrypted_reason_ref }),
    refused_at: refusedAt,
    blocking,
  };
  await deps.store.insertG4Refusal(entry);
  await deps.eventBus?.emit({
    event_id: entry.refusal_id,
    schema_version: "s2-5.1",
    event_type: "g4.refused",
    created_at: refusedAt,
    partner_id: input.partner_id,
    pda_id: input.pda_id,
    data: refusalEventData(entry),
  });
  return {
    entry,
    blocking,
    advisory: !blocking,
  };
}

function refusalEventData(entry: G4RefusalEntry): Record<string, unknown> {
  return {
    authorizationId: entry.authorization_id,
    h_commit: entry.h_commit,
    reason_code: entry.reason_code_hex,
    reason_label: entry.reason_label,
    reason_visibility: entry.reason_visibility,
    blocking: entry.blocking,
    ...(entry.encrypted_reason_ref === undefined
      ? {}
      : { encrypted_reason_ref: entry.encrypted_reason_ref }),
  };
}

export class InMemoryG4RefusalStore implements G4RefusalStore {
  readonly entries: G4RefusalEntry[] = [];

  insertG4Refusal(entry: G4RefusalEntry): void {
    this.entries.push(entry);
  }
}

// ---- assembleRefusalDelivery (internal integration-gap close, 2026-05-14) ----
//
// Closes an internal integration-gap item. The brief's `revealDeliveryAssembler.assembleRefusal()`
// terminology overloads two distinct S2-5 §3.6 surfaces (webhook envelope vs.
// JCS bundle digest); the actual normative refusal-delivery surface is the
// webhook + Problem+JSON path. `assembleRefusalDelivery` is the ergonomic
// wrapper recommended in the internal integration-gap log (Option 1 PREFERRED): one call
// returning BOTH the persisted entry AND the delivered envelope.
//
// Composition:
//   1. Call `handleG4Refusal` to persist + side-emit on the eventBus.
//   2. Construct the canonical `WebhookEnvelope<RefusalEventData>` returned
//      to the caller — same envelope shape `handleG4Refusal` already emits
//      via `eventBus.emit`.
//   3. Return `{ entry, blocking, advisory, webhook }` so callers can route
//      the envelope through the webhook signer + dispatcher of their choice
//      (HMAC signing lives in `../webhooks/signer.ts`, NOT here — this
//      function returns the unsigned envelope so signers stay swappable).

export type RefusalWebhookEnvelope = WebhookEnvelope<Record<string, unknown>>;

export interface AssembleRefusalDeliveryInput extends HandleG4RefusalInput {}

export interface AssembleRefusalDeliveryResult {
  readonly entry: G4RefusalEntry;
  readonly blocking: boolean;
  readonly advisory: boolean;
  readonly webhook: RefusalWebhookEnvelope;
}

/**
 * Composes `handleG4Refusal` + canonical webhook-envelope construction in one
 * call. Mirrors the brief's `revealDeliveryAssembler.assembleRefusal({...})`
 * ergonomic shape, while preserving the spec-correct S2-5 §3.6 surface
 * (webhook + Problem+JSON; no parallel JCS-canonical bundle digest).
 *
 * The returned `webhook` envelope is UNSIGNED. Webhook HMAC signing is a
 * separate dispatcher concern (see `../webhooks/signer.ts`); keeping the
 * surfaces orthogonal lets tests + recipients verify the envelope shape
 * independent of signing configuration.
 *
 * Same `eventBus` semantics as `handleG4Refusal`: if `deps.eventBus` is
 * provided, the same envelope is also side-emitted to it (idempotent for
 * an in-memory eventBus; for a real queue, the dispatcher in
 * `../webhooks/dispatcher.ts` handles delivery once via the eventBus path —
 * callers consume the returned envelope for synchronous use cases).
 */
export async function assembleRefusalDelivery(
  input: AssembleRefusalDeliveryInput,
  deps: {
    readonly store: G4RefusalStore;
    readonly eventBus?: G4RefusalEventBus;
    readonly now?: () => Date;
    readonly idFactory?: () => string;
  },
): Promise<AssembleRefusalDeliveryResult> {
  const handling = await handleG4Refusal(input, deps);
  const webhook: RefusalWebhookEnvelope = {
    event_id: handling.entry.refusal_id,
    schema_version: "s2-5.1",
    event_type: "g4.refused",
    created_at: handling.entry.refused_at,
    partner_id: handling.entry.partner_id,
    pda_id: handling.entry.pda_id,
    data: refusalEventData(handling.entry),
  };
  return {
    entry: handling.entry,
    blocking: handling.blocking,
    advisory: handling.advisory,
    webhook,
  };
}
