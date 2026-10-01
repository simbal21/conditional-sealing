import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { buildWebhookSignaturePreimage } from "../auth/canonical-request.js";
import { canonicalizeJcs } from "../bundle/canonicalize-jcs.js";
import { WEBHOOK_REPLAY_WINDOW_SECONDS, type WebhookDeliveryHeaders } from "../types/webhook-events.js";

const textEncoder = new TextEncoder();

export interface SignedWebhookBody {
  readonly rawBody: Uint8Array;
  readonly headers: WebhookDeliveryHeaders;
}

/**
 * Typed error thrown when the envelope body contains a JS value that has no
 * representation under RFC 8785 (JCS) canonicalization — e.g., `BigInt`,
 * non-finite numbers (NaN, ±Infinity), functions, symbols.
 *
 * Per the GATE-4 fail-closed discipline locked in `JCS-DESIGN-LOCK.md`: the
 * signer MUST surface this loudly rather than silently falling back to a
 * non-canonical serializer (which would re-introduce the canonicalization-
 * drift defect that this fix closes). The Rule-47 `safeRefs` carry the
 * offending type-name for downstream diagnostics without leaking payload
 * content.
 */
export class WebhookEnvelopeNotJcsCompatibleError extends Error {
  readonly safeRefs: {
    readonly cause_name: string;
    readonly cause_message: string;
  };
  constructor(cause: unknown) {
    const causeMessage = cause instanceof Error ? cause.message : String(cause);
    const causeName = cause instanceof Error ? cause.name : typeof cause;
    super(`WEBHOOK_ENVELOPE_NOT_JCS_COMPATIBLE: ${causeMessage}`);
    this.name = "WebhookEnvelopeNotJcsCompatibleError";
    this.safeRefs = { cause_name: causeName, cause_message: causeMessage };
  }
}

export function signWebhookEnvelope(input: {
  readonly envelope: { readonly event_id: string; readonly event_type: string };
  readonly body: unknown;
  readonly secret: Uint8Array | string;
  readonly timestamp?: string;
}): SignedWebhookBody {
  // JCS-canonical (RFC 8785) preimage construction — closes the
  // non-canonical-serializer drift vulnerability per JCS-DESIGN-LOCK.md.
  // canonicalizeJcs is the shared canonicalization seam used by bundle
  // assembly + per-recipient (single source of truth). GATE-4 fail-closed:
  // any envelope value that has no JCS representation throws
  // WebhookEnvelopeNotJcsCompatibleError rather than silently coercing.
  let rawBody: Uint8Array;
  try {
    rawBody = canonicalizeJcs(input.body);
  } catch (err) {
    throw new WebhookEnvelopeNotJcsCompatibleError(err);
  }
  const timestamp = input.timestamp ?? Math.floor(Date.now() / 1000).toString();
  const signature = webhookSignatureHex(timestamp, rawBody, input.secret);
  return {
    rawBody,
    headers: {
      "x-cealis-signature": `sha256=${signature}`,
      "x-cealis-timestamp": timestamp,
      "x-cealis-event": input.envelope.event_type,
      "x-cealis-delivery": input.envelope.event_id,
    },
  };
}

export function verifyWebhookSignature(input: {
  readonly rawBody: Uint8Array;
  readonly headers: WebhookDeliveryHeaders | Record<string, string | undefined>;
  readonly secret: Uint8Array | string;
  readonly now?: Date;
}): boolean {
  const timestamp = input.headers["x-cealis-timestamp"];
  const signature = input.headers["x-cealis-signature"];
  if (!timestamp || !signature || !/^sha256=[0-9a-f]+$/i.test(signature)) return false;
  const tsMs = Number(timestamp) * 1000;
  if (!Number.isFinite(tsMs)) return false;
  const nowMs = (input.now ?? new Date()).getTime();
  if (Math.abs(nowMs - tsMs) > WEBHOOK_REPLAY_WINDOW_SECONDS * 1000) return false;
  const expected = `sha256=${webhookSignatureHex(timestamp, input.rawBody, input.secret)}`;
  return constantTimeAsciiEqual(expected, signature);
}

export function webhookSignatureHex(timestamp: string, rawBody: Uint8Array, secret: Uint8Array | string): string {
  const preimage = buildWebhookSignaturePreimage(timestamp, rawBody);
  return bytesToHex(hmac(sha256, secretBytes(secret), preimage));
}

function secretBytes(secret: Uint8Array | string): Uint8Array {
  if (secret instanceof Uint8Array) return secret;
  if (/^0x[0-9a-fA-F]+$/.test(secret) && secret.length % 2 === 0) return hexToBytes(secret.slice(2));
  return textEncoder.encode(secret);
}

function constantTimeAsciiEqual(left: string, right: string): boolean {
  const a = textEncoder.encode(left);
  const b = textEncoder.encode(right);
  const len = Math.max(a.length, b.length);
  let diff = a.length ^ b.length;
  for (let index = 0; index < len; index += 1) diff |= (a[index] ?? 0) ^ (b[index] ?? 0);
  return diff === 0;
}
