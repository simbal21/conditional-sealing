// HMAC canonical-request builder — verbatim from S2-5 §1.2 lines 164-171.
//
// LOCKED at Phase A (signature only). Phase D middleware implements body.
//
// Critical: TWO DIFFERENT HMAC SCHEMES (per §1.2 + §7.2). Do NOT swap:
//
// 1. Partner REQUEST canonical-request (this file):
//      METHOD "\n"
//      PATH_WITH_QUERY "\n"
//      X-Cealis-Timestamp "\n"
//      X-Cealis-Nonce "\n"
//      sha256(raw_request_body)
//
// 2. WEBHOOK signature input (§7.2 line 837 — see `src/webhooks/signer.ts`):
//      utf8(X-Cealis-Timestamp) "." raw_request_body
//
// Phase A foundation test asserts the round-trip vector from §1.2 prose.

import type { CanonicalRequestInput } from "../types/auth.js";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex } from "@noble/hashes/utils";

/**
 * Build the canonical request preimage per §1.2.
 *
 * NOTE: `\n` is the literal LF byte (0x0A), not CRLF. UTF-8 encoded.
 *
 * Returns a Uint8Array suitable for `hmac(sha256, signingSecret, preimage)`.
 *
 * Phase A signature only — body is mechanical; Phase D smoke-tests against
 * the §1.2 example.
 */
export function buildCanonicalRequest(input: CanonicalRequestInput): Uint8Array {
  const bodyDigest = bytesToHex(sha256(input.rawRequestBody));
  const text =
    `${input.method}\n` +
    `${input.pathWithQuery}\n` +
    `${input.timestamp}\n` +
    `${input.nonce}\n` +
    bodyDigest;
  return new TextEncoder().encode(text);
}

/**
 * Webhook signature preimage per §7.2 line 837:
 *
 *   `utf8(X-Cealis-Timestamp) "." raw_request_body`
 *
 * Note: the literal "." is a single ASCII byte (0x2E), not a separator pattern.
 * `raw_request_body` is the byte sequence delivered on the wire — NOT JSON-
 * normalized.
 *
 * verify-sdk also uses this preimage. Phase E re-implements; Phase A locks
 * the signature here so Phase D server-side webhook signer matches.
 */
export function buildWebhookSignaturePreimage(
  timestamp: string,
  rawRequestBody: Uint8Array,
): Uint8Array {
  const timestampBytes = new TextEncoder().encode(timestamp);
  const dotByte = new Uint8Array([0x2e]);
  const preimage = new Uint8Array(timestampBytes.length + 1 + rawRequestBody.length);
  preimage.set(timestampBytes, 0);
  preimage.set(dotByte, timestampBytes.length);
  preimage.set(rawRequestBody, timestampBytes.length + 1);
  return preimage;
}
