// @cealis/verify-sdk — verifyRefusalArtifact
//
// Closes an internal integration-gap item (2026-05-14).
//
// Recipient-side verification of a G4 refusal payload delivered per
// S2-5 §3.6. Composes the existing HMAC webhook verifier
// (`verifyWebhook`) with content validation of the `RefusalEntryShape`:
//
//   * webhook signature + replay window
//   * `event_type === "g4.refused"` discriminator
//   * reason_code in 0x01..0x0A
//   * `encrypted_reason_ref` present iff reason_code in {0x02, 0x03}
//   * reason_visibility matches the encrypted-reason class
//   * blocking flag matches the code's blocking class (0x01..0x09 blocking,
//     0x0A advisory)
//   * reason_code_hex matches the numeric code's 0xNN form
//
// INDEPENDENCE INVARIANT (S2-5 §4.7 + §9.1): this file does NOT import
// @cealis/v3-api, @cealis/v3-custody, axios, node-fetch, or any Cealis URL.
// The refusal-entry shape is declared STRUCTURALLY in ./types.ts so
// `@cealis/v3-api`'s `G4RefusalEntry` is assignment-compatible without
// import.

import { verifyWebhook } from "./verify-webhook.js";
import { failCheck, passCheck } from "./checks/canonicalization.js";
import type {
  RefusalEntryShape,
  VerifyCheck,
  VerifyRefusalArtifactInput,
  VerifyRefusalArtifactResult,
  VerifyStatus,
} from "./types.js";
import {
  REFUSAL_BLOCKING_MAX,
  REFUSAL_ENCRYPTED_REASON_CODES,
  REFUSAL_REASON_CODE_MAX,
  REFUSAL_REASON_CODE_MIN,
} from "./types.js";

const REFUSAL_EVENT_TYPE = "g4.refused";

/**
 * Verifies a G4 refusal artifact delivered via webhook.
 *
 * Returns `{verified: true, kind: "refusal", reasonCode}` when ALL of:
 *   1. webhook HMAC + replay window pass
 *   2. webhook event_type === "g4.refused" (via header + parsed body)
 *   3. refusalEntry.reason_code is in 0x01..0x0A
 *   4. encrypted_reason_ref present iff visibility === "encrypted"
 *      (mandatory for 0x02 / 0x03 per S2-2 §14.3)
 *   5. reason_visibility matches the encrypted-reason class
 *   6. blocking flag matches the code's blocking class
 *   7. reason_code_hex matches the numeric code
 *
 * If webhook verification fails, returns `{verified: false}` early without
 * inspecting the refusalEntry — content validation MUST NOT run before
 * signature passes (mirrors `verifyWebhook` parser-differential discipline).
 *
 * Safe-refs surface: only reason_code_hex, reason_label, reason_visibility,
 * blocking, event_id, partner_id, pda_id leak into check.safe_refs — never PII.
 */
export async function verifyRefusalArtifact(
  input: VerifyRefusalArtifactInput,
): Promise<VerifyRefusalArtifactResult> {
  const webhookResult = await verifyWebhook(
    input.webhookBody,
    input.webhookHeaders,
    input.webhookSecret,
    input.now ?? new Date(),
  );

  const entry = input.refusalEntry;

  // Webhook signature gate — if signature failed, return early. Do NOT
  // inspect entry; this mirrors verifyWebhook's parser-differential
  // discipline. Content checks are surfaced as "skipped" since the
  // pre-condition failed.
  if (webhookResult.checks.signature.status !== "pass") {
    return earlyFail(webhookResult, entry, "REFUSAL.WEBHOOK_SIGNATURE_PRECONDITION_FAILED");
  }

  // Webhook overall (timestamp + replay) gate — same discipline.
  if (webhookResult.overall === "fail") {
    return earlyFail(webhookResult, entry, "REFUSAL.WEBHOOK_PRECONDITION_FAILED");
  }

  // 2. event_type discriminator
  const headerEvent = input.webhookHeaders["x-cealis-event"];
  const bodyEvent = webhookResult.event_type;
  const eventTypeCheck: VerifyCheck =
    bodyEvent === REFUSAL_EVENT_TYPE && headerEvent === REFUSAL_EVENT_TYPE
      ? passCheck("REFUSAL.EVENT_TYPE.PASS", {
          event_type: REFUSAL_EVENT_TYPE,
          ...(webhookResult.event_id === undefined ? {} : { event_id: webhookResult.event_id }),
        })
      : failCheck(
          "REFUSAL.EVENT_TYPE.MISMATCH",
          `Webhook event_type must be "${REFUSAL_EVENT_TYPE}" in BOTH header and body.`,
          {
            header_event_type: headerEvent,
            body_event_type: bodyEvent ?? "<absent>",
          },
        );

  // 3. reason_code range
  const rc = entry.reason_code;
  const reasonCodeCheck: VerifyCheck =
    Number.isInteger(rc) && rc >= REFUSAL_REASON_CODE_MIN && rc <= REFUSAL_REASON_CODE_MAX
      ? passCheck("REFUSAL.REASON_CODE.PASS", { reason_code_hex: entry.reason_code_hex })
      : failCheck(
          "REFUSAL.REASON_CODE.OUT_OF_RANGE",
          `reason_code must be 0x01..0x0A; received ${entry.reason_code_hex}.`,
          { reason_code_hex: entry.reason_code_hex },
        );

  // 4. encrypted_reason_ref required iff reason_code in {0x02, 0x03}.
  const requiresEncryptedReason = (REFUSAL_ENCRYPTED_REASON_CODES as readonly number[]).includes(rc);
  const hasEncryptedReason = entry.encrypted_reason_ref !== undefined;
  const encryptedReasonCheck: VerifyCheck =
    requiresEncryptedReason === hasEncryptedReason
      ? passCheck("REFUSAL.ENCRYPTED_REASON.PASS", {
          reason_code_hex: entry.reason_code_hex,
          encrypted_reason_required: requiresEncryptedReason,
        })
      : failCheck(
          requiresEncryptedReason
            ? "REFUSAL.ENCRYPTED_REASON.MISSING"
            : "REFUSAL.ENCRYPTED_REASON.UNEXPECTED",
          requiresEncryptedReason
            ? "encrypted_reason_ref is mandatory for reason_code 0x02 / 0x03."
            : "encrypted_reason_ref must only be present for reason_code 0x02 / 0x03.",
          {
            reason_code_hex: entry.reason_code_hex,
            encrypted_reason_required: requiresEncryptedReason,
            encrypted_reason_present: hasEncryptedReason,
          },
        );

  // 5. reason_visibility consistency with encrypted-reason class.
  const expectedVisibility = requiresEncryptedReason ? "encrypted" : "plaintext";
  const visibilityCheck: VerifyCheck =
    entry.reason_visibility === expectedVisibility
      ? passCheck("REFUSAL.VISIBILITY.PASS", {
          reason_visibility: entry.reason_visibility,
          reason_code_hex: entry.reason_code_hex,
        })
      : failCheck(
          "REFUSAL.VISIBILITY.MISMATCH",
          `reason_visibility must be "${expectedVisibility}" for reason_code ${entry.reason_code_hex}.`,
          {
            reason_visibility: entry.reason_visibility,
            reason_code_hex: entry.reason_code_hex,
            expected_visibility: expectedVisibility,
          },
        );

  // 6. blocking flag consistency.
  const expectedBlocking = rc >= REFUSAL_REASON_CODE_MIN && rc <= REFUSAL_BLOCKING_MAX;
  const blockingCheck: VerifyCheck =
    entry.blocking === expectedBlocking
      ? passCheck("REFUSAL.BLOCKING.PASS", {
          blocking: entry.blocking,
          reason_code_hex: entry.reason_code_hex,
        })
      : failCheck(
          "REFUSAL.BLOCKING.MISMATCH",
          `blocking flag must be ${expectedBlocking} for reason_code ${entry.reason_code_hex}.`,
          {
            blocking: entry.blocking,
            reason_code_hex: entry.reason_code_hex,
            expected_blocking: expectedBlocking,
          },
        );

  // 7. reason_code_hex string format consistency.
  const expectedHex = formatRefusalCodeHex(rc);
  const reasonCodeHexCheck: VerifyCheck =
    entry.reason_code_hex === expectedHex
      ? passCheck("REFUSAL.REASON_CODE_HEX.PASS", { reason_code_hex: entry.reason_code_hex })
      : failCheck(
          "REFUSAL.REASON_CODE_HEX.MISMATCH",
          `reason_code_hex "${entry.reason_code_hex}" must match numeric code formatted as "${expectedHex}".`,
          {
            reason_code_hex: entry.reason_code_hex,
            expected_reason_code_hex: expectedHex,
          },
        );

  const contentChecks: VerifyCheck[] = [
    eventTypeCheck,
    reasonCodeCheck,
    encryptedReasonCheck,
    visibilityCheck,
    blockingCheck,
    reasonCodeHexCheck,
  ];

  const allChecks: VerifyCheck[] = [...Object.values(webhookResult.checks), ...contentChecks];
  const verified =
    webhookResult.overall === "pass" &&
    contentChecks.every((c) => c.status === "pass");

  const result: VerifyRefusalArtifactResult = {
    verified,
    kind: "refusal",
    reasonCode: rc,
    reasonLabel: entry.reason_label,
    reasonVisibility: entry.reason_visibility,
    ...(entry.encrypted_reason_ref === undefined ? {} : { encryptedReasonRef: entry.encrypted_reason_ref }),
    blocking: entry.blocking,
    checks: {
      webhook: webhookResult,
      eventType: eventTypeCheck,
      reasonCode: reasonCodeCheck,
      encryptedReason: encryptedReasonCheck,
      visibilityConsistency: visibilityCheck,
      blockingConsistency: blockingCheck,
      reasonCodeHex: reasonCodeHexCheck,
    },
  };

  // Discard unused locals (rollupOptimization hint; no behavior change).
  void allChecks;
  void overallStatus;

  return result;
}

// ---- Helpers --------------------------------------------------------------

function earlyFail(
  webhookResult: VerifyRefusalArtifactResult["checks"]["webhook"],
  entry: RefusalEntryShape,
  preconditionCode: string,
): VerifyRefusalArtifactResult {
  const skipped: VerifyCheck = {
    status: "skipped",
    code: preconditionCode,
    message: "Content checks skipped — webhook verification did not pass.",
    safe_refs: {},
  };
  return {
    verified: false,
    kind: "refusal",
    reasonCode: entry.reason_code,
    reasonLabel: entry.reason_label,
    reasonVisibility: entry.reason_visibility,
    ...(entry.encrypted_reason_ref === undefined ? {} : { encryptedReasonRef: entry.encrypted_reason_ref }),
    blocking: entry.blocking,
    checks: {
      webhook: webhookResult,
      eventType: skipped,
      reasonCode: skipped,
      encryptedReason: skipped,
      visibilityConsistency: skipped,
      blockingConsistency: skipped,
      reasonCodeHex: skipped,
    },
  };
}

function formatRefusalCodeHex(code: number): string {
  return `0x${code.toString(16).padStart(2, "0")}`;
}

function overallStatus(checks: readonly VerifyCheck[]): VerifyStatus {
  if (checks.some((c) => c.status === "fail")) return "fail";
  if (checks.every((c) => c.status === "skipped")) return "skipped";
  return "pass";
}
