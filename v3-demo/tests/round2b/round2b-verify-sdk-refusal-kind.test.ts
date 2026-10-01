// Step 6 — recipient verify-sdk returns `kind: 'refusal'`.
//
// PER BRIEF (hard-rule): result is `{ verified: true, kind: 'refusal',
// reasonCode: 0x02 }`. Assertion via Phase A `assertRefusalReasonCode`.
//
// NOTE on brief vs upstream: verify-sdk's `verifyArtifactBundle` handles
// SUCCESS bundles only (no `verifyRefusalArtifact` upstream). See
// the internal integration-gap log. Round 2b's recipient-side verification uses the
// existing surfaces:
//   1. Webhook signature via @cealis/verify-sdk's `verifyWebhook` (HMAC
//      verification — covered by M5/verify-sdk's own test suite, not here).
//   2. Refusal payload shape validation (this test layer) — what
//      `verifyRecipientRefusalPayload` produces.

import { describe, it, expect } from "vitest";
import {
  runRound2b,
  makeDefaultRound2bDependencies,
  verifyRecipientRefusalPayload,
} from "../../src/rounds/round2b.js";
import { RefusalCode } from "@cealis/v3-api";

describe("Round 2b — verify-sdk refusal kind (Step 6)", () => {
  it("Result.recipientVerify === { verified: true, kind: 'refusal', reasonCode: 0x02 }", async () => {
    const deps = makeDefaultRound2bDependencies();
    const result = await runRound2b(deps);
    expect(result.recipientVerify).toMatchObject({
      verified: true,
      kind: "refusal",
      reasonCode: 0x02,
      reasonLabel: "art_17_erasure",
      reasonVisibility: "encrypted",
      blocking: true,
    });
  });

  it("Webhook event_type === 'g4.refused' is the recipient-side discriminator", async () => {
    const deps = makeDefaultRound2bDependencies();
    const result = await runRound2b(deps);
    expect(result.webhookEvent.event_type).toBe("g4.refused");
  });

  it("Webhook event_id matches refusal_id (delivery <-> entry binding)", async () => {
    const deps = makeDefaultRound2bDependencies();
    const result = await runRound2b(deps);
    expect(result.webhookEvent.event_id).toBe(result.refusalEntry.refusal_id);
  });

  it("verifyRecipientRefusalPayload rejects WRONG event_type", () => {
    const result = verifyRecipientRefusalPayload({
      webhookEventType: "reveal.completed",
      refusalEntry: {
        refusal_id: "x",
        authorization_id: "0xaa".padEnd(66, "a") as `0x${string}`,
        h_commit: "0xbb".padEnd(66, "b") as `0x${string}`,
        partner_id: "p",
        pda_id: "pda",
        reason_code: RefusalCode.Art17Erasure,
        reason_code_hex: "0x02",
        reason_label: "art_17_erasure",
        reason_visibility: "encrypted",
        encrypted_reason_ref: "ipfs://x",
        refused_at: new Date().toISOString(),
        blocking: true,
      },
    });
    expect(result.verified).toBe(false);
  });

  it("verifyRecipientRefusalPayload rejects MISSING encrypted_reason_ref for 0x02", () => {
    const result = verifyRecipientRefusalPayload({
      webhookEventType: "g4.refused",
      refusalEntry: {
        refusal_id: "x",
        authorization_id: "0xaa".padEnd(66, "a") as `0x${string}`,
        h_commit: "0xbb".padEnd(66, "b") as `0x${string}`,
        partner_id: "p",
        pda_id: "pda",
        reason_code: RefusalCode.Art17Erasure,
        reason_code_hex: "0x02",
        reason_label: "art_17_erasure",
        reason_visibility: "encrypted",
        // encrypted_reason_ref intentionally omitted → invariant violation
        refused_at: new Date().toISOString(),
        blocking: true,
      },
    });
    expect(result.verified).toBe(false);
  });
});
