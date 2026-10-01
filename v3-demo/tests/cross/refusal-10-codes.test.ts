// Phase E E4 — 10 G4 refusal codes parameterized (S2-2 §14.2 + S2-3 §5 +
// WP §N NORMATIVE).
//
// 3-class breakdown asserted independently:
//   per-commit-blocking (5):  0x01 0x02 0x03 0x04 0x05
//     • 0x02 + 0x03 are encrypted-reason mode (S2-2 §14.3)
//   class-wide-blocking (4):  0x06 0x07 0x08 0x09
//     • each invokes its dedicated deprecation ceremony per
//       REFUSAL_DEPRECATION_CEREMONY_MAP
//   advisory non-blocking (1): 0x0A
//     • synthesised advisory-marker outcome (recipient bundle remains success)

import { describe, it, expect } from "vitest";
import {
  runE4,
  runRefusalRow,
  REFUSAL_TABLE,
  RefusalCode,
  REASON_LABEL,
  isBlockingRefusal,
  isEncryptedReason,
  formatRefusalCodeHex,
} from "../../src/cross-round/refusal-escalation.js";

describe("Phase E4 — 10 G4 refusal codes (S2-2 §14.2 NORMATIVE)", () => {
  it("table has exactly 10 rows", () => {
    expect(REFUSAL_TABLE).toHaveLength(10);
  });

  it("class split is 5 + 4 + 1", () => {
    const perCommit = REFUSAL_TABLE.filter((r) => r.class === "per-commit-blocking");
    const classWide = REFUSAL_TABLE.filter((r) => r.class === "class-wide-blocking");
    const advisory = REFUSAL_TABLE.filter((r) => r.class === "advisory");
    expect(perCommit).toHaveLength(5);
    expect(classWide).toHaveLength(4);
    expect(advisory).toHaveLength(1);
  });

  it("codes 0x01-0x05 are per-commit-blocking", () => {
    for (const code of [0x01, 0x02, 0x03, 0x04, 0x05] as const) {
      const row = REFUSAL_TABLE.find((r) => r.code === code)!;
      expect(row.class).toBe("per-commit-blocking");
    }
  });

  it("codes 0x06-0x09 are class-wide-blocking and carry the correct ceremony slug", () => {
    const expectedSlugs: Readonly<Record<number, string>> = {
      0x06: "plugin-version-update",
      0x07: "g4-authority-rotation",
      0x08: "dsl-version-update",
      0x09: "oracle-rotation",
    };
    for (const code of [0x06, 0x07, 0x08, 0x09] as const) {
      const row = REFUSAL_TABLE.find((r) => r.code === code)!;
      expect(row.class).toBe("class-wide-blocking");
      expect(row.ceremonySlug).toBe(expectedSlugs[code]);
    }
  });

  it("code 0x0A is advisory and expectedRecipientBundleKind = success-with-advisory-marker", () => {
    const row = REFUSAL_TABLE.find((r) => r.code === RefusalCode.OptOutActive)!;
    expect(row.class).toBe("advisory");
    expect(row.expectedRecipientBundleKind).toBe("success-with-advisory-marker");
  });

  it("encryptedReasonDefault aligns with REASON_VISIBILITY for every row", () => {
    for (const row of REFUSAL_TABLE) {
      expect(row.encryptedReasonDefault).toBe(isEncryptedReason(row.code));
    }
  });

  describe("Per-row execution — 10 codes", () => {
    for (const row of REFUSAL_TABLE) {
      const hex = formatRefusalCodeHex(row.code);
      it(`${hex} ${row.name}: produces ${row.expectedRecipientBundleKind} bundle`, async () => {
        const outcome = await runRefusalRow(row);
        expect(outcome.row.code).toBe(row.code);
        expect(outcome.recipientBundleKind).toBe(row.expectedRecipientBundleKind);
        expect(outcome.refusalEntry.reason_code).toBe(row.code);
        expect(outcome.refusalEntry.reason_code_hex).toBe(hex);
        expect(outcome.refusalEntry.reason_label).toBe(REASON_LABEL[row.code]);
        expect(outcome.refusalEntry.blocking).toBe(isBlockingRefusal(row.code));
      });
    }
  });

  it("0x02 art_17_erasure: encrypted-reason mode + encrypted_reason_ref populated", async () => {
    const row = REFUSAL_TABLE.find((r) => r.code === RefusalCode.Art17Erasure)!;
    const outcome = await runRefusalRow(row);
    expect(outcome.refusalEntry.reason_visibility).toBe("encrypted");
    expect(outcome.refusalEntry.encrypted_reason_ref).toBeDefined();
    expect(outcome.refusalEntry.encrypted_reason_ref).toMatch(/^ipfs:\/\//);
  });

  it("0x03 art_18_restriction: encrypted-reason mode + encrypted_reason_ref populated", async () => {
    const row = REFUSAL_TABLE.find((r) => r.code === RefusalCode.Art18Restriction)!;
    const outcome = await runRefusalRow(row);
    expect(outcome.refusalEntry.reason_visibility).toBe("encrypted");
    expect(outcome.refusalEntry.encrypted_reason_ref).toBeDefined();
  });

  it("0x01 legal_compel: plaintext reason (no encrypted_reason_ref)", async () => {
    const row = REFUSAL_TABLE.find((r) => r.code === RefusalCode.LegalCompel)!;
    const outcome = await runRefusalRow(row);
    expect(outcome.refusalEntry.reason_visibility).toBe("plaintext");
    expect(outcome.refusalEntry.encrypted_reason_ref).toBeUndefined();
  });

  describe("Class-wide deprecation ceremony invocation (0x06-0x09)", () => {
    for (const code of [0x06, 0x07, 0x08, 0x09] as const) {
      const row = REFUSAL_TABLE.find((r) => r.code === code)!;
      const hex = formatRefusalCodeHex(row.code);
      it(`${hex} ${row.name}: deprecation ceremony completes successfully`, async () => {
        const outcome = await runRefusalRow(row);
        expect(outcome.deprecationCeremonyCompleted).toBe(true);
        expect(outcome.ceremonyOutcome).not.toBeNull();
        expect(outcome.ceremonyOutcome?.success).toBe(true);
        expect(outcome.ceremonyOutcome?.slug).toBe(row.ceremonySlug);
      });
    }
  });

  it("0x0A opt_out_active: advisory marker, NO webhook event, combiner CONTINUES", async () => {
    const row = REFUSAL_TABLE.find((r) => r.code === RefusalCode.OptOutActive)!;
    const outcome = await runRefusalRow(row);
    expect(outcome.recipientBundleKind).toBe("success-with-advisory-marker");
    expect(outcome.advisoryMarker).toBeDefined();
    expect(outcome.advisoryMarker?.blocks_reveal).toBe(false);
    expect(outcome.advisoryMarker?.signal_kind).toBe("AdvisorySignal");
    expect(outcome.advisoryMarker?.reason_code).toBe(0x0a);
    expect(outcome.combinerFailedClosed).toBe(false);
    expect(outcome.webhookEvent).toBeNull();
  });

  it("0x01-0x09: combiner fail-closed (combinerFailedClosed === true)", async () => {
    const blocking = REFUSAL_TABLE.filter((r) => r.class !== "advisory");
    for (const row of blocking) {
      const outcome = await runRefusalRow(row);
      expect(outcome.combinerFailedClosed).toBe(true);
    }
  });

  it("0x01-0x09: webhook event_type === 'g4.refused'", async () => {
    const blocking = REFUSAL_TABLE.filter((r) => r.class !== "advisory");
    for (const row of blocking) {
      const outcome = await runRefusalRow(row);
      expect(outcome.webhookEvent).not.toBeNull();
      expect(outcome.webhookEvent?.event_type).toBe("g4.refused");
    }
  });

  it("runE4 returns 10 outcomes with the class breakdown 5+4+1", async () => {
    const outcomes = await runE4();
    expect(outcomes).toHaveLength(10);
    const refusals = outcomes.filter((o) => o.recipientBundleKind === "refusal");
    const advisory = outcomes.filter((o) => o.recipientBundleKind === "success-with-advisory-marker");
    expect(refusals).toHaveLength(9);
    expect(advisory).toHaveLength(1);
  });
});
