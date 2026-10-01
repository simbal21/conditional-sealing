// Closure-proving tests for security-audit-2026-06-02:
//   - TS-API-F-05 (HIGH): Stage 3 PDA validation was a structural no-op
//     (adaptToStage3 / buildStage3Context ignored the submitted PDA and
//     synthesized surfaces from CLASS_TABLE_ROWS so Stage 3 ALWAYS passed).
//   - TS-API-F-08 (MED): assertPartnerInputRequiredFields existed but had
//     ZERO callers; prepareSubmittedPda silently coerced a missing partner_id
//     into the synthetic `partner_fixture` attribution.
//
// Each test exercises the real attack path and FAILS against the vulnerable
// code (pre-fix) / PASSES against the fixed code.

import { describe, expect, it } from "vitest";
import { kycLendingSubmittedPda } from "../../fixtures/app-a/index.js";
import {
  PartnerInputMissingRequiredFieldsError,
  adaptToStage3,
  buildStage3Context,
  emitPDA,
  prepareSubmittedPda,
  validatePDA,
} from "../../src/pda/emit.js";
import { validateStage3Pda } from "../../src/validate/stage3/index.js";
import { scaffoldFor } from "../../src/cli/init.js";

describe("TS-API-F-05 — Stage 3 validates the REAL submitted PDA (no longer synthetic↔synthetic)", () => {
  it("positive control: a legitimate prepared PDA still passes Stage 3", () => {
    const report = validatePDA(kycLendingSubmittedPda);
    // The fix must not regress the legitimate path — Stage 3 sees real values
    // that ARE within the PDA+ allow-list / bounds policy.
    expect(report.stage3).toEqual([]);
    expect(report.ok).toBe(true);
  });

  it("rejects a category-(c) parameter value outside the PDA+ bounds (end-to-end)", async () => {
    // retention_seconds survives prepareSubmittedPda untouched (toNumber pass-through)
    // and is a non-negative safe integer, so it clears Stage 1 (duration check)
    // and Stage 2, then reaches Stage 3. 9_999_999_999 > the PDA+ ceiling
    // (3_153_600_000 = 100 years), so Stage 3 MUST now reject it.
    //
    // PRE-FIX: adaptToStage3 ignored `submitted` and emitted only synthetic
    // in-bounds values, so this out-of-bounds retention NEVER reached the
    // bounds checker and validation incorrectly passed.
    const malicious = { ...kycLendingSubmittedPda, retention_seconds: 9_999_999_999 };
    const report = validatePDA(malicious);

    expect(report.ok).toBe(false);
    expect(report.stage3.length).toBeGreaterThan(0);
    const retentionFailure = report.stage3.find((failure) =>
      failure.stage_code.includes("retention_window_value"),
    );
    expect(retentionFailure).toBeDefined();
    expect(retentionFailure?.internal.failed_predicate).toContain("bounds");

    // emitPDA must also refuse to emit the malicious PDA.
    await expect(
      emitPDA(malicious, { allowFixtureDefaults: true }),
    ).rejects.toThrowError(/Stage 3 validation failed/);
  });

  it("accepts a REGISTERED template_id but REJECTS a bogus content-addressed template_id (end-to-end)", () => {
    // Positive: the shipping kyc-lending template_id is in the registered
    // content-addressed template catalog, so the template-pick surface (row 54)
    // passes — no ALLOW_LIST_MISSING, no TEMPLATE_ID_INACTIVE.
    expect(validatePDA(kycLendingSubmittedPda).stage3).toEqual([]);

    // Negative: a well-formed content-addressed id that is NOT in the registry
    // must STILL be rejected. Pre-fix `activeTemplateIds` was sourced from the
    // submitted PDA itself, so this self-validated — the no-op the fix closes.
    const bogusTemplate = `0x${"a".repeat(64)}`;
    const forgedTopLevel = { ...kycLendingSubmittedPda, template_id: bogusTemplate };
    const topLevelReport = validatePDA(forgedTopLevel);
    expect(topLevelReport.ok).toBe(false);
    const topLevelFailure = topLevelReport.stage3.find((failure) =>
      failure.stage_code.includes("template_id_pick"),
    );
    expect(topLevelFailure).toBeDefined();
    expect(topLevelFailure?.internal.failed_predicate).toContain("not active");

    // Same for the condition template pick (row 56.1).
    const forgedCondition = {
      ...kycLendingSubmittedPda,
      reveal_condition: {
        ...(kycLendingSubmittedPda.reveal_condition as Record<string, unknown>),
        template_pick: bogusTemplate,
      },
    };
    const conditionReport = validatePDA(forgedCondition);
    expect(conditionReport.ok).toBe(false);
    expect(
      conditionReport.stage3.find((failure) =>
        failure.stage_code.includes("payment_obligation_template_pick"),
      ),
    ).toBeDefined();
  });

  it("rejects a category-(b) pick whose REAL value is not in the PDA+ allow-list", () => {
    // Direct adaptToStage3 / buildStage3Context exercise: prove the submitted
    // value now flows through to the allow-list checker. A rogue g3_choice
    // (row 41) that is NOT in {dcipher, drand} must produce a Stage 3 failure.
    //
    // PRE-FIX: adaptToStage3(_submitted) discarded its argument and emitted
    // `allowed:41`, so this rogue value was structurally invisible and Stage 3
    // passed.
    const rogue = { ...kycLendingSubmittedPda, g3_choice: "rogue_threshold_network" };

    const surfaces = adaptToStage3(rogue);
    const g3Surface = surfaces.surfaces.find((surface) => surface.rowId === "41");
    expect(g3Surface).toBeDefined();
    // The surface carries the REAL submitted value, not a fixture.
    expect(g3Surface?.value).toBe("rogue_threshold_network");

    const failures = validateStage3Pda(surfaces, buildStage3Context(rogue));
    const g3Failure = failures.find((failure) => failure.stage_code.includes("g3_choice"));
    expect(g3Failure).toBeDefined();
    expect(g3Failure?.internal.failed_predicate).toContain("allow-list");

    // Sanity: the same surfaces against the same context PASS when the value
    // IS allowed — proving the check is genuine, not a blanket reject.
    const allowed = { ...kycLendingSubmittedPda, g3_choice: "drand" };
    const allowedSurfaces = adaptToStage3(allowed);
    const allowedG3 = allowedSurfaces.surfaces.find((surface) => surface.rowId === "41");
    expect(allowedG3?.value).toBe("drand");
    expect(
      validateStage3Pda(allowedSurfaces, buildStage3Context(allowed)).find((failure) =>
        failure.stage_code.includes("g3_choice"),
      ),
    ).toBeUndefined();
  });
});

describe("TS-API-F-08 — partner-supplied required fields are enforced at the boundary", () => {
  // A realistic raw partner PDA: the proven-valid KYC scaffold body (passes
  // Stages 1-5 per cli-init-smoke) PLUS the two required fields the scaffold
  // omits and the new guard requires (pda_id, pda_version). All 5
  // partner-supplied required fields are present.
  const rawPartnerInput = (): Record<string, unknown> => ({
    ...scaffoldFor("kyc-lending"),
    partner_id: "partner_real",
    pda_id: "pda_real_001",
    pda_version: 1,
  });

  it("validatePDA rejects a partner PDA missing partner_id (no silent fixture attribution)", () => {
    const { partner_id: _omit, ...missingPartnerId } = rawPartnerInput();
    expect(() => validatePDA(missingPartnerId)).toThrowError(PartnerInputMissingRequiredFieldsError);
    try {
      validatePDA(missingPartnerId);
    } catch (error) {
      expect(error).toBeInstanceOf(PartnerInputMissingRequiredFieldsError);
      expect((error as PartnerInputMissingRequiredFieldsError).code).toBe("MISSING_REQUIRED_FIELD");
      expect((error as PartnerInputMissingRequiredFieldsError).missingFields).toContain("partner_id");
    }
  });

  it("emitPDA rejects a partner PDA missing partner_id (would otherwise forge attribution)", async () => {
    const { partner_id: _omit, ...missingPartnerId } = rawPartnerInput();
    await expect(emitPDA(missingPartnerId)).rejects.toThrowError(
      PartnerInputMissingRequiredFieldsError,
    );
  });

  it("demonstrates the bypass the guard closes: without the guard the missing partner_id becomes 'partner_fixture'", () => {
    const { partner_id: _omit, ...missingPartnerId } = rawPartnerInput();
    // prepareSubmittedPda is the unguarded internal primitive — it STILL forges
    // the synthetic attribution. The guard at the boundary (validatePDA/emitPDA)
    // is what prevents that input from ever reaching here unflagged.
    const forged = prepareSubmittedPda(missingPartnerId);
    expect(forged.partner_id).toBe("partner_fixture");
  });

  it("internal fixtures may opt out of the guard via allowFixtureDefaults", async () => {
    // A prepared fixture has all required fields, so the guard passes anyway —
    // but the opt-out path is the documented escape hatch for generators that
    // legitimately rely on defaults. emit must succeed.
    const artifact = await emitPDA(
      kycLendingSubmittedPda as unknown as Record<string, unknown>,
      { allowFixtureDefaults: true },
    );
    expect(artifact.pdaRoot).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it("a fully-specified partner PDA still validates and emits", async () => {
    const report = validatePDA(rawPartnerInput());
    expect(report.ok).toBe(true);
    const artifact = await emitPDA(rawPartnerInput());
    expect(artifact.submitted.partner_id).toBe("partner_real");
  });
});
